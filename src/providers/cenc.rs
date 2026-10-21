use super::ProviderCursor;
use crate::models::{DisasterCategory, DisasterEvent, ProviderChannel, event_update_id};
use crate::runtime::{EventRuntime, RuntimeStatus};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::sync::watch;

const APP_ID: &str = "dkcxbftqof0h";
const VERSION_URL: &str = "https://yjfw.cenc.ac.cn/api/earthquake/event/v1/version";
const LIST_URL: &str = "https://dzyj.cenc.ac.cn/api/earthquake/event/cdn/v1/list";
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const PAGE_SIZE: usize = 20;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct CencSource {
    event_runtime: EventRuntime,
    client: reqwest::Client,
    reconnect_min: Duration,
    reconnect_max: Duration,
    runtime_status: RuntimeStatus,
}

impl CencSource {
    pub(crate) fn new(
        config: &crate::config::Config,
        event_runtime: EventRuntime,
        runtime_status: RuntimeStatus,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("disaster-alert/1.0 (https://github.com/noctiro/disaster-alert)")
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(2)
            .build()
            .context("failed to build CENC HTTP client")?;
        Ok(Self {
            event_runtime,
            client,
            reconnect_min: Duration::from_secs(config.reconnect_min_seconds),
            reconnect_max: Duration::from_secs(config.reconnect_max_seconds),
            runtime_status,
        })
    }

    pub(crate) async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let cursors = self
            .event_runtime
            .provider_cursors(
                ProviderChannel::Cenc,
                vec!["warning".to_string(), "report".to_string()],
            )
            .await?;
        let mut known = BTreeMap::new();
        for cursor in cursors {
            known.insert(
                cursor.stream().to_string(),
                CencCursor::decode(cursor.value())?,
            );
        }
        let mut delay = self.reconnect_min;
        loop {
            if *shutdown.borrow() {
                break;
            }
            let result = tokio::select! {
                biased;
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() { break; }
                    continue;
                }
                result = self.poll(&mut known, VERSION_URL, LIST_URL) => result,
            };
            let pause = match result {
                Ok(()) => {
                    self.runtime_status.cenc().set_connected(true);
                    self.runtime_status.cenc().record_message();
                    delay = self.reconnect_min;
                    POLL_INTERVAL
                }
                Err(error) => {
                    self.runtime_status.cenc().set_connected(false);
                    self.runtime_status.cenc().record_reconnect();
                    tracing::error!(event = "cenc.poll_failed", error = ?error, "cenc.poll_failed");
                    let pause = delay.max(POLL_INTERVAL);
                    delay = delay.saturating_mul(2).min(self.reconnect_max);
                    pause
                }
            };
            tokio::select! {
                biased;
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() { break; }
                }
                () = tokio::time::sleep(pause) => {}
            }
        }
        self.runtime_status.cenc().set_connected(false);
        Ok(())
    }

    async fn poll(
        &self,
        known: &mut BTreeMap<String, CencCursor>,
        version_url: &str,
        list_url: &str,
    ) -> Result<()> {
        let versions: Versions = fetch(&self.client, version_url, &[("app_id", APP_ID)])
            .await
            .inspect_err(|_| self.runtime_status.cenc().record_parse_error())?;
        let mut failures = Vec::new();
        for (stream, version) in [
            (CencStream::Warning, versions.warning_version),
            (CencStream::Report, versions.report_version),
        ] {
            let previous = known.get(stream.key());
            if previous.is_some_and(|cursor| cursor.version == version) {
                continue;
            }
            let poll = fetch_snapshot(&self.client, list_url, stream, version, previous).await;
            let poll = match poll {
                Ok(poll) => poll,
                Err(error) => {
                    self.runtime_status.cenc().record_parse_error();
                    failures.push(format!("{}: {error:#}", stream.key()));
                    continue;
                }
            };
            let cursor = ProviderCursor::new(stream.key(), serde_json::to_string(&poll.cursor)?)?;
            if !self
                .event_runtime
                .submit_provider_batch(ProviderChannel::Cenc, poll.events, cursor)
                .await
            {
                bail!("CENC event batch was not durably committed");
            }
            known.insert(stream.key().to_string(), poll.cursor);
        }
        ensure!(
            failures.is_empty(),
            "CENC streams failed: {}",
            failures.join("; ")
        );
        Ok(())
    }
}

async fn fetch<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    query: &[(&str, &str)],
) -> Result<T> {
    let mut url = reqwest::Url::parse(url).context("invalid CENC URL")?;
    url.query_pairs_mut().extend_pairs(query.iter().copied());
    let mut response = client
        .get(url)
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        .send()
        .await
        .context("CENC request failed")?
        .error_for_status()
        .context("CENC service returned an HTTP error")?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        bail!("CENC response exceeds {MAX_RESPONSE_BYTES} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read CENC response")?
    {
        ensure!(
            body.len().saturating_add(chunk.len()) <= MAX_RESPONSE_BYTES,
            "CENC response is too large"
        );
        body.extend_from_slice(&chunk);
    }
    let response: ApiResponse<T> =
        serde_json::from_slice(&body).context("invalid CENC response")?;
    ensure!(
        response.code == 0,
        "CENC service returned code {}: {}",
        response.code,
        response.msg
    );
    response.data.context("CENC response is missing data")
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    code: i64,
    #[serde(default)]
    msg: String,
    data: Option<T>,
}

#[derive(Deserialize)]
struct Versions {
    warning_version: String,
    report_version: String,
}

#[derive(Clone, Copy)]
enum CencStream {
    Warning,
    Report,
}

impl CencStream {
    fn key(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Report => "report",
        }
    }

    fn alarm_type(self) -> &'static str {
        match self {
            Self::Warning => "2",
            Self::Report => "1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CencCursor {
    version: String,
    events: BTreeMap<String, String>,
}

impl CencCursor {
    fn decode(value: &str) -> Result<Self> {
        let cursor: Self = serde_json::from_str(value).context("invalid CENC cursor")?;
        validate_version(&cursor.version)?;
        ensure!(
            cursor.events.len() <= PAGE_SIZE,
            "CENC cursor contains too many events"
        );
        Ok(cursor)
    }
}

struct CencPoll {
    events: Vec<DisasterEvent>,
    cursor: CencCursor,
}

#[derive(Deserialize)]
struct EventList {
    spot_infos: Vec<Earthquake>,
}

#[derive(Clone, Deserialize)]
struct Earthquake {
    id: String,
    location: String,
    level: String,
    depth: Option<f64>,
    latitude: f64,
    longitude: f64,
    epicenter_intensity: Option<f64>,
    serial_number: Option<u32>,
    created_at: i64,
}

fn validate_version(version: &str) -> Result<()> {
    ensure!(
        !version.is_empty()
            && version.len() <= 64
            && version.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid CENC version"
    );
    Ok(())
}

async fn fetch_snapshot(
    client: &reqwest::Client,
    url: &str,
    stream: CencStream,
    version: String,
    known: Option<&CencCursor>,
) -> Result<CencPoll> {
    validate_version(&version)?;
    let list: EventList = fetch(
        client,
        url,
        &[
            ("app_id", APP_ID),
            ("alarm_type", stream.alarm_type()),
            ("page_no", "1"),
            ("page_size", "20"),
            ("v", &version),
        ],
    )
    .await?;
    prepare_snapshot(stream, version, list.spot_infos, known)
}

fn prepare_snapshot(
    stream: CencStream,
    version: String,
    snapshot: Vec<Earthquake>,
    known: Option<&CencCursor>,
) -> Result<CencPoll> {
    ensure!(
        snapshot.len() <= PAGE_SIZE,
        "CENC snapshot contains too many events"
    );
    let mut cursor = CencCursor {
        version,
        events: BTreeMap::new(),
    };
    let mut events = Vec::new();
    for earthquake in snapshot {
        let event = normalize(stream, earthquake)?;
        let digest = event_update_id(&event);
        ensure!(
            cursor
                .events
                .insert(event.event_id.clone(), digest.clone())
                .is_none(),
            "duplicate CENC event ID"
        );
        // 首次列表作为历史基线；后续查询发送新增事件及内容发生变化的事件。
        if known.is_some_and(|known| known.events.get(&event.event_id) != Some(&digest)) {
            events.push(event);
        }
    }
    events.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then(left.report_num.cmp(&right.report_num))
    });
    Ok(CencPoll { events, cursor })
}

fn normalize(stream: CencStream, earthquake: Earthquake) -> Result<DisasterEvent> {
    ensure!(
        !earthquake.id.trim().is_empty() && earthquake.id.len() <= 128,
        "invalid CENC event ID"
    );
    let place = earthquake.location.trim();
    ensure!(!place.is_empty(), "CENC location is empty");
    ensure!(
        crate::utils::distance::validate_coordinates(earthquake.latitude, earthquake.longitude),
        "invalid CENC coordinates"
    );
    let magnitude: f64 = earthquake
        .level
        .trim()
        .parse()
        .context("invalid CENC magnitude")?;
    ensure!(
        magnitude.is_finite() && (0.0..=10.0).contains(&magnitude),
        "invalid CENC magnitude"
    );
    ensure!(
        earthquake
            .depth
            .is_none_or(|depth| depth.is_finite() && depth >= 0.0),
        "invalid CENC depth"
    );
    ensure!(
        earthquake
            .epicenter_intensity
            .is_none_or(|value| value.is_finite() && (0.0..=12.0).contains(&value)),
        "invalid CENC intensity"
    );
    ensure!(
        (0..=253_402_300_799).contains(&earthquake.created_at),
        "invalid CENC timestamp"
    );
    let (category, source, report_num, final_report) = match stream {
        CencStream::Warning => {
            let serial = earthquake
                .serial_number
                .context("CENC warning is missing serial_number")?;
            ensure!(serial > 0, "invalid CENC report number");
            (
                DisasterCategory::EarthquakeWarning,
                "cenc.warning",
                serial,
                false,
            )
        }
        CencStream::Report => (DisasterCategory::EarthquakeReport, "cenc.report", 1, true),
    };
    let mut description = format!("M{magnitude:.1} {place}");
    if let Some(intensity) = earthquake.epicenter_intensity {
        description.push_str(&format!(" 震中烈度{intensity:.1}"));
    }
    let mut event = DisasterEvent {
        category,
        channel: ProviderChannel::Cenc,
        source: source.to_string(),
        event_id: earthquake.id,
        revision: report_num.to_string(),
        report_num,
        title: format!("{} {place}", category.label()),
        description,
        latitude: Some(earthquake.latitude),
        longitude: Some(earthquake.longitude),
        magnitude: Some(magnitude),
        depth_km: earthquake.depth,
        affected_regions: Vec::new(),
        radius_km: None,
        level: if magnitude >= 7.0 {
            4
        } else if magnitude >= 6.0 {
            3
        } else if magnitude >= 5.0 {
            2
        } else {
            1
        },
        occurred_at: super::time::epoch_millis_to_rfc3339(earthquake.created_at * 1_000)?,
        final_report,
        cancel: false,
        training: false,
    };
    // 修订标识来自事件内容，同一报次的参数修订也有独立标识。
    event.revision = event_update_id(&event);
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::parse_event_epoch;
    use axum::{Json, Router, extract::Query, http::HeaderMap, routing::get};
    use serde_json::json;

    fn earthquake(id: &str, serial: u32) -> Result<Earthquake> {
        Ok(serde_json::from_value(json!({
            "id": id, "location": "四川绵阳市北川县", "level": "4.6",
            "latitude": 31.89, "longitude": 104.467,
            "epicenter_intensity": 6.4, "serial_number": serial,
            "created_at": 1792407428_i64
        }))?)
    }

    #[test]
    fn normalizes_warning_seconds_and_optional_depth() -> Result<()> {
        let event = normalize(CencStream::Warning, earthquake("event", 2)?)?;
        anyhow::ensure!(event.category == DisasterCategory::EarthquakeWarning);
        anyhow::ensure!(event.source == "cenc.warning");
        anyhow::ensure!(event.channel == ProviderChannel::Cenc);
        anyhow::ensure!(event.report_num == 2);
        anyhow::ensure!(event.magnitude == Some(4.6));
        anyhow::ensure!(event.depth_km == None);
        anyhow::ensure!(parse_event_epoch(&event) == Some(1_792_407_428));
        anyhow::ensure!(!event.final_report);
        Ok(())
    }

    #[test]
    fn normalizes_report_without_warning_fields() -> Result<()> {
        let mut value = earthquake("event", 1)?;
        value.serial_number = None;
        value.epicenter_intensity = None;
        let event = normalize(CencStream::Report, value)?;
        anyhow::ensure!(event.category == DisasterCategory::EarthquakeReport);
        anyhow::ensure!(event.source == "cenc.report");
        anyhow::ensure!(event.final_report);
        Ok(())
    }

    #[test]
    fn baselines_history_and_emits_new_or_revised_events() -> Result<()> {
        let first = prepare_snapshot(
            CencStream::Warning,
            "100".into(),
            vec![earthquake("old", 1)?],
            None,
        )?;
        anyhow::ensure!(first.events.is_empty());
        let same = prepare_snapshot(
            CencStream::Warning,
            "101".into(),
            vec![earthquake("old", 1)?],
            Some(&first.cursor),
        )?;
        anyhow::ensure!(same.events.is_empty());
        let next = prepare_snapshot(
            CencStream::Warning,
            "102".into(),
            vec![earthquake("new", 1)?, earthquake("old", 2)?],
            Some(&same.cursor),
        )?;
        anyhow::ensure!(next.events.len() == 2);
        anyhow::ensure!(
            next.events
                .iter()
                .any(|event| event.event_id == "old" && event.report_num == 2)
        );
        let replay = prepare_snapshot(
            CencStream::Warning,
            "103".into(),
            vec![earthquake("new", 1)?, earthquake("old", 2)?],
            Some(&next.cursor),
        )?;
        anyhow::ensure!(replay.events.is_empty());
        Ok(())
    }

    #[test]
    fn detects_parameter_corrections_within_the_same_report() -> Result<()> {
        let initial = earthquake("event", 1)?;
        let first = prepare_snapshot(
            CencStream::Report,
            "100".into(),
            vec![initial.clone()],
            None,
        )?;
        let mut correction = initial;
        correction.level = "4.8".to_string();
        let next = prepare_snapshot(
            CencStream::Report,
            "101".into(),
            vec![correction],
            Some(&first.cursor),
        )?;
        anyhow::ensure!(next.events.len() == 1);
        anyhow::ensure!(next.cursor.events != first.cursor.events);
        Ok(())
    }

    #[test]
    fn rejects_invalid_earthquake_fields() -> Result<()> {
        let valid = earthquake("event", 1)?;
        let mut invalid = vec![valid.clone(); 8];
        invalid[0].latitude = 91.0;
        invalid[1].longitude = -181.0;
        invalid[2].level = "NaN".into();
        invalid[3].depth = Some(-1.0);
        invalid[4].created_at = i64::MAX;
        invalid[5].serial_number = Some(0);
        invalid[6].location.clear();
        invalid[7].epicenter_intensity = Some(13.0);
        for value in invalid {
            anyhow::ensure!(normalize(CencStream::Warning, value).is_err());
        }
        anyhow::ensure!(
            prepare_snapshot(
                CencStream::Warning,
                "100".into(),
                vec![valid.clone(), valid],
                None
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn persisted_baseline_survives_reopen_without_replaying_history() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let first = prepare_snapshot(
            CencStream::Warning,
            "100".into(),
            vec![earthquake("event", 1)?],
            None,
        )?;
        {
            let storage = crate::storage::FjallStorage::open(directory.path())?;
            let value = serde_json::to_string(&first.cursor)?;
            storage.ingest_with_cursor(
                ProviderChannel::Cenc,
                first.events,
                Some(("warning", &value)),
            )?;
            storage.persist()?;
        }
        let storage = crate::storage::FjallStorage::open(directory.path())?;
        let cursors = storage.provider_cursors(ProviderChannel::Cenc, &["warning".into()])?;
        let known = CencCursor::decode(&cursors[0].1)?;
        let poll = prepare_snapshot(
            CencStream::Warning,
            "101".into(),
            vec![earthquake("event", 1)?],
            Some(&known),
        )?;
        anyhow::ensure!(poll.events.is_empty());
        anyhow::ensure!(storage.pending_inbox(1)?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn list_request_carries_version_and_alarm_type() -> Result<()> {
        let app = Router::new().route(
            "/list",
            get(
                async |Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap| {
                    let valid = query.get("app_id").map(String::as_str) == Some(APP_ID)
                        && query.get("v").map(String::as_str) == Some("123")
                        && query.get("alarm_type").map(String::as_str) == Some("2")
                        && query.get("page_no").map(String::as_str) == Some("1")
                        && query.get("page_size").map(String::as_str) == Some("20")
                        && headers
                            .get("cache-control")
                            .and_then(|value| value.to_str().ok())
                            == Some("no-store");
                    Json(json!({"code": if valid { 0 } else { 101 }, "data": {"spot_infos": []}}))
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/list", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let result = fetch_snapshot(
            &reqwest::Client::new(),
            &url,
            CencStream::Warning,
            "123".into(),
            None,
        )
        .await;
        server.abort();
        anyhow::ensure!(result?.events.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn rejects_business_errors_without_advancing_the_cursor() -> Result<()> {
        let app = Router::new().route(
            "/list",
            get(async || Json(json!({"code": 101, "msg": "invalid version"}))),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/list", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let result = fetch_snapshot(
            &reqwest::Client::new(),
            &url,
            CencStream::Report,
            "123".into(),
            None,
        )
        .await;
        server.abort();
        anyhow::ensure!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn streams_commit_independently_and_skip_unchanged_versions() -> Result<()> {
        use crate::delivery::{BarkNotifier, BarkPushConfig, NotificationLinkService};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };

        let revision = Arc::new(AtomicUsize::new(1));
        let report_failed = Arc::new(AtomicBool::new(true));
        let list_calls = Arc::new(AtomicUsize::new(0));
        let version_revision = Arc::clone(&revision);
        let list_revision = Arc::clone(&revision);
        let list_failed = Arc::clone(&report_failed);
        let calls = Arc::clone(&list_calls);
        let app = Router::new()
            .route(
                "/version",
                get(move || {
                    let revision = Arc::clone(&version_revision);
                    async move {
                        Json(json!({"code": 0, "data": {
                            "warning_version": revision.load(Ordering::Relaxed).to_string(),
                            "report_version": "100"
                        }}))
                    }
                }),
            )
            .route(
                "/list",
                get(move |Query(query): Query<BTreeMap<String, String>>| {
                    let revision = Arc::clone(&list_revision);
                    let failed = Arc::clone(&list_failed);
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::Relaxed);
                        if query.get("alarm_type").map(String::as_str) == Some("1") {
                            if failed.load(Ordering::Relaxed) {
                                return Json(json!({"code": 101, "msg": "try again"}));
                            }
                            return Json(json!({"code": 0, "data": {"spot_infos": []}}));
                        }
                        Json(json!({"code": 0, "data": {"spot_infos": [{
                            "id": "warning", "location": "测试地区", "level": "4.6",
                            "latitude": 31.89, "longitude": 104.467,
                            "serial_number": revision.load(Ordering::Relaxed),
                            "created_at": 1792407428_i64
                        }]}}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let directory = tempfile::tempdir()?;
        let storage = crate::storage::Storage::open(directory.path())?;
        let notifier = BarkNotifier::new(
            vec!["https://api.day.app".into()],
            1,
            1,
            BarkPushConfig::new(None, 10, "test".into(), false),
        )?;
        let links = NotificationLinkService::for_test(&storage);
        let source = CencSource {
            event_runtime: EventRuntime::for_test(storage.clone(), notifier, links)?,
            client: reqwest::Client::new(),
            reconnect_min: POLL_INTERVAL,
            reconnect_max: POLL_INTERVAL,
            runtime_status: RuntimeStatus::default(),
        };
        let mut known = BTreeMap::new();
        let version_url = format!("{base}/version");
        let list_url = format!("{base}/list");
        anyhow::ensure!(
            source
                .poll(&mut known, &version_url, &list_url)
                .await
                .is_err()
        );
        anyhow::ensure!(known.contains_key("warning"));
        anyhow::ensure!(!known.contains_key("report"));
        report_failed.store(false, Ordering::Relaxed);
        source.poll(&mut known, &version_url, &list_url).await?;
        anyhow::ensure!(list_calls.load(Ordering::Relaxed) == 3);
        source.poll(&mut known, &version_url, &list_url).await?;
        anyhow::ensure!(list_calls.load(Ordering::Relaxed) == 3);
        revision.store(2, Ordering::Relaxed);
        source.poll(&mut known, &version_url, &list_url).await?;
        server.abort();
        anyhow::ensure!(list_calls.load(Ordering::Relaxed) == 4);
        let inbox = storage.inner().pending_inbox(10)?;
        anyhow::ensure!(inbox.len() == 1);
        anyhow::ensure!(inbox[0].event.report_num == 2);
        let persisted = storage
            .inner()
            .provider_cursors(ProviderChannel::Cenc, &["warning".into()])?;
        anyhow::ensure!(CencCursor::decode(&persisted[0].1)? == known["warning"]);
        Ok(())
    }
}
