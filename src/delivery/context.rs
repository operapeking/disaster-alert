use crate::config::Config;
use crate::delivery::AlertTiming;
use crate::models::{
    AlertRule, DisasterCategory, DisasterEvent, IncidentId, IntensityBand, InterruptionLevel,
    MonitoringTarget, SourceSelection,
};
use crate::storage::{FjallStorage, Storage, try_now_millis};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

const SIGNATURE_DOMAIN: &[u8] = b"disaster-alert:notification-context:v1\0";
const MAX_TOKEN_BYTES: usize = 256;
const MAX_DETAIL_URL_BYTES: usize = 3_000;

#[derive(Clone)]
pub(crate) struct NotificationLinkService {
    inner: Arc<NotificationLinkInner>,
}

#[derive(Debug)]
pub(crate) enum NotificationVerifyError {
    Invalid(anyhow::Error),
    Storage(anyhow::Error),
}

impl std::fmt::Display for NotificationVerifyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(error) | Self::Storage(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for NotificationVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(error) | Self::Storage(error) => error.source(),
        }
    }
}

pub(crate) struct NotificationContextInput<'a> {
    pub(crate) incident_id: &'a IncidentId,
    pub(crate) event: &'a DisasterEvent,
    pub(crate) target: &'a MonitoringTarget,
    pub(crate) timing: Option<&'a AlertTiming>,
    pub(crate) interruption_level: &'a str,
    pub(crate) matched_rule: &'a AlertRule,
    pub(crate) issued_at_ms: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedNotificationContext {
    pub(crate) url: String,
    pub(crate) context_id: String,
    pub(crate) encoded_value: Vec<u8>,
}

struct NotificationLinkInner {
    base_url: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    context_storage: NotificationContextStorage,
}

#[derive(Clone)]
struct NotificationContextStorage {
    storage: FjallStorage,
}

#[derive(Serialize, Deserialize)]
struct StoredContext {
    stored_at_ms: i64,
    snapshot: NotificationSnapshot,
}

impl NotificationContextStorage {
    fn new(storage: FjallStorage) -> Self {
        Self { storage }
    }

    fn prepare(&self, snapshot: &NotificationSnapshot) -> Result<(String, Vec<u8>)> {
        let snapshot_bytes = serde_json::to_vec(snapshot)?;
        let mut hash = sha2::Sha256::new();
        use sha2::Digest as _;
        hash.update(b"disaster-alert:notification-context-id:v1\0");
        hash.update(&snapshot_bytes);
        let id = URL_SAFE_NO_PAD.encode(&hash.finalize()[..16]);
        let stored = StoredContext {
            stored_at_ms: try_now_millis()?,
            snapshot: snapshot.clone(),
        };
        Ok((id, serde_json::to_vec(&stored)?))
    }

    fn put_prepared(&self, context: &PreparedNotificationContext) -> Result<()> {
        self.storage
            .put_context(&context.context_id, context.encoded_value.clone())
    }

    fn get(&self, id: &str) -> Result<Option<NotificationSnapshot>> {
        anyhow::ensure!(
            id.len() == 22
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "invalid notification context ID"
        );
        let snapshot = self
            .storage
            .context(id)?
            .map(|value| {
                serde_json::from_slice::<StoredContext>(&value)
                    .map(|stored| stored.snapshot)
                    .context("invalid notification context")
            })
            .transpose()?;
        if let Some(snapshot) = &snapshot {
            anyhow::ensure!(
                context_id(snapshot)? == id,
                "notification context key does not match its snapshot"
            );
        }
        Ok(snapshot)
    }

    fn prune(&self, cutoff_ms: i64) -> Result<usize> {
        let mut removed = 0usize;
        for (id, value) in self.storage.context_records()? {
            let stored: StoredContext = match serde_json::from_slice(&value) {
                Ok(stored) => stored,
                Err(error) => {
                    tracing::warn!(
                        event = "notification.context_invalid",
                        context_id = id,
                        error = ?error,
                        "notification.context_invalid"
                    );
                    self.storage.remove_context(&id)?;
                    removed = removed.saturating_add(1);
                    continue;
                }
            };
            if stored.stored_at_ms <= cutoff_ms {
                self.storage.remove_context(&id)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotificationSnapshot {
    #[serde(rename = "v")]
    pub(crate) schema_version: u8,
    #[serde(rename = "i")]
    pub(crate) incident_id: IncidentId,
    #[serde(rename = "at")]
    pub(crate) issued_at_ms: i64,
    #[serde(rename = "e")]
    pub(crate) event: NotificationEventSnapshot,
    #[serde(rename = "t")]
    pub(crate) target: NotificationTargetSnapshot,
    #[serde(rename = "x")]
    pub(crate) timing: Option<NotificationTimingSnapshot>,
    #[serde(rename = "l")]
    pub(crate) interruption_level: String,
    #[serde(rename = "r")]
    pub(crate) matched_rule: NotificationRuleSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotificationEventSnapshot {
    #[serde(rename = "c")]
    pub(crate) category: DisasterCategory,
    #[serde(rename = "s")]
    pub(crate) source: String,
    #[serde(rename = "i")]
    pub(crate) source_event_id: String,
    #[serde(rename = "r")]
    pub(crate) revision: String,
    #[serde(rename = "n")]
    pub(crate) report_num: u32,
    #[serde(rename = "t")]
    pub(crate) title: String,
    #[serde(rename = "a")]
    pub(crate) description: String,
    #[serde(rename = "g")]
    pub(crate) affected_regions: Vec<String>,
    #[serde(rename = "y")]
    pub(crate) latitude: Option<f64>,
    #[serde(rename = "x")]
    pub(crate) longitude: Option<f64>,
    #[serde(rename = "m")]
    pub(crate) magnitude: Option<f64>,
    #[serde(rename = "d")]
    pub(crate) depth_km: Option<f64>,
    #[serde(rename = "o", default, skip_serializing_if = "Option::is_none")]
    pub(crate) radius_km: Option<f64>,
    #[serde(rename = "l")]
    pub(crate) level: u8,
    #[serde(rename = "at")]
    pub(crate) occurred_at: String,
    #[serde(rename = "f")]
    pub(crate) final_report: bool,
    #[serde(rename = "z")]
    pub(crate) cancel: bool,
    #[serde(rename = "q")]
    pub(crate) training: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotificationTargetSnapshot {
    #[serde(rename = "n")]
    pub(crate) label: String,
    #[serde(rename = "y")]
    pub(crate) latitude: f64,
    #[serde(rename = "x")]
    pub(crate) longitude: f64,
    #[serde(rename = "p")]
    pub(crate) province: String,
    #[serde(rename = "c")]
    pub(crate) city: String,
    #[serde(rename = "d")]
    pub(crate) district: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotificationTimingSnapshot {
    #[serde(rename = "e")]
    pub(crate) epicentral_distance_km: f64,
    #[serde(rename = "h")]
    pub(crate) hypocentral_distance_km: f64,
    #[serde(rename = "i")]
    pub(crate) estimated_intensity: f64,
    #[serde(rename = "p")]
    pub(crate) p_arrival_at_ms: i64,
    #[serde(rename = "s")]
    pub(crate) s_arrival_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum NotificationRuleSnapshot {
    EarthquakeWarning {
        #[serde(rename = "s")]
        sources: NotificationSourcesSnapshot,
        #[serde(rename = "b")]
        intensity_bands: Vec<NotificationIntensityBandSnapshot>,
    },
    EarthquakeReport {
        #[serde(rename = "s")]
        sources: NotificationSourcesSnapshot,
        #[serde(rename = "m")]
        min_magnitude: f64,
    },
    WeatherWarning {
        #[serde(rename = "s")]
        sources: NotificationSourcesSnapshot,
        #[serde(rename = "v")]
        min_severity: u8,
        #[serde(rename = "r")]
        fallback_radius_km: f64,
    },
    Tsunami {
        #[serde(rename = "s")]
        sources: NotificationSourcesSnapshot,
        #[serde(rename = "v")]
        min_severity: u8,
    },
    Typhoon {
        #[serde(rename = "s")]
        sources: NotificationSourcesSnapshot,
        #[serde(rename = "r")]
        max_center_distance_km: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "m", content = "i", rename_all = "snake_case")]
pub(crate) enum NotificationSourcesSnapshot {
    All,
    Include(Vec<String>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotificationIntensityBandSnapshot {
    #[serde(rename = "n")]
    pub(crate) min: u8,
    #[serde(rename = "x")]
    pub(crate) max: u8,
    #[serde(rename = "l")]
    pub(crate) interruption_level: InterruptionLevel,
}

impl NotificationLinkService {
    pub(crate) fn new(config: &Config, storage: &Storage) -> Result<Self> {
        let secret =
            decode_secret_array::<32>(config.alert_signing_key.expose(), "ALERT_SIGNING_KEY")?;
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            inner: Arc::new(NotificationLinkInner {
                base_url: config
                    .alert_detail_base_url
                    .trim_end_matches('/')
                    .to_string(),
                signing_key,
                verifying_key,
                context_storage: NotificationContextStorage::new(storage.inner()),
            }),
        })
    }

    #[cfg(any(test, feature = "benchmarks"))]
    pub(crate) fn for_test(storage: &Storage) -> Self {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let verifying_key = signing_key.verifying_key();
        Self {
            inner: Arc::new(NotificationLinkInner {
                base_url: "https://alerts.example.test".to_string(),
                signing_key,
                verifying_key,
                context_storage: NotificationContextStorage::new(storage.inner()),
            }),
        }
    }

    pub(crate) fn prune_retained(&self, retention_days: u64) -> Result<usize> {
        let millis = retention_days.saturating_mul(86_400_000);
        let retention_ms = i64::try_from(millis).unwrap_or(i64::MAX);
        self.inner
            .context_storage
            .prune(try_now_millis()?.saturating_sub(retention_ms))
    }

    #[cfg(test)]
    fn create_url(
        &self,
        incident_id: &IncidentId,
        event: &DisasterEvent,
        target: &MonitoringTarget,
        timing: Option<&AlertTiming>,
        interruption_level: &str,
        matched_rule: &AlertRule,
    ) -> Result<String> {
        self.create_url_for(NotificationContextInput {
            incident_id,
            event,
            target,
            timing,
            interruption_level,
            matched_rule,
            issued_at_ms: try_now_millis()?,
        })
    }

    #[cfg(test)]
    fn create_url_for(&self, input: NotificationContextInput<'_>) -> Result<String> {
        let prepared = self.prepare_url_for(input)?;
        self.inner.context_storage.put_prepared(&prepared)?;
        Ok(prepared.url)
    }

    pub(crate) fn prepare_url_for(
        &self,
        input: NotificationContextInput<'_>,
    ) -> Result<PreparedNotificationContext> {
        let NotificationContextInput {
            incident_id,
            event,
            target,
            timing,
            interruption_level,
            matched_rule,
            issued_at_ms,
        } = input;
        let snapshot = NotificationSnapshot {
            schema_version: 1,
            incident_id: incident_id.clone(),
            issued_at_ms,
            event: NotificationEventSnapshot::from_event(event),
            target: NotificationTargetSnapshot::from_target(target),
            timing: timing.map(NotificationTimingSnapshot::from_timing),
            interruption_level: interruption_level.to_string(),
            matched_rule: NotificationRuleSnapshot::from_rule(matched_rule),
        };
        validate_snapshot(&snapshot)?;
        let (context_id, encoded_value) = self.inner.context_storage.prepare(&snapshot)?;
        let message = signature_message(&context_id);
        let signature = self.inner.signing_key.sign(&message);
        let token = format!(
            "{}.{}",
            context_id,
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        anyhow::ensure!(
            token.len() <= MAX_TOKEN_BYTES,
            "notification token exceeded {MAX_TOKEN_BYTES} bytes"
        );
        let url = format!(
            "{}/incidents/{}/notifications/{}",
            self.inner.base_url,
            incident_id.as_str(),
            token
        );
        anyhow::ensure!(
            url.len() <= MAX_DETAIL_URL_BYTES,
            "notification detail URL exceeded {MAX_DETAIL_URL_BYTES} bytes"
        );
        Ok(PreparedNotificationContext {
            url,
            context_id,
            encoded_value,
        })
    }

    pub(crate) fn persist_prepared(&self, context: &PreparedNotificationContext) -> Result<()> {
        self.inner.context_storage.put_prepared(context)
    }

    pub(crate) fn verify(
        &self,
        incident_id: &IncidentId,
        token: &str,
    ) -> std::result::Result<NotificationSnapshot, NotificationVerifyError> {
        let context_id = (|| -> Result<&str> {
            anyhow::ensure!(token.len() <= MAX_TOKEN_BYTES, "invalid notification token");
            let mut parts = token.split('.');
            let context_id = parts.next().context("invalid notification token")?;
            let signature = parts.next().context("invalid notification token")?;
            anyhow::ensure!(parts.next().is_none(), "invalid notification token");
            let signature = decode_array::<64>(signature, "notification signature")?;
            self.inner
                .verifying_key
                .verify_strict(
                    &signature_message(context_id),
                    &Signature::from_bytes(&signature),
                )
                .context("invalid notification signature")?;
            Ok(context_id)
        })()
        .map_err(NotificationVerifyError::Invalid)?;
        let snapshot = self
            .inner
            .context_storage
            .get(context_id)
            .map_err(NotificationVerifyError::Storage)?
            .ok_or_else(|| {
                NotificationVerifyError::Invalid(anyhow::anyhow!("notification context not found"))
            })?;
        validate_snapshot(&snapshot).map_err(NotificationVerifyError::Storage)?;
        if &snapshot.incident_id != incident_id {
            return Err(NotificationVerifyError::Invalid(anyhow::anyhow!(
                "notification token does not belong to this incident"
            )));
        }
        Ok(snapshot)
    }
}

fn context_id(snapshot: &NotificationSnapshot) -> Result<String> {
    let snapshot_bytes = serde_json::to_vec(snapshot)?;
    let mut hash = sha2::Sha256::new();
    use sha2::Digest as _;
    hash.update(b"disaster-alert:notification-context-id:v1\0");
    hash.update(snapshot_bytes);
    Ok(URL_SAFE_NO_PAD.encode(&hash.finalize()[..16]))
}

impl NotificationEventSnapshot {
    fn from_event(event: &DisasterEvent) -> Self {
        Self {
            category: event.category,
            source: truncate_bytes(&event.source, 128),
            source_event_id: truncate_bytes(&event.event_id, 128),
            revision: truncate_bytes(&event.revision, 96),
            report_num: event.report_num,
            title: truncate_bytes(&event.title, 180),
            description: truncate_bytes(&event.description, 400),
            affected_regions: event
                .affected_regions
                .iter()
                .take(8)
                .map(|region| truncate_bytes(region, 60))
                .collect(),
            latitude: event.latitude,
            longitude: event.longitude,
            magnitude: event.magnitude,
            depth_km: event.depth_km,
            radius_km: event.radius_km,
            level: event.level,
            occurred_at: truncate_bytes(&event.occurred_at, 80),
            final_report: event.final_report,
            cancel: event.cancel,
            training: event.training,
        }
    }
}

impl NotificationTargetSnapshot {
    fn from_target(target: &MonitoringTarget) -> Self {
        Self {
            label: truncate_bytes(&target.label, 80),
            latitude: target.point.latitude,
            longitude: target.point.longitude,
            province: truncate_bytes(&target.region.province, 80),
            city: truncate_bytes(&target.region.city, 80),
            district: truncate_bytes(&target.region.district, 80),
        }
    }
}

impl NotificationRuleSnapshot {
    fn from_rule(rule: &AlertRule) -> Self {
        match rule {
            AlertRule::EarthquakeWarning {
                sources,
                estimated_intensity_bands,
            } => Self::EarthquakeWarning {
                sources: NotificationSourcesSnapshot::from_sources(sources),
                intensity_bands: estimated_intensity_bands
                    .iter()
                    .map(NotificationIntensityBandSnapshot::from_band)
                    .collect(),
            },
            AlertRule::EarthquakeReport {
                sources,
                min_magnitude,
            } => Self::EarthquakeReport {
                sources: NotificationSourcesSnapshot::from_sources(sources),
                min_magnitude: *min_magnitude,
            },
            AlertRule::WeatherWarning {
                sources,
                min_severity,
                fallback_radius_km,
            } => Self::WeatherWarning {
                sources: NotificationSourcesSnapshot::from_sources(sources),
                min_severity: *min_severity,
                fallback_radius_km: *fallback_radius_km,
            },
            AlertRule::Tsunami {
                sources,
                min_severity,
            } => Self::Tsunami {
                sources: NotificationSourcesSnapshot::from_sources(sources),
                min_severity: *min_severity,
            },
            AlertRule::Typhoon {
                sources,
                max_center_distance_km,
            } => Self::Typhoon {
                sources: NotificationSourcesSnapshot::from_sources(sources),
                max_center_distance_km: *max_center_distance_km,
            },
        }
    }
}

impl NotificationSourcesSnapshot {
    fn from_sources(sources: &SourceSelection) -> Self {
        match sources {
            SourceSelection::All => Self::All,
            SourceSelection::Include { ids } => {
                Self::Include(ids.iter().map(|id| truncate_bytes(id, 128)).collect())
            }
        }
    }
}

impl NotificationIntensityBandSnapshot {
    fn from_band(band: &IntensityBand) -> Self {
        Self {
            min: band.min,
            max: band.max,
            interruption_level: band.interruption_level,
        }
    }
}

impl NotificationTimingSnapshot {
    fn from_timing(timing: &AlertTiming) -> Self {
        Self {
            epicentral_distance_km: timing.distance_km,
            hypocentral_distance_km: timing.hypocentral_km,
            estimated_intensity: timing.estimated_intensity,
            p_arrival_at_ms: timing.p_arrival_at_ms,
            s_arrival_at_ms: timing.s_arrival_at_ms,
        }
    }
}

fn validate_snapshot(snapshot: &NotificationSnapshot) -> Result<()> {
    anyhow::ensure!(
        snapshot.schema_version == 1,
        "unsupported notification token version"
    );
    anyhow::ensure!(snapshot.event.source.len() <= 128, "invalid event source");
    anyhow::ensure!(
        snapshot.event.source_event_id.len() <= 128,
        "invalid event ID"
    );
    anyhow::ensure!(
        snapshot.event.revision.len() <= 96,
        "invalid event revision"
    );
    anyhow::ensure!(snapshot.event.title.len() <= 180, "invalid event title");
    anyhow::ensure!(
        snapshot.event.description.len() <= 400
            && snapshot.event.affected_regions.len() <= 8
            && snapshot
                .event
                .affected_regions
                .iter()
                .all(|region| region.len() <= 60)
            && snapshot.event.occurred_at.len() <= 80,
        "invalid event details"
    );
    anyhow::ensure!(
        snapshot.event.latitude.is_none_or(f64::is_finite)
            && snapshot.event.longitude.is_none_or(f64::is_finite)
            && snapshot.event.magnitude.is_none_or(f64::is_finite)
            && snapshot.event.depth_km.is_none_or(f64::is_finite)
            && snapshot
                .event
                .radius_km
                .is_none_or(|radius| radius.is_finite() && radius >= 0.0)
            && snapshot.event.latitude.is_some() == snapshot.event.longitude.is_some()
            && snapshot
                .event
                .latitude
                .zip(snapshot.event.longitude)
                .is_none_or(|(latitude, longitude)| {
                    crate::utils::distance::validate_coordinates(latitude, longitude)
                }),
        "invalid event measurements"
    );
    anyhow::ensure!(snapshot.target.label.len() <= 80, "invalid target label");
    anyhow::ensure!(
        crate::utils::distance::validate_coordinates(
            snapshot.target.latitude,
            snapshot.target.longitude
        ),
        "invalid target coordinates"
    );
    anyhow::ensure!(
        [
            snapshot.target.province.as_str(),
            snapshot.target.city.as_str(),
            snapshot.target.district.as_str(),
        ]
        .into_iter()
        .all(|value| value.len() <= 80),
        "invalid target region"
    );
    anyhow::ensure!(
        matches!(
            snapshot.interruption_level.as_str(),
            "passive" | "active" | "critical"
        ),
        "invalid interruption level"
    );
    if let Some(timing) = snapshot.timing {
        anyhow::ensure!(
            timing.epicentral_distance_km.is_finite()
                && timing.epicentral_distance_km >= 0.0
                && timing.hypocentral_distance_km.is_finite()
                && timing.hypocentral_distance_km >= 0.0
                && timing.estimated_intensity.is_finite(),
            "invalid impact estimate"
        );
    }
    validate_rule(snapshot.event.category, &snapshot.matched_rule)?;
    Ok(())
}

fn validate_rule(category: DisasterCategory, rule: &NotificationRuleSnapshot) -> Result<()> {
    let (rule_category, sources) = match rule {
        NotificationRuleSnapshot::EarthquakeWarning {
            sources,
            intensity_bands,
        } => {
            anyhow::ensure!(
                !intensity_bands.is_empty()
                    && intensity_bands.len() <= 3
                    && intensity_bands
                        .iter()
                        .all(|band| band.min <= band.max && band.max <= 7),
                "invalid intensity rule"
            );
            (DisasterCategory::EarthquakeWarning, sources)
        }
        NotificationRuleSnapshot::EarthquakeReport {
            sources,
            min_magnitude,
        } => {
            anyhow::ensure!(
                min_magnitude.is_finite() && (0.0..=10.0).contains(min_magnitude),
                "invalid magnitude rule"
            );
            (DisasterCategory::EarthquakeReport, sources)
        }
        NotificationRuleSnapshot::WeatherWarning {
            sources,
            min_severity,
            fallback_radius_km,
        } => {
            anyhow::ensure!(
                (1..=4).contains(min_severity)
                    && fallback_radius_km.is_finite()
                    && (1.0..=2_000.0).contains(fallback_radius_km),
                "invalid weather rule"
            );
            (DisasterCategory::WeatherWarning, sources)
        }
        NotificationRuleSnapshot::Tsunami {
            sources,
            min_severity,
        } => {
            anyhow::ensure!((1..=4).contains(min_severity), "invalid tsunami rule");
            (DisasterCategory::Tsunami, sources)
        }
        NotificationRuleSnapshot::Typhoon {
            sources,
            max_center_distance_km,
        } => {
            anyhow::ensure!(
                max_center_distance_km.is_finite()
                    && (1.0..=3_000.0).contains(max_center_distance_km),
                "invalid typhoon rule"
            );
            (DisasterCategory::Typhoon, sources)
        }
    };
    anyhow::ensure!(
        rule_category == category,
        "notification rule category mismatch"
    );
    if let NotificationSourcesSnapshot::Include(ids) = sources {
        anyhow::ensure!(
            !ids.is_empty()
                && ids.len() <= 16
                && ids.iter().all(|id| !id.is_empty() && id.len() <= 128),
            "invalid notification sources"
        );
    }
    Ok(())
}

fn truncate_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes.min(value.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_string()
}

fn signature_message(context_id: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + context_id.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(context_id.as_bytes());
    message
}

fn decode_array<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value.trim())
        .with_context(|| format!("{name} must be URL-safe base64 without padding"))?;
    decoded
        .try_into()
        .map_err(|_decoded| anyhow::anyhow!("{name} must decode to exactly {N} bytes"))
}

fn decode_secret_array<const N: usize>(value: &str, name: &str) -> Result<Zeroizing<[u8; N]>> {
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value.trim())
            .with_context(|| format!("{name} must be URL-safe base64 without padding"))?,
    );
    let bytes: [u8; N] = decoded
        .as_slice()
        .try_into()
        .map_err(|_decoded| anyhow::anyhow!("{name} must decode to exactly {N} bytes"))?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AdministrativeRegion, GeoPoint, ProviderChannel, SourceSelection};

    struct TestService {
        service: NotificationLinkService,
        _directory: tempfile::TempDir,
    }

    fn service(secret: [u8; 32]) -> Result<TestService> {
        let directory = tempfile::tempdir()?;
        let storage = Storage::open(directory.path().join("contexts.fjall"))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        Ok(TestService {
            service: NotificationLinkService {
                inner: Arc::new(NotificationLinkInner {
                    base_url: "https://alert.example.com".to_string(),
                    signing_key,
                    verifying_key,
                    context_storage: NotificationContextStorage::new(storage.inner()),
                }),
            },
            _directory: directory,
        })
    }

    fn event() -> DisasterEvent {
        DisasterEvent {
            category: DisasterCategory::EarthquakeWarning,
            channel: ProviderChannel::Wolfx,
            source: "wolfx.jma_eew".to_string(),
            event_id: "event-42".to_string(),
            revision: "3".to_string(),
            report_num: 3,
            title: "地震预警 <测试>".to_string(),
            description: "预计震感明显".to_string(),
            latitude: Some(35.1),
            longitude: Some(139.2),
            magnitude: Some(5.7),
            depth_km: Some(12.0),
            affected_regions: vec!["东京都".to_string()],
            radius_km: Some(180.0),
            level: 3,
            occurred_at: "2026-07-12 12:34:56".to_string(),
            final_report: false,
            cancel: false,
            training: false,
        }
    }

    fn target() -> MonitoringTarget {
        MonitoringTarget {
            label: "住所".to_string(),
            point: GeoPoint {
                latitude: 35.6,
                longitude: 139.6,
            },
            region: AdministrativeRegion {
                province: "东京都".to_string(),
                city: "东京".to_string(),
                district: "千代田区".to_string(),
            },
        }
    }

    fn timing() -> AlertTiming {
        AlertTiming {
            distance_km: 55.0,
            hypocentral_km: 57.0,
            estimated_intensity: 3.4,
            p_arrival_at_ms: 4_000,
            s_arrival_at_ms: 11_000,
        }
    }

    fn create_url(service: &NotificationLinkService, incident: IncidentId) -> Result<String> {
        service.create_url(
            &incident,
            &event(),
            &target(),
            Some(&timing()),
            "critical",
            &AlertRule::EarthquakeWarning {
                sources: SourceSelection::All,
                estimated_intensity_bands: vec![IntensityBand {
                    min: 3,
                    max: 7,
                    interruption_level: InterruptionLevel::Critical,
                }],
            },
        )
    }

    fn token(url: &str) -> &str {
        url.rsplit('/').next().unwrap_or("")
    }

    fn mutate_part(token: &str, index: usize) -> String {
        let mut parts = token.split('.').map(str::to_string).collect::<Vec<_>>();
        let replacement = if parts[index].starts_with('A') {
            'B'
        } else {
            'A'
        };
        parts[index].replace_range(0..1, &replacement.to_string());
        parts.join(".")
    }

    #[test]
    fn signed_url_round_trip_preserves_recipient_context() -> Result<()> {
        let service = service([7; 32])?.service;
        let incident = IncidentId::derive("wolfx.jma_eew:event-42");
        let url = create_url(&service, incident.clone())?;
        anyhow::ensure!(token(&url).split('.').count() == 2);
        let snapshot = service.verify(&incident, token(&url))?;

        anyhow::ensure!(snapshot.incident_id == incident);
        anyhow::ensure!(snapshot.target.label == "住所");
        anyhow::ensure!(snapshot.event.description == "预计震感明显");
        anyhow::ensure!(snapshot.event.affected_regions == ["东京都"]);
        anyhow::ensure!(snapshot.event.radius_km == Some(180.0));
        anyhow::ensure!(snapshot.timing.is_some_and(|timing| {
            timing.estimated_intensity == 3.4 && timing.s_arrival_at_ms > timing.p_arrival_at_ms
        }));
        anyhow::ensure!(url.len() <= MAX_DETAIL_URL_BYTES);
        Ok(())
    }

    #[test]
    fn legacy_snapshot_without_radius_keeps_its_content_address() -> Result<()> {
        let incident = IncidentId::derive("legacy:event");
        let mut event = event();
        event.radius_km = None;
        let snapshot = NotificationSnapshot {
            schema_version: 1,
            incident_id: incident,
            issued_at_ms: 123,
            event: NotificationEventSnapshot::from_event(&event),
            target: NotificationTargetSnapshot::from_target(&target()),
            timing: Some(NotificationTimingSnapshot::from_timing(&timing())),
            interruption_level: "critical".to_string(),
            matched_rule: NotificationRuleSnapshot::from_rule(&AlertRule::EarthquakeWarning {
                sources: SourceSelection::All,
                estimated_intensity_bands: vec![IntensityBand {
                    min: 3,
                    max: 7,
                    interruption_level: InterruptionLevel::Critical,
                }],
            }),
        };
        let legacy_json = serde_json::to_vec(&snapshot)?;
        anyhow::ensure!(!String::from_utf8_lossy(&legacy_json).contains("\"o\""));

        let decoded: NotificationSnapshot = serde_json::from_slice(&legacy_json)?;
        anyhow::ensure!(decoded.event.radius_km.is_none());
        anyhow::ensure!(serde_json::to_vec(&decoded)? == legacy_json);
        anyhow::ensure!(context_id(&decoded)? == context_id(&snapshot)?);
        Ok(())
    }

    #[test]
    fn retries_reuse_the_same_context_url() -> Result<()> {
        let service = service([14; 32])?.service;
        let incident = IncidentId::derive("wolfx.jma_eew:event-42");
        let create = || {
            service.create_url_for(NotificationContextInput {
                incident_id: &incident,
                event: &event(),
                target: &target(),
                timing: Some(&timing()),
                interruption_level: "critical",
                matched_rule: &AlertRule::EarthquakeWarning {
                    sources: SourceSelection::All,
                    estimated_intensity_bands: vec![IntensityBand {
                        min: 3,
                        max: 7,
                        interruption_level: InterruptionLevel::Critical,
                    }],
                },
                issued_at_ms: 123,
            })
        };
        anyhow::ensure!(create()? == create()?);
        Ok(())
    }

    #[test]
    fn modified_payload_or_signature_is_rejected() -> Result<()> {
        let service = service([8; 32])?.service;
        let incident = IncidentId::derive("event-a");
        let url = create_url(&service, incident.clone())?;
        let token = token(&url);

        anyhow::ensure!(service.verify(&incident, &mutate_part(token, 0)).is_err());
        anyhow::ensure!(service.verify(&incident, &mutate_part(token, 1)).is_err());
        Ok(())
    }

    #[test]
    fn context_key_must_match_snapshot_hash() -> Result<()> {
        let service = service([15; 32])?.service;
        let incident = IncidentId::derive("event-a");
        let prepared = service.prepare_url_for(NotificationContextInput {
            incident_id: &incident,
            event: &event(),
            target: &target(),
            timing: Some(&timing()),
            interruption_level: "critical",
            matched_rule: &AlertRule::EarthquakeWarning {
                sources: SourceSelection::All,
                estimated_intensity_bands: vec![IntensityBand {
                    min: 3,
                    max: 7,
                    interruption_level: InterruptionLevel::Critical,
                }],
            },
            issued_at_ms: 123,
        })?;
        let wrong_context_id = "AAAAAAAAAAAAAAAAAAAAAA";
        anyhow::ensure!(wrong_context_id != prepared.context_id);
        service
            .inner
            .context_storage
            .storage
            .put_context(wrong_context_id, prepared.encoded_value)?;
        let signature = service
            .inner
            .signing_key
            .sign(&signature_message(wrong_context_id));
        let token = format!(
            "{wrong_context_id}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );

        anyhow::ensure!(matches!(
            service.verify(&incident, &token),
            Err(NotificationVerifyError::Storage(_))
        ));
        Ok(())
    }

    #[test]
    fn token_is_bound_to_incident_path() -> Result<()> {
        let service = service([9; 32])?.service;
        let incident = IncidentId::derive("event-a");
        let other = IncidentId::derive("event-b");
        let url = create_url(&service, incident)?;

        anyhow::ensure!(service.verify(&other, token(&url)).is_err());
        Ok(())
    }

    #[test]
    fn link_signed_by_a_different_key_is_rejected() -> Result<()> {
        let old = service([10; 32])?.service;
        let current_signing_key = SigningKey::from_bytes(&[11; 32]);
        let current_verifying_key = current_signing_key.verifying_key();
        let current = NotificationLinkService {
            inner: Arc::new(NotificationLinkInner {
                base_url: "https://alert.example.com".to_string(),
                signing_key: current_signing_key,
                verifying_key: current_verifying_key,
                context_storage: old.inner.context_storage.clone(),
            }),
        };
        let incident = IncidentId::derive("event-a");
        let url = create_url(&old, incident.clone())?;

        anyhow::ensure!(current.verify(&incident, token(&url)).is_err());
        Ok(())
    }

    #[test]
    fn long_display_fields_fit_within_the_detail_url_limit() -> Result<()> {
        let service = service([12; 32])?.service;
        let incident = IncidentId::derive("event-a");
        let mut event = event();
        event.title = "震".repeat(180);
        event.description = "描述".repeat(400);
        event.affected_regions = vec!["区域".repeat(60); 8];
        let mut target = target();
        target.label = "地点".repeat(80);
        target.region.province = "省".repeat(80);
        target.region.city = "市".repeat(80);
        target.region.district = "区".repeat(80);

        let url = service.create_url(
            &incident,
            &event,
            &target,
            Some(&timing()),
            "critical",
            &AlertRule::EarthquakeWarning {
                sources: SourceSelection::All,
                estimated_intensity_bands: vec![IntensityBand {
                    min: 3,
                    max: 7,
                    interruption_level: InterruptionLevel::Critical,
                }],
            },
        )?;

        anyhow::ensure!(url.len() <= MAX_DETAIL_URL_BYTES);
        let snapshot = service.verify(&incident, token(&url))?;
        anyhow::ensure!(snapshot.target.latitude == 35.6);
        anyhow::ensure!(snapshot.target.longitude == 139.6);
        anyhow::ensure!(snapshot.event.source_event_id == "event-42");
        anyhow::ensure!(snapshot.event.title.len() <= 180);
        anyhow::ensure!(snapshot.event.description.len() <= 400);
        anyhow::ensure!(snapshot.event.affected_regions.len() <= 8);
        Ok(())
    }

    #[test]
    fn short_context_urls_preserve_display_fields_with_a_long_base_path() -> Result<()> {
        let mut service = service([13; 32])?.service;
        Arc::get_mut(&mut service.inner)
            .context("test service should have unique ownership")?
            .base_url = format!("https://alert.example.com/{}", "path/".repeat(80));
        let incident = IncidentId::derive("event-a");
        let mut event = event();
        event.title = "震".repeat(180);
        event.description = "描述".repeat(400);
        event.affected_regions = vec!["区域".repeat(60); 8];
        let mut target = target();
        target.label = "地点".repeat(80);
        target.region.province = "省".repeat(80);
        target.region.city = "市".repeat(80);
        target.region.district = "区".repeat(80);

        let url = service.create_url(
            &incident,
            &event,
            &target,
            Some(&timing()),
            "critical",
            &AlertRule::EarthquakeWarning {
                sources: SourceSelection::All,
                estimated_intensity_bands: vec![IntensityBand {
                    min: 3,
                    max: 7,
                    interruption_level: InterruptionLevel::Critical,
                }],
            },
        )?;
        let snapshot = service.verify(&incident, token(&url))?;

        anyhow::ensure!(url.len() <= MAX_DETAIL_URL_BYTES);
        anyhow::ensure!(snapshot.event.description.len() <= 400);
        anyhow::ensure!(snapshot.event.affected_regions.len() <= 8);
        anyhow::ensure!(snapshot.event.source_event_id == "event-42");
        Ok(())
    }
}
