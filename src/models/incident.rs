use crate::models::{DisasterCategory, DisasterEvent, event_update_id};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::VecDeque;

pub const MAX_INCIDENT_TIMELINE: usize = 16;
const MAX_LATEST_SOURCES: usize = 8;
const MAX_SOURCE_EVENT_KEYS: usize = 32;
const MAX_STREAM_WATERMARKS: usize = 32;
const MAX_CURRENT_REPORT_UPDATES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IncidentId(String);

impl IncidentId {
    pub fn derive(event_key: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"disaster-alert:incident:v1\0");
        hasher.update(event_key.as_bytes());
        let digest = hasher.finalize();
        Self(URL_SAFE_NO_PAD.encode(&digest[..16]))
    }

    pub fn parse(value: &str) -> Option<Self> {
        if value.len() != 22
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return None;
        }
        Some(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentRecord {
    pub schema_version: u8,
    pub id: IncidentId,
    pub category: DisasterCategory,
    pub first_seen_at_ms: i64,
    pub updated_at_ms: i64,
    pub state_version: u64,
    pub source_event_keys: Vec<String>,
    pub latest_by_source: Vec<DisasterEvent>,
    pub stream_watermarks: Vec<IncidentStreamWatermark>,
    pub timeline: VecDeque<IncidentReportSummary>,
    pub has_matched_subscribers: bool,
    pub pending_match_jobs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentStreamWatermark {
    pub category: DisasterCategory,
    pub source: String,
    pub event_id: String,
    pub report_num: u32,
    pub level: u8,
    pub final_report: bool,
    pub cancel: bool,
    pub current_report_updates: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentApplyOutcome {
    Applied,
    Replay,
    Rejected,
    CapacityExceeded(IncidentCapacity),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentCapacity {
    StreamWatermarks,
    CurrentReportUpdates,
    SourceEventKeys,
    StateVersions,
    CorrelationCandidates,
}

impl IncidentApplyOutcome {
    pub const fn applied(self) -> bool {
        matches!(self, Self::Applied)
    }

    pub const fn should_project(self) -> bool {
        matches!(self, Self::Applied | Self::Replay)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentReportSummary {
    pub category: DisasterCategory,
    pub source: String,
    pub report_num: u32,
    pub revision: String,
    pub observed_at_ms: i64,
    pub magnitude: Option<f64>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub depth_km: Option<f64>,
    pub level: u8,
    pub final_report: bool,
    pub cancel: bool,
}

impl IncidentRecord {
    pub fn new(id: IncidentId, event: &DisasterEvent, now_ms: i64) -> Self {
        let event = bounded_event(event);
        let category = event.category;
        let source_event_key = event.event_key();
        let stream_watermark = IncidentStreamWatermark::from_event(&event);
        let summary = IncidentReportSummary::from_event(&event, now_ms);
        Self {
            schema_version: 1,
            id,
            category,
            first_seen_at_ms: now_ms,
            updated_at_ms: now_ms,
            state_version: 1,
            source_event_keys: vec![source_event_key],
            latest_by_source: vec![event.into_owned()],
            stream_watermarks: vec![stream_watermark],
            timeline: VecDeque::from([summary]),
            has_matched_subscribers: false,
            pending_match_jobs: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn apply(&mut self, event: &DisasterEvent, now_ms: i64) -> bool {
        self.apply_outcome(event, now_ms).applied()
    }

    pub fn apply_outcome(&mut self, event: &DisasterEvent, now_ms: i64) -> IncidentApplyOutcome {
        let event = bounded_event(event);
        if self.state_version == u64::MAX {
            return IncidentApplyOutcome::CapacityExceeded(IncidentCapacity::StateVersions);
        }
        let watermark = self
            .stream_watermarks
            .iter()
            .position(|watermark| watermark.matches(&event));
        let outcome = match watermark {
            Some(index) => self.stream_watermarks[index].outcome(&event),
            None if self.stream_watermarks.len() >= MAX_STREAM_WATERMARKS => {
                IncidentApplyOutcome::CapacityExceeded(IncidentCapacity::StreamWatermarks)
            }
            None => IncidentApplyOutcome::Applied,
        };
        if !outcome.applied() {
            return outcome;
        }
        let existing = self.latest_by_source.iter().position(|current| {
            current.source == event.source
                && current.category == event.category
                && current.event_id == event.event_id
        });
        if let Some(index) = watermark {
            self.stream_watermarks[index].commit(&event);
        } else {
            self.stream_watermarks
                .push(IncidentStreamWatermark::from_event(&event));
        }
        let summary = IncidentReportSummary::from_event(&event, now_ms);
        if self
            .timeline
            .back()
            .is_none_or(|current| !current.same_report(&summary))
        {
            if self.timeline.len() >= MAX_INCIDENT_TIMELINE {
                self.timeline.pop_front();
            }
            self.timeline.push_back(summary);
        }
        let event = event.into_owned();
        if let Some(index) = existing {
            self.latest_by_source[index] = event;
        } else {
            if self.latest_by_source.len() >= MAX_LATEST_SOURCES {
                self.latest_by_source.remove(0);
            }
            self.latest_by_source.push(event);
        }
        self.updated_at_ms = self.updated_at_ms.max(now_ms);
        self.state_version = self.state_version.saturating_add(1);
        IncidentApplyOutcome::Applied
    }

    pub fn remember_source_event_keys<'a>(
        &mut self,
        keys: impl IntoIterator<Item = &'a str>,
    ) -> std::result::Result<bool, IncidentCapacity> {
        let mut additions = Vec::new();
        for key in keys {
            if key.is_empty()
                || self.source_event_keys.iter().any(|current| current == key)
                || additions.iter().any(|current: &String| current == key)
            {
                continue;
            }
            if self.source_event_keys.len().saturating_add(additions.len()) >= MAX_SOURCE_EVENT_KEYS
            {
                return Err(IncidentCapacity::SourceEventKeys);
            }
            additions.push(key.to_string());
        }
        let changed = !additions.is_empty();
        self.source_event_keys.extend(additions);
        Ok(changed)
    }
}

impl IncidentStreamWatermark {
    fn from_event(event: &DisasterEvent) -> Self {
        let mut watermark = Self {
            category: event.category,
            source: event.source.clone(),
            event_id: event.event_id.clone(),
            report_num: event.report_num,
            level: event.level,
            final_report: event.final_report,
            cancel: event.cancel,
            current_report_updates: Vec::new(),
        };
        watermark.remember_update(event, false);
        watermark
    }

    fn matches(&self, event: &DisasterEvent) -> bool {
        self.category == event.category
            && self.source == event.source
            && self.event_id == event.event_id
    }

    fn outcome(&self, event: &DisasterEvent) -> IncidentApplyOutcome {
        if self.cancel && !event.cancel || self.final_report && !event.final_report && !event.cancel
        {
            return IncidentApplyOutcome::Rejected;
        }
        let terminal_transition =
            event.cancel && !self.cancel || event.final_report && !self.final_report;
        if event.report_num > self.report_num {
            return IncidentApplyOutcome::Applied;
        }
        if event.report_num < self.report_num {
            // Terminal state is monotonic and may arrive through a delayed source path. A plain
            // severity increase is not terminal and must never let an old report bypass ordering.
            if terminal_transition {
                return IncidentApplyOutcome::Applied;
            }
            if (event.cancel && self.cancel || event.final_report && self.final_report)
                && self.has_seen_update(event)
            {
                return IncidentApplyOutcome::Replay;
            }
            return IncidentApplyOutcome::Rejected;
        }
        if terminal_transition {
            return IncidentApplyOutcome::Applied;
        }
        if event.level > self.level {
            return IncidentApplyOutcome::Applied;
        }
        if event.level < self.level {
            return IncidentApplyOutcome::Rejected;
        }
        if self.has_seen_update(event) {
            return IncidentApplyOutcome::Replay;
        }
        if self.current_report_updates.len() < MAX_CURRENT_REPORT_UPDATES {
            IncidentApplyOutcome::Applied
        } else {
            IncidentApplyOutcome::CapacityExceeded(IncidentCapacity::CurrentReportUpdates)
        }
    }

    fn commit(&mut self, event: &DisasterEvent) {
        let newer_report = event.report_num > self.report_num;
        let safety_transition = self.is_safety_transition(event);
        if newer_report || safety_transition && event.report_num == self.report_num {
            self.current_report_updates.clear();
        }
        if event.report_num >= self.report_num {
            self.report_num = event.report_num;
            self.level = event.level;
        }
        self.final_report |= event.final_report;
        self.cancel |= event.cancel;
        self.remember_update(
            event,
            safety_transition && event.report_num == self.report_num,
        );
    }

    fn is_safety_transition(&self, event: &DisasterEvent) -> bool {
        event.cancel && !self.cancel
            || event.final_report && !self.final_report
            || event.level > self.level
    }

    fn has_seen_update(&self, event: &DisasterEvent) -> bool {
        self.current_report_updates
            .contains(&event_update_id(event))
    }

    fn remember_update(&mut self, event: &DisasterEvent, replace_oldest: bool) {
        let digest = event_update_id(event);
        if self.current_report_updates.contains(&digest) {
            return;
        }
        if self.current_report_updates.len() >= MAX_CURRENT_REPORT_UPDATES {
            if !replace_oldest {
                return;
            }
            self.current_report_updates.remove(0);
        }
        self.current_report_updates.push(digest);
    }
}

impl IncidentReportSummary {
    fn from_event(event: &DisasterEvent, observed_at_ms: i64) -> Self {
        Self {
            category: event.category,
            source: event.source.clone(),
            report_num: event.report_num,
            revision: event.revision.clone(),
            observed_at_ms,
            magnitude: event.magnitude,
            latitude: event.latitude,
            longitude: event.longitude,
            depth_km: event.depth_km,
            level: event.level,
            final_report: event.final_report,
            cancel: event.cancel,
        }
    }

    fn same_report(&self, other: &Self) -> bool {
        self.category == other.category
            && self.source == other.source
            && self.report_num == other.report_num
            && self.revision == other.revision
            && self.magnitude == other.magnitude
            && self.latitude == other.latitude
            && self.longitude == other.longitude
            && self.depth_km == other.depth_km
            && self.level == other.level
            && self.final_report == other.final_report
            && self.cancel == other.cancel
    }
}

fn bounded_event(event: &DisasterEvent) -> Cow<'_, DisasterEvent> {
    let exceeds_bounds = exceeds_char_limit(&event.title, 180)
        || exceeds_char_limit(&event.description, 4_000)
        || exceeds_char_limit(&event.occurred_at, 80)
        || event.affected_regions.len() > 20
        || event
            .affected_regions
            .iter()
            .any(|region| exceeds_char_limit(region, 80));
    if !exceeds_bounds {
        return Cow::Borrowed(event);
    }

    let mut bounded = event.clone();
    truncate_in_place(&mut bounded.title, 180);
    truncate_in_place(&mut bounded.description, 4_000);
    truncate_in_place(&mut bounded.occurred_at, 80);
    bounded.affected_regions.truncate(20);
    for region in &mut bounded.affected_regions {
        truncate_in_place(region, 80);
    }
    Cow::Owned(bounded)
}

fn exceeds_char_limit(value: &str, max_chars: usize) -> bool {
    value.chars().nth(max_chars).is_some()
}

fn truncate_in_place(value: &mut String, max_chars: usize) {
    if let Some((byte_index, _character)) = value.char_indices().nth(max_chars) {
        value.truncate(byte_index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProviderChannel;

    fn event(source: &str, report_num: u32) -> DisasterEvent {
        DisasterEvent {
            category: DisasterCategory::EarthquakeWarning,
            channel: ProviderChannel::Cenc,
            source: source.to_string(),
            event_id: format!("{source}-event"),
            revision: report_num.to_string(),
            report_num,
            title: "earthquake".to_string(),
            description: String::new(),
            latitude: Some(35.0),
            longitude: Some(139.0),
            magnitude: Some(5.0),
            depth_km: Some(10.0),
            affected_regions: Vec::new(),
            radius_km: None,
            level: 2,
            occurred_at: "2026-07-12 12:00:00".to_string(),
            final_report: false,
            cancel: false,
            training: false,
        }
    }

    #[test]
    fn timeline_is_bounded_to_latest_reports() {
        let id = IncidentId::derive("source:event");
        let mut record = IncidentRecord::new(id, &event("source", 1), 1);
        for report_num in 2..=32 {
            assert!(record.apply(&event("source", report_num), i64::from(report_num)));
        }

        assert_eq!(record.timeline.len(), MAX_INCIDENT_TIMELINE);
        assert_eq!(
            record.timeline.front().map(|item| item.report_num),
            Some(17)
        );
        assert_eq!(record.timeline.back().map(|item| item.report_num), Some(32));
    }

    #[test]
    fn stale_or_terminal_regression_does_not_replace_latest_source() {
        let id = IncidentId::derive("source:event");
        let mut final_report = event("source", 5);
        final_report.final_report = true;
        let mut record = IncidentRecord::new(id, &final_report, 5);
        let mut regression = event("source", 6);
        regression.final_report = false;

        assert!(!record.apply(&regression, 6));
        assert!(!record.apply(&event("source", 4), 7));
        assert_eq!(record.latest_by_source[0].report_num, 5);
        assert!(record.latest_by_source[0].final_report);
        assert_eq!(record.timeline.len(), 1);
    }

    #[test]
    fn newer_report_can_authoritatively_lower_the_current_level() {
        let id = IncidentId::derive("source:event");
        let mut first = event("source", 1);
        first.level = 4;
        let mut record = IncidentRecord::new(id, &first, 1);
        let mut newer = event("source", 2);
        newer.level = 2;

        assert!(record.apply(&newer, 2));
        assert_eq!(record.latest_by_source[0].level, 2);
        assert_eq!(record.stream_watermarks[0].level, 2);
        assert_eq!(record.timeline.back().map(|item| item.level), Some(2));
    }

    #[test]
    fn low_report_number_cancel_is_applied_once_without_lowering_the_watermark() {
        let id = IncidentId::derive("source:event");
        let active = event("source", 5);
        let mut record = IncidentRecord::new(id, &active, 1);
        let mut cancel = event("source", 0);
        cancel.revision = "cancel".to_string();
        cancel.cancel = true;

        assert_eq!(
            record.apply_outcome(&cancel, 2),
            IncidentApplyOutcome::Applied
        );
        assert!(record.stream_watermarks[0].cancel);
        assert_eq!(record.stream_watermarks[0].report_num, 5);
        assert_eq!(
            record.apply_outcome(&cancel, 3),
            IncidentApplyOutcome::Replay
        );
        assert_eq!(record.state_version, 2);
    }

    #[test]
    fn revisionless_payload_correction_applies_once() {
        let id = IncidentId::derive("source:event");
        let mut first = event("source", 1);
        first.revision.clear();
        let mut record = IncidentRecord::new(id, &first, 1);
        let mut correction = first.clone();
        correction.title = "corrected title".to_string();

        assert_eq!(
            record.apply_outcome(&correction, 2),
            IncidentApplyOutcome::Applied
        );
        assert_eq!(record.latest_by_source[0].title, "corrected title");
        assert_eq!(
            record.apply_outcome(&correction, 3),
            IncidentApplyOutcome::Replay
        );
    }

    #[test]
    fn normal_replay_does_not_change_incident_state() {
        let id = IncidentId::derive("source:event");
        let original = event("source", 1);
        let mut record = IncidentRecord::new(id, &original, 1);

        assert_eq!(
            record.apply_outcome(&original, 2),
            IncidentApplyOutcome::Replay
        );
        assert_eq!(record.state_version, 1);
        assert_eq!(record.updated_at_ms, 1);
        assert_eq!(record.timeline.len(), 1);
    }

    #[test]
    fn changes_beyond_persisted_payload_bounds_are_replays() {
        let id = IncidentId::derive("source:event");
        let mut original = event("source", 1);
        original.revision.clear();
        original.title = format!("{}x", "a".repeat(180));
        original.description = format!("{}x", "b".repeat(4_000));
        original.affected_regions = (0..21)
            .map(|index| format!("{}-{index}", "region".repeat(20)))
            .collect();
        let mut record = IncidentRecord::new(id, &original, 1);
        let mut outside_only = original;
        outside_only.title.pop();
        outside_only.title.push('y');
        outside_only.description.pop();
        outside_only.description.push('y');
        outside_only.affected_regions[20] = "different discarded region".to_string();

        assert_eq!(
            record.apply_outcome(&outside_only, 2),
            IncidentApplyOutcome::Replay
        );
        assert_eq!(record.state_version, 1);
        assert_eq!(record.latest_by_source[0].title, "a".repeat(180));
        assert_eq!(record.latest_by_source[0].affected_regions.len(), 20);
    }

    #[test]
    fn correction_within_persisted_payload_bounds_is_applied() {
        let id = IncidentId::derive("source:event");
        let mut original = event("source", 1);
        original.revision.clear();
        original.title = "a".repeat(181);
        let mut record = IncidentRecord::new(id, &original, 1);
        let mut correction = original;
        correction.title.replace_range(..1, "b");

        assert_eq!(
            record.apply_outcome(&correction, 2),
            IncidentApplyOutcome::Applied
        );
        assert!(record.latest_by_source[0].title.starts_with('b'));
        assert_eq!(record.latest_by_source[0].title.chars().count(), 180);
    }

    #[test]
    fn reports_from_separate_sources_coexist() {
        let id = IncidentId::derive("source-a:event");
        let mut record = IncidentRecord::new(id, &event("source-a", 1), 1);

        assert!(record.apply(&event("source-b", 3), 2));
        assert_eq!(record.latest_by_source.len(), 2);
        assert!(
            record
                .latest_by_source
                .iter()
                .any(|item| item.source == "source-a" && item.report_num == 1)
        );
        assert!(
            record
                .latest_by_source
                .iter()
                .any(|item| item.source == "source-b" && item.report_num == 3)
        );
    }

    #[test]
    fn warning_and_report_streams_from_the_same_source_coexist() {
        let id = IncidentId::derive("source:event");
        let mut record = IncidentRecord::new(id, &event("source", 1), 1);
        let mut report = event("source", 1);
        report.category = DisasterCategory::EarthquakeReport;

        assert!(record.apply(&report, 2));
        assert_eq!(record.latest_by_source.len(), 2);
        assert!(
            record
                .latest_by_source
                .iter()
                .any(|event| event.category == DisasterCategory::EarthquakeWarning)
        );
        assert!(
            record
                .latest_by_source
                .iter()
                .any(|event| event.category == DisasterCategory::EarthquakeReport)
        );
    }

    #[test]
    fn evicted_stream_keeps_its_ordering_and_terminal_watermark() {
        let id = IncidentId::derive("source-0:event");
        let mut latest = event("source-0", 5);
        latest.final_report = true;
        let mut record = IncidentRecord::new(id, &latest, 1);
        for source in 1..=MAX_LATEST_SOURCES {
            assert!(record.apply(&event(&format!("source-{source}"), 1), source as i64 + 1));
        }
        assert!(
            !record
                .latest_by_source
                .iter()
                .any(|event| event.source == "source-0")
        );

        assert!(!record.apply(&event("source-0", 4), 20));
        let mut terminal_regression = event("source-0", 6);
        terminal_regression.final_report = false;
        assert!(!record.apply(&terminal_regression, 21));
        assert_eq!(record.latest_by_source.len(), MAX_LATEST_SOURCES);
    }

    #[test]
    fn saturated_incident_watermarks_stay_within_storage_bound() -> anyhow::Result<()> {
        let id = IncidentId::derive("source-0:event");
        let mut record = IncidentRecord::new(id, &event("source-0", 1), 1);
        for stream in 0..MAX_STREAM_WATERMARKS {
            for revision in 1..=MAX_CURRENT_REPORT_UPDATES {
                let mut update = event(&format!("source-{stream:02}-{}", "x".repeat(100)), 1);
                update.event_id = format!("event-{stream:02}-{}", "y".repeat(101));
                update.revision = format!("revision-{revision:02}-{}", "z".repeat(100));
                let _changed = record.apply(&update, i64::try_from(stream + revision)?);
            }
        }
        anyhow::ensure!(serde_json::to_vec(&record)?.len() <= 64 * 1024);
        Ok(())
    }

    #[test]
    fn capacity_limits_preserve_existing_stream_ordering() {
        let id = IncidentId::derive("source-0:event");
        let mut record = IncidentRecord::new(id, &event("source-0", 1), 1);
        for stream in 1..MAX_STREAM_WATERMARKS {
            assert!(record.apply(&event(&format!("source-{stream}"), 1), stream as i64 + 1));
        }
        assert_eq!(
            record.apply_outcome(&event("source-new", 1), 100),
            IncidentApplyOutcome::CapacityExceeded(IncidentCapacity::StreamWatermarks)
        );

        let mut correction = event("source-1", 1);
        for revision in 2..=MAX_CURRENT_REPORT_UPDATES {
            correction.revision = format!("revision-{revision}");
            assert!(record.apply(&correction, 100 + revision as i64));
        }
        correction.revision = "after-capacity".to_string();
        assert_eq!(
            record.apply_outcome(&correction, 200),
            IncidentApplyOutcome::CapacityExceeded(IncidentCapacity::CurrentReportUpdates)
        );
        correction.cancel = true;
        assert!(record.apply(&correction, 201));
        assert_eq!(
            record.apply_outcome(&correction, 202),
            IncidentApplyOutcome::Replay
        );
    }

    #[test]
    fn long_identity_fields_are_not_merged_by_a_shared_prefix() {
        let id = IncidentId::derive("source:event");
        let mut first = event(&format!("{}a", "s".repeat(128)), 1);
        first.event_id = format!("{}a", "e".repeat(128));
        let mut second = first.clone();
        second.source = format!("{}b", "s".repeat(128));
        second.event_id = format!("{}b", "e".repeat(128));
        let mut record = IncidentRecord::new(id, &first, 1);

        assert!(record.apply(&second, 2));
        assert_eq!(record.stream_watermarks.len(), 2);
    }
}
