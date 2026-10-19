use crate::events::MatchJob;
use crate::models::{DisasterCategory, IncidentRecord, parse_event_epoch};
use crate::storage::{FjallStorage, InboxItem, IncidentResolutionCapacity, try_now_millis};
use anyhow::{Context, Result};

#[derive(Clone)]
pub(crate) struct EventCoordinator {
    storage: FjallStorage,
    policy: EventPolicy,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EventPolicy {
    pub(crate) push_updates: bool,
    pub(crate) update_min_report_gap: u32,
    pub(crate) ignore_training: bool,
    pub(crate) ignore_cancel: bool,
    pub(crate) stale_origin_seconds: i64,
}

impl Default for EventPolicy {
    fn default() -> Self {
        Self {
            push_updates: true,
            update_min_report_gap: 1,
            ignore_training: false,
            ignore_cancel: false,
            stale_origin_seconds: 0,
        }
    }
}

impl EventCoordinator {
    #[cfg(test)]
    pub(crate) fn new(storage: FjallStorage) -> Self {
        Self::with_policy(storage, EventPolicy::default())
    }

    pub(crate) fn with_policy(storage: FjallStorage, policy: EventPolicy) -> Self {
        Self { storage, policy }
    }

    pub(crate) fn process_next(&self) -> Result<Option<MatchJob>> {
        let Some(item) = self.storage.pending_inbox(1)?.into_iter().next() else {
            return Ok(None);
        };
        self.process(item)
    }

    fn process(&self, item: InboxItem) -> Result<Option<MatchJob>> {
        let _lock = self.storage.lock_incident_pipeline()?;
        let incident_id = match self.storage.resolve_incident(&item.event) {
            Ok(incident_id) => incident_id,
            Err(error) => {
                let Some(capacity) = error.downcast_ref::<IncidentResolutionCapacity>() else {
                    return Err(error);
                };
                return self.reject_capacity(item, capacity.0);
            }
        };
        let current = self.storage.incident(&incident_id)?;
        let now_ms = try_now_millis()?;
        let transition =
            match super::reducer::reduce_incident_at(current.as_ref(), &item.event, now_ms) {
                Ok(transition) => transition,
                Err(super::reducer::IncidentError::Capacity(capacity)) => {
                    return self.reject_capacity(item, capacity);
                }
            };
        if !transition.outcome.applied() {
            self.storage.complete_inbox(item.id)?;
            return Ok(None);
        }
        if !self.should_match(current.as_ref(), &item.event, now_ms) {
            self.storage
                .commit_incident_without_match(&transition.incident, &item.event, item.id)
                .context("failed to atomically advance Incident without matching")?;
            return Ok(None);
        }
        let job = MatchJob {
            id: self.storage.next_id("match_job")?,
            incident_id,
            event_revision: self.storage.next_id("event_revision")?,
            created_at_ms: now_ms,
        };
        self.storage
            .commit_incident_match_job(&transition.incident, &item.event, &job, item.id)
            .context("failed to atomically advance EventCoordinator")?;
        Ok(Some(job))
    }

    fn reject_capacity(
        &self,
        item: InboxItem,
        capacity: crate::models::IncidentCapacity,
    ) -> Result<Option<MatchJob>> {
        let inbox_id = item.id;
        self.storage
            .reject_inbox(item, format!("incident capacity exceeded: {capacity:?}"))?;
        tracing::warn!(
            event = "event.inbox_rejected",
            inbox_id,
            capacity = ?capacity,
            "event.inbox_rejected"
        );
        Ok(None)
    }

    fn should_match(
        &self,
        current: Option<&IncidentRecord>,
        event: &crate::models::DisasterEvent,
        now_ms: i64,
    ) -> bool {
        if event.training && self.policy.ignore_training
            || event.cancel && self.policy.ignore_cancel
            || stale_origin(event, self.policy.stale_origin_seconds, now_ms)
        {
            return false;
        }
        if event.cancel || current.is_none() {
            return true;
        }
        if !self.policy.push_updates {
            return false;
        }
        let previous_report = current
            .and_then(|incident| {
                incident.stream_watermarks.iter().find(|watermark| {
                    watermark.category == event.category
                        && watermark.source == event.source
                        && watermark.event_id == event.event_id
                })
            })
            .map_or(0, |watermark| watermark.report_num);
        event.report_num.saturating_sub(previous_report) >= self.policy.update_min_report_gap.max(1)
            || event.final_report
    }
}

fn stale_origin(
    event: &crate::models::DisasterEvent,
    stale_origin_seconds: i64,
    now_ms: i64,
) -> bool {
    if stale_origin_seconds <= 0
        || !matches!(
            event.category,
            DisasterCategory::EarthquakeWarning
                | DisasterCategory::EarthquakeReport
                | DisasterCategory::WeatherWarning
        )
    {
        return false;
    }
    parse_event_epoch(event).is_none_or(|occurred| {
        now_ms.div_euclid(1_000).saturating_sub(occurred) > stale_origin_seconds
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryBatch, DeliveryRow};
    use crate::models::{DisasterCategory, DisasterEvent, InterruptionLevel, ProviderChannel};
    use crate::subscriptions::{DestinationNumericId, SubscriptionId};

    #[test]
    fn incident_and_match_job_commit_with_inbox_completion() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage = FjallStorage::open(directory.path())?;
        let event = DisasterEvent {
            category: DisasterCategory::EarthquakeWarning,
            channel: ProviderChannel::Wolfx,
            source: "wolfx.cenc_eew".to_string(),
            event_id: "event".to_string(),
            revision: "1".to_string(),
            report_num: 1,
            title: String::new(),
            description: String::new(),
            latitude: Some(35.0),
            longitude: Some(105.0),
            magnitude: Some(5.0),
            depth_km: Some(10.0),
            affected_regions: Vec::new(),
            radius_km: None,
            level: 2,
            occurred_at: "2026-07-13T00:00:00Z".to_string(),
            final_report: false,
            cancel: false,
            training: false,
        };
        storage.ingest_with_cursor(ProviderChannel::Wolfx, vec![event], None)?;
        let coordinator = EventCoordinator::new(storage.clone());
        let job = coordinator.process_next()?.context("missing job")?;
        anyhow::ensure!(storage.pending_inbox(1)?.is_empty());
        anyhow::ensure!(storage.pending_match_jobs(1)? == vec![job]);
        Ok(())
    }

    #[test]
    fn cross_source_earthquakes_correlate_after_reopen() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let first_id = {
            let storage = FjallStorage::open(directory.path())?;
            let mut first = test_event("cenc.report", "first");
            first.channel = ProviderChannel::Cenc;
            storage.ingest_with_cursor(ProviderChannel::Cenc, vec![first], None)?;
            let job = EventCoordinator::new(storage.clone())
                .process_next()?
                .context("missing first job")?;
            storage.persist()?;
            job.incident_id
        };
        let storage = FjallStorage::open(directory.path())?;
        let mut second = test_event("wolfx.cenc_eew", "second");
        second.category = DisasterCategory::EarthquakeWarning;
        second.channel = ProviderChannel::Wolfx;
        second.latitude = Some(35.05);
        second.longitude = Some(105.05);
        second.magnitude = Some(5.4);
        second.occurred_at = "2026-07-13T00:01:00Z".to_string();
        storage.ingest_with_cursor(ProviderChannel::Wolfx, vec![second], None)?;
        let second_job = EventCoordinator::new(storage.clone())
            .process_next()?
            .context("missing second job")?;
        anyhow::ensure!(second_job.incident_id == first_id);
        let incident = storage.incident(&first_id)?.context("missing incident")?;
        anyhow::ensure!(incident.source_event_keys.len() == 2);
        Ok(())
    }

    #[test]
    fn replay_consumes_inbox_without_creating_another_match_job() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage = FjallStorage::open(directory.path())?;
        let event = test_event("cenc.report", "same");
        storage.ingest_with_cursor(ProviderChannel::Cenc, vec![event.clone()], None)?;
        let coordinator = EventCoordinator::new(storage.clone());
        let first = coordinator.process_next()?.context("missing first job")?;
        commit_matched_job(&storage, &first)?;
        storage.ingest_with_cursor(ProviderChannel::Cenc, vec![event], None)?;
        anyhow::ensure!(coordinator.process_next()?.is_none());
        anyhow::ensure!(storage.pending_inbox(1)?.is_empty());
        anyhow::ensure!(storage.pending_match_jobs(1)?.is_empty());
        Ok(())
    }

    #[test]
    fn suppressed_update_still_advances_incident_without_a_match_job() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage = FjallStorage::open(directory.path())?;
        let coordinator = EventCoordinator::with_policy(
            storage.clone(),
            EventPolicy {
                push_updates: false,
                ..EventPolicy::default()
            },
        );
        storage.ingest_with_cursor(
            ProviderChannel::Cenc,
            vec![test_event("cenc.report", "same")],
            None,
        )?;
        let first = coordinator.process_next()?.context("missing first job")?;
        commit_matched_job(&storage, &first)?;
        let mut update = test_event("cenc.report", "same");
        update.report_num = 2;
        update.revision = "2".to_string();
        storage.ingest_with_cursor(ProviderChannel::Cenc, vec![update], None)?;
        anyhow::ensure!(coordinator.process_next()?.is_none());
        let incident = storage
            .incident(&first.incident_id)?
            .context("missing updated incident")?;
        anyhow::ensure!(incident.stream_watermarks[0].report_num == 2);
        anyhow::ensure!(storage.pending_match_jobs(1)?.is_empty());
        Ok(())
    }

    #[test]
    fn first_policy_skipped_event_does_not_create_an_incident() -> Result<()> {
        let cases: [(EventPolicy, fn(&mut DisasterEvent)); 3] = [
            (
                EventPolicy {
                    ignore_training: true,
                    ..EventPolicy::default()
                },
                |event: &mut DisasterEvent| event.training = true,
            ),
            (
                EventPolicy {
                    ignore_cancel: true,
                    ..EventPolicy::default()
                },
                |event: &mut DisasterEvent| event.cancel = true,
            ),
            (
                EventPolicy {
                    stale_origin_seconds: 1,
                    ..EventPolicy::default()
                },
                |_: &mut DisasterEvent| {},
            ),
        ];
        for (policy, mutate) in cases {
            let directory = tempfile::tempdir()?;
            let storage = FjallStorage::open(directory.path())?;
            let mut event = test_event("cenc.report", "policy-skipped");
            mutate(&mut event);
            let incident_id = crate::models::IncidentId::derive(&event.event_key());
            storage.ingest_with_cursor(ProviderChannel::Cenc, vec![event], None)?;

            let job = EventCoordinator::with_policy(storage.clone(), policy).process_next()?;

            anyhow::ensure!(job.is_none());
            anyhow::ensure!(storage.pending_inbox(1)?.is_empty());
            anyhow::ensure!(storage.pending_match_jobs(1)?.is_empty());
            anyhow::ensure!(storage.incident(&incident_id)?.is_none());
        }
        Ok(())
    }

    fn commit_matched_job(storage: &FjallStorage, job: &MatchJob) -> Result<()> {
        let event = storage
            .event(job.event_revision)?
            .context("missing job event")?;
        storage.commit_match_batches(
            job.id,
            &[DeliveryBatch {
                id: storage.next_id("delivery_batch")?,
                incident_id: job.incident_id.clone(),
                event_revision: job.event_revision,
                category: event.category,
                shard: 0,
                created_at_ms: job.created_at_ms,
                rows: vec![DeliveryRow {
                    destination_id: DestinationNumericId(1),
                    subscription_id: SubscriptionId(1),
                    generation: 1,
                    target_ordinal: 0,
                    match_kind: 1,
                    interruption_level: InterruptionLevel::Active,
                    distance_m: 1_000,
                    intensity_cent: 100,
                }],
            }],
        )
    }

    #[test]
    fn capacity_failure_is_quarantined_without_blocking_newer_reports() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage = FjallStorage::open(directory.path())?;
        let coordinator = EventCoordinator::new(storage.clone());
        let mut current = test_event("cenc.report", "same");
        for update in 0..=16 {
            current.title = format!("correction-{update}");
            storage.ingest_with_cursor(ProviderChannel::Cenc, vec![current.clone()], None)?;
            drop(coordinator.process_next()?);
        }
        anyhow::ensure!(storage.pending_inbox(1)?.is_empty());
        anyhow::ensure!(storage.rejected_inbox_count()? == 1);

        current.report_num = 2;
        current.revision = "2".to_string();
        storage.ingest_with_cursor(ProviderChannel::Cenc, vec![current], None)?;
        anyhow::ensure!(coordinator.process_next()?.is_some());
        anyhow::ensure!(storage.pending_inbox(1)?.is_empty());
        Ok(())
    }

    fn test_event(source: &str, event_id: &str) -> DisasterEvent {
        DisasterEvent {
            category: DisasterCategory::EarthquakeReport,
            channel: ProviderChannel::Cenc,
            source: source.to_string(),
            event_id: event_id.to_string(),
            revision: "1".to_string(),
            report_num: 1,
            title: String::new(),
            description: String::new(),
            latitude: Some(35.0),
            longitude: Some(105.0),
            magnitude: Some(5.0),
            depth_km: Some(10.0),
            affected_regions: Vec::new(),
            radius_km: None,
            level: 2,
            occurred_at: "2026-07-13T00:00:00Z".to_string(),
            final_report: false,
            cancel: false,
            training: false,
        }
    }
}
