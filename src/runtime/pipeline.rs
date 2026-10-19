use crate::config::Config;
use crate::delivery::{
    AlertRecipient, AlertTiming, BarkDeliveryError, BarkNotifier, CountdownRecipient,
    DeadLetterItem, DeliverySuccess, NotificationContextInput, NotificationLinkService,
    remaining_seconds,
};
use crate::delivery::{DeliveryBatch, DeliveryRow, RetryItem};
use crate::events::{EventCoordinator, EventPolicy};
use crate::matching::{MatchEngine, MatchPlan};
use crate::models::{
    DisasterCategory, DisasterEvent, IncidentId, InterruptionLevel, ProviderChannel,
    parse_event_epoch,
};
use crate::providers::ProviderCursor;
use crate::runtime::RuntimeStatus;
use crate::runtime::ready_queue::ReadyQueue;
use crate::storage::Storage;
use crate::storage::{FjallStorage, try_now_millis};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

const SCAN_INTERVAL: Duration = Duration::from_millis(25);
const READY_QUEUE_CAPACITY: usize = 4_096;
const READY_QUEUE_BYTES: usize = 64 * 1024;
const DELIVERY_PAGE: usize = 128;
const MAX_ACTIVE_DELIVERY_BATCHES: usize = 64;
const MAX_ACTIVE_RETRIES: usize = 64;
const DELIVERY_ROWS_PER_BATCH: usize = 512;
const DELIVERY_SHARDS: u64 = 64;
const MAX_RETRY_ATTEMPTS: u16 = 12;
const MAX_RETRY_AGE_MS: i64 = 24 * 60 * 60 * 1_000;
const COUNTDOWN_COMMAND_CAPACITY: usize = 4_096;

#[derive(Clone)]
pub(crate) struct EventRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    storage: FjallStorage,
    coordinator: EventCoordinator,
    matcher: Arc<MatchEngine>,
    notifier: BarkNotifier,
    notification_links: NotificationLinkService,
    runtime_status: RuntimeStatus,
    p_wave_km_s: f64,
    s_wave_km_s: f64,
    closing: AtomicBool,
    event_stopped: AtomicBool,
    match_stopped: AtomicBool,
    delivery_stopped: AtomicBool,
    inbox_ready: ReadyQueue<AcceptedEvent>,
    match_ready: ReadyQueue<ReadyMatchJob>,
    delivery_ready: ReadyQueue<ReadyDeliveryBatch>,
    destination_locks: Mutex<HashMap<u64, Weak<AsyncMutex<()>>>>,
    countdown_commands: mpsc::Sender<CountdownCommand>,
    countdown_receiver: Mutex<Option<mpsc::Receiver<CountdownCommand>>>,
    countdown_shutdown: watch::Sender<bool>,
    next_countdown_id: AtomicU64,
}

#[derive(Clone, Copy)]
struct AcceptedEvent(u64);

#[derive(Clone, Copy)]
struct ReadyMatchJob(u64);

#[derive(Clone, Copy)]
struct ReadyDeliveryBatch(u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CountdownKey {
    incident_id: IncidentId,
    destination_id: u64,
    target_ordinal: u8,
}

struct EarthquakeCountdown {
    key: CountdownKey,
    subscription_id: crate::subscriptions::SubscriptionId,
    generation: u64,
    recipient: CountdownRecipient,
    event: Arc<DisasterEvent>,
    timing: AlertTiming,
    detail_url: String,
}

enum CountdownCommand {
    Schedule(EarthquakeCountdown),
    Cancel(CountdownKey),
}

struct ActiveCountdown {
    id: u64,
    cancel: watch::Sender<bool>,
}

#[derive(Default)]
struct DeliveryLaneOutcome {
    completed_rows: Vec<u32>,
    skipped_rows: Vec<u32>,
    successes: Vec<DeliverySuccess>,
    retries: Vec<RetryItem>,
    dead_letters: Vec<DeadLetterItem>,
}

impl EventRuntime {
    pub(crate) fn new(
        storage: Storage,
        config: &Config,
        notifier: BarkNotifier,
        notification_links: NotificationLinkService,
        runtime_status: RuntimeStatus,
    ) -> Result<Self> {
        let storage = storage.inner();
        let (countdown_commands, countdown_receiver) = mpsc::channel(COUNTDOWN_COMMAND_CAPACITY);
        let (countdown_shutdown, _countdown_shutdown_receiver) = watch::channel(false);
        let match_threads = std::thread::available_parallelism().map_or(1, |value| value.get());
        let inbox_ready_metrics = runtime_status.inbox_ready_metrics();
        let match_ready_metrics = runtime_status.match_ready_metrics();
        let delivery_ready_metrics = runtime_status.delivery_ready_metrics();
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                coordinator: EventCoordinator::with_policy(
                    storage.clone(),
                    EventPolicy {
                        push_updates: config.push_updates,
                        update_min_report_gap: config.update_min_report_gap,
                        ignore_training: config.ignore_training,
                        ignore_cancel: config.ignore_cancel,
                        stale_origin_seconds: config.stale_origin_seconds,
                    },
                ),
                matcher: Arc::new(MatchEngine::new(match_threads)?),
                storage,
                notifier,
                notification_links,
                runtime_status,
                p_wave_km_s: config.p_wave_km_s,
                s_wave_km_s: config.s_wave_km_s,
                closing: AtomicBool::new(false),
                event_stopped: AtomicBool::new(false),
                match_stopped: AtomicBool::new(false),
                delivery_stopped: AtomicBool::new(false),
                inbox_ready: ReadyQueue::new(
                    READY_QUEUE_CAPACITY,
                    READY_QUEUE_BYTES,
                    inbox_ready_metrics,
                ),
                match_ready: ReadyQueue::new(
                    READY_QUEUE_CAPACITY,
                    READY_QUEUE_BYTES,
                    match_ready_metrics,
                ),
                delivery_ready: ReadyQueue::new(
                    READY_QUEUE_CAPACITY,
                    READY_QUEUE_BYTES,
                    delivery_ready_metrics,
                ),
                destination_locks: Mutex::new(HashMap::new()),
                countdown_commands,
                countdown_receiver: Mutex::new(Some(countdown_receiver)),
                countdown_shutdown,
                next_countdown_id: AtomicU64::new(1),
            }),
        })
    }

    #[cfg(any(test, feature = "benchmarks"))]
    pub(crate) fn for_test(
        storage: Storage,
        notifier: BarkNotifier,
        notification_links: NotificationLinkService,
    ) -> Result<Self> {
        let storage = storage.inner();
        let runtime_status = RuntimeStatus::default();
        let (countdown_commands, countdown_receiver) = mpsc::channel(COUNTDOWN_COMMAND_CAPACITY);
        let (countdown_shutdown, _countdown_shutdown_receiver) = watch::channel(false);
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                coordinator: EventCoordinator::with_policy(storage.clone(), EventPolicy::default()),
                matcher: Arc::new(MatchEngine::new(1)?),
                storage,
                notifier,
                notification_links,
                runtime_status: runtime_status.clone(),
                p_wave_km_s: 6.0,
                s_wave_km_s: 3.5,
                closing: AtomicBool::new(false),
                event_stopped: AtomicBool::new(false),
                match_stopped: AtomicBool::new(false),
                delivery_stopped: AtomicBool::new(false),
                inbox_ready: ReadyQueue::new(
                    READY_QUEUE_CAPACITY,
                    READY_QUEUE_BYTES,
                    runtime_status.inbox_ready_metrics(),
                ),
                match_ready: ReadyQueue::new(
                    READY_QUEUE_CAPACITY,
                    READY_QUEUE_BYTES,
                    runtime_status.match_ready_metrics(),
                ),
                delivery_ready: ReadyQueue::new(
                    READY_QUEUE_CAPACITY,
                    READY_QUEUE_BYTES,
                    runtime_status.delivery_ready_metrics(),
                ),
                destination_locks: Mutex::new(HashMap::new()),
                countdown_commands,
                countdown_receiver: Mutex::new(Some(countdown_receiver)),
                countdown_shutdown,
                next_countdown_id: AtomicU64::new(1),
            }),
        })
    }

    #[cfg(feature = "benchmarks")]
    pub(crate) async fn process_delivery_batch_for_benchmark(
        &self,
        batch: DeliveryBatch,
    ) -> Result<()> {
        self.process_delivery_batch(batch).await
    }

    pub(crate) async fn submit_nonblocking(&self, event: DisasterEvent) -> bool {
        self.submit_provider_batch_inner(event.channel, vec![event], None)
            .await
    }

    pub(crate) async fn submit_provider_batch(
        &self,
        provider: ProviderChannel,
        events: Vec<DisasterEvent>,
        cursor: ProviderCursor,
    ) -> bool {
        self.submit_provider_batch_inner(provider, events, Some(cursor))
            .await
    }

    pub(crate) async fn submit_provider_snapshot_batch(
        &self,
        provider: ProviderChannel,
        events: Vec<DisasterEvent>,
        cursor: Option<ProviderCursor>,
    ) -> bool {
        self.submit_provider_batch_inner(provider, events, cursor)
            .await
    }

    async fn submit_provider_batch_inner(
        &self,
        provider: ProviderChannel,
        events: Vec<DisasterEvent>,
        cursor: Option<ProviderCursor>,
    ) -> bool {
        if self.inner.closing.load(Ordering::Acquire) {
            return false;
        }
        let events = match events
            .into_iter()
            .enumerate()
            .map(|(index, event)| sanitize_event(event).map_err(|reason| (index, reason)))
            .collect::<std::result::Result<Vec<_>, _>>()
        {
            Ok(events) => events,
            Err((index, reason)) => {
                tracing::warn!(
                    event = "event.provider_batch_rejected",
                    provider = provider.as_str(),
                    event_index = index,
                    reason,
                    "event.provider_batch_rejected"
                );
                return false;
            }
        };
        let storage = self.inner.storage.clone();
        let committed = tokio::task::spawn_blocking(move || {
            storage.ingest_with_cursor(
                provider,
                events,
                cursor.as_ref().map(|value| (value.stream(), value.value())),
            )
        })
        .await;
        match committed {
            Ok(Ok(ids)) => {
                for id in ids {
                    let _queued = self.inner.inbox_ready.try_push(AcceptedEvent(id));
                }
                true
            }
            Ok(Err(error)) => {
                tracing::error!(event = "event.ingest_failed", error = ?error, "event.ingest_failed");
                false
            }
            Err(error) => {
                tracing::error!(event = "event.ingest_task_failed", error = ?error, "event.ingest_task_failed");
                false
            }
        }
    }

    pub(crate) async fn provider_cursors(
        &self,
        provider: ProviderChannel,
        streams: Vec<String>,
    ) -> Result<Vec<ProviderCursor>> {
        let storage = self.inner.storage.clone();
        tokio::task::spawn_blocking(move || {
            storage.provider_cursors(provider, &streams).map(|values| {
                values
                    .into_iter()
                    .map(|(stream, value)| ProviderCursor::new(stream, value))
                    .collect()
            })
        })
        .await
        .context("provider cursor recovery task failed")??
    }

    pub(crate) async fn close(&self) {
        self.inner.closing.store(true, Ordering::Release);
        let _result = self.inner.countdown_shutdown.send(true);
        self.inner.inbox_ready.notify_waiters();
        self.inner.match_ready.notify_waiters();
        self.inner.delivery_ready.notify_waiters();
    }

    pub(crate) async fn recover(&self) -> Result<()> {
        self.queue_delivery_recovery().await?;
        self.queue_match_recovery().await?;
        self.queue_event_recovery().await
    }

    async fn queue_event_recovery(&self) -> Result<()> {
        let storage = self.inner.storage.clone();
        let ids = tokio::task::spawn_blocking(move || {
            storage
                .pending_inbox(READY_QUEUE_CAPACITY)
                .map(|items| items.into_iter().map(|item| item.id).collect::<Vec<_>>())
        })
        .await
        .context("Inbox recovery task failed")??;
        for id in ids {
            let _queued = self.inner.inbox_ready.try_push(AcceptedEvent(id));
        }
        Ok(())
    }

    async fn queue_match_recovery(&self) -> Result<()> {
        let storage = self.inner.storage.clone();
        let ids = tokio::task::spawn_blocking(move || {
            storage
                .pending_match_jobs(READY_QUEUE_CAPACITY)
                .map(|jobs| jobs.into_iter().map(|job| job.id).collect::<Vec<_>>())
        })
        .await
        .context("Match recovery task failed")??;
        for id in ids {
            let _queued = self.inner.match_ready.try_push(ReadyMatchJob(id));
        }
        Ok(())
    }

    async fn queue_delivery_recovery(&self) -> Result<()> {
        let storage = self.inner.storage.clone();
        let ids = tokio::task::spawn_blocking(move || {
            storage
                .pending_delivery_batches(READY_QUEUE_CAPACITY)
                .map(|batches| {
                    batches
                        .into_iter()
                        .map(|batch| batch.id)
                        .collect::<Vec<_>>()
                })
        })
        .await
        .context("Delivery recovery task failed")??;
        for id in ids {
            let _queued = self.inner.delivery_ready.try_push(ReadyDeliveryBatch(id));
        }
        Ok(())
    }

    pub(crate) async fn run(&self) -> Result<()> {
        let mut workers = tokio::task::JoinSet::new();
        let runtime = self.clone();
        workers.spawn(async move { ("event coordinator", runtime.run_event_coordinator().await) });
        let runtime = self.clone();
        workers.spawn(async move { ("match engine", runtime.run_match_engine().await) });
        let runtime = self.clone();
        workers.spawn(async move { ("delivery engine", runtime.run_delivery_engine().await) });
        let runtime = self.clone();
        workers.spawn(async move { ("retry engine", runtime.run_retry_engine().await) });
        let runtime = self.clone();
        workers.spawn(async move { ("countdown engine", runtime.run_countdown_engine().await) });
        while let Some(joined) = workers.join_next().await {
            match joined {
                Ok((name, Ok(()))) if !self.inner.closing.load(Ordering::Acquire) => {
                    self.close().await;
                    workers.abort_all();
                    while workers.join_next().await.is_some() {}
                    anyhow::bail!("{name} terminated unexpectedly");
                }
                Ok((_name, Ok(()))) => {}
                Ok((name, Err(error))) => {
                    self.close().await;
                    workers.abort_all();
                    while workers.join_next().await.is_some() {}
                    return Err(error).with_context(|| format!("{name} failed"));
                }
                Err(error) => {
                    self.close().await;
                    workers.abort_all();
                    while workers.join_next().await.is_some() {}
                    return Err(error).context("event runtime worker panicked or was cancelled");
                }
            }
        }
        Ok(())
    }

    async fn run_event_coordinator(&self) -> Result<()> {
        loop {
            if let Some(AcceptedEvent(_notified_id)) = self.inner.inbox_ready.pop() {
                let coordinator = self.inner.coordinator.clone();
                let job = tokio::task::spawn_blocking(move || coordinator.process_next())
                    .await
                    .context("EventCoordinator notification task failed")??;
                if let Some(job) = job {
                    let _queued = self.inner.match_ready.try_push(ReadyMatchJob(job.id));
                }
                continue;
            }
            let coordinator = self.inner.coordinator.clone();
            let job = tokio::task::spawn_blocking(move || coordinator.process_next())
                .await
                .context("EventCoordinator task failed")??;
            if let Some(job) = job {
                let _queued = self.inner.match_ready.try_push(ReadyMatchJob(job.id));
                continue;
            }
            if self.inner.closing.load(Ordering::Acquire) {
                self.inner.event_stopped.store(true, Ordering::Release);
                self.inner.match_ready.notify_waiters();
                return Ok(());
            }
            tokio::select! {
                () = self.inner.inbox_ready.notified() => {}
                () = tokio::time::sleep(SCAN_INTERVAL) => {}
            }
        }
    }

    async fn run_match_engine(&self) -> Result<()> {
        loop {
            let job = if let Some(ReadyMatchJob(id)) = self.inner.match_ready.pop() {
                let storage = self.inner.storage.clone();
                tokio::task::spawn_blocking(move || storage.match_job(id))
                    .await
                    .context("match notification task failed")??
            } else {
                let storage = self.inner.storage.clone();
                tokio::task::spawn_blocking(move || storage.next_match_job())
                    .await
                    .context("match recovery task failed")??
            };
            let Some(job) = job else {
                if self.inner.closing.load(Ordering::Acquire) {
                    if self.inner.event_stopped.load(Ordering::Acquire) {
                        self.inner.match_stopped.store(true, Ordering::Release);
                        self.inner.delivery_ready.notify_waiters();
                        return Ok(());
                    }
                    tokio::select! {
                        () = self.inner.match_ready.notified() => {}
                        () = tokio::time::sleep(SCAN_INTERVAL) => {}
                    }
                    continue;
                }
                tokio::select! {
                    () = self.inner.match_ready.notified() => {}
                    () = tokio::time::sleep(SCAN_INTERVAL) => {}
                }
                continue;
            };
            for batch_id in self.process_match_job(job).await? {
                let _queued = self
                    .inner
                    .delivery_ready
                    .try_push(ReadyDeliveryBatch(batch_id));
            }
        }
    }

    async fn process_match_job(&self, job: crate::events::MatchJob) -> Result<Vec<u64>> {
        let storage = self.inner.storage.clone();
        let matcher = Arc::clone(&self.inner.matcher);
        tokio::task::spawn_blocking(move || {
            let event = storage
                .event(job.event_revision)?
                .context("MatchJob references missing event")?;
            let category = event.category;
            let mut rows = if event.cancel {
                cancellation_rows(storage.delivered_rows(&job.incident_id, event.category)?)
            } else {
                let plan = MatchPlan::for_event(&event)?;
                let blocks = storage.posting_blocks(&plan)?;
                let subscriptions = storage.load_compiled_blocks(&blocks)?;
                matcher.match_blocks(Arc::new(event), blocks, &subscriptions)
            };
            rows.sort_unstable_by_key(|row| {
                (
                    delivery_shard(row.destination_id.0),
                    row.destination_id.0,
                    row.subscription_id.0,
                )
            });
            let batches = build_delivery_batches(&storage, &job, category, &rows)?;
            let ids = batches.iter().map(|batch| batch.id).collect();
            storage.commit_match_batches(job.id, &batches)?;
            Ok::<_, anyhow::Error>(ids)
        })
        .await
        .context("MatchEngine task failed")?
    }

    async fn run_delivery_engine(&self) -> Result<()> {
        let mut attempts = tokio::task::JoinSet::new();
        let mut active = std::collections::HashSet::new();
        loop {
            while let Some(result) = attempts.try_join_next() {
                let (batch_id, result) = result.context("delivery batch task failed")?;
                active.remove(&batch_id);
                result?;
            }
            if attempts.len() < MAX_ACTIVE_DELIVERY_BATCHES {
                let notified_id = self
                    .inner
                    .delivery_ready
                    .pop()
                    .map(|ReadyDeliveryBatch(id)| id)
                    .filter(|id| !active.contains(id));
                let storage = self.inner.storage.clone();
                let active_ids = active.clone();
                let batch = tokio::task::spawn_blocking(move || {
                    if let Some(id) = notified_id
                        && let Some(batch) = storage.pending_delivery_batch(id)?
                    {
                        return Ok(Some(batch));
                    }
                    storage
                        .pending_delivery_batches(DELIVERY_PAGE)
                        .map(|batches| {
                            batches
                                .into_iter()
                                .find(|batch| !active_ids.contains(&batch.id))
                        })
                })
                .await
                .context("delivery recovery task failed")??;
                if let Some(batch) = batch {
                    let batch_id = batch.id;
                    active.insert(batch_id);
                    let runtime = self.clone();
                    attempts.spawn(async move {
                        (batch_id, runtime.process_delivery_batch(batch).await)
                    });
                    continue;
                }
            }
            if self.inner.closing.load(Ordering::Acquire)
                && self.inner.match_stopped.load(Ordering::Acquire)
                && attempts.is_empty()
            {
                self.inner.delivery_stopped.store(true, Ordering::Release);
                self.inner.delivery_ready.notify_waiters();
                return Ok(());
            }
            tokio::select! {
                result = attempts.join_next(), if !attempts.is_empty() => {
                    if let Some(result) = result {
                        let (batch_id, result) = result.context("delivery batch task failed")?;
                        active.remove(&batch_id);
                        result?;
                    }
                }
                () = self.inner.delivery_ready.notified() => {}
                () = tokio::time::sleep(SCAN_INTERVAL) => {}
            }
        }
    }

    async fn process_delivery_batch(&self, batch: DeliveryBatch) -> Result<()> {
        let storage = self.inner.storage.clone();
        let event_revision = batch.event_revision;
        let batch_id = batch.id;
        let (event, pending_rows) = tokio::task::spawn_blocking(move || {
            let event = storage
                .event(event_revision)?
                .context("DeliveryBatch references missing event")?;
            let pending_rows = storage.pending_delivery_rows(batch_id)?;
            Ok::<_, anyhow::Error>((event, pending_rows))
        })
        .await
        .context("delivery batch read task failed")??;
        let event = Arc::new(event);
        let batch = Arc::new(batch);
        let mut lanes = HashMap::<u64, Vec<(usize, DeliveryRow)>>::new();
        for (row_index, row) in pending_rows {
            lanes
                .entry(row.destination_id.0)
                .or_default()
                .push((row_index, row));
        }
        let mut attempts = tokio::task::JoinSet::new();
        for rows in lanes.into_values() {
            let runtime = self.clone();
            let event = Arc::clone(&event);
            let batch = Arc::clone(&batch);
            attempts
                .spawn(async move { runtime.process_destination_lane(&event, &batch, rows).await });
        }
        while let Some(result) = attempts.join_next().await {
            result.context("delivery destination lane task failed")??;
        }
        Ok(())
    }

    async fn process_destination_lane(
        &self,
        event: &Arc<DisasterEvent>,
        batch: &DeliveryBatch,
        rows: Vec<(usize, DeliveryRow)>,
    ) -> Result<DeliveryLaneOutcome> {
        let Some((first_row_index, first)) = rows.first() else {
            return Ok(DeliveryLaneOutcome::default());
        };
        let destination_id = first.destination_id;
        let lock = self.destination_lock(destination_id.0);
        let guard = lock.lock().await;
        let first_index =
            u32::try_from(*first_row_index).context("delivery row index exceeds u32")?;
        let storage = self.inner.storage.clone();
        let batch_id = batch.id;
        let is_head = tokio::task::spawn_blocking(move || {
            storage.delivery_is_destination_head(destination_id, batch_id, first_index)
        })
        .await
        .context("delivery destination head task failed")??;
        if !is_head {
            let mut outcome = DeliveryLaneOutcome::default();
            for (row_index, row) in rows {
                let row_index =
                    u32::try_from(row_index).context("delivery row index exceeds u32")?;
                outcome.completed_rows.push(row_index);
                outcome.retries.push(
                    self.retry_item(
                        batch.id,
                        row_index,
                        row,
                        0,
                        try_now_millis()?.saturating_add(retry_delay_ms(0)),
                        "blocked by an earlier delivery for this destination",
                    )
                    .await?,
                );
            }
            self.commit_delivery_lane_outcome(batch.id, &outcome)
                .await?;
            return Ok(outcome);
        }
        let mut blocked = false;
        let mut outcome = DeliveryLaneOutcome::default();
        for (row_index, row) in rows {
            let row_index_u32 =
                u32::try_from(row_index).context("delivery row index exceeds u32")?;
            outcome.completed_rows.push(row_index_u32);
            if blocked {
                outcome.retries.push(
                    self.retry_item(
                        batch.id,
                        row_index_u32,
                        row,
                        0,
                        try_now_millis()?.saturating_add(retry_delay_ms(0)),
                        "blocked by an earlier delivery for this destination",
                    )
                    .await?,
                );
                continue;
            }
            match self
                .deliver_row_locked(event, &row, batch, row_index_u32)
                .await
            {
                Ok(Some(success)) => outcome.successes.push(success),
                Ok(None) => outcome.skipped_rows.push(row_index_u32),
                Err(error) if !error.is_permanent() => {
                    outcome.retries.push(
                        self.retry_item(
                            batch.id,
                            row_index_u32,
                            row,
                            1,
                            try_now_millis()?.saturating_add(retry_delay_ms(0)),
                            &error.to_string(),
                        )
                        .await?,
                    );
                    blocked = true;
                }
                Err(error) => {
                    outcome.dead_letters.push(
                        self.dead_letter(
                            batch.id,
                            row_index_u32,
                            row.destination_id,
                            1,
                            batch.created_at_ms,
                            &error,
                        )
                        .await?,
                    );
                    tracing::warn!(event = "delivery.permanent_failure", destination_id = row.destination_id.0, error = ?error, "delivery.permanent_failure");
                }
            }
        }
        self.commit_delivery_lane_outcome(batch.id, &outcome)
            .await?;
        drop(guard);
        Ok(outcome)
    }

    async fn retry_item(
        &self,
        batch_id: u64,
        row_index: u32,
        row: DeliveryRow,
        attempts: u16,
        due_at_ms: i64,
        error: &str,
    ) -> Result<RetryItem> {
        let storage = self.inner.storage.clone();
        let id = tokio::task::spawn_blocking(move || storage.next_id("retry"))
            .await
            .context("retry ID task failed")??;
        Ok(RetryItem {
            id,
            batch_id,
            row_index,
            destination_id: row.destination_id,
            due_at_ms,
            attempts,
            created_at_ms: try_now_millis()?,
            last_error: error.chars().take(1_024).collect(),
        })
    }

    async fn dead_letter(
        &self,
        batch_id: u64,
        row_index: u32,
        destination_id: crate::subscriptions::DestinationNumericId,
        attempts: u16,
        created_at_ms: i64,
        error: &BarkDeliveryError,
    ) -> Result<DeadLetterItem> {
        let storage = self.inner.storage.clone();
        let id = tokio::task::spawn_blocking(move || storage.next_id("dead_letter"))
            .await
            .context("dead-letter ID task failed")??;
        Ok(DeadLetterItem {
            id,
            batch_id,
            row_index,
            destination_id,
            attempts,
            created_at_ms,
            failed_at_ms: try_now_millis()?,
            permanent: error.is_permanent(),
            last_error: error.to_string().chars().take(1_024).collect(),
        })
    }

    async fn commit_delivery_lane_outcome(
        &self,
        batch_id: u64,
        outcome: &DeliveryLaneOutcome,
    ) -> Result<()> {
        let storage = self.inner.storage.clone();
        let completed_rows = outcome.completed_rows.clone();
        let skipped_rows = outcome.skipped_rows.clone();
        let successes = outcome.successes.clone();
        let retries = outcome.retries.clone();
        let dead_letters = outcome.dead_letters.clone();
        tokio::task::spawn_blocking(move || {
            storage.commit_delivery_lane_outcome(
                batch_id,
                &completed_rows,
                &skipped_rows,
                &successes,
                &retries,
                &dead_letters,
            )
        })
        .await
        .context("delivery lane commit task failed")?
    }

    async fn run_retry_engine(&self) -> Result<()> {
        let mut attempts = tokio::task::JoinSet::new();
        let mut active_retries = HashSet::new();
        let mut active_destinations = HashSet::new();
        loop {
            while let Some(result) = attempts.try_join_next() {
                let (retry_id, destination_id, result) =
                    result.context("delivery retry task failed")?;
                active_retries.remove(&retry_id);
                active_destinations.remove(&destination_id);
                result?;
            }

            let stopping = self.inner.closing.load(Ordering::Acquire)
                && self.inner.delivery_stopped.load(Ordering::Acquire);
            if !stopping && attempts.len() < MAX_ACTIVE_RETRIES {
                let storage = self.inner.storage.clone();
                let retries = tokio::task::spawn_blocking(move || {
                    storage.due_retry_heads(try_now_millis()?, DELIVERY_PAGE)
                })
                .await
                .context("retry scan task failed")??;
                for retry in retries {
                    if attempts.len() >= MAX_ACTIVE_RETRIES {
                        break;
                    }
                    if active_retries.contains(&retry.id)
                        || active_destinations.contains(&retry.destination_id.0)
                    {
                        continue;
                    }
                    active_retries.insert(retry.id);
                    active_destinations.insert(retry.destination_id.0);
                    let runtime = self.clone();
                    attempts.spawn(async move {
                        let retry_id = retry.id;
                        let destination_id = retry.destination_id.0;
                        (retry_id, destination_id, runtime.process_retry(retry).await)
                    });
                }
            }

            if stopping && attempts.is_empty() {
                return Ok(());
            }
            tokio::select! {
                result = attempts.join_next(), if !attempts.is_empty() => {
                    if let Some(result) = result {
                        let (retry_id, destination_id, result) =
                            result.context("delivery retry task failed")?;
                        active_retries.remove(&retry_id);
                        active_destinations.remove(&destination_id);
                        result?;
                    }
                }
                () = self.inner.delivery_ready.notified() => {}
                () = tokio::time::sleep(SCAN_INTERVAL) => {}
            }
        }
    }

    async fn run_countdown_engine(&self) -> Result<()> {
        let mut commands = self
            .inner
            .countdown_receiver
            .lock()
            .map_err(|error| anyhow::anyhow!("countdown receiver lock poisoned: {error}"))?
            .take()
            .context("countdown engine can only be started once")?;
        let mut shutdown = self.inner.countdown_shutdown.subscribe();
        let mut tasks = tokio::task::JoinSet::new();
        let mut active = HashMap::<CountdownKey, ActiveCountdown>::new();
        loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else {
                        if self.inner.closing.load(Ordering::Acquire) {
                            break;
                        }
                        anyhow::bail!("countdown command channel closed unexpectedly");
                    };
                    match command {
                        CountdownCommand::Schedule(countdown) => {
                            if let Some(current) = active.remove(&countdown.key) {
                                let _result = current.cancel.send(true);
                            }
                            let id = self.inner.next_countdown_id.fetch_add(1, Ordering::Relaxed);
                            let (cancel, cancel_receiver) = watch::channel(false);
                            let key = countdown.key.clone();
                            active.insert(key.clone(), ActiveCountdown { id, cancel });
                            let runtime = self.clone();
                            let task_shutdown = shutdown.clone();
                            tasks.spawn(async move {
                                runtime
                                    .run_earthquake_countdown(countdown, cancel_receiver, task_shutdown)
                                    .await;
                                (key, id)
                            });
                        }
                        CountdownCommand::Cancel(key) => {
                            if let Some(current) = active.remove(&key) {
                                let _result = current.cancel.send(true);
                            }
                        }
                    }
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    let (key, id) = completed
                        .context("earthquake countdown task set closed unexpectedly")?
                        .context("earthquake countdown task panicked or was cancelled")?;
                    if active.get(&key).is_some_and(|current| current.id == id) {
                        active.remove(&key);
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        for current in active.into_values() {
            let _result = current.cancel.send(true);
        }
        while let Some(completed) = tasks.join_next().await {
            let _finished =
                completed.context("earthquake countdown task failed during shutdown")?;
        }
        Ok(())
    }

    async fn run_earthquake_countdown(
        &self,
        countdown: EarthquakeCountdown,
        mut cancel: watch::Receiver<bool>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let initial_now = match try_now_millis() {
            Ok(now_ms) => now_ms,
            Err(error) => {
                tracing::warn!(event = "delivery.countdown_clock_failed", error = ?error, "delivery.countdown_clock_failed");
                return;
            }
        };
        if remaining_seconds(countdown.timing.s_arrival_at_ms, initial_now) == 0 {
            return;
        }
        loop {
            let now_ms = match try_now_millis() {
                Ok(now_ms) => now_ms,
                Err(error) => {
                    tracing::warn!(event = "delivery.countdown_clock_failed", error = ?error, "delivery.countdown_clock_failed");
                    return;
                }
            };
            let seconds = remaining_seconds(countdown.timing.s_arrival_at_ms, now_ms);
            let arrived = seconds == 0;
            let delay_ms = countdown_tick_delay_ms(countdown.timing.s_arrival_at_ms, now_ms);
            if wait_for_countdown_delay(delay_ms, &mut cancel, &mut shutdown).await {
                return;
            }
            if !self.countdown_subscription_is_current(&countdown).await {
                return;
            }
            if self
                .send_countdown_tick(&countdown, &mut cancel, &mut shutdown)
                .await
            {
                return;
            }
            if arrived
                || try_now_millis().is_ok_and(|now_ms| now_ms >= countdown.timing.s_arrival_at_ms)
            {
                return;
            }
        }
    }

    async fn countdown_subscription_is_current(&self, countdown: &EarthquakeCountdown) -> bool {
        let storage = self.inner.storage.clone();
        let subscription_id = countdown.subscription_id;
        let current =
            tokio::task::spawn_blocking(move || storage.stored_subscription(subscription_id)).await;
        match current {
            Ok(Ok(Some(record))) => record.active && record.generation == countdown.generation,
            Ok(Ok(None)) => false,
            Ok(Err(error)) => {
                tracing::warn!(event = "delivery.countdown_subscription_failed", error = ?error, "delivery.countdown_subscription_failed");
                false
            }
            Err(error) => {
                tracing::warn!(event = "delivery.countdown_subscription_task_failed", error = ?error, "delivery.countdown_subscription_task_failed");
                false
            }
        }
    }

    async fn send_countdown_tick(
        &self,
        countdown: &EarthquakeCountdown,
        cancel: &mut watch::Receiver<bool>,
        shutdown: &mut watch::Receiver<bool>,
    ) -> bool {
        if *cancel.borrow() || *shutdown.borrow() {
            return true;
        }
        let lock = self.destination_lock(countdown.key.destination_id);
        let guard = tokio::select! {
            guard = lock.lock() => guard,
            changed = cancel.changed() => return changed.is_err() || *cancel.borrow(),
            changed = shutdown.changed() => return changed.is_err() || *shutdown.borrow(),
        };
        let result = tokio::select! {
            result = self.inner.notifier.send_disaster_countdown(
                &countdown.recipient,
                &countdown.event,
                &countdown.timing,
                &countdown.detail_url,
            ) => Some(result),
            changed = cancel.changed() => {
                drop(guard);
                return changed.is_err() || *cancel.borrow();
            }
            changed = shutdown.changed() => {
                drop(guard);
                return changed.is_err() || *shutdown.borrow();
            }
        };
        drop(guard);
        if let Some(result) = result {
            self.inner
                .runtime_status
                .channel(countdown.event.channel)
                .record_notification(result.is_ok());
            if let Err(error) = result {
                tracing::warn!(
                    event = "delivery.countdown_tick_failed",
                    destination_id = countdown.key.destination_id,
                    error = ?error,
                    "delivery.countdown_tick_failed"
                );
            }
        }
        false
    }

    async fn queue_countdown_command(&self, command: CountdownCommand) {
        if let Err(error) = self.inner.countdown_commands.send(command).await {
            tracing::warn!(
                event = "delivery.countdown_command_dropped",
                error = %error,
                "delivery.countdown_command_dropped"
            );
        }
    }

    async fn process_retry(&self, mut retry: RetryItem) -> Result<()> {
        let lock = self.destination_lock(retry.destination_id.0);
        let _guard = lock.lock().await;
        enum RetryLoad {
            NotHead,
            Completed,
            Corrupt,
            Ready(DeliveryBatch, DeliveryRow, Box<DisasterEvent>),
        }
        let storage = self.inner.storage.clone();
        let retry_for_load = retry.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            if !storage.retry_is_destination_head(&retry_for_load)? {
                return Ok(RetryLoad::NotHead);
            }
            let Some(batch) = storage.delivery_batch(retry_for_load.batch_id)? else {
                storage.complete_retry(&retry_for_load)?;
                return Ok(RetryLoad::Completed);
            };
            let Some(row) = usize::try_from(retry_for_load.row_index)
                .ok()
                .and_then(|index| batch.rows.get(index))
                .copied()
            else {
                storage.complete_retry(&retry_for_load)?;
                return Ok(RetryLoad::Completed);
            };
            if row.destination_id != retry_for_load.destination_id {
                storage.complete_retry(&retry_for_load)?;
                return Ok(RetryLoad::Corrupt);
            }
            let event = storage
                .event(batch.event_revision)?
                .context("retry batch event is missing")?;
            Ok::<_, anyhow::Error>(RetryLoad::Ready(batch, row, Box::new(event)))
        })
        .await
        .context("retry load task failed")??;
        let (batch, row, event) = match loaded {
            RetryLoad::Ready(batch, row, event) => (batch, row, event),
            RetryLoad::NotHead | RetryLoad::Completed => return Ok(()),
            RetryLoad::Corrupt => {
                tracing::warn!(
                    event = "delivery.retry_corrupt",
                    retry_id = retry.id,
                    "delivery.retry_corrupt"
                );
                return Ok(());
            }
        };
        let event = Arc::from(event);
        let result = self
            .deliver_row_locked(&event, &row, &batch, retry.row_index)
            .await;
        let now_ms = try_now_millis()?;
        match result {
            Ok(success) => {
                let storage = self.inner.storage.clone();
                let retry_for_commit = retry.clone();
                tokio::task::spawn_blocking(move || {
                    storage.complete_retry_with_success(&retry_for_commit, success.as_ref())
                })
                .await
                .context("retry success commit task failed")??;
            }
            Err(error)
                if !error.is_permanent()
                    && retry.attempts < MAX_RETRY_ATTEMPTS
                    && now_ms.saturating_sub(retry.created_at_ms) < MAX_RETRY_AGE_MS =>
            {
                let previous = retry.clone();
                retry.attempts = retry.attempts.saturating_add(1);
                retry.due_at_ms = now_ms.saturating_add(retry_delay_ms(retry.attempts));
                retry.last_error = error.to_string().chars().take(1_024).collect();
                let storage = self.inner.storage.clone();
                let next = retry.clone();
                tokio::task::spawn_blocking(move || storage.reschedule_retry(&previous, &next))
                    .await
                    .context("retry reschedule task failed")??;
            }
            Err(error) => {
                let dead_letter = self
                    .dead_letter(
                        retry.batch_id,
                        retry.row_index,
                        retry.destination_id,
                        retry.attempts.saturating_add(1),
                        retry.created_at_ms,
                        &error,
                    )
                    .await?;
                tracing::warn!(event = "delivery.retry_exhausted", destination_id = row.destination_id.0, error = ?error, "delivery.retry_exhausted");
                let storage = self.inner.storage.clone();
                let retry_for_commit = retry.clone();
                tokio::task::spawn_blocking(move || {
                    storage.dead_letter_retry(&retry_for_commit, &dead_letter)
                })
                .await
                .context("retry dead-letter task failed")??;
            }
        }
        Ok(())
    }

    async fn deliver_row_locked(
        &self,
        event: &Arc<DisasterEvent>,
        row: &DeliveryRow,
        batch: &DeliveryBatch,
        row_index: u32,
    ) -> std::result::Result<Option<DeliverySuccess>, BarkDeliveryError> {
        let storage = self.inner.storage.clone();
        let incident_id = batch.incident_id.clone();
        let category = batch.category;
        let destination_id = row.destination_id;
        let event_revision = batch.event_revision;
        if tokio::task::spawn_blocking(move || {
            storage.delivery_recorded(&incident_id, category, destination_id, event_revision)
        })
        .await
        .map_err(|error| BarkDeliveryError::transient(anyhow::anyhow!(error)))?
        .map_err(BarkDeliveryError::transient)?
        {
            return Ok(None);
        }
        let storage = self.inner.storage.clone();
        let subscription_id = row.subscription_id;
        let record =
            tokio::task::spawn_blocking(move || storage.stored_subscription(subscription_id))
                .await
                .map_err(|error| BarkDeliveryError::transient(anyhow::anyhow!(error)))?
                .map_err(BarkDeliveryError::transient)?;
        let Some(record) =
            record.filter(|record| record.active && record.generation == row.generation)
        else {
            return Ok(None);
        };
        let target = record
            .subscription
            .targets
            .get(usize::from(row.target_ordinal))
            .ok_or_else(|| {
                BarkDeliveryError::permanent(anyhow::anyhow!("compiled target ordinal is invalid"))
            })?;
        let rule = record.subscription.alert(batch.category).ok_or_else(|| {
            BarkDeliveryError::permanent(anyhow::anyhow!(
                "subscription no longer has matching rule"
            ))
        })?;
        let timing = self
            .alert_timing(event, row)
            .map_err(BarkDeliveryError::transient)?;
        let context = self
            .inner
            .notification_links
            .prepare_url_for(NotificationContextInput {
                incident_id: &batch.incident_id,
                event,
                target,
                timing: timing.as_ref(),
                interruption_level: row.interruption_level.as_str(),
                matched_rule: rule,
                issued_at_ms: batch.created_at_ms,
            })
            .map_err(BarkDeliveryError::transient)?;
        let links = self.inner.notification_links.clone();
        let context_for_persist = context.clone();
        tokio::task::spawn_blocking(move || links.persist_prepared(&context_for_persist))
            .await
            .map_err(|error| BarkDeliveryError::transient(anyhow::anyhow!(error)))?
            .map_err(BarkDeliveryError::transient)?;
        let recipient = AlertRecipient::new(&record.subscription, target);
        let countdown_key = CountdownKey {
            incident_id: batch.incident_id.clone(),
            destination_id: row.destination_id.0,
            target_ordinal: row.target_ordinal,
        };
        if event.category == DisasterCategory::EarthquakeWarning {
            self.queue_countdown_command(CountdownCommand::Cancel(countdown_key.clone()))
                .await;
        }
        let result = self
            .inner
            .notifier
            .send_disaster_alert(
                &recipient,
                row.interruption_level.as_str(),
                event,
                timing.as_ref(),
                &context.url,
            )
            .await;
        self.inner
            .runtime_status
            .channel(event.channel)
            .record_notification(result.is_ok());
        result?;
        if event.category == DisasterCategory::EarthquakeWarning && !event.cancel {
            if let Some(timing) = timing.filter(|timing| {
                try_now_millis()
                    .is_ok_and(|now_ms| remaining_seconds(timing.s_arrival_at_ms, now_ms) > 0)
            }) {
                self.queue_countdown_command(CountdownCommand::Schedule(EarthquakeCountdown {
                    key: countdown_key,
                    subscription_id: row.subscription_id,
                    generation: row.generation,
                    recipient: recipient.to_countdown_recipient(),
                    event: Arc::clone(event),
                    timing,
                    detail_url: context.url,
                }))
                .await;
            }
        }
        Ok(Some(DeliverySuccess {
            row_index,
            row: *row,
        }))
    }

    fn alert_timing(
        &self,
        event: &DisasterEvent,
        row: &DeliveryRow,
    ) -> Result<Option<AlertTiming>> {
        if !matches!(
            event.category,
            DisasterCategory::EarthquakeWarning | DisasterCategory::EarthquakeReport
        ) {
            return Ok(None);
        }
        let distance_km = f64::from(row.distance_m) / 1_000.0;
        let depth = event.depth_km.unwrap_or_default().max(0.0);
        let hypocentral_km = distance_km.mul_add(distance_km, depth * depth).sqrt();
        let estimated_intensity = event.magnitude.map_or(0.0, |magnitude| {
            crate::utils::intensity::estimate_intensity(magnitude, hypocentral_km)
        });
        let occurred_at_ms = match parse_event_epoch(event) {
            Some(seconds) => seconds.saturating_mul(1_000),
            None => try_now_millis()?,
        };
        Ok(Some(AlertTiming {
            distance_km,
            hypocentral_km,
            estimated_intensity: if event.category == DisasterCategory::EarthquakeWarning {
                f64::from(row.intensity_cent) / 100.0
            } else {
                estimated_intensity
            },
            p_arrival_at_ms: arrival_at(occurred_at_ms, hypocentral_km, self.inner.p_wave_km_s),
            s_arrival_at_ms: arrival_at(occurred_at_ms, hypocentral_km, self.inner.s_wave_km_s),
        }))
    }

    fn destination_lock(&self, destination_id: u64) -> Arc<AsyncMutex<()>> {
        let mut locks = self
            .inner
            .destination_locks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        locks.retain(|_, weak| weak.strong_count() > 0);
        if let Some(lock) = locks.get(&destination_id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(destination_id, Arc::downgrade(&lock));
        lock
    }
}

async fn wait_for_countdown_delay(
    delay_ms: i64,
    cancel: &mut watch::Receiver<bool>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    if *cancel.borrow() || *shutdown.borrow() {
        return true;
    }
    let delay = Duration::from_millis(u64::try_from(delay_ms.max(0)).unwrap_or(u64::MAX));
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        changed = cancel.changed() => changed.is_err() || *cancel.borrow(),
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

fn countdown_tick_delay_ms(arrival_at_ms: i64, now_ms: i64) -> i64 {
    let delta_ms = arrival_at_ms.saturating_sub(now_ms).max(0);
    let seconds = remaining_seconds(arrival_at_ms, now_ms);
    if seconds == 0 {
        0
    } else {
        delta_ms.saturating_sub(seconds.saturating_sub(1).saturating_mul(1_000))
    }
}

fn sanitize_event(mut event: DisasterEvent) -> std::result::Result<DisasterEvent, &'static str> {
    if event.source.is_empty()
        || event.source.len() > 128
        || event.event_id.is_empty()
        || event.event_id.len() > 256
    {
        return Err("source or event ID is missing or oversized");
    }
    match event.latitude.zip(event.longitude) {
        Some((latitude, longitude))
            if !crate::utils::distance::validate_coordinates(latitude, longitude) =>
        {
            return Err("coordinates are outside the supported range");
        }
        None if event.latitude.is_some() || event.longitude.is_some() => {
            return Err("latitude and longitude must be supplied together");
        }
        Some(_) | None => {}
    }
    if [event.magnitude, event.depth_km, event.radius_km]
        .into_iter()
        .flatten()
        .any(|value| !value.is_finite())
    {
        return Err("numeric event fields must be finite");
    }
    event.title = truncate(&event.title, 512);
    event.description = truncate(&event.description, 16 * 1024);
    event.affected_regions.truncate(64);
    Ok(event)
}

fn cancellation_rows(mut rows: Vec<DeliveryRow>) -> Vec<DeliveryRow> {
    for row in &mut rows {
        row.interruption_level = InterruptionLevel::Active;
    }
    rows
}

fn truncate(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_string()
}

fn retry_delay_ms(attempts: u16) -> i64 {
    1_000_i64
        .saturating_mul(1_i64 << u32::from(attempts.min(10)))
        .min(15 * 60 * 1_000)
}

fn arrival_at(occurred_at_ms: i64, distance_km: f64, speed_km_s: f64) -> i64 {
    occurred_at_ms.saturating_add((distance_km / speed_km_s * 1_000.0).round() as i64)
}

fn build_delivery_batches(
    storage: &FjallStorage,
    job: &crate::events::MatchJob,
    category: crate::models::DisasterCategory,
    rows: &[DeliveryRow],
) -> Result<Vec<DeliveryBatch>> {
    let created_at_ms = try_now_millis()?;
    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < rows.len() {
        let shard = delivery_shard(rows[start].destination_id.0);
        let shard_end = rows[start..]
            .iter()
            .position(|row| delivery_shard(row.destination_id.0) != shard)
            .map_or(rows.len(), |offset| start + offset);
        while start < shard_end {
            let mut end = start.saturating_add(DELIVERY_ROWS_PER_BATCH).min(shard_end);
            let id = storage.next_id("delivery_batch")?;
            loop {
                let batch = DeliveryBatch {
                    id,
                    incident_id: job.incident_id.clone(),
                    event_revision: job.event_revision,
                    category,
                    shard,
                    created_at_ms,
                    rows: rows[start..end].to_vec(),
                };
                if batch.encoded_len()? <= crate::delivery::MAX_DELIVERY_BATCH_BYTES {
                    batches.push(batch);
                    start = end;
                    break;
                }
                anyhow::ensure!(
                    end > start + 1,
                    "one delivery row exceeds the batch size limit"
                );
                end = start + (end - start) / 2;
            }
        }
    }
    Ok(batches)
}

fn delivery_shard(destination_id: u64) -> u16 {
    u16::try_from(destination_id % DELIVERY_SHARDS).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AlertRule, DisasterCategory, GeoPoint, IncidentId, MonitoringTarget,
        NotificationDestination, Subscription,
    };
    use crate::subscriptions::{DestinationNumericId, SubscriptionId};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn countdown_ticks_align_to_remaining_second_boundaries() {
        assert_eq!(countdown_tick_delay_ms(10_500, 0), 500);
        assert_eq!(countdown_tick_delay_ms(10_000, 0), 1_000);
        assert_eq!(countdown_tick_delay_ms(500, 0), 500);
        assert_eq!(countdown_tick_delay_ms(0, 0), 0);
        assert_eq!(countdown_tick_delay_ms(5_719_500, 0), 500);
    }

    #[test]
    fn cancellation_preserves_historical_generation() {
        let historical = DeliveryRow {
            destination_id: DestinationNumericId(7),
            subscription_id: SubscriptionId(11),
            generation: 3,
            target_ordinal: 2,
            match_kind: 1,
            interruption_level: InterruptionLevel::Passive,
            distance_m: 4_000,
            intensity_cent: 250,
        };

        let rows = cancellation_rows(vec![historical]);

        assert_eq!(rows[0].generation, historical.generation);
        assert_eq!(rows[0].interruption_level, InterruptionLevel::Active);
        assert_eq!(rows[0].subscription_id, historical.subscription_id);
        assert_eq!(rows[0].destination_id, historical.destination_id);
    }

    #[test]
    fn destination_lock_table_removes_expired_entries() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage = Storage::open(directory.path())?;
        let notifier = BarkNotifier::new(
            vec!["https://api.day.app".to_string()],
            1,
            1,
            crate::delivery::BarkPushConfig::new(None, 10, "test".to_string(), false),
        )?;
        let links = NotificationLinkService::for_test(&storage);
        let runtime = EventRuntime::for_test(storage, notifier, links)?;

        drop(runtime.destination_lock(1));
        let active = runtime.destination_lock(2);
        let locks = runtime
            .inner
            .destination_locks
            .lock()
            .map_err(|error| anyhow::anyhow!("destination lock table poisoned: {error}"))?;
        anyhow::ensure!(locks.len() == 1);
        drop(locks);
        drop(active);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_provider_batch_does_not_commit_events_or_cursor() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage = Storage::open(directory.path())?;
        let notifier = BarkNotifier::new(
            vec!["https://api.day.app".to_string()],
            1,
            1,
            crate::delivery::BarkPushConfig::new(None, 10, "test".to_string(), false),
        )?;
        let links = NotificationLinkService::for_test(&storage);
        let runtime = EventRuntime::for_test(storage.clone(), notifier, links)?;
        let valid = test_delivery_event(1, "valid");
        let mut invalid = valid.clone();
        invalid.event_id.clear();

        let accepted = runtime
            .submit_provider_batch(
                ProviderChannel::Cenc,
                vec![valid, invalid],
                ProviderCursor::new("report", "cursor-1")?,
            )
            .await;

        anyhow::ensure!(!accepted);
        anyhow::ensure!(storage.inner().pending_inbox(1)?.is_empty());
        anyhow::ensure!(
            runtime
                .provider_cursors(ProviderChannel::Cenc, vec!["report".to_string()])
                .await?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn unmatched_event_is_not_retained() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage = Storage::open(directory.path())?;
        let notifier = BarkNotifier::new(
            vec!["https://api.day.app".to_string()],
            1,
            1,
            crate::delivery::BarkPushConfig::new(None, 10, "test".to_string(), false),
        )?;
        let links = NotificationLinkService::for_test(&storage);
        let runtime = EventRuntime::for_test(storage.clone(), notifier, links)?;
        let job = persist_test_event(&storage.inner(), test_delivery_event(1, "unmatched"))?;

        let batch_ids = runtime.process_match_job(job.clone()).await?;

        anyhow::ensure!(batch_ids.is_empty());
        anyhow::ensure!(storage.inner().incident(&job.incident_id)?.is_none());
        anyhow::ensure!(storage.inner().event(job.event_revision)?.is_none());
        anyhow::ensure!(storage.inner().match_job(job.id)?.is_none());
        anyhow::ensure!(storage.inner().pending_delivery_batches(1)?.is_empty());
        Ok(())
    }

    #[test]
    fn delivery_batches_are_sharded_ordered_and_bounded() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage = FjallStorage::open(directory.path())?;
        let job = crate::events::MatchJob {
            id: 1,
            incident_id: IncidentId::derive("batch-test"),
            event_revision: 1,
            created_at_ms: 1,
        };
        let mut rows = (0..2_000_u64)
            .rev()
            .map(|id| DeliveryRow {
                destination_id: DestinationNumericId(id + 1),
                subscription_id: SubscriptionId(id + 1),
                generation: 1,
                target_ordinal: 0,
                match_kind: 1,
                interruption_level: InterruptionLevel::Active,
                distance_m: 1,
                intensity_cent: 0,
            })
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| {
            (
                delivery_shard(row.destination_id.0),
                row.destination_id.0,
                row.subscription_id.0,
            )
        });
        let batches =
            build_delivery_batches(&storage, &job, DisasterCategory::EarthquakeReport, &rows)?;
        anyhow::ensure!(batches.iter().all(|batch| {
            batch.encoded_len().is_ok_and(|size| {
                size <= crate::delivery::MAX_DELIVERY_BATCH_BYTES
                    && batch
                        .rows
                        .iter()
                        .all(|row| delivery_shard(row.destination_id.0) == batch.shard)
            })
        }));
        anyhow::ensure!(batches.iter().map(|batch| batch.rows.len()).sum::<usize>() == rows.len());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delivery_engine_isolates_slow_destinations_and_preserves_order() -> Result<()> {
        #[derive(Clone)]
        struct BarkState {
            slow_release: Arc<tokio::sync::Notify>,
            slow_calls: Arc<AtomicUsize>,
            fast_calls: Arc<AtomicUsize>,
            subtitles: tokio::sync::mpsc::UnboundedSender<String>,
        }

        async fn slow_push(
            axum::extract::State(state): axum::extract::State<BarkState>,
            axum::Json(payload): axum::Json<serde_json::Value>,
        ) -> axum::Json<serde_json::Value> {
            let call = state.slow_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(subtitle) = payload.get("subtitle").and_then(serde_json::Value::as_str) {
                let _sent = state.subtitles.send(subtitle.to_string());
            }
            if call == 0 {
                state.slow_release.notified().await;
            }
            axum::Json(serde_json::json!({ "code": 200 }))
        }

        async fn fast_push(
            axum::extract::State(state): axum::extract::State<BarkState>,
        ) -> axum::Json<serde_json::Value> {
            state.fast_calls.fetch_add(1, Ordering::SeqCst);
            axum::Json(serde_json::json!({ "code": 200 }))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (subtitles_tx, mut subtitles_rx) = tokio::sync::mpsc::unbounded_channel();
        let state = BarkState {
            slow_release: Arc::new(tokio::sync::Notify::new()),
            slow_calls: Arc::new(AtomicUsize::new(0)),
            fast_calls: Arc::new(AtomicUsize::new(0)),
            subtitles: subtitles_tx,
        };
        let app = axum::Router::new()
            .route("/slow/push", axum::routing::post(slow_push))
            .route("/fast/push", axum::routing::post(fast_push))
            .with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let directory = tempfile::tempdir()?;
        let storage = Storage::open(directory.path())?;
        let slow_url = format!("http://{address}/slow");
        let fast_url = format!("http://{address}/fast");
        let slow_subscription = test_subscription(&slow_url, "slowdevice");
        let fast_subscription = test_subscription(&fast_url, "fastdevice");
        let subscriptions = storage.subscription_manager();
        subscriptions.upsert_subscription(slow_subscription.clone())?;
        subscriptions.upsert_subscription(fast_subscription.clone())?;
        let slow = storage
            .inner()
            .stored_subscription_by_destination(&slow_subscription.destination_id())?
            .context("missing slow subscription")?;
        let fast = storage
            .inner()
            .stored_subscription_by_destination(&fast_subscription.destination_id())?
            .context("missing fast subscription")?;

        let first_job = persist_test_event(&storage.inner(), test_delivery_event(1, "slow-first"))?;
        let first_batch =
            test_delivery_batch(1, &first_job, slow.destination_id, slow.id, slow.generation);
        let fast_batch =
            test_delivery_batch(2, &first_job, fast.destination_id, fast.id, fast.generation);
        storage
            .inner()
            .commit_match_batches(first_job.id, &[first_batch.clone(), fast_batch.clone()])?;
        let second_job =
            persist_test_event(&storage.inner(), test_delivery_event(2, "slow-second"))?;
        let second_batch = test_delivery_batch(
            3,
            &second_job,
            slow.destination_id,
            slow.id,
            slow.generation,
        );
        storage
            .inner()
            .commit_match_batches(second_job.id, std::slice::from_ref(&second_batch))?;

        let notifier = BarkNotifier::new(
            vec![slow_url, fast_url],
            4,
            4,
            crate::delivery::BarkPushConfig::new(None, 10, "test".to_string(), false),
        )?;
        let notification_links = NotificationLinkService::for_test(&storage);
        let runtime = EventRuntime::for_test(storage.clone(), notifier, notification_links)?;
        runtime.inner.closing.store(true, Ordering::Release);
        runtime.inner.match_stopped.store(true, Ordering::Release);
        let delivery_runtime = runtime.clone();
        let delivery = tokio::spawn(async move { delivery_runtime.run_delivery_engine().await });

        let first_subtitle = tokio::time::timeout(Duration::from_secs(2), subtitles_rx.recv())
            .await
            .context("slow Bark request did not start")?
            .context("slow Bark subtitle channel closed")?;
        anyhow::ensure!(first_subtitle.starts_with("slow-first · M5.0"));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !storage.inner().delivery_recorded(
                &fast_batch.incident_id,
                fast_batch.category,
                fast.destination_id,
                fast_batch.event_revision,
            )? {
                tokio::time::sleep(SCAN_INTERVAL).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("fast destination was blocked by the slow destination")??;
        anyhow::ensure!(state.fast_calls.load(Ordering::SeqCst) == 1);
        anyhow::ensure!(state.slow_calls.load(Ordering::SeqCst) == 1);
        anyhow::ensure!(subtitles_rx.try_recv().is_err());

        state.slow_release.notify_waiters();
        tokio::time::timeout(Duration::from_secs(2), delivery)
            .await
            .context("delivery engine did not stop")?
            .context("delivery engine task failed")??;
        anyhow::ensure!(state.slow_calls.load(Ordering::SeqCst) == 2);
        let second_subtitle = subtitles_rx
            .try_recv()
            .context("newer slow-destination delivery did not run after the older row")?;
        anyhow::ensure!(second_subtitle.starts_with("slow-second · M5.0"));
        server.abort();
        Ok(())
    }

    fn test_subscription(base_url: &str, device_key: &str) -> Subscription {
        Subscription::new(
            NotificationDestination::Bark {
                base_url: base_url.to_string(),
                device_key: device_key.to_string(),
            },
            vec![MonitoringTarget {
                label: "target".to_string(),
                point: GeoPoint {
                    latitude: 35.0,
                    longitude: 105.0,
                },
                region: Default::default(),
            }],
            vec![AlertRule::default_for(DisasterCategory::EarthquakeReport)],
        )
    }

    fn persist_test_event(
        storage: &FjallStorage,
        event: DisasterEvent,
    ) -> Result<crate::events::MatchJob> {
        storage.ingest_with_cursor(event.channel, vec![event], None)?;
        EventCoordinator::new(storage.clone())
            .process_next()?
            .context("missing test MatchJob")
    }

    fn test_delivery_event(report_num: u32, title: &str) -> DisasterEvent {
        DisasterEvent {
            category: DisasterCategory::EarthquakeReport,
            channel: ProviderChannel::Cenc,
            source: "cenc.report".to_string(),
            event_id: "delivery-engine-order".to_string(),
            revision: report_num.to_string(),
            report_num,
            title: title.to_string(),
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

    fn test_delivery_batch(
        id: u64,
        job: &crate::events::MatchJob,
        destination_id: DestinationNumericId,
        subscription_id: SubscriptionId,
        generation: u64,
    ) -> DeliveryBatch {
        DeliveryBatch {
            id,
            incident_id: job.incident_id.clone(),
            event_revision: job.event_revision,
            category: DisasterCategory::EarthquakeReport,
            shard: delivery_shard(destination_id.0),
            created_at_ms: job.created_at_ms,
            rows: vec![DeliveryRow {
                destination_id,
                subscription_id,
                generation,
                target_ordinal: 0,
                match_kind: 1,
                interruption_level: InterruptionLevel::Active,
                distance_m: 1_000,
                intensity_cent: 100,
            }],
        }
    }
}
