use crate::delivery::{
    BarkNotifier, BarkPushConfig, DeliveryBatch, DeliveryRow, NotificationLinkService,
};
use crate::events::{EventCoordinator, EventPolicy};
use crate::matching::{MatchEngine, MatchPlan, PostingBlock};
use crate::models::{IncidentId, InterruptionLevel};
use crate::runtime::EventRuntime;
use crate::storage::Storage;
use crate::subscriptions::{
    CompiledSubscription, DestinationNumericId, SubscriptionCompiler, SubscriptionId,
};
use anyhow::Result;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, HashMap};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

pub use crate::models::{
    AdministrativeRegion, AlertRule, DisasterCategory, DisasterEvent, GeoPoint, MonitoringTarget,
    NotificationDestination, ProviderChannel, Subscription,
};

pub struct ExactMatchBenchmark {
    matcher: MatchEngine,
    event: Arc<DisasterEvent>,
    subscriptions: HashMap<SubscriptionId, CompiledSubscription>,
    candidate_blocks: Vec<PostingBlock>,
}

impl ExactMatchBenchmark {
    pub fn new(
        threads: usize,
        subscriptions: Vec<Subscription>,
        event: DisasterEvent,
    ) -> Result<Self> {
        let compiled = subscriptions
            .iter()
            .enumerate()
            .map(|(index, subscription)| {
                let id = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
                SubscriptionCompiler::compile(
                    SubscriptionId(id),
                    DestinationNumericId(id),
                    1,
                    subscription,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let mut candidate_blocks = BTreeMap::<u64, RoaringBitmap>::new();
        for subscription in &compiled {
            candidate_blocks
                .entry(subscription.subscription_id.posting_block())
                .or_default()
                .insert(subscription.subscription_id.posting_offset());
        }
        let candidate_blocks = candidate_blocks
            .into_iter()
            .map(|(id_block, ids)| PostingBlock { id_block, ids })
            .collect();
        let subscriptions = compiled
            .into_iter()
            .map(|value| (value.subscription_id, value))
            .collect();
        Ok(Self {
            matcher: MatchEngine::new(threads)?,
            event: Arc::new(event),
            subscriptions,
            candidate_blocks,
        })
    }

    pub fn exact_match(&self) -> usize {
        self.matcher
            .match_blocks(
                Arc::clone(&self.event),
                self.candidate_blocks
                    .iter()
                    .map(|block| PostingBlock {
                        id_block: block.id_block,
                        ids: block.ids.clone(),
                    })
                    .collect(),
                &self.subscriptions,
            )
            .len()
    }

    pub fn plan(&self) -> Result<usize> {
        Ok(MatchPlan::for_event(&self.event)?.scopes.len())
    }
}

pub struct DeliveryEncodingBenchmark {
    batch: DeliveryBatch,
}

pub struct SubscriptionWriteBenchmark {
    storage: Storage,
}

pub struct PostingQueryBenchmark {
    storage: Storage,
    event: DisasterEvent,
}

pub struct SlowBarkIsolationBenchmark {
    runtime: tokio::runtime::Runtime,
    event_runtime: EventRuntime,
    storage: Storage,
    slow: BenchmarkDestination,
    fast: BenchmarkDestination,
    sequence: AtomicU64,
}

#[derive(Clone, Copy)]
struct BenchmarkDestination {
    destination_id: DestinationNumericId,
    subscription_id: SubscriptionId,
    generation: u64,
}

impl SubscriptionWriteBenchmark {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(Self {
            storage: Storage::open(path)?,
        })
    }

    pub fn upsert(&self, subscription: Subscription) -> Result<()> {
        self.storage
            .subscription_manager()
            .upsert_subscription(subscription)
    }

    pub fn import_batch(&self, subscriptions: Vec<Subscription>) -> Result<usize> {
        self.storage
            .inner()
            .import_subscription_batch(subscriptions)
    }
}

impl PostingQueryBenchmark {
    pub fn open(
        path: impl AsRef<std::path::Path>,
        subscriptions: Vec<Subscription>,
        event: DisasterEvent,
    ) -> Result<Self> {
        let storage = Storage::open(path)?;
        for chunk in subscriptions.chunks(5_000) {
            storage.inner().import_subscription_batch(chunk.to_vec())?;
        }
        Ok(Self { storage, event })
    }

    pub fn candidates(&self) -> Result<usize> {
        let plan = MatchPlan::for_event(&self.event)?;
        let blocks = self.storage.inner().posting_blocks(&plan)?;
        Ok(blocks
            .iter()
            .map(|block| usize::try_from(block.ids.len()).unwrap_or(usize::MAX))
            .fold(0, usize::saturating_add))
    }
}

impl SlowBarkIsolationBenchmark {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
        let address = listener.local_addr()?;
        let app = axum::Router::new()
            .route(
                "/slow/push",
                axum::routing::post(|| async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    axum::Json(serde_json::json!({ "code": 200 }))
                }),
            )
            .route(
                "/fast/push",
                axum::routing::post(|| async { axum::Json(serde_json::json!({ "code": 200 })) }),
            );
        let _server = runtime.spawn(async move {
            let _result = axum::serve(listener, app).await;
        });
        let slow_url = format!("http://{address}/slow");
        let fast_url = format!("http://{address}/fast");
        let notifier = BarkNotifier::new(
            vec![slow_url.clone(), fast_url.clone()],
            2,
            2,
            BarkPushConfig::new(None, 10, "benchmark".to_string(), false),
        )?;
        let subscription = |base_url: String, device_key: &str| {
            Subscription::new(
                NotificationDestination::Bark {
                    base_url,
                    device_key: device_key.to_string(),
                },
                vec![MonitoringTarget {
                    label: "benchmark".to_string(),
                    point: GeoPoint {
                        latitude: 39.9,
                        longitude: 116.4,
                    },
                    region: AdministrativeRegion::default(),
                }],
                vec![AlertRule::default_for(DisasterCategory::EarthquakeReport)],
            )
        };
        let storage = Storage::open(path)?;
        let slow_subscription = subscription(slow_url, "slowdevice");
        let fast_subscription = subscription(fast_url, "fastdevice");
        let manager = storage.subscription_manager();
        manager.upsert_subscription(slow_subscription.clone())?;
        manager.upsert_subscription(fast_subscription.clone())?;
        let load_destination = |subscription: &Subscription| -> Result<BenchmarkDestination> {
            let stored = storage
                .inner()
                .stored_subscription_by_destination(&subscription.destination_id())?
                .ok_or_else(|| anyhow::anyhow!("benchmark subscription was not stored"))?;
            Ok(BenchmarkDestination {
                destination_id: stored.destination_id,
                subscription_id: stored.id,
                generation: stored.generation,
            })
        };
        let slow = load_destination(&slow_subscription)?;
        let fast = load_destination(&fast_subscription)?;
        let links = NotificationLinkService::for_test(&storage);
        let event_runtime = EventRuntime::for_test(storage.clone(), notifier, links)?;
        Ok(Self {
            runtime,
            event_runtime,
            storage,
            slow,
            fast,
            sequence: AtomicU64::new(0),
        })
    }

    pub fn fast_completion(&self) -> Result<Duration> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mut event = benchmark_event();
        event.event_id = format!("benchmark-delivery-{sequence}");
        let storage = self.storage.inner();
        storage.ingest_with_cursor(event.channel, vec![event], None)?;
        let job = EventCoordinator::with_policy(storage.clone(), EventPolicy::default())
            .process_next()?
            .ok_or_else(|| anyhow::anyhow!("benchmark event did not produce a MatchJob"))?;
        let slow = benchmark_delivery_batch(storage.next_id("delivery_batch")?, &job, self.slow);
        let fast = benchmark_delivery_batch(storage.next_id("delivery_batch")?, &job, self.fast);
        storage.commit_match_batches(job.id, &[slow.clone(), fast.clone()])?;
        self.runtime.block_on(async {
            let started = Instant::now();
            let slow = self
                .event_runtime
                .process_delivery_batch_for_benchmark(slow);
            let fast = self
                .event_runtime
                .process_delivery_batch_for_benchmark(fast);
            tokio::pin!(slow);
            tokio::pin!(fast);
            let fast_elapsed = tokio::select! {
                result = &mut fast => {
                    result?;
                    started.elapsed()
                }
                result = &mut slow => {
                    result?;
                    anyhow::bail!("slow Bark destination completed before fast destination")
                }
            };
            slow.await?;
            Ok(fast_elapsed)
        })
    }
}

fn benchmark_delivery_batch(
    id: u64,
    job: &crate::events::MatchJob,
    destination: BenchmarkDestination,
) -> DeliveryBatch {
    DeliveryBatch {
        id,
        incident_id: job.incident_id.clone(),
        event_revision: job.event_revision,
        category: DisasterCategory::EarthquakeReport,
        shard: u16::try_from(destination.destination_id.0 % 64).unwrap_or(0),
        created_at_ms: job.created_at_ms,
        rows: vec![DeliveryRow {
            destination_id: destination.destination_id,
            subscription_id: destination.subscription_id,
            generation: destination.generation,
            target_ordinal: 0,
            match_kind: 1,
            interruption_level: InterruptionLevel::Active,
            distance_m: 1_000,
            intensity_cent: 100,
        }],
    }
}

fn benchmark_event() -> DisasterEvent {
    DisasterEvent {
        category: DisasterCategory::EarthquakeReport,
        channel: ProviderChannel::Cenc,
        source: "cenc.report".to_string(),
        event_id: "benchmark-event".to_string(),
        revision: "1".to_string(),
        report_num: 1,
        title: "benchmark".to_string(),
        description: String::new(),
        latitude: Some(39.9),
        longitude: Some(116.4),
        magnitude: Some(5.0),
        depth_km: Some(10.0),
        affected_regions: Vec::new(),
        radius_km: None,
        level: 2,
        occurred_at: "2026-07-12T00:00:00Z".to_string(),
        final_report: false,
        cancel: false,
        training: false,
    }
}

impl DeliveryEncodingBenchmark {
    #[must_use]
    pub fn new(rows: u64) -> Self {
        Self {
            batch: DeliveryBatch {
                id: 1,
                incident_id: IncidentId::derive("benchmark"),
                event_revision: 1,
                category: DisasterCategory::EarthquakeReport,
                shard: 0,
                created_at_ms: 1,
                rows: (0..rows)
                    .map(|index| DeliveryRow {
                        destination_id: DestinationNumericId(index + 1),
                        subscription_id: SubscriptionId(index + 1),
                        generation: 1,
                        target_ordinal: 0,
                        match_kind: 1,
                        interruption_level: InterruptionLevel::Active,
                        distance_m: 10_000,
                        intensity_cent: 0,
                    })
                    .collect(),
            },
        }
    }

    #[must_use]
    pub fn rows(&self) -> usize {
        self.batch.rows.len()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        crate::storage::encode_record(&self.batch)
    }
}
