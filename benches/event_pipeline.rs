use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use disaster_alert::benchmark_support::{
    AdministrativeRegion, AlertRule, DeliveryEncodingBenchmark, DisasterCategory, DisasterEvent,
    ExactMatchBenchmark, GeoPoint, MonitoringTarget, NotificationDestination,
    PostingQueryBenchmark, ProviderChannel, SlowBarkIsolationBenchmark, Subscription,
    SubscriptionWriteBenchmark,
};
use std::hint::black_box;

fn required<T, E: std::fmt::Display>(result: Result<T, E>, operation: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            let message = format!("benchmark {operation} failed: {error}\n");
            let _result =
                std::io::Write::write_all(&mut std::io::stderr().lock(), message.as_bytes());
            std::process::abort();
        }
    }
}

fn subscription(index: usize) -> Subscription {
    Subscription::new(
        NotificationDestination::Bark {
            base_url: "https://api.day.app".to_string(),
            device_key: format!("device{index:016}"),
        },
        vec![MonitoringTarget {
            label: "home".to_string(),
            point: GeoPoint {
                latitude: 39.9 + (index % 10) as f64 / 100.0,
                longitude: 116.4,
            },
            region: AdministrativeRegion {
                province: "北京市".to_string(),
                city: "北京市".to_string(),
                district: String::new(),
            },
        }],
        vec![AlertRule::default_for(DisasterCategory::EarthquakeReport)],
    )
}

fn event() -> DisasterEvent {
    DisasterEvent {
        category: DisasterCategory::EarthquakeReport,
        channel: ProviderChannel::Cenc,
        source: "cenc.report".to_string(),
        event_id: "bench-event".to_string(),
        revision: "1".to_string(),
        report_num: 1,
        title: "benchmark earthquake".to_string(),
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

fn event_pipeline(criterion: &mut Criterion) {
    let count = 10_000usize;
    let matcher = required(
        ExactMatchBenchmark::new(4, (0..count).map(subscription).collect(), event()),
        "matcher creation",
    );

    let mut group = criterion.benchmark_group("fjall_pipeline");
    group.throughput(Throughput::Elements(count as u64));
    group.bench_function(BenchmarkId::new("exact_match", count), |bencher| {
        bencher.iter(|| black_box(matcher.exact_match()));
    });
    group.throughput(Throughput::Elements(1));
    group.bench_function("match_plan", |bencher| {
        bencher.iter(|| black_box(required(matcher.plan(), "match plan")));
    });

    let posting_directory = required(tempfile::tempdir(), "posting temporary directory");
    let posting = required(
        PostingQueryBenchmark::open(
            posting_directory.path(),
            (count..count.saturating_mul(2)).map(subscription).collect(),
            event(),
        ),
        "posting benchmark creation",
    );
    group.bench_function(BenchmarkId::new("posting_query", count), |bencher| {
        bencher.iter(|| black_box(required(posting.candidates(), "posting query")));
    });

    let batch = DeliveryEncodingBenchmark::new(512);
    group.throughput(Throughput::Elements(batch.rows() as u64));
    group.bench_function("delivery_batch_encode", |bencher| {
        bencher.iter(|| black_box(required(batch.encode(), "batch encoding")));
    });
    group.finish();

    let mut writes = criterion.benchmark_group("fjall_writes");
    writes.bench_function("subscription_upsert", |bencher| {
        let directory = required(tempfile::tempdir(), "temporary directory");
        let writer = required(
            SubscriptionWriteBenchmark::open(directory.path()),
            "storage open",
        );
        let mut index = 0usize;
        bencher.iter(|| {
            index = index.saturating_add(1);
            let mut value = subscription(0);
            value.targets[0].label = format!("home-{index}");
            required(writer.upsert(value), "subscription upsert");
            black_box(index)
        });
    });
    writes.throughput(Throughput::Elements(256));
    writes.bench_function("subscription_batch_256", |bencher| {
        let directory = required(tempfile::tempdir(), "batch temporary directory");
        let writer = required(
            SubscriptionWriteBenchmark::open(directory.path()),
            "batch storage open",
        );
        let mut sequence = 100_000usize;
        bencher.iter_batched(
            || {
                let start = sequence;
                sequence = sequence.saturating_add(256);
                (start..start.saturating_add(256))
                    .map(subscription)
                    .collect::<Vec<_>>()
            },
            |batch| {
                black_box(required(
                    writer.import_batch(batch),
                    "subscription batch write",
                ))
            },
            criterion::BatchSize::SmallInput,
        );
    });
    writes.finish();

    let isolation_directory = required(tempfile::tempdir(), "isolation temporary directory");
    let isolation = required(
        SlowBarkIsolationBenchmark::open(isolation_directory.path()),
        "slow Bark benchmark creation",
    );
    criterion.bench_function("bark_slow_destination_isolation", |bencher| {
        bencher.iter_custom(|iterations| {
            (0..iterations).fold(std::time::Duration::ZERO, |total, _| {
                total
                    + black_box(required(
                        isolation.fast_completion(),
                        "slow Bark destination isolation",
                    ))
            })
        });
    });
}

criterion_group!(benches, event_pipeline);
criterion_main!(benches);
