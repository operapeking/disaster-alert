use crate::delivery::DeliveryRow;
use crate::models::{DisasterCategory, DisasterEvent, InterruptionLevel};
use crate::subscriptions::{
    CompiledRule, CompiledSubscription, CompiledTarget, RegionId, SourceId, SubscriptionId,
    region_id, source_id,
};
use crate::utils::region;
use anyhow::{Context, Result};
use rayon::prelude::*;
use roaring::RoaringBitmap;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct PostingBlock {
    pub(crate) id_block: u64,
    pub(crate) ids: RoaringBitmap,
}

struct EventMatchContext<'a> {
    event: &'a DisasterEvent,
    source_id: SourceId,
    region_ids: Vec<RegionId>,
    coordinate: Option<EventCoordinate>,
}

#[derive(Clone, Copy)]
struct EventCoordinate {
    latitude_radians: f64,
    longitude: f64,
    cos_latitude: f64,
}

pub(crate) struct MatchEngine {
    pool: rayon::ThreadPool,
}

impl MatchEngine {
    pub(crate) fn new(threads: usize) -> Result<Self> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads.max(1))
            .thread_name(|index| format!("disaster-match-{index}"))
            .build()
            .context("failed to build matching thread pool")?;
        Ok(Self { pool })
    }

    pub(crate) fn match_blocks(
        &self,
        event: Arc<DisasterEvent>,
        blocks: Vec<PostingBlock>,
        subscriptions: &HashMap<SubscriptionId, CompiledSubscription>,
    ) -> Vec<DeliveryRow> {
        let context = EventMatchContext::new(&event);
        self.pool.install(|| {
            let rows = blocks
                .into_par_iter()
                .flat_map_iter(|block| {
                    let mut best = HashMap::new();
                    for raw_id in block.ids {
                        let Some(id) = SubscriptionId::from_posting(block.id_block, raw_id) else {
                            continue;
                        };
                        let Some(subscription) = subscriptions.get(&id) else {
                            continue;
                        };
                        if let Some(row) = match_compiled_with_context(subscription, &context) {
                            best.entry(row.subscription_id.0).or_insert(row);
                        }
                    }
                    best.into_values()
                })
                .collect::<Vec<_>>();
            let mut best = HashMap::with_capacity(rows.len());
            for row in rows {
                best.entry(row.subscription_id.0).or_insert(row);
            }
            best.into_values().collect()
        })
    }
}

#[cfg(test)]
fn match_compiled(
    subscription: &CompiledSubscription,
    event: &DisasterEvent,
) -> Option<DeliveryRow> {
    match_compiled_with_context(subscription, &EventMatchContext::new(event))
}

fn match_compiled_with_context(
    subscription: &CompiledSubscription,
    context: &EventMatchContext<'_>,
) -> Option<DeliveryRow> {
    let event = context.event;
    let rule = subscription
        .rules
        .iter()
        .find(|rule| rule.category == event.category)?;
    if !rule_matches(rule, event, context.source_id) {
        return None;
    }
    let mut best: Option<(&CompiledTarget, f64, u8, f64, InterruptionLevel)> = None;
    for target in &subscription.targets {
        let administrative = regions_intersect(&target.region_ids, &context.region_ids);
        let distance = context
            .coordinate
            .map(|coordinate| haversine_precomputed(coordinate, target));
        let (distance, match_kind) = match event.category {
            DisasterCategory::EarthquakeWarning | DisasterCategory::EarthquakeReport => {
                (distance?, 1)
            }
            DisasterCategory::WeatherWarning if administrative => (distance.unwrap_or(0.0), 2),
            DisasterCategory::WeatherWarning => {
                (distance.filter(|value| *value <= rule.distance_km)?, 1)
            }
            DisasterCategory::Tsunami if administrative => (distance.unwrap_or(0.0), 2),
            DisasterCategory::Tsunami => continue,
            DisasterCategory::Typhoon => (distance.filter(|value| *value <= rule.distance_km)?, 1),
        };
        if matches!(
            event.category,
            DisasterCategory::EarthquakeWarning | DisasterCategory::EarthquakeReport
        ) && distance > rule.distance_km
        {
            continue;
        }
        let estimated = if event.category == DisasterCategory::EarthquakeWarning {
            let depth = event.depth_km.unwrap_or_default().max(0.0);
            let hypocentral = (distance.mul_add(distance, depth * depth)).sqrt();
            crate::utils::intensity::estimate_intensity(event.magnitude?, hypocentral)
        } else {
            0.0
        };
        let interruption_level = if rule.intensity_bands.is_empty() {
            bark_level(event.level)
        } else {
            let value = estimated.round() as u8;
            let Some(band) = rule
                .intensity_bands
                .iter()
                .find(|band| value >= band.min && value <= band.max)
            else {
                continue;
            };
            band.interruption_level
        };
        if best.is_none_or(|(_, current, _, _, _)| distance < current) {
            best = Some((target, distance, match_kind, estimated, interruption_level));
        }
    }
    let (target, distance_km, match_kind, estimated, interruption_level) = best?;
    Some(DeliveryRow {
        destination_id: subscription.destination_id,
        subscription_id: subscription.subscription_id,
        generation: subscription.generation,
        target_ordinal: target.ordinal,
        match_kind,
        interruption_level,
        distance_m: (distance_km * 1_000.0)
            .round()
            .clamp(0.0, f64::from(u32::MAX)) as u32,
        intensity_cent: (estimated * 100.0).round().clamp(0.0, f64::from(u16::MAX)) as u16,
    })
}

fn rule_matches(rule: &CompiledRule, event: &DisasterEvent, event_source: SourceId) -> bool {
    rule.accepts_source(event_source)
        && event.magnitude.unwrap_or_default() >= rule.min_magnitude
        && event.level >= rule.min_severity
}

fn haversine_precomputed(event: EventCoordinate, target: &CompiledTarget) -> f64 {
    let delta_latitude = target.latitude_radians - event.latitude_radians;
    let target_longitude = f64::from(target.longitude_e7) / 10_000_000.0;
    let delta_longitude = (target_longitude - event.longitude).to_radians();
    let a = ((delta_latitude / 2.0).sin().powi(2)
        + event.cos_latitude * target.cos_latitude * (delta_longitude / 2.0).sin().powi(2))
    .clamp(0.0, 1.0);
    6_371.008_8 * 2.0 * a.sqrt().atan2((1.0 - a).sqrt())
}

impl<'a> EventMatchContext<'a> {
    fn new(event: &'a DisasterEvent) -> Self {
        let mut region_ids = event
            .affected_regions
            .iter()
            .map(|value| region::normalize(value))
            .filter(|value| !value.is_empty())
            .map(|value| region_id(&value))
            .collect::<Vec<_>>();
        region_ids.sort_unstable_by_key(|value| value.0);
        region_ids.dedup();
        let coordinate = event
            .latitude
            .zip(event.longitude)
            .map(|(latitude, longitude)| {
                let latitude_radians = latitude.to_radians();
                EventCoordinate {
                    latitude_radians,
                    longitude,
                    cos_latitude: latitude_radians.cos(),
                }
            });
        Self {
            event,
            source_id: source_id(&event.source),
            region_ids,
            coordinate,
        }
    }
}

fn regions_intersect(left: &[RegionId], right: &[RegionId]) -> bool {
    let (mut left_index, mut right_index) = (0, 0);
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].0.cmp(&right[right_index].0) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Greater => right_index += 1,
        }
    }
    false
}

fn bark_level(level: u8) -> InterruptionLevel {
    if level >= 3 {
        InterruptionLevel::Critical
    } else if level >= 2 {
        InterruptionLevel::Active
    } else {
        InterruptionLevel::Passive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DisasterCategory, ProviderChannel};
    use crate::subscriptions::{CompiledIntensityBand, DestinationNumericId};

    fn event(category: DisasterCategory) -> DisasterEvent {
        DisasterEvent {
            category,
            channel: ProviderChannel::Cenc,
            source: match category {
                DisasterCategory::WeatherWarning => "test.weather_warning",
                DisasterCategory::Tsunami => "test.tsunami",
                DisasterCategory::Typhoon => "test.typhoon",
                DisasterCategory::EarthquakeWarning | DisasterCategory::EarthquakeReport => {
                    "cenc.report"
                }
            }
            .to_string(),
            event_id: "event".to_string(),
            revision: "1".to_string(),
            report_num: 1,
            title: String::new(),
            description: String::new(),
            latitude: Some(31.2),
            longitude: Some(121.5),
            magnitude: Some(5.0),
            depth_km: Some(10.0),
            affected_regions: vec!["上海市".to_string()],
            radius_km: None,
            level: 2,
            occurred_at: "2026-07-13T00:00:00Z".to_string(),
            final_report: false,
            cancel: false,
            training: false,
        }
    }

    fn subscription(category: DisasterCategory, region: Option<&str>) -> CompiledSubscription {
        let latitude = 31.2_f64.to_radians();
        CompiledSubscription {
            subscription_id: SubscriptionId(7),
            destination_id: DestinationNumericId(9),
            generation: 3,
            targets: vec![CompiledTarget {
                ordinal: 0,
                latitude_e7: 312_000_000,
                longitude_e7: 1_215_000_000,
                latitude_radians: latitude,
                sin_latitude: latitude.sin(),
                cos_latitude: latitude.cos(),
                region_ids: region
                    .into_iter()
                    .map(|value| region_id(&region::normalize(value)))
                    .collect(),
                h3_cells: [0; 3],
            }],
            rules: vec![CompiledRule {
                category,
                source_mask: 0,
                wildcard_source: true,
                min_magnitude: 0.0,
                min_severity: 1,
                distance_km: 100.0,
                intensity_bands: if category == DisasterCategory::EarthquakeWarning {
                    vec![CompiledIntensityBand {
                        min: 0,
                        max: 7,
                        interruption_level: InterruptionLevel::Active,
                    }]
                } else {
                    Vec::new()
                },
            }],
        }
    }

    #[test]
    fn coordinate_less_tsunami_requires_an_administrative_match() {
        let mut tsunami = event(DisasterCategory::Tsunami);
        tsunami.latitude = None;
        tsunami.longitude = None;
        assert!(
            match_compiled(
                &subscription(DisasterCategory::Tsunami, Some("上海")),
                &tsunami
            )
            .is_some()
        );
        assert!(
            match_compiled(
                &subscription(DisasterCategory::Tsunami, Some("北京")),
                &tsunami
            )
            .is_none()
        );
    }

    #[test]
    fn earthquakes_and_typhoons_require_coordinates() {
        for category in [
            DisasterCategory::EarthquakeReport,
            DisasterCategory::Typhoon,
        ] {
            let mut value = event(category);
            value.latitude = None;
            value.longitude = None;
            assert!(match_compiled(&subscription(category, None), &value).is_none());
        }
    }

    #[test]
    fn posting_block_reconstructs_the_full_subscription_id() -> Result<()> {
        let expected = SubscriptionId((5_u64 << 16) | 17);
        let mut ids = RoaringBitmap::new();
        ids.insert(17);
        let engine = MatchEngine::new(1)?;
        let rows = engine.match_blocks(
            Arc::new(event(DisasterCategory::WeatherWarning)),
            vec![PostingBlock { id_block: 5, ids }],
            &HashMap::from([(expected, {
                let mut value = subscription(DisasterCategory::WeatherWarning, Some("上海"));
                value.subscription_id = expected;
                value
            })]),
        );
        anyhow::ensure!(rows.len() == 1);
        anyhow::ensure!(rows[0].subscription_id == expected);
        Ok(())
    }

    #[test]
    fn earthquake_warning_selects_from_targets_that_match_an_intensity_band() -> Result<()> {
        let warning = event(DisasterCategory::EarthquakeWarning);
        let mut value = subscription(DisasterCategory::EarthquakeWarning, None);
        value.rules[0].distance_km = 20_000.0;
        value.rules[0].intensity_bands = vec![CompiledIntensityBand {
            min: 0,
            max: 0,
            interruption_level: InterruptionLevel::Passive,
        }];
        let latitude = 0.0_f64.to_radians();
        value.targets.push(CompiledTarget {
            ordinal: 1,
            latitude_e7: 0,
            longitude_e7: 0,
            latitude_radians: latitude,
            sin_latitude: latitude.sin(),
            cos_latitude: latitude.cos(),
            region_ids: Vec::new(),
            h3_cells: [0; 3],
        });

        let matched = match_compiled(&value, &warning).context("far target should match")?;
        anyhow::ensure!(matched.target_ordinal == 1);
        anyhow::ensure!(matched.interruption_level == InterruptionLevel::Passive);
        Ok(())
    }
}
