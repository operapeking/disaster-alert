use crate::models::{
    AlertRule, DisasterCategory, InterruptionLevel, SourceSelection, Subscription,
};
use crate::utils::region;
use anyhow::{Context, Result};
use h3o::{LatLng, Resolution};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const H3_RESOLUTIONS: [Resolution; 3] =
    [Resolution::Two, Resolution::Five, Resolution::Eight];
const UNKNOWN_SOURCE_ID: SourceId = SourceId(u16::MAX);
const POSTING_ID_BITS: u32 = 16;
const POSTING_ID_MASK: u64 = (1_u64 << POSTING_ID_BITS) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SubscriptionId(pub(crate) u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct DestinationNumericId(pub(crate) u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SourceId(pub(crate) u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct RegionId(pub(crate) u64);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompiledSubscription {
    pub(crate) subscription_id: SubscriptionId,
    pub(crate) destination_id: DestinationNumericId,
    pub(crate) generation: u64,
    pub(crate) targets: Vec<CompiledTarget>,
    pub(crate) rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompiledTarget {
    pub(crate) ordinal: u8,
    pub(crate) latitude_e7: i32,
    pub(crate) longitude_e7: i32,
    pub(crate) latitude_radians: f64,
    pub(crate) sin_latitude: f64,
    pub(crate) cos_latitude: f64,
    pub(crate) region_ids: Vec<RegionId>,
    pub(crate) h3_cells: [u64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompiledRule {
    pub(crate) category: DisasterCategory,
    pub(crate) source_mask: u64,
    pub(crate) wildcard_source: bool,
    pub(crate) min_magnitude: f64,
    pub(crate) min_severity: u8,
    pub(crate) distance_km: f64,
    pub(crate) intensity_bands: Vec<CompiledIntensityBand>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompiledIntensityBand {
    pub(crate) min: u8,
    pub(crate) max: u8,
    pub(crate) interruption_level: InterruptionLevel,
}

pub(crate) struct SubscriptionCompiler;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MatchPostingKey {
    pub(crate) category: DisasterCategory,
    pub(crate) source: Option<SourceId>,
    pub(crate) kind: u8,
    pub(crate) value: u64,
    pub(crate) id_block: u64,
}

impl MatchPostingKey {
    pub(crate) fn encode(self) -> [u8; 20] {
        let mut key = [0; 20];
        key[0] = category_code(self.category);
        key[1] = self.kind;
        key[2..4].copy_from_slice(&self.source.map_or(0, |value| value.0).to_be_bytes());
        key[4..12].copy_from_slice(&self.value.to_be_bytes());
        key[12..20].copy_from_slice(&self.id_block.to_be_bytes());
        key
    }

    pub(crate) fn for_subscription(subscription: &CompiledSubscription) -> Vec<Self> {
        let mut keys = Vec::new();
        let id_block = subscription.subscription_id.posting_block();
        for rule in &subscription.rules {
            let sources = if rule.wildcard_source {
                vec![None]
            } else {
                source_ids_in_mask(rule.source_mask).map(Some).collect()
            };
            for source in sources {
                keys.push(Self {
                    category: rule.category,
                    source,
                    kind: 0,
                    value: 0,
                    id_block,
                });
                for target in &subscription.targets {
                    for (resolution_index, cell) in target.h3_cells.iter().enumerate() {
                        keys.push(Self {
                            category: rule.category,
                            source,
                            kind: 1 + u8::try_from(resolution_index).unwrap_or(0),
                            value: *cell,
                            id_block,
                        });
                    }
                    for region in &target.region_ids {
                        keys.push(Self {
                            category: rule.category,
                            source,
                            kind: 4,
                            value: region.0,
                            id_block,
                        });
                    }
                }
            }
        }
        keys.sort_unstable_by_key(|key| key.encode());
        keys.dedup();
        keys
    }
}

fn category_code(category: DisasterCategory) -> u8 {
    match category {
        DisasterCategory::EarthquakeWarning => 1,
        DisasterCategory::EarthquakeReport => 2,
        DisasterCategory::WeatherWarning => 3,
        DisasterCategory::Tsunami => 4,
        DisasterCategory::Typhoon => 5,
    }
}

impl SubscriptionCompiler {
    pub(crate) fn compile(
        subscription_id: SubscriptionId,
        destination_id: DestinationNumericId,
        generation: u64,
        subscription: &Subscription,
    ) -> Result<CompiledSubscription> {
        subscription
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid subscription: {error}"))?;
        let targets = subscription
            .targets
            .iter()
            .enumerate()
            .map(|(ordinal, target)| {
                let latitude = target.point.latitude;
                let longitude = target.point.longitude;
                let lat_lng = LatLng::new(latitude, longitude)
                    .context("failed to encode target as H3 coordinate")?;
                let latitude_radians = latitude.to_radians();
                let mut region_ids = [
                    target.region.province.as_str(),
                    target.region.city.as_str(),
                    target.region.district.as_str(),
                ]
                .into_iter()
                .map(region::normalize)
                .filter(|value| !value.is_empty())
                .map(|value| region_id(&value))
                .collect::<Vec<_>>();
                region_ids.sort_unstable_by_key(|value| value.0);
                region_ids.dedup();
                Ok(CompiledTarget {
                    ordinal: u8::try_from(ordinal).context("target ordinal exceeds u8")?,
                    latitude_e7: fixed_coordinate(latitude)?,
                    longitude_e7: fixed_coordinate(longitude)?,
                    latitude_radians,
                    sin_latitude: latitude_radians.sin(),
                    cos_latitude: latitude_radians.cos(),
                    region_ids,
                    h3_cells: H3_RESOLUTIONS
                        .map(|resolution| u64::from(lat_lng.to_cell(resolution))),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let rules = subscription
            .alerts
            .iter()
            .map(compile_rule)
            .collect::<Result<_>>()?;
        Ok(CompiledSubscription {
            subscription_id,
            destination_id,
            generation,
            targets,
            rules,
        })
    }
}

pub(crate) fn source_id(value: &str) -> SourceId {
    // 持久化订阅使用固定编号，新增或移除来源时保持已有编号。
    match value {
        "wolfx.jma_eew" => SourceId(1),
        "wolfx.sc_eew" => SourceId(2),
        "wolfx.cenc_eew" => SourceId(3),
        "wolfx.fj_eew" => SourceId(4),
        "wolfx.cq_eew" => SourceId(5),
        "huania.earlywarning" => SourceId(31),
        "cenc.warning" => SourceId(32),
        "cenc.report" => SourceId(33),
        _ => UNKNOWN_SOURCE_ID,
    }
}

impl SubscriptionId {
    pub(crate) const fn posting_block(self) -> u64 {
        self.0 >> POSTING_ID_BITS
    }

    pub(crate) const fn posting_offset(self) -> u32 {
        (self.0 & POSTING_ID_MASK) as u32
    }

    pub(crate) const fn from_posting(block: u64, offset: u32) -> Option<Self> {
        if offset as u64 > POSTING_ID_MASK || block > (u64::MAX >> POSTING_ID_BITS) {
            return None;
        }
        Some(Self((block << POSTING_ID_BITS) | offset as u64))
    }
}

impl SourceId {
    const fn bit(self) -> Option<u64> {
        if self.0 == 0 || self.0 > 64 {
            return None;
        }
        Some(1_u64 << (self.0 - 1))
    }
}

impl CompiledRule {
    pub(crate) fn accepts_source(&self, source: SourceId) -> bool {
        self.wildcard_source || source.bit().is_some_and(|bit| self.source_mask & bit != 0)
    }
}

fn source_ids_in_mask(mask: u64) -> impl Iterator<Item = SourceId> {
    (0_u16..64).filter_map(move |bit| {
        (mask & (1_u64 << bit) != 0).then_some(SourceId(bit.saturating_add(1)))
    })
}

pub(crate) fn region_id(value: &str) -> RegionId {
    let mut hash = Sha256::new();
    hash.update(b"disaster-alert:region-id:v1\0");
    hash.update(value.as_bytes());
    let digest = hash.finalize();
    RegionId(u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8])))
}

fn fixed_coordinate(value: f64) -> Result<i32> {
    let scaled = (value * 10_000_000.0).round();
    anyhow::ensure!(
        scaled.is_finite() && scaled >= f64::from(i32::MIN) && scaled <= f64::from(i32::MAX),
        "coordinate exceeds fixed-point range"
    );
    Ok(scaled as i32)
}

fn compile_rule(rule: &AlertRule) -> Result<CompiledRule> {
    let (min_magnitude, min_severity, distance_km, intensity_bands) = match rule {
        AlertRule::EarthquakeWarning {
            estimated_intensity_bands,
            ..
        } => (
            0.0,
            0,
            20_000.0,
            estimated_intensity_bands
                .iter()
                .map(|band| CompiledIntensityBand {
                    min: band.min,
                    max: band.max,
                    interruption_level: band.interruption_level,
                })
                .collect(),
        ),
        AlertRule::EarthquakeReport { min_magnitude, .. } => {
            (*min_magnitude, 0, 20_000.0, Vec::new())
        }
        AlertRule::WeatherWarning {
            min_severity,
            fallback_radius_km,
            ..
        } => (0.0, *min_severity, *fallback_radius_km, Vec::new()),
        AlertRule::Tsunami { min_severity, .. } => (0.0, *min_severity, 20_000.0, Vec::new()),
        AlertRule::Typhoon {
            max_center_distance_km,
            ..
        } => (0.0, 0, *max_center_distance_km, Vec::new()),
    };
    let (wildcard_source, source_mask) = match rule.sources() {
        SourceSelection::All => (true, 0),
        SourceSelection::Include { ids } => (
            false,
            ids.iter().try_fold(0_u64, |mask, value| {
                let id = source_id(value);
                let bit = id.bit().with_context(|| {
                    format!("source {value:?} cannot be represented in source mask")
                })?;
                Ok::<_, anyhow::Error>(mask | bit)
            })?,
        ),
    };
    Ok(CompiledRule {
        category: rule.category(),
        source_mask,
        wildcard_source,
        min_magnitude,
        min_severity,
        distance_km,
        intensity_bands,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ids_are_stable_with_a_reserved_unknown_value() {
        assert_eq!(source_id("wolfx.cenc_eew"), SourceId(3));
        assert_eq!(source_id("huania.earlywarning"), SourceId(31));
        assert_eq!(source_id("cenc.warning"), SourceId(32));
        assert_eq!(source_id("cenc.report"), SourceId(33));
        let ids = crate::source_registry::SOURCES
            .iter()
            .map(|source| source_id(source.id))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), crate::source_registry::SOURCES.len());
        assert!(!ids.contains(&UNKNOWN_SOURCE_ID));
        assert_eq!(source_id("unknown.source"), UNKNOWN_SOURCE_ID);
        assert!(crate::source_registry::SOURCES.len() <= 64);
    }

    #[test]
    fn posting_ids_round_trip_at_block_boundaries() {
        for raw in [0, 1, 65_535, 65_536, u32::MAX as u64, u64::MAX] {
            let id = SubscriptionId(raw);
            assert_eq!(
                SubscriptionId::from_posting(id.posting_block(), id.posting_offset()),
                Some(id)
            );
        }
    }
}
