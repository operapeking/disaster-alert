use crate::models::{DisasterCategory, DisasterEvent};
use crate::subscriptions::{H3_RESOLUTIONS, RegionId, SourceId, region_id, source_id};
use crate::utils::region;
use anyhow::{Context, Result};
use h3o::LatLng;

#[derive(Debug, Clone)]
pub(crate) enum MatchScope {
    Cells {
        resolution_index: u8,
        cells: Vec<u64>,
    },
    Regions(Vec<RegionId>),
    Broad,
}

#[derive(Debug, Clone)]
pub(crate) struct MatchPlan {
    pub(crate) category: DisasterCategory,
    pub(crate) source_id: SourceId,
    pub(crate) scopes: Vec<MatchScope>,
}

impl MatchPlan {
    pub(crate) fn for_event(event: &DisasterEvent) -> Result<Self> {
        let mut scopes = Vec::with_capacity(2);
        if matches!(
            event.category,
            DisasterCategory::EarthquakeWarning | DisasterCategory::EarthquakeReport
        ) {
            scopes.push(MatchScope::Broad);
        }
        let mut regions = event
            .affected_regions
            .iter()
            .map(|value| region::normalize(value))
            .filter(|value| !value.is_empty())
            .map(|value| region_id(&value))
            .collect::<Vec<_>>();
        regions.sort_unstable_by_key(|value| value.0);
        regions.dedup();
        if !regions.is_empty() {
            scopes.push(MatchScope::Regions(regions));
        }
        if matches!(
            event.category,
            DisasterCategory::WeatherWarning | DisasterCategory::Typhoon
        ) && let Some((latitude, longitude)) = event.latitude.zip(event.longitude)
        {
            let radius = maximum_candidate_radius(event.category);
            let resolution_index = resolution_for(radius);
            let coordinate =
                LatLng::new(latitude, longitude).context("invalid event H3 coordinate")?;
            let cell = coordinate.to_cell(H3_RESOLUTIONS[usize::from(resolution_index)]);
            let edge_km = edge_length_km(resolution_index);
            // Two extra rings account for the origin and target cells' circumradii.
            let ring = (radius / edge_km).ceil() as u32 + 2;
            scopes.push(MatchScope::Cells {
                resolution_index,
                cells: cell
                    .grid_disk::<Vec<_>>(ring)
                    .into_iter()
                    .map(u64::from)
                    .collect(),
            });
        }
        if scopes.is_empty() {
            scopes.push(MatchScope::Broad);
        }
        Ok(Self {
            category: event.category,
            source_id: source_id(&event.source),
            scopes,
        })
    }
}

fn resolution_for(radius_km: f64) -> u8 {
    if radius_km <= 15.0 {
        2
    } else if radius_km <= 300.0 {
        1
    } else {
        0
    }
}

fn maximum_candidate_radius(category: DisasterCategory) -> f64 {
    match category {
        DisasterCategory::EarthquakeWarning | DisasterCategory::EarthquakeReport => 20_000.0,
        DisasterCategory::WeatherWarning => 2_000.0,
        DisasterCategory::Tsunami => 0.0,
        DisasterCategory::Typhoon => 3_000.0,
    }
}

fn edge_length_km(resolution_index: u8) -> f64 {
    // Conservative lower bounds across the globe. Using average H3 edge lengths here can
    // under-enumerate cells at high latitudes and silently drop boundary candidates.
    match resolution_index {
        2 => 0.3,
        1 => 5.5,
        _ => 100.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProviderChannel;

    fn event(category: DisasterCategory) -> DisasterEvent {
        DisasterEvent {
            category,
            channel: ProviderChannel::Cenc,
            source: "test.typhoon".to_string(),
            event_id: "event".to_string(),
            revision: "1".to_string(),
            report_num: 1,
            title: String::new(),
            description: String::new(),
            latitude: Some(20.0),
            longitude: Some(120.0),
            magnitude: None,
            depth_km: None,
            affected_regions: Vec::new(),
            radius_km: Some(1.0),
            level: 2,
            occurred_at: "2026-07-13T00:00:00Z".to_string(),
            final_report: false,
            cancel: false,
            training: false,
        }
    }

    #[test]
    fn broad_typhoon_plan_uses_coarse_cells_without_a_truncating_ring_cap() -> Result<()> {
        let plan = MatchPlan::for_event(&event(DisasterCategory::Typhoon))?;
        let cells = plan.scopes.iter().find_map(|scope| match scope {
            MatchScope::Cells {
                resolution_index,
                cells,
            } => Some((*resolution_index, cells.len())),
            MatchScope::Regions(_) | MatchScope::Broad => None,
        });
        let (resolution, count) = cells.context("missing cell scope")?;
        anyhow::ensure!(resolution == 0);
        anyhow::ensure!(count > 1_000);
        Ok(())
    }

    #[test]
    fn tsunami_without_regions_does_not_use_coordinate_candidates() -> Result<()> {
        let plan = MatchPlan::for_event(&event(DisasterCategory::Tsunami))?;
        anyhow::ensure!(matches!(plan.scopes.as_slice(), [MatchScope::Broad]));
        Ok(())
    }
}
