use crate::models::{AlertRule, DisasterCategory, ProviderChannel};
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub(crate) struct SourceDefinition {
    pub(crate) id: &'static str,
    pub(crate) provider_key: &'static str,
    pub(crate) channel: ProviderChannel,
    pub(crate) category: DisasterCategory,
    pub(crate) group_id: &'static str,
    pub(crate) group_label: &'static str,
    pub(crate) label: &'static str,
    pub(crate) default_utc_offset_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SourceGroup {
    pub(crate) id: &'static str,
    pub(crate) label: &'static str,
    pub(crate) sources: Vec<SourceOption>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CategoryOption {
    pub(crate) id: &'static str,
    pub(crate) label: &'static str,
    pub(crate) source_groups: Vec<SourceGroup>,
    pub(crate) default_alert: AlertRule,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct SourceOption {
    pub(crate) id: &'static str,
    pub(crate) label: &'static str,
}

pub(crate) fn default_utc_offset_seconds(source: &str) -> Option<i64> {
    find(source).and_then(|definition| definition.default_utc_offset_seconds)
}

macro_rules! source {
    ($id:literal, $key:literal, $channel:ident, $category:ident, $group:literal, $group_label:literal, $label:literal, $offset:expr) => {
        SourceDefinition {
            id: $id,
            provider_key: $key,
            channel: ProviderChannel::$channel,
            category: DisasterCategory::$category,
            group_id: $group,
            group_label: $group_label,
            label: $label,
            default_utc_offset_seconds: $offset,
        }
    };
}

pub(crate) const SOURCES: &[SourceDefinition] = &[
    source!(
        "wolfx.jma_eew",
        "jma_eew",
        Wolfx,
        EarthquakeWarning,
        "wolfx-earthquake-warning",
        "Wolfx 地震预警",
        "Wolfx 日本气象厅",
        Some(9 * 3600)
    ),
    source!(
        "wolfx.sc_eew",
        "sc_eew",
        Wolfx,
        EarthquakeWarning,
        "wolfx-earthquake-warning",
        "Wolfx 地震预警",
        "Wolfx 四川地震局",
        Some(8 * 3600)
    ),
    source!(
        "wolfx.cenc_eew",
        "cenc_eew",
        Wolfx,
        EarthquakeWarning,
        "wolfx-earthquake-warning",
        "Wolfx 地震预警",
        "Wolfx 中国地震台网",
        Some(8 * 3600)
    ),
    source!(
        "wolfx.fj_eew",
        "fj_eew",
        Wolfx,
        EarthquakeWarning,
        "wolfx-earthquake-warning",
        "Wolfx 地震预警",
        "Wolfx 福建地震局",
        Some(8 * 3600)
    ),
    source!(
        "wolfx.cq_eew",
        "cq_eew",
        Wolfx,
        EarthquakeWarning,
        "wolfx-earthquake-warning",
        "Wolfx 地震预警",
        "Wolfx 重庆地震局",
        Some(8 * 3600)
    ),
    source!(
        "cenc.warning",
        "warning",
        Cenc,
        EarthquakeWarning,
        "cenc-earthquake-warning",
        "中国地震台网地震预警",
        "中国地震台网",
        Some(8 * 3600)
    ),
    source!(
        "cenc.report",
        "report",
        Cenc,
        EarthquakeReport,
        "cenc-earthquake-report",
        "中国地震台网地震速报",
        "中国地震台网",
        Some(8 * 3600)
    ),
    source!(
        "huania.earlywarning",
        "earlywarning",
        Huania,
        EarthquakeWarning,
        "huania-earthquake-warning",
        "Huania 地震预警",
        "Huania 地震预警",
        None
    ),
];

pub(crate) fn find(id: &str) -> Option<&'static SourceDefinition> {
    SOURCES.iter().find(|source| source.id == id)
}

pub(crate) fn find_provider(
    channel: ProviderChannel,
    provider_key: &str,
) -> Option<&'static SourceDefinition> {
    SOURCES
        .iter()
        .find(|source| source.channel == channel && source.provider_key == provider_key)
}

pub(crate) fn category_options() -> Vec<CategoryOption> {
    DisasterCategory::ALL
        .into_iter()
        .filter(|category| SOURCES.iter().any(|source| source.category == *category))
        .map(|category| {
            let mut source_groups = Vec::<SourceGroup>::new();
            for source in SOURCES.iter().filter(|source| source.category == category) {
                if let Some(group) = source_groups
                    .iter_mut()
                    .find(|group| group.id == source.group_id)
                {
                    group.sources.push(SourceOption {
                        id: source.id,
                        label: source.label,
                    });
                } else {
                    source_groups.push(SourceGroup {
                        id: source.group_id,
                        label: source.group_label,
                        sources: vec![SourceOption {
                            id: source.id,
                            label: source.label,
                        }],
                    });
                }
            }
            CategoryOption {
                id: category.as_str(),
                label: category.label(),
                source_groups,
                default_alert: AlertRule::default_for(category),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_ids_are_unique_and_every_source_is_grouped() {
        let ids = SOURCES
            .iter()
            .map(|source| source.id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), SOURCES.len());
        let provider_keys = SOURCES
            .iter()
            .map(|source| (source.channel, source.provider_key))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(provider_keys.len(), SOURCES.len());
        let mut group_metadata = std::collections::HashMap::new();
        for source in SOURCES {
            let metadata = (source.category, source.group_label);
            assert_eq!(
                group_metadata.entry(source.group_id).or_insert(metadata),
                &metadata
            );
            assert_eq!(
                default_utc_offset_seconds(source.id),
                source.default_utc_offset_seconds
            );
            assert!(
                source
                    .default_utc_offset_seconds
                    .is_none_or(|offset| matches!(offset, 28_800 | 32_400))
            );
        }
        assert_eq!(
            category_options()
                .iter()
                .flat_map(|category| &category.source_groups)
                .map(|group| group.sources.len())
                .sum::<usize>(),
            SOURCES.len()
        );
    }

    #[test]
    fn source_time_contracts_are_declared_in_the_registry() {
        assert_eq!(default_utc_offset_seconds("wolfx.jma_eew"), Some(32_400));
        assert_eq!(default_utc_offset_seconds("cenc.warning"), Some(28_800));
        assert_eq!(default_utc_offset_seconds("cenc.report"), Some(28_800));
        assert_eq!(default_utc_offset_seconds("huania.earlywarning"), None);
    }
}
