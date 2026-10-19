use crate::models::{DisasterCategory, DisasterEvent, MonitoringTarget};
use serde::{Deserialize, Serialize};

const MAX_INLINE_REGIONS: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertTiming {
    pub(crate) distance_km: f64,
    pub(crate) hypocentral_km: f64,
    pub(crate) estimated_intensity: f64,
    pub(crate) p_arrival_at_ms: i64,
    pub(crate) s_arrival_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DisasterAlertContent {
    pub(crate) title: String,
    pub(crate) subtitle: String,
    pub(crate) body: String,
}

pub(crate) fn format_disaster_alert(
    event: &DisasterEvent,
    target: &MonitoringTarget,
    timing: Option<&AlertTiming>,
    now_ms: i64,
) -> DisasterAlertContent {
    match event.category {
        DisasterCategory::EarthquakeWarning => {
            format_earthquake(event, target, timing, now_ms, true)
        }
        DisasterCategory::EarthquakeReport => {
            format_earthquake(event, target, timing, now_ms, false)
        }
        DisasterCategory::WeatherWarning => format_weather(event, target),
        DisasterCategory::Tsunami => format_tsunami(event, target),
        DisasterCategory::Typhoon => format_typhoon(event, target),
    }
}

pub(crate) fn remaining_seconds(arrival_at_ms: i64, now_ms: i64) -> i64 {
    let delta_ms = arrival_at_ms.saturating_sub(now_ms);
    if delta_ms <= 0 {
        0
    } else {
        delta_ms.saturating_add(999) / 1_000
    }
}

fn format_earthquake(
    event: &DisasterEvent,
    target: &MonitoringTarget,
    timing: Option<&AlertTiming>,
    now_ms: i64,
    warning: bool,
) -> DisasterAlertContent {
    let base_title = if warning {
        "地震播报"
    } else {
        "地震速报"
    };
    let title = stateful_title(base_title, event, timing, now_ms);
    let target_name = target_name(target);
    let place = earthquake_place(event);
    let mut subtitle = Vec::new();
    if !place.is_empty() {
        subtitle.push(place.clone());
    }
    if let Some(magnitude) = event.magnitude {
        subtitle.push(format!("M{magnitude:.1}"));
    }
    if let Some(timing) = timing {
        subtitle.push(format!("预计烈度 {:.1}", timing.estimated_intensity));
    }
    subtitle.push(format!("监测点 {target_name}"));
    append_report_state(event, &mut subtitle);

    let mut lines = Vec::new();
    if event.training {
        lines.push("演练信息：这是一条模拟预警，请勿恐慌。".to_string());
    }
    if !place.is_empty() {
        lines.push(format!("震中位置：{place}"));
    }
    lines.push(format!("监测地点：{target_name}"));
    if let Some(timing) = timing {
        lines.push(format!(
            "震波到达：{} · {}",
            wave_status("P波", timing.p_arrival_at_ms, now_ms),
            wave_status("S波", timing.s_arrival_at_ms, now_ms)
        ));
        lines.push(format!(
            "距离估算：震中距 {:.0} km · 震源距 {:.0} km",
            timing.distance_km, timing.hypocentral_km
        ));
    }
    let mut earthquake = Vec::new();
    if let Some(magnitude) = event.magnitude {
        earthquake.push(format!("震级 M{magnitude:.1}"));
    }
    if let Some(depth_km) = event.depth_km {
        earthquake.push(format!("深度 {depth_km:.0} km"));
    }
    if !earthquake.is_empty() {
        lines.push(format!("地震参数：{}", earthquake.join(" · ")));
    }
    append_regions(event, "可能影响", &mut lines);
    append_time(event, "发生时间", &mut lines);
    lines.push("安全提示：请保持冷静，远离玻璃、悬挂物和不稳固家具。".to_string());

    DisasterAlertContent {
        title,
        subtitle: subtitle.join(" · "),
        body: lines.join("\n"),
    }
}

fn format_weather(event: &DisasterEvent, target: &MonitoringTarget) -> DisasterAlertContent {
    let title = stateful_title("气象预警", event, None, 0);
    let target_name = target_name(target);
    let event_title = clean_inline(&event.title);
    let mut subtitle = vec![
        event_title
            .is_empty()
            .then_some("气象部门发布预警".to_string())
            .unwrap_or(event_title),
    ];
    subtitle.push(format!("监测点 {target_name}"));
    append_report_state(event, &mut subtitle);

    let mut lines = vec![format!("监测地点：{target_name}")];
    append_regions(event, "预警区域", &mut lines);
    append_description(event, "预警内容", &mut lines);
    append_time(event, "发布时间", &mut lines);
    lines.push("防范提示：请关注临近预报，合理调整出行和户外活动。".to_string());

    DisasterAlertContent {
        title,
        subtitle: subtitle.join(" · "),
        body: lines.join("\n"),
    }
}

fn format_tsunami(event: &DisasterEvent, target: &MonitoringTarget) -> DisasterAlertContent {
    let title = stateful_title("海啸预警", event, None, 0);
    let target_name = target_name(target);
    let event_title = clean_inline(&event.title);
    let mut subtitle = vec![
        event_title
            .is_empty()
            .then_some("海啸风险信息".to_string())
            .unwrap_or(event_title),
    ];
    subtitle.push(format!("监测点 {target_name}"));
    append_report_state(event, &mut subtitle);

    let mut lines = vec![format!("监测地点：{target_name}")];
    append_regions(event, "影响区域", &mut lines);
    append_description(event, "预警说明", &mut lines);
    let mut earthquake = Vec::new();
    if let Some(magnitude) = event.magnitude {
        earthquake.push(format!("震级 M{magnitude:.1}"));
    }
    if let Some(depth_km) = event.depth_km {
        earthquake.push(format!("深度 {depth_km:.0} km"));
    }
    if !earthquake.is_empty() {
        lines.push(format!("相关地震：{}", earthquake.join(" · ")));
    }
    append_time(event, "更新时间", &mut lines);
    lines.push("避险提示：沿海及河口区域人员请远离岸线，按官方指引向高处转移。".to_string());

    DisasterAlertContent {
        title,
        subtitle: subtitle.join(" · "),
        body: lines.join("\n"),
    }
}

fn format_typhoon(event: &DisasterEvent, target: &MonitoringTarget) -> DisasterAlertContent {
    let title = stateful_title("台风动态", event, None, 0);
    let target_name = target_name(target);
    let event_title = clean_inline(&event.title);
    let mut subtitle = vec![
        event_title
            .is_empty()
            .then_some("台风最新动态".to_string())
            .unwrap_or(event_title),
    ];
    subtitle.push(format!("监测点 {target_name}"));
    append_report_state(event, &mut subtitle);

    let mut lines = vec![format!("监测地点：{target_name}")];
    if let Some((latitude, longitude)) = event.latitude.zip(event.longitude) {
        lines.push(format!("台风中心：{latitude:.2}°, {longitude:.2}°"));
    }
    if let Some(radius_km) = event.radius_km {
        lines.push(format!("七级风圈：约 {radius_km:.0} km"));
    }
    append_regions(event, "可能影响", &mut lines);
    append_description(event, "强度信息", &mut lines);
    append_time(event, "更新时间", &mut lines);
    lines.push("防范提示：请加固门窗和室外物品，避免前往沿海、山区及低洼地带。".to_string());

    DisasterAlertContent {
        title,
        subtitle: subtitle.join(" · "),
        body: lines.join("\n"),
    }
}

fn stateful_title(
    base: &str,
    event: &DisasterEvent,
    timing: Option<&AlertTiming>,
    now_ms: i64,
) -> String {
    let title = if event.cancel {
        format!("{base}已解除")
    } else if let Some(timing) = timing {
        let seconds = remaining_seconds(timing.s_arrival_at_ms, now_ms);
        if seconds > 0 {
            format!("{base} {seconds}秒后到达")
        } else {
            format!("{base} 震波已到达")
        }
    } else if event.final_report {
        format!("{base}终报")
    } else {
        base.to_string()
    };
    if event.training {
        format!("演练 · {title}")
    } else {
        title
    }
}

fn wave_status(name: &str, arrival_at_ms: i64, now_ms: i64) -> String {
    let seconds = remaining_seconds(arrival_at_ms, now_ms);
    if seconds > 0 {
        format!("{name}还有 {seconds} 秒")
    } else {
        format!("{name}已到达")
    }
}

fn earthquake_place(event: &DisasterEvent) -> String {
    let title = clean_inline(&event.title);
    for prefix in ["地震预警", "地震信息", "地震速报", "地震播报"] {
        if let Some(place) = title.strip_prefix(prefix) {
            return place.trim_matches(['：', ':', ' ']).to_string();
        }
    }
    title
}

fn target_name(target: &MonitoringTarget) -> String {
    let label = clean_inline(&target.label);
    if !label.is_empty() {
        return label;
    }
    for value in [
        &target.region.district,
        &target.region.city,
        &target.region.province,
    ] {
        let value = clean_inline(value);
        if !value.is_empty() {
            return value;
        }
    }
    "所选地点".to_string()
}

fn append_report_state(event: &DisasterEvent, parts: &mut Vec<String>) {
    if event.cancel {
        parts.push("解除/取消".to_string());
    } else if event.final_report {
        parts.push("最终报告".to_string());
    }
}

fn append_regions(event: &DisasterEvent, label: &str, lines: &mut Vec<String>) {
    let regions = event
        .affected_regions
        .iter()
        .map(|region| clean_inline(region))
        .filter(|region| !region.is_empty())
        .take(MAX_INLINE_REGIONS)
        .collect::<Vec<_>>();
    if !regions.is_empty() {
        lines.push(format!("{label}：{}", regions.join("、")));
    }
}

fn append_description(event: &DisasterEvent, label: &str, lines: &mut Vec<String>) {
    let description = clean_inline(&event.description);
    if !description.is_empty() && description != clean_inline(&event.title) {
        lines.push(format!("{label}：{description}"));
    }
}

fn append_time(event: &DisasterEvent, label: &str, lines: &mut Vec<String>) {
    let occurred_at = clean_inline(&event.occurred_at);
    if !occurred_at.is_empty() {
        lines.push(format!("{label}：{occurred_at}"));
    }
}

fn clean_inline(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AdministrativeRegion, GeoPoint, ProviderChannel};

    fn target() -> MonitoringTarget {
        MonitoringTarget {
            label: "上海家中".to_string(),
            point: GeoPoint {
                latitude: 31.2,
                longitude: 121.5,
            },
            region: AdministrativeRegion {
                province: "上海市".to_string(),
                city: "上海市".to_string(),
                district: "浦东新区".to_string(),
            },
        }
    }

    fn event(category: DisasterCategory) -> DisasterEvent {
        DisasterEvent {
            category,
            channel: ProviderChannel::Cenc,
            source: "internal.provider.channel".to_string(),
            event_id: "internal-event-id".to_string(),
            revision: "internal-revision".to_string(),
            report_num: 3,
            title: match category {
                DisasterCategory::EarthquakeWarning => "地震预警 四川泸定".to_string(),
                DisasterCategory::EarthquakeReport => "地震信息 四川泸定".to_string(),
                DisasterCategory::WeatherWarning => "上海市雷电黄色预警".to_string(),
                DisasterCategory::Tsunami => "海啸黄色警报".to_string(),
                DisasterCategory::Typhoon => "台风 海棠".to_string(),
            },
            description: "预计未来六小时有明显影响".to_string(),
            latitude: Some(29.6),
            longitude: Some(102.1),
            magnitude: Some(6.2),
            depth_km: Some(10.0),
            affected_regions: vec!["上海市".to_string(), "浙江沿海".to_string()],
            radius_km: Some(180.0),
            level: 3,
            occurred_at: "2026-07-14 10:20:30".to_string(),
            final_report: false,
            cancel: false,
            training: false,
        }
    }

    fn timing() -> AlertTiming {
        AlertTiming {
            distance_km: 82.4,
            hypocentral_km: 83.0,
            estimated_intensity: 3.2,
            p_arrival_at_ms: 104_000,
            s_arrival_at_ms: 112_000,
        }
    }

    #[test]
    fn earthquake_title_and_body_count_down_to_the_monitoring_target() {
        let content = format_disaster_alert(
            &event(DisasterCategory::EarthquakeWarning),
            &target(),
            Some(&timing()),
            101_000,
        );

        assert_eq!(content.title, "地震播报 11秒后到达");
        assert!(content.subtitle.contains("四川泸定 · M6.2 · 预计烈度 3.2"));
        assert!(content.body.contains("P波还有 3 秒 · S波还有 11 秒"));
        assert!(content.body.contains("震中距 82 km · 震源距 83 km"));
        assert_no_internal_fields(&content);
    }

    #[test]
    fn earthquake_report_uses_broadcast_wording_and_arrived_state() {
        let content = format_disaster_alert(
            &event(DisasterCategory::EarthquakeReport),
            &target(),
            Some(&timing()),
            112_000,
        );

        assert_eq!(content.title, "地震速报 震波已到达");
        assert!(content.body.contains("P波已到达 · S波已到达"));
        assert_no_internal_fields(&content);
    }

    #[test]
    fn non_earthquake_categories_have_distinct_user_facing_layouts() {
        let cases = [
            (DisasterCategory::WeatherWarning, "气象预警", "预警内容"),
            (DisasterCategory::Tsunami, "海啸预警", "避险提示"),
            (DisasterCategory::Typhoon, "台风动态", "七级风圈"),
        ];
        for (category, title, body_fragment) in cases {
            let content = format_disaster_alert(&event(category), &target(), None, 0);
            assert_eq!(content.title, title);
            assert!(content.body.contains(body_fragment));
            assert_no_internal_fields(&content);
        }
    }

    #[test]
    fn cancellation_replaces_countdown_wording() {
        let mut cancelled = event(DisasterCategory::EarthquakeWarning);
        cancelled.cancel = true;
        let content = format_disaster_alert(&cancelled, &target(), Some(&timing()), 101_000);

        assert_eq!(content.title, "地震播报已解除");
        assert!(content.subtitle.contains("解除/取消"));
    }

    fn assert_no_internal_fields(content: &DisasterAlertContent) {
        let rendered = format!("{}\n{}\n{}", content.title, content.subtitle, content.body);
        for internal in [
            "internal.provider.channel",
            "internal-event-id",
            "internal-revision",
            "Cenc",
            "来源：",
            "渠道：",
        ] {
            assert!(!rendered.contains(internal), "leaked field: {internal}");
        }
    }
}
