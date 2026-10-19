use crate::delivery::{
    NotificationRuleSnapshot, NotificationSnapshot, NotificationSourcesSnapshot,
};
use crate::models::{DisasterEvent, IncidentRecord, IncidentReportSummary};
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sha2::{Digest as _, Sha256 as Sha256Hasher};
use std::sync::OnceLock;

static DETAIL_CSP: OnceLock<HeaderValue> = OnceLock::new();

pub(crate) fn render_incident_page(
    snapshot: &NotificationSnapshot,
    incident: Option<&IncidentRecord>,
) -> String {
    let mut html = String::with_capacity(36 * 1024);
    html.push_str("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\"><meta name=\"color-scheme\" content=\"light\"><title>");
    escape_into(&snapshot.event.title, &mut html);
    html.push_str(" - 灾害详情</title><link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.css\" integrity=\"sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=\" crossorigin=\"anonymous\"><style>");
    html.push_str(DETAIL_STYLE);
    html.push_str("</style></head><body class=\"detail-page\"><header class=\"map-hero\"><div class=\"map-stage\"><div id=\"incident-map\" class=\"incident-map\" aria-label=\"灾害事件与关注地点地图\">");
    render_map_fallback(snapshot, incident, &mut html);
    render_map_data(snapshot, incident, &mut html);
    html.push_str("</div><div class=\"map-shade\" aria-hidden=\"true\"></div></div><div class=\"hero-topbar\"><div class=\"hero-brand\"><span class=\"brand-symbol\" aria-hidden=\"true\"></span><span>灾害态势</span></div></div><div class=\"hero-layout\"><section class=\"floating-panel event-panel\" aria-labelledby=\"overview-heading\"><div class=\"panel-topline\"><div class=\"trust-row\"><span class=\"category\">");
    escape_into(snapshot.event.category.label(), &mut html);
    html.push_str("</span>");
    if snapshot.event.training {
        html.push_str("<span class=\"training\">演练 / 测试</span>");
    }
    html.push_str("</div>");
    html.push_str(incident.map_or_else(
        || status_badge(snapshot.event.cancel, snapshot.event.final_report),
        aggregate_status_badge,
    ));
    html.push_str(
        "</div><span class=\"section-kicker\">事件态势</span><h1 id=\"overview-heading\">",
    );
    escape_into(&snapshot.event.title, &mut html);
    html.push_str("</h1><p class=\"headline-meta\">");
    escape_into(&snapshot.event.source, &mut html);
    html.push_str(" · 第 ");
    html.push_str(&snapshot.event.report_num.to_string());
    html.push_str(" 报 · ");
    escape_into(&snapshot.event.occurred_at, &mut html);
    html.push_str("</p><div class=\"hero-metrics\">");
    if let Some(magnitude) = snapshot.event.magnitude {
        hero_metric("震级", &format!("M{magnitude:.1}"), true, &mut html);
    }
    hero_metric(
        "事件等级",
        &snapshot.event.level.to_string(),
        snapshot.event.magnitude.is_none(),
        &mut html,
    );
    if let Some(depth) = snapshot.event.depth_km {
        hero_metric("深度", &format!("{depth:.1} km"), false, &mut html);
    }
    if let Some(radius) = snapshot.event.radius_km {
        hero_metric("影响半径", &format!("{radius:.0} km"), false, &mut html);
    }
    html.push_str("</div>");
    if !snapshot.event.description.trim().is_empty() {
        html.push_str("<p class=\"hero-description\">");
        escape_into(&snapshot.event.description, &mut html);
        html.push_str("</p>");
    }
    html.push_str("</section><section class=\"floating-panel impact-panel\" aria-labelledby=\"impact-heading\"><div class=\"panel-topline\"><div><span class=\"section-kicker\">影响提示</span><h2 id=\"impact-heading\">关注地点</h2></div><span class=\"notification-level ");
    escape_into(&snapshot.interruption_level, &mut html);
    html.push_str("\">");
    escape_into(
        interruption_level_label(&snapshot.interruption_level),
        &mut html,
    );
    html.push_str("</span></div><div class=\"target-summary\"><span class=\"target-pin\" aria-hidden=\"true\"></span><div><span>关注地点</span><strong>");
    escape_into(&snapshot.target.label, &mut html);
    html.push_str("</strong><small>");
    let region = [
        snapshot.target.province.as_str(),
        snapshot.target.city.as_str(),
        snapshot.target.district.as_str(),
    ]
    .into_iter()
    .filter(|value| !value.is_empty())
    .collect::<Vec<_>>()
    .join(" / ");
    if region.is_empty() {
        escape_into(
            &format!(
                "{:.4}, {:.4}",
                snapshot.target.latitude, snapshot.target.longitude
            ),
            &mut html,
        );
    } else {
        escape_into(&region, &mut html);
    }
    html.push_str("</small></div></div>");
    if let Some(timing) = snapshot.timing {
        html.push_str("<dl class=\"impact-metrics\">");
        impact_metric(
            "预计烈度",
            &format!("{:.1}", timing.estimated_intensity),
            &mut html,
        );
        impact_metric(
            "震中距离",
            &format!("{:.1} km", timing.epicentral_distance_km),
            &mut html,
        );
        html.push_str("</dl>");
    } else {
        html.push_str("<p class=\"empty-note\">暂未提供影响估算</p>");
    }
    html.push_str("</section></div><div class=\"map-footer\"><div class=\"map-legend\"><span><i class=\"legend-dot event\"></i>事件位置</span><span><i class=\"legend-dot current\"></i>最新报告</span><span><i class=\"legend-dot target\"></i>关注地点</span></div><button id=\"map-fit-button\" class=\"map-fit-button\" type=\"button\" title=\"显示全部位置\" aria-label=\"显示全部位置\"><span class=\"fit-icon\" aria-hidden=\"true\"></span></button></div><div class=\"map-attribution\"><a href=\"https://www.openstreetmap.org/copyright\" rel=\"noreferrer\">OpenStreetMap</a> · <a href=\"https://carto.com/attributions\" rel=\"noreferrer\">CARTO</a></div></header><main class=\"detail-main\">");

    html.push_str("<section class=\"detail-band regions-band\" aria-labelledby=\"regions-heading\"><div class=\"section-heading\"><div><span class=\"section-kicker\">影响范围</span><h2 id=\"regions-heading\">可能受影响区域</h2></div>");
    if let Some(timing) = snapshot.timing {
        html.push_str("<span class=\"impact-distance\">");
        html.push_str(&format!("距离 {:.0} km", timing.epicentral_distance_km));
        html.push_str("</span>");
    }
    html.push_str("</div>");
    if !snapshot.event.affected_regions.is_empty() {
        html.push_str("<div class=\"region-focus\">");
        render_region_list(&snapshot.event.affected_regions, &mut html);
        html.push_str("</div>");
    }
    if snapshot.event.affected_regions.is_empty() {
        html.push_str("<p class=\"empty-note\">暂未划定影响区域</p>");
    }
    html.push_str("</section>");

    html.push_str("<section class=\"detail-band current-band\" aria-labelledby=\"current-heading\"><div class=\"section-heading\"><div><span class=\"section-kicker\">最新动态</span><h2 id=\"current-heading\">当前事件状态</h2></div>");
    if let Some(incident) = incident {
        html.push_str("<span class=\"source-count\">");
        html.push_str(&incident.latest_by_source.len().to_string());
        html.push_str(" 个来源</span></div><div class=\"sources\">");
        for event in &incident.latest_by_source {
            render_event(event, &mut html);
        }
        html.push_str("</div>");
    } else {
        html.push_str("</div>");
        render_snapshot_event(snapshot, &mut html);
    }
    html.push_str("</section>");

    html.push_str("<details class=\"detail-disclosure\"><summary><span>事件详情</span><small>通知时数据</small></summary><div class=\"disclosure-content\"><div class=\"section-heading\"><div><span class=\"section-kicker\">事件记录</span><h2>通知时完整信息</h2></div><span class=\"issued\">签发于 ");
    escape_into(&format_epoch_ms(snapshot.issued_at_ms), &mut html);
    html.push_str("</span></div><dl class=\"fact-grid\">");
    fact("灾害类别", snapshot.event.category.label(), &mut html);
    fact(
        "来源与报告",
        &format!(
            "{} · 第 {} 报",
            snapshot.event.source, snapshot.event.report_num
        ),
        &mut html,
    );
    fact("事件等级", &snapshot.event.level.to_string(), &mut html);
    if let Some(magnitude) = snapshot.event.magnitude {
        fact("震级", &format!("M{magnitude:.1}"), &mut html);
    }
    if let Some(depth) = snapshot.event.depth_km {
        fact("深度", &format!("{depth:.1} km"), &mut html);
    }
    if let Some(radius) = snapshot.event.radius_km {
        fact("影响半径", &format!("{radius:.0} km"), &mut html);
    }
    if let (Some(latitude), Some(longitude)) = (snapshot.event.latitude, snapshot.event.longitude) {
        fact(
            "事件位置",
            &format!("{latitude:.4}, {longitude:.4}"),
            &mut html,
        );
    }
    if let Some(incident) = incident {
        fact(
            "当前更新",
            &format_epoch_ms(incident.updated_at_ms),
            &mut html,
        );
    }
    html.push_str("</dl>");
    if !snapshot.event.description.trim().is_empty() {
        html.push_str("<div class=\"event-description\"><strong>通知时说明</strong><p>");
        escape_into(&snapshot.event.description, &mut html);
        html.push_str("</p></div>");
    }
    html.push_str("</div></details>");

    html.push_str("<details class=\"detail-disclosure\"><summary><span>预警条件</span><small>地点与订阅规则</small></summary><div class=\"disclosure-content\"><div class=\"section-heading\"><div><span class=\"section-kicker\">预警条件</span><h2>关注地点与命中规则</h2></div><span class=\"notification-level ");
    escape_into(&snapshot.interruption_level, &mut html);
    html.push_str("\">");
    escape_into(
        interruption_level_label(&snapshot.interruption_level),
        &mut html,
    );
    html.push_str(
        "</span></div><div class=\"detail-columns\"><div><h3>关注地点</h3><dl class=\"data-list\">",
    );
    row("名称", &snapshot.target.label, &mut html);
    row(
        "坐标",
        &format!(
            "{:.6}, {:.6}",
            snapshot.target.latitude, snapshot.target.longitude
        ),
        &mut html,
    );
    if !region.is_empty() {
        row("行政区", &region, &mut html);
    }
    html.push_str("</dl></div><div><h3>影响估算</h3><dl class=\"data-list\">");

    if let Some(timing) = snapshot.timing {
        row(
            "预计烈度",
            &format!("{:.2}", timing.estimated_intensity),
            &mut html,
        );
        row(
            "震中距离",
            &format!("{:.2} km", timing.epicentral_distance_km),
            &mut html,
        );
        row(
            "震源距离",
            &format!("{:.2} km", timing.hypocentral_distance_km),
            &mut html,
        );
        row(
            "P 波预计到达",
            &format_epoch_ms(timing.p_arrival_at_ms),
            &mut html,
        );
        row(
            "S 波预计到达",
            &format_epoch_ms(timing.s_arrival_at_ms),
            &mut html,
        );
        html.push_str("</dl>");
    } else {
        html.push_str("</dl><p class=\"empty-note\">暂未提供影响估算</p>");
    }
    html.push_str(
        "</div></div><div class=\"rule-block\"><h3>命中规则</h3><dl class=\"data-list rule-list\">",
    );

    render_matched_rule(&snapshot.matched_rule, &mut html);
    html.push_str("</dl></div></div></details>");

    if let Some(incident) = incident {
        html.push_str("<details class=\"detail-disclosure timeline-disclosure\"><summary><span>报告变更</span><small>最近 ");
        html.push_str(&incident.timeline.len().to_string());
        html.push_str(
            " 条</small></summary><div class=\"disclosure-content\"><ol class=\"timeline\">",
        );
        for report in incident.timeline.iter().rev() {
            render_report_summary(report, &mut html);
        }
        html.push_str("</ol></div></details>");
    }
    html.push_str("</main><script src=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.js\" integrity=\"sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=\" crossorigin=\"anonymous\"></script><script>");
    html.push_str(DETAIL_SCRIPT);
    html.push_str("</script></body></html>");
    html
}

struct MapPoint {
    role: &'static str,
    label: String,
    latitude: f64,
    longitude: f64,
}

fn collect_map_points(
    snapshot: &NotificationSnapshot,
    incident: Option<&IncidentRecord>,
) -> Vec<MapPoint> {
    let mut points =
        Vec::with_capacity(2 + incident.map_or(0, |current| current.latest_by_source.len()));
    if let (Some(latitude), Some(longitude)) = (snapshot.event.latitude, snapshot.event.longitude)
        && valid_map_coordinate(latitude, longitude)
    {
        points.push(MapPoint {
            role: "event",
            label: "事件位置".to_string(),
            latitude,
            longitude,
        });
    }
    if let Some(incident) = incident {
        for event in &incident.latest_by_source {
            if let (Some(latitude), Some(longitude)) = (event.latitude, event.longitude)
                && valid_map_coordinate(latitude, longitude)
            {
                points.push(MapPoint {
                    role: "current",
                    label: format!("最新报告 · {} 第 {} 报", event.source, event.report_num),
                    latitude,
                    longitude,
                });
            }
        }
    }
    if valid_map_coordinate(snapshot.target.latitude, snapshot.target.longitude) {
        points.push(MapPoint {
            role: "target",
            label: snapshot.target.label.clone(),
            latitude: snapshot.target.latitude,
            longitude: snapshot.target.longitude,
        });
    }
    points
}

fn valid_map_coordinate(latitude: f64, longitude: f64) -> bool {
    latitude.is_finite()
        && longitude.is_finite()
        && (-90.0..=90.0).contains(&latitude)
        && (-180.0..=180.0).contains(&longitude)
}

fn render_map_data(
    snapshot: &NotificationSnapshot,
    incident: Option<&IncidentRecord>,
    html: &mut String,
) {
    html.push_str("<div id=\"map-data\" hidden>");
    for point in collect_map_points(snapshot, incident) {
        html.push_str("<span class=\"map-point-data\" data-role=\"");
        html.push_str(point.role);
        html.push_str("\" data-label=\"");
        escape_into(&point.label, html);
        html.push_str("\" data-lat=\"");
        html.push_str(&format!("{:.8}", point.latitude));
        html.push_str("\" data-lon=\"");
        html.push_str(&format!("{:.8}", point.longitude));
        if point.role == "event"
            && let Some(radius_km) = snapshot.event.radius_km
            && radius_km.is_finite()
            && radius_km > 0.0
        {
            html.push_str("\" data-radius-km=\"");
            html.push_str(&format!("{radius_km:.3}"));
        }
        html.push_str("\"></span>");
    }
    html.push_str("</div>");
}

fn render_map_fallback(
    snapshot: &NotificationSnapshot,
    incident: Option<&IncidentRecord>,
    html: &mut String,
) {
    const MAP_LEFT: f64 = 90.0;
    const MAP_TOP: f64 = 70.0;
    const MAP_WIDTH: f64 = 820.0;
    const MAP_HEIGHT: f64 = 540.0;

    let points = collect_map_points(snapshot, incident);
    let (mut min_latitude, mut max_latitude, mut min_longitude, mut max_longitude) =
        points.first().map_or((-10.0, 10.0, -10.0, 10.0), |point| {
            (
                point.latitude,
                point.latitude,
                point.longitude,
                point.longitude,
            )
        });
    for point in &points {
        min_latitude = min_latitude.min(point.latitude);
        max_latitude = max_latitude.max(point.latitude);
        min_longitude = min_longitude.min(point.longitude);
        max_longitude = max_longitude.max(point.longitude);
    }
    let latitude_span = (max_latitude - min_latitude).max(0.5);
    let longitude_span = (max_longitude - min_longitude).max(0.5);
    let latitude_padding = latitude_span * 0.22;
    let longitude_padding = longitude_span * 0.22;
    min_latitude -= latitude_padding;
    max_latitude += latitude_padding;
    min_longitude -= longitude_padding;
    max_longitude += longitude_padding;

    let project = |point: &MapPoint| {
        let x = MAP_LEFT
            + (point.longitude - min_longitude) / (max_longitude - min_longitude) * MAP_WIDTH;
        let y =
            MAP_TOP + (max_latitude - point.latitude) / (max_latitude - min_latitude) * MAP_HEIGHT;
        (x, y)
    };

    html.push_str("<svg class=\"map-fallback\" viewBox=\"0 0 1000 700\" preserveAspectRatio=\"xMidYMid slice\" role=\"img\" aria-label=\"事件位置坐标态势图\"><defs><pattern id=\"minor-grid\" width=\"50\" height=\"50\" patternUnits=\"userSpaceOnUse\"><path d=\"M 50 0 L 0 0 0 50\" fill=\"none\" stroke=\"#b8c8c3\" stroke-width=\"1\"/></pattern><pattern id=\"major-grid\" width=\"200\" height=\"200\" patternUnits=\"userSpaceOnUse\"><rect width=\"200\" height=\"200\" fill=\"url(#minor-grid)\"/><path d=\"M 200 0 L 0 0 0 200\" fill=\"none\" stroke=\"#92aaa3\" stroke-width=\"1.5\"/></pattern><filter id=\"point-shadow\" x=\"-100%\" y=\"-100%\" width=\"300%\" height=\"300%\"><feDropShadow dx=\"0\" dy=\"3\" stdDeviation=\"4\" flood-opacity=\".25\"/></filter></defs><rect width=\"1000\" height=\"700\" fill=\"#dce7e3\"/><rect width=\"1000\" height=\"700\" fill=\"url(#major-grid)\"/><path class=\"fallback-terrain\" d=\"M0 540 C140 490 215 555 345 505 S610 420 760 480 900 475 1000 420 V700 H0Z\"/><path class=\"fallback-terrain secondary\" d=\"M0 165 C125 225 235 130 355 185 S580 250 715 165 890 180 1000 125 V0 H0Z\"/>");

    let event_point = points.iter().find(|point| point.role == "event");
    let target_point = points.iter().find(|point| point.role == "target");
    if let (Some(event), Some(target)) = (event_point, target_point) {
        let (event_x, event_y) = project(event);
        let (target_x, target_y) = project(target);
        html.push_str("<line class=\"fallback-connection\" x1=\"");
        html.push_str(&format!("{event_x:.1}"));
        html.push_str("\" y1=\"");
        html.push_str(&format!("{event_y:.1}"));
        html.push_str("\" x2=\"");
        html.push_str(&format!("{target_x:.1}"));
        html.push_str("\" y2=\"");
        html.push_str(&format!("{target_y:.1}"));
        html.push_str("\"/>");
    }
    for point in &points {
        let (x, y) = project(point);
        html.push_str("<g class=\"fallback-marker ");
        html.push_str(point.role);
        html.push_str("\" transform=\"translate(");
        html.push_str(&format!("{x:.1} {y:.1}"));
        html.push_str(")\"><circle class=\"fallback-halo\" r=\"22\"/><circle class=\"fallback-core\" r=\"9\" filter=\"url(#point-shadow)\"/><text x=\"16\" y=\"-14\">");
        escape_into(&point.label, html);
        html.push_str("</text></g>");
    }
    html.push_str("<text class=\"fallback-caption\" x=\"34\" y=\"665\">灾害位置态势</text></svg>");
}

fn hero_metric(label: &str, value: &str, primary: bool, html: &mut String) {
    html.push_str(if primary {
        "<div class=\"hero-metric primary\"><span>"
    } else {
        "<div class=\"hero-metric\"><span>"
    });
    escape_into(label, html);
    html.push_str("</span><strong>");
    escape_into(value, html);
    html.push_str("</strong></div>");
}

fn impact_metric(label: &str, value: &str, html: &mut String) {
    html.push_str("<div><dt>");
    escape_into(label, html);
    html.push_str("</dt><dd>");
    escape_into(value, html);
    html.push_str("</dd></div>");
}

fn source_metric(label: &str, value: &str, primary: bool, html: &mut String) {
    html.push_str(if primary {
        "<div class=\"source-metric primary\"><span>"
    } else {
        "<div class=\"source-metric\"><span>"
    });
    escape_into(label, html);
    html.push_str("</span><strong>");
    escape_into(value, html);
    html.push_str("</strong></div>");
}

fn render_event(event: &DisasterEvent, html: &mut String) {
    html.push_str("<article class=\"source-report\"><div class=\"article-head\"><div><span class=\"source-label\">");
    escape_into(&event.source, html);
    html.push_str("</span><h3>");
    escape_into(&event.title, html);
    html.push_str("</h3><p class=\"source-time\">");
    escape_into(&event.occurred_at, html);
    html.push_str("</p></div><div class=\"report-state\"><span>第 ");
    html.push_str(&event.report_num.to_string());
    html.push_str(" 报</span>");
    html.push_str(status_badge(event.cancel, event.final_report));
    html.push_str("</div></div><div class=\"source-vitals\">");
    if let Some(magnitude) = event.magnitude {
        source_metric("震级", &format!("M{magnitude:.1}"), true, html);
    }
    if let Some(depth) = event.depth_km {
        source_metric("深度", &format!("{depth:.1} km"), false, html);
    }
    source_metric(
        "等级",
        &event.level.to_string(),
        event.magnitude.is_none(),
        html,
    );
    html.push_str("</div>");
    render_regions(&event.affected_regions, html);
    if !event.description.is_empty() {
        html.push_str("<p class=\"report-description\">");
        escape_into(&event.description, html);
        html.push_str("</p>");
    }
    html.push_str("<details class=\"source-disclosure\"><summary>数据详情</summary><dl class=\"data-list event-data\">");
    row("灾害类别", event.category.label(), html);
    if let (Some(latitude), Some(longitude)) = (event.latitude, event.longitude) {
        row("事件位置", &format!("{latitude:.4}, {longitude:.4}"), html);
    }
    if let Some(radius) = event.radius_km {
        row("影响半径", &format!("{radius:.0} km"), html);
    }
    html.push_str("</dl></details>");
    html.push_str("</article>");
}

fn render_snapshot_event(snapshot: &NotificationSnapshot, html: &mut String) {
    html.push_str("<article class=\"source-report snapshot-report\"><div class=\"article-head\"><div><span class=\"source-label\">");
    escape_into(&snapshot.event.source, html);
    html.push_str("</span><h3>");
    escape_into(&snapshot.event.title, html);
    html.push_str("</h3><p class=\"source-time\">");
    escape_into(&snapshot.event.occurred_at, html);
    html.push_str("</p></div><div class=\"report-state\"><span>第 ");
    html.push_str(&snapshot.event.report_num.to_string());
    html.push_str(" 报</span>");
    html.push_str(status_badge(
        snapshot.event.cancel,
        snapshot.event.final_report,
    ));
    html.push_str("</div></div><div class=\"source-vitals\">");
    if let Some(magnitude) = snapshot.event.magnitude {
        source_metric("震级", &format!("M{magnitude:.1}"), true, html);
    }
    if let Some(depth) = snapshot.event.depth_km {
        source_metric("深度", &format!("{depth:.1} km"), false, html);
    }
    source_metric(
        "等级",
        &snapshot.event.level.to_string(),
        snapshot.event.magnitude.is_none(),
        html,
    );
    html.push_str("</div>");
    render_regions(&snapshot.event.affected_regions, html);
    if !snapshot.event.description.is_empty() {
        html.push_str("<p class=\"report-description\">");
        escape_into(&snapshot.event.description, html);
        html.push_str("</p>");
    }
    html.push_str("<details class=\"source-disclosure\"><summary>数据详情</summary><dl class=\"data-list event-data\">");
    row("灾害类别", snapshot.event.category.label(), html);
    if let (Some(latitude), Some(longitude)) = (snapshot.event.latitude, snapshot.event.longitude) {
        row("事件位置", &format!("{latitude:.4}, {longitude:.4}"), html);
    }
    if let Some(radius) = snapshot.event.radius_km {
        row("影响半径", &format!("{radius:.0} km"), html);
    }
    html.push_str("</dl></details>");
    html.push_str("</article>");
}

fn render_matched_rule(rule: &NotificationRuleSnapshot, html: &mut String) {
    match rule {
        NotificationRuleSnapshot::EarthquakeWarning {
            sources,
            intensity_bands,
        } => {
            row("灾害类别", "地震预警", html);
            row("来源范围", &format_sources(sources), html);
            let bands = intensity_bands
                .iter()
                .map(|band| {
                    format!(
                        "{}-{}: {}",
                        band.min,
                        band.max,
                        interruption_level_label(band.interruption_level.as_str())
                    )
                })
                .collect::<Vec<_>>()
                .join("；");
            row("烈度规则", &bands, html);
        }
        NotificationRuleSnapshot::EarthquakeReport {
            sources,
            min_magnitude,
        } => {
            row("灾害类别", "地震速报", html);
            row("来源范围", &format_sources(sources), html);
            row("最低震级", &format!("M{min_magnitude:.1}"), html);
        }
        NotificationRuleSnapshot::WeatherWarning {
            sources,
            min_severity,
            fallback_radius_km,
        } => {
            row("灾害类别", "气象预警", html);
            row("来源范围", &format_sources(sources), html);
            row("最低严重度", &min_severity.to_string(), html);
            row("坐标回退半径", &format!("{fallback_radius_km:.1} km"), html);
        }
        NotificationRuleSnapshot::Tsunami {
            sources,
            min_severity,
        } => {
            row("灾害类别", "海啸预警", html);
            row("来源范围", &format_sources(sources), html);
            row("最低严重度", &min_severity.to_string(), html);
        }
        NotificationRuleSnapshot::Typhoon {
            sources,
            max_center_distance_km,
        } => {
            row("灾害类别", "台风信息", html);
            row("来源范围", &format_sources(sources), html);
            row(
                "中心最大距离",
                &format!("{max_center_distance_km:.1} km"),
                html,
            );
        }
    }
}

fn format_sources(sources: &NotificationSourcesSnapshot) -> String {
    match sources {
        NotificationSourcesSnapshot::All => "全部来源".to_string(),
        NotificationSourcesSnapshot::Include(ids) => ids.join("、"),
    }
}

fn interruption_level_label(value: &str) -> &'static str {
    match value {
        "passive" => "静默",
        "active" => "主动",
        "critical" => "紧急",
        _ => "未知",
    }
}

fn render_report_summary(report: &IncidentReportSummary, html: &mut String) {
    html.push_str("<li><time>");
    escape_into(&format_epoch_ms(report.observed_at_ms), html);
    html.push_str("</time><div class=\"timeline-content\"><div class=\"timeline-title\"><strong>");
    escape_into(&report.source, html);
    html.push_str(" · 第 ");
    html.push_str(&report.report_num.to_string());
    html.push_str(" 报</strong>");
    html.push_str(status_badge(report.cancel, report.final_report));
    html.push_str("</div><p>");
    if let Some(magnitude) = report.magnitude {
        html.push_str(&format!("M{magnitude:.1} "));
    }
    if let Some(depth) = report.depth_km {
        html.push_str(&format!("深度{depth:.1}km "));
    }
    if let (Some(latitude), Some(longitude)) = (report.latitude, report.longitude) {
        html.push_str(&format!("{latitude:.3}, {longitude:.3} "));
    }
    html.push_str("等级 ");
    html.push_str(&report.level.to_string());
    html.push_str("</p></div></li>");
}

fn render_regions(regions: &[String], html: &mut String) {
    if regions.is_empty() {
        return;
    }
    html.push_str("<div class=\"regions\"><strong>影响区域</strong>");
    render_region_list(regions, html);
    html.push_str("</div>");
}

fn render_region_list(regions: &[String], html: &mut String) {
    html.push_str("<ul>");
    for region in regions {
        html.push_str("<li>");
        escape_into(region, html);
        html.push_str("</li>");
    }
    html.push_str("</ul>");
}

fn fact(label: &str, value: &str, html: &mut String) {
    html.push_str("<div><dt>");
    escape_into(label, html);
    html.push_str("</dt><dd>");
    escape_into(value, html);
    html.push_str("</dd></div>");
}

fn status_badge(cancel: bool, final_report: bool) -> &'static str {
    if cancel {
        "<span class=\"status cancel\">已解除</span>"
    } else if final_report {
        "<span class=\"status final\">终报</span>"
    } else {
        "<span class=\"status active\">进行中</span>"
    }
}

fn aggregate_status_badge(incident: &IncidentRecord) -> &'static str {
    let stream_count = incident.stream_watermarks.len();
    let cancelled = incident
        .stream_watermarks
        .iter()
        .filter(|stream| stream.cancel)
        .count();
    let final_reports = incident
        .stream_watermarks
        .iter()
        .filter(|stream| !stream.cancel && stream.final_report)
        .count();
    let active = stream_count
        .saturating_sub(cancelled)
        .saturating_sub(final_reports);
    if stream_count > 0 && cancelled == stream_count {
        status_badge(true, false)
    } else if stream_count > 0 && final_reports == stream_count {
        status_badge(false, true)
    } else if stream_count > 0 && active == stream_count {
        status_badge(false, false)
    } else {
        "<span class=\"status mixed\">来源状态不一致</span>"
    }
}

fn row(label: &str, value: &str, html: &mut String) {
    html.push_str("<dt>");
    escape_into(label, html);
    html.push_str("</dt><dd>");
    escape_into(value, html);
    html.push_str("</dd>");
}

fn escape_into(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
}

fn format_epoch_ms(value: i64) -> String {
    let seconds = value.div_euclid(1_000);
    let millis = value.rem_euclid(1_000);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03} UTC")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

pub(crate) fn detail_response(html: String) -> Response {
    let mut response = Html(html).into_response();
    apply_detail_headers(response.headers_mut());
    response
}

pub(crate) fn detail_not_found() -> Response {
    let mut response = detail_message_response(
        StatusCode::NOT_FOUND,
        "无法打开灾害详情",
        "请从原始灾害通知重新进入。",
    );
    apply_detail_headers(response.headers_mut());
    response
}

pub(crate) fn detail_error() -> Response {
    let mut response = detail_message_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "灾害详情加载失败",
        "请稍后重新尝试。",
    );
    apply_detail_headers(response.headers_mut());
    response
}

pub(crate) fn detail_unavailable() -> Response {
    let mut response = detail_message_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "灾害详情暂不可用",
        "当前访问较多，请稍后重试。",
    );
    apply_detail_headers(response.headers_mut());
    response
}

fn detail_message_response(status: StatusCode, title: &str, message: &str) -> Response {
    let (tone, can_retry) = match status {
        StatusCode::NOT_FOUND => ("invalid", false),
        StatusCode::SERVICE_UNAVAILABLE => ("limited", true),
        _ => ("offline", true),
    };
    let mut html = String::with_capacity(4_096);
    html.push_str("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\"><meta name=\"color-scheme\" content=\"dark\"><title>");
    escape_into(title, &mut html);
    html.push_str(" - 灾害详情</title><style>");
    html.push_str(DETAIL_STYLE);
    html.push_str("</style></head><body class=\"message-page message-");
    html.push_str(tone);
    html.push_str("\"><main class=\"message-scene\"><div class=\"message-map\" aria-hidden=\"true\"><svg viewBox=\"0 0 1440 900\" preserveAspectRatio=\"xMidYMid slice\"><defs><pattern id=\"message-grid\" width=\"64\" height=\"64\" patternUnits=\"userSpaceOnUse\"><path d=\"M64 0H0V64\"/></pattern><radialGradient id=\"hazard-zone\"><stop offset=\"0\" stop-color=\"#ee6656\" stop-opacity=\".32\"/><stop offset=\"1\" stop-color=\"#ee6656\" stop-opacity=\"0\"/></radialGradient></defs><rect width=\"1440\" height=\"900\" class=\"message-map-base\"/><rect width=\"1440\" height=\"900\" fill=\"url(#message-grid)\" class=\"message-grid\"/><g class=\"message-contours\"><path d=\"M-90 190C95 75 242 270 418 168S740 72 898 194s321 95 606-76\"/><path d=\"M-70 260C118 145 254 332 438 237S752 135 921 258s344 75 591-62\"/><path d=\"M-56 690C146 555 274 727 474 620s337-94 506 21 322 72 520-48\"/><path d=\"M-72 760C133 628 306 795 493 688s337-72 495 30 315 70 536-55\"/></g><g class=\"hazard-zone\" transform=\"translate(1060 430)\"><circle r=\"310\" fill=\"url(#hazard-zone)\"/><circle r=\"250\"/><circle r=\"170\"/><circle r=\"92\"/><path d=\"M-330 0H330M0-330V330\"/><circle class=\"hazard-core\" r=\"13\"/></g></svg></div><div class=\"message-shade\" aria-hidden=\"true\"></div><header class=\"message-topbar\"><a class=\"message-brand\" href=\"/\" aria-label=\"返回灾害态势首页\"><span class=\"brand-symbol\" aria-hidden=\"true\"></span><strong>灾害态势</strong></a></header><section class=\"message-copy\" aria-labelledby=\"message-title\"><div class=\"message-state\"><span aria-hidden=\"true\"></span>灾害详情</div><h1 id=\"message-title\">");
    escape_into(title, &mut html);
    html.push_str("</h1><p class=\"message-lead\">");
    escape_into(message, &mut html);
    html.push_str("</p><nav class=\"message-actions\" aria-label=\"详情页操作\"><a class=\"message-home\" href=\"/\">返回灾害态势<span aria-hidden=\"true\">→</span></a>");
    if can_retry {
        html.push_str("<a class=\"message-retry\" href=\"\">重新尝试</a>");
    }
    html.push_str("</nav></section></main></body></html>");
    (status, Html(html)).into_response()
}

fn apply_detail_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow, noarchive"),
    );
    let csp = DETAIL_CSP.get_or_init(|| {
        let style_digest = Sha256Hasher::digest(DETAIL_STYLE.as_bytes());
        let script_digest = Sha256Hasher::digest(DETAIL_SCRIPT.as_bytes());
        let policy = format!(
            "default-src 'none'; style-src 'none'; style-src-elem 'sha256-{}' https://unpkg.com; style-src-attr 'unsafe-inline'; script-src 'sha256-{}' https://unpkg.com; img-src data: https://*.basemaps.cartocdn.com; font-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            BASE64_STANDARD.encode(style_digest),
            BASE64_STANDARD.encode(script_digest)
        );
        HeaderValue::from_str(&policy).unwrap_or_else(|error| {
            tracing::error!(
                event = "incident.detail_csp_invalid",
                error = ?error,
                "incident.detail_csp_invalid"
            );
            HeaderValue::from_static(
                "default-src 'none'; style-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            )
        })
    });
    headers.insert("content-security-policy", csp.clone());
}

const DETAIL_STYLE: &str = r#"
:root{--ink:#17211f;--muted:#64716e;--line:#d9e1de;--paper:#f6f8f7;--panel:rgba(255,255,255,.94);--green:#176a56;--red:#df4b3f;--amber:#d49a2f;--blue:#2878c7;--shadow:0 18px 45px rgba(11,30,25,.18)}
*{box-sizing:border-box}
html{background:var(--paper)}
body{min-height:100vh;margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}
a{color:inherit}h1,h2,h3{overflow-wrap:anywhere}h1{margin:0;font-size:30px;line-height:1.2}h2{margin:0;font-size:20px;line-height:1.25}h3{margin:0 0 12px;font-size:16px;line-height:1.35}
.trust-row,.section-heading,.article-head,.timeline-title{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.trust-row{align-items:center;justify-content:flex-start;flex-wrap:wrap;font-size:13px}.section-heading{align-items:center;margin-bottom:20px}
.category,.training,.notification-level,.status{display:inline-flex;align-items:center;min-height:26px;padding:3px 9px;border-radius:4px;font-size:12px;font-weight:700;white-space:nowrap}.category{background:#e1f0ea;color:#1d6452}.training{background:#fff0ce;color:#765316}.status{border:1px solid transparent}.status.active{background:#fff0c2;color:#704d00}.status.final{background:#dcecff;color:#154c79}.status.cancel{background:#dfe8e2;color:#28583b}.status.mixed{background:#ffe1d7;color:#7a2c19}
.section-kicker{display:block;margin-bottom:4px;color:#35706a;font-size:12px;font-weight:700}.issued,.source-count{color:var(--muted);font-size:13px;text-align:right}.empty-note{margin:0;color:var(--muted);font-size:13px}
.fact-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px 20px;margin:0}.fact-grid>div{min-width:0}.fact-grid dt,.data-list dt{color:var(--muted);font-size:13px}.fact-grid dd{margin:3px 0 0;font-weight:650;overflow-wrap:anywhere}
.regions{display:flex;align-items:flex-start;gap:12px;margin-top:20px;padding-top:16px}.regions strong{flex:0 0 auto;color:#536765;font-size:13px}.regions ul{display:flex;flex-wrap:wrap;gap:6px 8px;padding:0;margin:0;list-style:none}.regions li{padding:3px 8px;border-radius:4px;background:#e7f1ed;color:#2d5c50;font-size:13px}
.event-description,.report-description{margin:18px 0 0;padding:14px 16px;border-left:3px solid #6fa997;background:#edf3f1}.event-description strong{color:#48615d;font-size:13px}.event-description p,.report-description{margin-bottom:0;white-space:pre-wrap;overflow-wrap:anywhere}
.detail-columns{display:grid;grid-template-columns:1fr 1fr;gap:24px}.detail-columns>div+div{padding-left:24px;border-left:1px solid #e3eae8}.data-list{display:grid;grid-template-columns:minmax(100px,130px) 1fr;gap:9px 14px;margin:0}.data-list dd{margin:0;overflow-wrap:anywhere}.rule-block{margin-top:24px;padding-top:20px;border-top:1px solid #e3eae8}.rule-list{grid-template-columns:minmax(110px,160px) 1fr}
.sources{display:grid}.source-report{padding:18px 0}.article-head>div:first-child{min-width:0}.source-label{display:block;color:#35706a;font-size:13px;font-weight:700}.source-report h3{margin:4px 0 0}.report-state{display:flex;align-items:flex-end;flex:0 0 auto;flex-direction:column;gap:8px;color:#60716e;font-size:13px}.event-data{margin-top:14px}.snapshot-report{padding-top:0}
.timeline{list-style:none;padding:0;margin:0}.timeline li{display:grid;grid-template-columns:180px 1fr;gap:18px;padding:16px 0}.timeline time{color:var(--muted);font-size:13px}.timeline-content{min-width:0}.timeline-title{align-items:center}.timeline-title strong{overflow-wrap:anywhere}.timeline-title .status{flex:0 0 auto}.timeline p{margin:6px 0 0;color:#596966;font-size:13px}
.detail-page{display:block;min-height:100vh;background:var(--paper);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.message-page{min-height:100vh;overflow:hidden;background:#102e2b;color:#f5f7f5}.message-scene{position:relative;isolation:isolate;display:grid;min-height:100svh;grid-template-columns:1fr;grid-template-rows:auto 1fr;overflow:hidden;padding:max(26px,env(safe-area-inset-top)) max(38px,env(safe-area-inset-right)) max(34px,env(safe-area-inset-bottom)) max(38px,env(safe-area-inset-left))}.message-map,.message-shade{position:absolute;inset:0}.message-map{z-index:-3}.message-map svg{display:block;width:100%;height:100%}.message-map-base{fill:#1f4843}.message-grid{fill-opacity:.5;stroke:#a3bdb7;stroke-width:1;stroke-opacity:.12}.message-contours{fill:none;stroke:#bad0ca;stroke-width:2;stroke-opacity:.19}.hazard-zone>circle:not(.hazard-core){fill:none;stroke:#f07767;stroke-width:2;stroke-opacity:.28}.hazard-zone>path{fill:none;stroke:#f07767;stroke-width:1.5;stroke-dasharray:10 12;stroke-opacity:.28}.hazard-zone .hazard-core{fill:#f07767;stroke:#fff;stroke-width:5;transform-box:fill-box;transform-origin:center;animation:hazard-pulse 2.5s ease-out infinite}.message-shade{z-index:-2;background:linear-gradient(90deg,rgba(7,28,25,.94) 0,rgba(8,30,27,.82) 37%,rgba(8,30,27,.28) 72%,rgba(8,30,27,.45) 100%),linear-gradient(180deg,rgba(6,23,21,.25),transparent 55%,rgba(5,23,20,.7))}.message-topbar{grid-column:1/-1;display:flex;align-items:center}.message-brand{display:inline-flex;align-items:center;gap:10px;color:#f4f8f6;text-decoration:none}.message-brand .brand-symbol{border-color:#f06b58}.message-brand .brand-symbol:before,.message-brand .brand-symbol:after{background:#f06b58}.message-brand strong{font-size:14px}.message-copy{align-self:center;max-width:640px;padding:80px 0 120px}.message-state{display:flex;align-items:center;gap:9px;color:#f5aa83;font-size:12px;font-weight:800}.message-state span{width:28px;height:2px;background:#f07767}.message-copy h1{max-width:620px;margin:18px 0 0;color:#fff;font-size:50px;line-height:1.12}.message-lead{max-width:520px;margin:20px 0 0;color:#d3dfdb;font-size:17px;line-height:1.75}.message-actions{display:flex;align-items:center;gap:24px;margin-top:34px}.message-actions a{font-size:13px;font-weight:800;text-decoration:none}.message-home{display:inline-flex;align-items:center;gap:16px;min-height:44px;padding:0 17px;border:1px solid rgba(255,255,255,.52);border-radius:4px;background:#f2f6f4;color:#173934}.message-home span{font-size:18px}.message-retry{color:#f0f5f3;border-bottom:1px solid rgba(226,236,232,.5)}@keyframes hazard-pulse{0%{opacity:1;transform:scale(.72)}70%,100%{opacity:.35;transform:scale(1.28)}}
.map-hero{position:relative;isolation:isolate;min-height:clamp(690px,86svh,900px);overflow:hidden;background:#dce7e3;color:var(--ink);border:0}
.map-stage,.incident-map,.map-fallback,.map-shade{position:absolute;inset:0;width:100%;height:100%}
.incident-map{z-index:0;background:#dce7e3;overflow:hidden}
.map-fallback{z-index:0;transition:opacity .3s ease}
.incident-map.tiles-ready>.map-fallback{opacity:0}
.fallback-terrain{fill:#c3d4cf;opacity:.72}.fallback-terrain.secondary{fill:#edf2f0;opacity:.8}.fallback-connection{stroke:#577b72;stroke-width:3;stroke-dasharray:10 8;opacity:.72}.fallback-marker .fallback-halo{fill:none;stroke-width:4;opacity:.25}.fallback-marker .fallback-core{stroke:#fff;stroke-width:4}.fallback-marker text{fill:#243b35;font-size:14px;font-weight:750;paint-order:stroke;stroke:#f5f8f7;stroke-width:4;stroke-linejoin:round}.fallback-marker.event .fallback-halo,.fallback-marker.event .fallback-core{stroke:var(--red)}.fallback-marker.event .fallback-core{fill:var(--red)}.fallback-marker.current .fallback-halo,.fallback-marker.current .fallback-core{stroke:var(--amber)}.fallback-marker.current .fallback-core{fill:var(--amber)}.fallback-marker.target .fallback-halo,.fallback-marker.target .fallback-core{stroke:var(--blue)}.fallback-marker.target .fallback-core{fill:var(--blue)}.fallback-caption{fill:#687b76;font-size:13px;font-weight:700}
.map-shade{z-index:500;pointer-events:none;background:linear-gradient(180deg,rgba(21,39,34,.24) 0,transparent 22%,transparent 60%,rgba(17,31,27,.2) 100%)}
.hero-topbar{position:absolute;z-index:700;top:max(24px,env(safe-area-inset-top));left:max(28px,env(safe-area-inset-left));right:max(28px,env(safe-area-inset-right));display:flex;align-items:center;justify-content:space-between;gap:16px;pointer-events:none}
.hero-brand{display:inline-flex;align-items:center;gap:9px;height:38px;padding:0 13px;border:1px solid rgba(255,255,255,.56);border-radius:6px;background:rgba(255,255,255,.9);box-shadow:0 8px 24px rgba(15,35,29,.12);backdrop-filter:blur(16px);color:#173b31;font-size:13px;font-weight:800}.brand-symbol{position:relative;width:18px;height:18px;border:2px solid var(--red);border-radius:50%}.brand-symbol:before,.brand-symbol:after{content:"";position:absolute;background:var(--red)}.brand-symbol:before{width:2px;height:24px;left:6px;top:-5px}.brand-symbol:after{width:24px;height:2px;left:-5px;top:6px}
.hero-layout{position:absolute;z-index:650;left:max(28px,env(safe-area-inset-left));right:max(28px,env(safe-area-inset-right));bottom:82px;display:grid;grid-template-columns:minmax(0,500px) minmax(310px,370px);align-items:end;justify-content:space-between;gap:28px;pointer-events:none}
.floating-panel{min-width:0;padding:22px;border:1px solid rgba(255,255,255,.68);border-radius:8px;background:var(--panel);box-shadow:var(--shadow);backdrop-filter:blur(18px);pointer-events:auto}
.panel-topline{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.floating-panel .trust-row{gap:7px}.floating-panel .category,.floating-panel .training,.floating-panel .notification-level,.floating-panel .status{min-height:25px;border-radius:4px;padding:3px 8px;font-size:11px}.floating-panel .category{background:#e1f0ea;color:#1d6452}.floating-panel .training{background:#fff0ce;color:#765316}.floating-panel .section-kicker{margin:17px 0 5px;color:#51716a;font-size:11px;text-transform:uppercase}.event-panel h1{max-width:100%;margin:0;color:#14201d;font-size:38px;line-height:1.12;letter-spacing:0;overflow-wrap:anywhere}.event-panel .headline-meta{margin:9px 0 0;color:#5f706c;font-size:13px;line-height:1.45}.hero-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0;margin-top:20px;border-top:1px solid #dce4e1}.hero-metric{min-width:0;padding:14px 10px 0;border-left:1px solid #dce4e1}.hero-metric:first-child{padding-left:0;border-left:0}.hero-metric span{display:block;color:#788581;font-size:11px}.hero-metric strong{display:block;margin-top:2px;color:#22302c;font-size:16px;line-height:1.3;overflow-wrap:anywhere}.hero-metric.primary strong{color:var(--red);font-size:22px}.hero-description{display:-webkit-box;margin:16px 0 0;color:#53635f;font-size:13px;line-height:1.5;overflow:hidden;-webkit-box-orient:vertical;-webkit-line-clamp:2;white-space:pre-wrap}
.impact-panel{padding:20px}.impact-panel h2{margin:3px 0 0;color:#1b2925;font-size:18px}.impact-panel .section-kicker{margin:0}.notification-level.critical{background:#fee5e2;color:#ad3128}.notification-level.active{background:#fff0c9;color:#73500d}.notification-level.passive{background:#e5edf5;color:#315978}.target-summary{display:grid;grid-template-columns:32px minmax(0,1fr);gap:11px;margin-top:18px;padding:13px 0;border-top:1px solid #dce4e1;border-bottom:1px solid #dce4e1}.target-pin{position:relative;width:28px;height:28px;border:7px solid #dcebf9;border-radius:50%;background:var(--blue);box-shadow:inset 0 0 0 4px #fff}.target-summary span,.target-summary small{display:block;color:#7a8783;font-size:11px}.target-summary strong{display:block;margin:1px 0;color:#24322e;font-size:14px;overflow-wrap:anywhere}.impact-metrics{display:grid;grid-template-columns:1fr 1fr;gap:11px 18px;margin:15px 0 0}.impact-metrics>div{min-width:0}.impact-metrics dt{color:#7a8783;font-size:11px}.impact-metrics dd{margin:2px 0 0;color:#25332f;font-size:13px;font-weight:750;overflow-wrap:anywhere}.impact-metrics>div:nth-child(n+3) dd{font-size:11px;font-weight:650}.impact-panel .empty-note{margin-top:15px}
.map-footer{position:absolute;z-index:700;left:max(28px,env(safe-area-inset-left));right:max(28px,env(safe-area-inset-right));bottom:24px;display:flex;align-items:center;justify-content:space-between;gap:16px;pointer-events:none}.map-legend{display:flex;align-items:center;gap:15px;padding:9px 12px;border:1px solid rgba(255,255,255,.56);border-radius:6px;background:rgba(255,255,255,.88);box-shadow:0 6px 18px rgba(14,35,29,.12);backdrop-filter:blur(14px);color:#485b56;font-size:11px;font-weight:700}.map-legend span{display:inline-flex;align-items:center;gap:6px}.legend-dot{display:block;width:8px;height:8px;border:2px solid #fff;border-radius:50%;box-shadow:0 0 0 1px rgba(21,42,35,.15)}.legend-dot.event{background:var(--red)}.legend-dot.current{background:var(--amber)}.legend-dot.target{background:var(--blue)}.map-fit-button{display:none;place-items:center;width:38px;height:38px;padding:0;border:1px solid rgba(255,255,255,.7);border-radius:6px;background:rgba(255,255,255,.94);box-shadow:0 6px 18px rgba(14,35,29,.16);color:#2e5148;pointer-events:auto;cursor:pointer}.map-hero.map-ready .map-fit-button{display:grid}.fit-icon{position:relative;width:17px;height:17px;background:linear-gradient(currentColor,currentColor) left top/7px 2px no-repeat,linear-gradient(currentColor,currentColor) left top/2px 7px no-repeat,linear-gradient(currentColor,currentColor) right top/7px 2px no-repeat,linear-gradient(currentColor,currentColor) right top/2px 7px no-repeat,linear-gradient(currentColor,currentColor) left bottom/7px 2px no-repeat,linear-gradient(currentColor,currentColor) left bottom/2px 7px no-repeat,linear-gradient(currentColor,currentColor) right bottom/7px 2px no-repeat,linear-gradient(currentColor,currentColor) right bottom/2px 7px no-repeat}
.map-attribution{position:absolute;z-index:700;right:max(78px,calc(env(safe-area-inset-right) + 50px));bottom:31px;color:#536962;font-size:10px}.map-attribution a{color:inherit;text-decoration:none}
.incident-map .leaflet-control-zoom{margin-right:28px;margin-top:82px;border:1px solid rgba(255,255,255,.76);border-radius:6px;box-shadow:0 8px 24px rgba(15,35,29,.14);overflow:hidden}.incident-map .leaflet-control-zoom a{display:grid;place-items:center;width:36px;height:36px;border-bottom:1px solid #dce4e1;background:rgba(255,255,255,.94);color:#24453d;font:700 18px/1 system-ui}.incident-map .leaflet-control-zoom a:last-child{border-bottom:0}.incident-marker{position:relative;display:block;width:24px;height:24px;border:6px solid rgba(255,255,255,.9);border-radius:50%;box-shadow:0 3px 12px rgba(12,32,26,.3)}.incident-marker:after{content:"";position:absolute;inset:-12px;border:3px solid currentColor;border-radius:50%;opacity:.24}.incident-marker.event{background:var(--red);color:var(--red)}.incident-marker.current{width:20px;height:20px;background:var(--amber);color:var(--amber)}.incident-marker.target{background:var(--blue);color:var(--blue)}.incident-map .leaflet-tooltip{padding:6px 8px;border:1px solid rgba(255,255,255,.75);border-radius:4px;background:rgba(255,255,255,.94);box-shadow:0 5px 16px rgba(14,34,28,.15);color:#253832;font:700 11px/1.3 system-ui}.incident-map .leaflet-tooltip:before{display:none}
.detail-main{width:min(100% - 48px,1180px);margin:0 auto;padding:34px 0 48px}.detail-page .detail-band{padding:34px 0;border:0;border-bottom:1px solid var(--line);border-radius:0;background:transparent;box-shadow:none}.detail-page .detail-band:first-child{padding-top:8px}.detail-page .detail-band:last-child{border-bottom:0}.detail-page .section-heading{margin-bottom:24px}.detail-page .section-kicker{color:#367363;font-size:11px}.detail-page .section-heading h2{font-size:22px}.detail-page .issued,.detail-page .source-count{color:var(--muted)}.detail-page .fact-grid{grid-template-columns:repeat(4,minmax(0,1fr));gap:15px}.detail-page .fact-grid>div{padding:14px;border:1px solid #e0e6e4;border-radius:6px;background:#fff}.detail-page .fact-grid dt,.detail-page .data-list dt{color:#78847f}.detail-page .regions{border-top:0}.detail-page .regions li{border:0;border-radius:4px;background:#e7f1ed;color:#2d5c50}.detail-page .event-description,.detail-page .report-description{border-left:3px solid #6fa997;border-radius:0;background:#edf3f1}.detail-page .detail-columns{gap:42px}.detail-page .detail-columns>div+div{padding-left:42px}.detail-page .rule-block{margin-top:28px}.detail-page .sources{grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:22px}.detail-page .source-report{padding:18px;border:1px solid #dfe6e3;border-radius:6px;background:#fff}.detail-page .source-report:first-child{padding-top:18px;border-top:1px solid #dfe6e3}.detail-page .source-report .regions{display:block;margin-top:15px;padding-top:0}.detail-page .source-report .regions ul{margin-top:7px}.detail-page .source-report .report-description{padding:11px 12px}.detail-page .timeline{position:relative}.detail-page .timeline:before{content:"";position:absolute;left:187px;top:5px;bottom:10px;width:1px;background:#d6e0dc}.detail-page .timeline li{position:relative;grid-template-columns:170px 1fr;gap:34px;border:0}.detail-page .timeline li:before{content:"";position:absolute;left:181px;top:23px;width:13px;height:13px;border:3px solid var(--paper);border-radius:50%;background:#5c8b7e}
@media(max-width:900px){.map-hero{min-height:840px}.event-panel h1{font-size:30px}.hero-layout{grid-template-columns:minmax(0,1.2fr) minmax(280px,.8fr);gap:16px}.hero-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.hero-metric:nth-child(3){padding-left:0;border-left:0}.detail-page .fact-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.detail-page .sources{grid-template-columns:1fr}}
@media(max-width:700px){.map-hero{min-height:1010px}.hero-topbar{top:max(14px,env(safe-area-inset-top));left:14px;right:14px}.hero-brand{height:34px;padding:0 10px}.hero-layout{left:12px;right:12px;bottom:78px;display:flex;flex-direction:column;justify-content:flex-end;gap:10px}.floating-panel{width:100%;padding:17px}.event-panel h1{font-size:25px}.event-panel .section-kicker{margin-top:13px}.hero-description{display:none}.hero-metrics{margin-top:15px}.hero-metric{padding-top:11px}.impact-panel{padding:16px}.target-summary{margin-top:13px;padding:10px 0}.impact-metrics{margin-top:12px}.map-footer{left:12px;right:12px;bottom:22px}.map-legend{gap:9px;padding:8px 9px;font-size:10px}.map-attribution{display:none}.map-shade{background:linear-gradient(180deg,rgba(17,35,29,.3),rgba(17,35,29,.03) 28%,rgba(17,31,27,.38) 100%)}.incident-map .leaflet-control-zoom{display:none}.detail-main{width:min(100% - 28px,1180px);padding-top:18px}.detail-page .detail-band{padding:27px 0}.detail-page .section-heading{display:flex;align-items:flex-start}.detail-page .detail-columns{grid-template-columns:1fr;gap:24px}.detail-page .detail-columns>div+div{padding:24px 0 0;border-left:0;border-top:1px solid var(--line)}.detail-page .timeline:before{left:5px}.detail-page .timeline li{grid-template-columns:1fr;gap:5px;padding:15px 0 15px 28px}.detail-page .timeline li:before{left:-1px;top:21px}}
@media(max-width:440px){.map-hero{min-height:1040px}.hero-brand>span:last-child{display:none}.floating-panel .panel-topline{gap:8px}.event-panel h1{font-size:23px}.hero-metric strong{font-size:14px}.hero-metric.primary strong{font-size:19px}.impact-metrics{gap:9px 12px}.map-legend span:nth-child(2){display:none}.detail-page .section-heading{display:block}.detail-page .issued,.detail-page .source-count{margin-top:7px;text-align:left}.detail-page .fact-grid{grid-template-columns:1fr 1fr;gap:9px}.detail-page .fact-grid>div{padding:11px}.detail-page .data-list,.detail-page .rule-list{grid-template-columns:1fr}.detail-page .data-list dd{margin-bottom:8px}.detail-page .article-head{display:block}.detail-page .report-state{align-items:flex-start;flex-direction:row;margin-top:10px}}
.detail-page .regions-band{padding-top:10px}.impact-distance{color:#566a65;font-size:13px;font-weight:700}.region-focus ul{display:flex;flex-wrap:wrap;gap:9px;padding:0;margin:0;list-style:none}.region-focus li{padding:8px 11px;border-left:3px solid #e15b4e;background:#fff;color:#263d37;font-size:13px;font-weight:750}.source-time{margin:5px 0 0;color:#74827e;font-size:12px}.source-vitals{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));margin-top:18px;border-top:1px solid #dfe6e3}.source-metric{min-width:0;padding:13px 12px 0;border-left:1px solid #dfe6e3}.source-metric:first-child{padding-left:0;border-left:0}.source-metric span,.source-metric strong{display:block}.source-metric span{color:#7a8783;font-size:11px}.source-metric strong{margin-top:2px;color:#263832;font-size:16px;overflow-wrap:anywhere}.source-metric.primary strong{color:#cf4339;font-size:20px}.source-disclosure{margin-top:16px;border-top:1px solid #e1e7e5}.source-disclosure summary{display:flex;align-items:center;justify-content:space-between;padding:12px 0 0;color:#536761;font-size:12px;font-weight:750;cursor:pointer;list-style:none}.source-disclosure summary::-webkit-details-marker{display:none}.source-disclosure summary:after{content:"+";color:#547169;font-size:17px;font-weight:400}.source-disclosure[open] summary:after{content:"−"}.source-disclosure .event-data{margin-top:13px;padding-top:13px;border-top:1px solid #edf1ef}.detail-disclosure{border-bottom:1px solid #d5dfdc}.detail-disclosure:first-of-type{border-top:1px solid #d5dfdc}.detail-disclosure>summary{position:relative;display:grid;grid-template-columns:minmax(0,1fr) auto 20px;align-items:center;gap:20px;min-height:76px;padding:0 4px;color:#233a34;cursor:pointer;list-style:none}.detail-disclosure>summary::-webkit-details-marker{display:none}.detail-disclosure>summary>span{font-size:17px;font-weight:800}.detail-disclosure>summary>small{color:#7b8985;font-size:12px}.detail-disclosure>summary:after{content:"+";color:#496b62;font-size:21px;font-weight:350;line-height:1}.detail-disclosure[open]>summary:after{content:"−"}.detail-disclosure[open]>summary{border-bottom:1px solid #e1e7e4}.disclosure-content{padding:28px 4px 36px}.disclosure-content .section-heading{margin-bottom:22px}.timeline-disclosure{margin-bottom:20px}
@media(max-width:700px){.region-focus li{padding:7px 9px}.source-vitals{grid-template-columns:repeat(3,minmax(0,1fr))}.detail-disclosure>summary{min-height:68px}.disclosure-content{padding:24px 0 30px}.message-scene{padding:max(20px,env(safe-area-inset-top)) max(20px,env(safe-area-inset-right)) max(24px,env(safe-area-inset-bottom)) max(20px,env(safe-area-inset-left))}.message-copy{align-self:end;padding:100px 0 64px}.message-copy h1{font-size:38px}.message-map svg{width:155%;margin-left:-42%}.message-shade{background:linear-gradient(180deg,rgba(7,28,25,.32),rgba(7,28,25,.3) 35%,rgba(6,27,24,.92) 76%)}}@media(max-width:440px){.source-report{padding:16px}.source-metric{padding-right:7px;padding-left:7px}.source-metric strong{font-size:14px}.source-metric.primary strong{font-size:18px}.detail-disclosure>summary{grid-template-columns:minmax(0,1fr) 18px;gap:10px}.detail-disclosure>summary>small{display:none}.message-brand strong{display:inline}.message-copy{padding-bottom:44px}.message-copy h1{font-size:34px}.message-actions{align-items:flex-start;flex-direction:column;gap:18px}.message-home{width:100%;justify-content:space-between}}@media(prefers-reduced-motion:reduce){.hazard-zone .hazard-core{animation:none}}
"#;

const DETAIL_SCRIPT: &str = r##"
(()=>{const container=document.querySelector("#incident-map");const data=document.querySelector("#map-data");if(!container||!data||!window.L)return;const points=[...data.querySelectorAll(".map-point-data")].map(node=>({role:node.dataset.role,label:node.dataset.label||"",lat:Number(node.dataset.lat),lon:Number(node.dataset.lon),radius:Number(node.dataset.radiusKm||0)})).filter(point=>Number.isFinite(point.lat)&&Number.isFinite(point.lon));if(!points.length)return;const map=L.map(container,{attributionControl:false,zoomControl:false,scrollWheelZoom:true,minZoom:2,maxZoom:18});container.classList.add("map-enhanced");container.closest(".map-hero")?.classList.add("map-ready");const tiles=L.tileLayer("https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png",{subdomains:"abcd",maxZoom:19,crossOrigin:true});tiles.once("load",()=>container.classList.add("tiles-ready"));tiles.addTo(map);L.control.zoom({position:"topright"}).addTo(map);const bounds=L.latLngBounds([]);let eventPoint=null;let targetPoint=null;for(const point of points){const size=point.role==="current"?20:24;const icon=L.divIcon({className:"",html:`<span class="incident-marker ${point.role}"></span>`,iconSize:[size,size],iconAnchor:[size/2,size/2]});const marker=L.marker([point.lat,point.lon],{icon,zIndexOffset:point.role==="target"?300:point.role==="event"?200:100}).addTo(map);const label=document.createElement("span");label.textContent=point.label;marker.bindTooltip(label,{direction:"top",offset:[0,-14]});bounds.extend(marker.getLatLng());if(point.role==="event"&&!eventPoint)eventPoint=point;if(point.role==="target"&&!targetPoint)targetPoint=point;if(point.role==="event"&&point.radius>0){L.circle([point.lat,point.lon],{radius:point.radius*1000,color:"#df4b3f",weight:1.5,opacity:.7,fillColor:"#df4b3f",fillOpacity:.07,interactive:false}).addTo(map);bounds.extend(L.latLng(point.lat,point.lon).toBounds(point.radius*2000))}}if(eventPoint&&targetPoint)L.polyline([[eventPoint.lat,eventPoint.lon],[targetPoint.lat,targetPoint.lon]],{color:"#3e7063",weight:2,dashArray:"7 8",opacity:.7,interactive:false}).addTo(map);const fit=()=>{if(points.length===1&&!points[0].radius){map.setView([points[0].lat,points[0].lon],7);return}map.fitBounds(bounds.pad(.2),{paddingTopLeft:[48,72],paddingBottomRight:[48,72],maxZoom:9})};fit();document.querySelector("#map-fit-button")?.addEventListener("click",fit);requestAnimationFrame(()=>map.invalidateSize())})();
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{
        NotificationEventSnapshot, NotificationIntensityBandSnapshot, NotificationTargetSnapshot,
        NotificationTimingSnapshot,
    };
    use crate::models::InterruptionLevel;
    use crate::models::{DisasterCategory, IncidentId, ProviderChannel};

    fn event(source: &str) -> DisasterEvent {
        DisasterEvent {
            category: DisasterCategory::EarthquakeWarning,
            channel: ProviderChannel::Cenc,
            source: source.to_string(),
            event_id: format!("{source}-event"),
            revision: "1".to_string(),
            report_num: 1,
            title: "<script>alert(1)</script>".to_string(),
            description: "A & B".to_string(),
            latitude: Some(35.0),
            longitude: Some(139.0),
            magnitude: Some(5.0),
            depth_km: Some(10.0),
            affected_regions: Vec::new(),
            radius_km: None,
            level: 3,
            occurred_at: "2026-07-12 12:00:00".to_string(),
            final_report: false,
            cancel: false,
            training: false,
        }
    }

    fn snapshot() -> NotificationSnapshot {
        NotificationSnapshot {
            schema_version: 1,
            incident_id: IncidentId::derive("source:event"),
            issued_at_ms: 0,
            event: NotificationEventSnapshot {
                category: DisasterCategory::EarthquakeWarning,
                source: "source".to_string(),
                source_event_id: "event".to_string(),
                revision: "1".to_string(),
                report_num: 1,
                title: "<script>alert(1)</script>".to_string(),
                description: "A & B".to_string(),
                affected_regions: vec!["<东京>".to_string()],
                latitude: Some(35.0),
                longitude: Some(139.0),
                magnitude: Some(5.0),
                depth_km: Some(10.0),
                radius_km: Some(120.0),
                level: 3,
                occurred_at: "2026-07-12 12:00:00".to_string(),
                final_report: false,
                cancel: false,
                training: false,
            },
            target: NotificationTargetSnapshot {
                label: "<住所>".to_string(),
                latitude: 35.6,
                longitude: 139.6,
                province: "东京都".to_string(),
                city: "东京".to_string(),
                district: String::new(),
            },
            timing: Some(NotificationTimingSnapshot {
                epicentral_distance_km: 50.0,
                hypocentral_distance_km: 51.0,
                estimated_intensity: 3.2,
                p_arrival_at_ms: 1_000,
                s_arrival_at_ms: 2_000,
            }),
            interruption_level: "critical".to_string(),
            matched_rule: NotificationRuleSnapshot::EarthquakeWarning {
                sources: NotificationSourcesSnapshot::All,
                intensity_bands: vec![NotificationIntensityBandSnapshot {
                    min: 3,
                    max: 7,
                    interruption_level: InterruptionLevel::Critical,
                }],
            },
        }
    }

    #[test]
    fn page_escapes_signed_and_stored_dynamic_content() {
        let snapshot = snapshot();
        let mut incident = IncidentRecord::new(snapshot.incident_id.clone(), &event("source-a"), 1);
        let mut cancelled = event("source-b");
        cancelled.cancel = true;
        assert!(incident.apply(&cancelled, 2));

        let html = render_incident_page(&snapshot, Some(&incident));

        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&lt;住所&gt;"));
        assert!(html.contains("A &amp; B"));
        assert!(html.contains("来源状态不一致"));
        assert!(html.contains("命中规则"));
        assert!(html.contains("3-7: 紧急"));
        assert!(html.contains("notification-level critical\">紧急"));
        assert!(html.contains("事件态势"));
        assert!(html.contains("关注地点"));
        assert!(html.contains("当前事件状态"));
        assert!(html.contains("报告变更"));
        assert!(html.contains("影响半径</dt><dd>120 km"));
        assert!(html.contains("<li>&lt;东京&gt;</li>"));
        assert!(html.contains("2 个来源"));
        assert_eq!(html.matches("class=\"detail-disclosure").count(), 3);
        assert!(html.contains("class=\"source-disclosure\""));
        assert!(!html.contains("<details class=\"detail-disclosure\" open"));
        assert!(!html.contains("通知快照签名有效"));
    }

    #[test]
    fn page_falls_back_to_the_verified_snapshot_after_incident_retention() {
        let html = render_incident_page(&snapshot(), None);

        assert!(html.contains("当前事件状态"));
        assert!(html.contains("影响半径</dt><dd>120 km"));
        assert!(html.contains("<span class=\"source-label\">source</span>"));
        assert!(!html.contains("<details class=\"detail-disclosure timeline-disclosure\""));
    }

    #[test]
    fn aggregate_status_uses_non_evictable_stream_watermarks() {
        let snapshot = snapshot();
        let mut active = event("source-0");
        active.final_report = false;
        let mut incident = IncidentRecord::new(snapshot.incident_id, &active, 1);
        for index in 1..=8 {
            let mut terminal = event(&format!("source-{index}"));
            terminal.final_report = true;
            assert!(incident.apply(&terminal, index + 1));
        }
        assert_eq!(incident.latest_by_source.len(), 8);
        assert_eq!(incident.stream_watermarks.len(), 9);
        assert!(aggregate_status_badge(&incident).contains("mixed"));
    }

    #[test]
    fn utc_formatter_handles_epoch_and_negative_milliseconds() {
        assert_eq!(format_epoch_ms(0), "1970-01-01 00:00:00.000 UTC");
        assert_eq!(format_epoch_ms(-1), "1969-12-31 23:59:59.999 UTC");
        assert_eq!(
            format_epoch_ms(1_783_814_400_123),
            "2026-07-12 00:00:00.123 UTC"
        );
    }

    #[test]
    fn detail_responses_apply_private_security_headers() {
        let response = detail_response("ok".to_string());
        let headers = response.headers();
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("private, no-store")
        );
        assert_eq!(
            headers
                .get(header::REFERRER_POLICY)
                .and_then(|value| value.to_str().ok()),
            Some("no-referrer")
        );
        assert_eq!(
            headers
                .get(header::PRAGMA)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        assert!(headers.get("content-security-policy").is_some_and(|value| {
            value.to_str().is_ok_and(|value| {
                value.contains("default-src 'none'") && value.contains("frame-ancestors 'none'")
            })
        }));
    }

    #[test]
    fn content_security_policy_hash_matches_the_inline_stylesheet() {
        let expected_style = format!(
            "sha256-{}",
            BASE64_STANDARD.encode(Sha256Hasher::digest(DETAIL_STYLE))
        );
        let expected_script = format!(
            "sha256-{}",
            BASE64_STANDARD.encode(Sha256Hasher::digest(DETAIL_SCRIPT))
        );
        let response = detail_response("ok".to_string());
        let policy = response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");

        assert!(policy.contains(&expected_style));
        assert!(policy.contains(&expected_script));
        assert!(policy.contains("style-src-attr 'unsafe-inline'"));
        assert!(!policy.contains("script-src 'unsafe-inline'"));
        assert!(policy.contains("https://*.basemaps.cartocdn.com"));
    }

    #[test]
    fn page_renders_map_points_and_progressive_map_assets() {
        let snapshot = snapshot();
        let incident = IncidentRecord::new(snapshot.incident_id.clone(), &event("source-a"), 1);

        let html = render_incident_page(&snapshot, Some(&incident));

        assert!(html.contains("id=\"incident-map\""));
        assert!(html.contains("class=\"map-fallback\""));
        assert!(html.contains("data-role=\"event\""));
        assert!(html.contains("data-role=\"current\""));
        assert!(html.contains("data-role=\"target\""));
        assert!(html.contains("data-radius-km=\"120.000\""));
        assert!(html.contains("leaflet@1.9.4/dist/leaflet.js"));
        assert!(html.contains("basemaps.cartocdn.com/light_all"));
        assert!(html.contains("class=\"floating-panel event-panel\""));
        assert!(html.contains("class=\"floating-panel impact-panel\""));
        assert!(html.contains("可能受影响区域"));
        assert!(html.contains("class=\"source-vitals\""));
    }

    #[tokio::test]
    async fn error_pages_are_styled_clear_and_private() -> anyhow::Result<()> {
        for (response, expected_status, expected_message) in [
            (
                detail_not_found(),
                StatusCode::NOT_FOUND,
                "无法打开灾害详情",
            ),
            (
                detail_error(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "灾害详情加载失败",
            ),
            (
                detail_unavailable(),
                StatusCode::SERVICE_UNAVAILABLE,
                "灾害详情暂不可用",
            ),
        ] {
            anyhow::ensure!(response.status() == expected_status);
            anyhow::ensure!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok())
                    == Some("private, no-store")
            );
            let body = axum::body::to_bytes(response.into_body(), 32 * 1024).await?;
            let body = std::str::from_utf8(&body)?;
            anyhow::ensure!(body.contains(DETAIL_STYLE));
            anyhow::ensure!(body.contains(expected_message));
            anyhow::ensure!(body.contains("class=\"message-scene\""));
            anyhow::ensure!(body.contains("class=\"message-map\""));
            anyhow::ensure!(body.contains("class=\"message-copy\""));
            anyhow::ensure!(body.contains("class=\"hazard-zone\""));
            anyhow::ensure!(!body.contains("私密响应"));
            anyhow::ensure!(!body.contains("详情页不会缓存"));
            anyhow::ensure!(!body.contains("DETAIL STATUS"));
            anyhow::ensure!(!body.contains("HTTP RESPONSE"));
            anyhow::ensure!(!body.contains("message-header"));
            anyhow::ensure!(!body.contains("message-panel"));
        }
        Ok(())
    }
}
