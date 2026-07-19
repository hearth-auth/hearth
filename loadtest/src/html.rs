//! Sub-millisecond Min/Max in the Goose HTML report (HEA-1788 board follow-up).
//!
//! Goose renders its **Request Metrics** table with whole-millisecond `Min (ms)`
//! and `Max (ms)` columns while the `Average (ms)` column carries two decimals.
//! At Hearth's sub-ms latencies that rounds a 0.09 ms fastest request up to `1`
//! and can make `Min` read *larger* than the average — exactly the confusion the
//! board flagged. Our [`crate::latency`] registry already measures each journey's
//! true microsecond extremes (the same figures `report.json` surfaces); this
//! module rewrites the rendered HTML so the table shows them un-rounded too.
//!
//! The rewrite is scoped to the `<div class="requests">` block and only touches
//! the two extreme cells of each nine-cell request row, so the transaction /
//! coordinated-omission / response tables and every other cell are left byte-for-
//! byte intact.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::{Captures, Regex};

use crate::latency::LatencyExtremes;

/// Formats a microsecond extreme as millimeters-of-a-second with microsecond
/// precision (three decimals) — exact for our `u64` µs samples and unit-matched
/// to the `Average (ms)` column, so a sub-ms min no longer rounds to a whole ms.
fn format_ms(us: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let ms = us as f64 / 1000.0;
    format!("{ms:.3}")
}

/// Matches one nine-cell **request-metrics** row: `<tr>` then exactly nine plain
/// `<td>…</td>` cells then `</tr>`. Transaction rows open with `<td colspan="2">`
/// and response rows carry ten cells, so neither matches — only request rows do.
fn row_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Built from adjacent literals (no backslash line-continuation, which a
        // raw string would treat as a literal `\`) to keep the pattern readable.
        let pattern = concat!(
            r"(?s)<tr>\s*<td>(?P<method>[^<]*)</td>\s*<td>(?P<name>[^<]*)</td>\s*",
            r"<td>(?P<req>[^<]*)</td>\s*<td>(?P<fail>[^<]*)</td>\s*",
            r"<td>(?P<avg>[^<]*)</td>\s*<td>(?P<min>[^<]*)</td>\s*",
            r"<td>(?P<max>[^<]*)</td>\s*<td>(?P<rps>[^<]*)</td>\s*",
            r"<td>(?P<fps>[^<]*)</td>\s*</tr>",
        );
        Regex::new(pattern).expect("static request-row regex is valid")
    })
}

/// Rewrites the `Min (ms)` / `Max (ms)` cells of every request-metrics row in the
/// Goose HTML `report` using the microsecond `latency` extremes, keyed by journey
/// name. The synthetic `Aggregated` row uses the overall min/max across all
/// journeys. Rows whose name is absent from `latency` (and the aggregate when no
/// journey was recorded) are left exactly as Goose rendered them.
///
/// Pure and total: an HTML string with no requests block is returned unchanged.
#[must_use]
pub fn rewrite_request_extremes(
    report: &str,
    latency: &HashMap<&'static str, LatencyExtremes>,
) -> String {
    // Scope the rewrite to the Request Metrics table so no other table's cells
    // can be touched, even if a future Goose layout collides with the row shape.
    let Some(start) = report.find(r#"<div class="requests">"#) else {
        return report.to_string();
    };
    let Some(rel_end) = report[start..].find("</div>") else {
        return report.to_string();
    };
    let end = start + rel_end;

    let agg = aggregate_extremes(latency);
    let region = &report[start..end];
    let rewritten = row_regex().replace_all(region, |caps: &Captures| {
        let name = &caps["name"];
        let extremes = if name == "Aggregated" {
            agg
        } else {
            latency.get(name).copied()
        };
        let (min_cell, max_cell) = match extremes {
            Some(e) => (format_ms(e.min_us), format_ms(e.max_us)),
            // Unknown journey (or empty aggregate): keep Goose's original cells.
            None => (caps["min"].to_string(), caps["max"].to_string()),
        };
        format!(
            "<tr>\n        <td>{method}</td>\n        <td>{name}</td>\n        \
             <td>{req}</td>\n        <td>{fail}</td>\n        <td>{avg}</td>\n        \
             <td>{min_cell}</td>\n        <td>{max_cell}</td>\n        <td>{rps}</td>\n        \
             <td>{fps}</td>\n    </tr>",
            method = &caps["method"],
            req = &caps["req"],
            fail = &caps["fail"],
            avg = &caps["avg"],
            rps = &caps["rps"],
            fps = &caps["fps"],
        )
    });

    format!("{}{}{}", &report[..start], rewritten, &report[end..])
}

/// Overall extremes across every recorded journey: the smallest min and largest
/// max. `None` when no journey was recorded (so the aggregate row is left as-is).
fn aggregate_extremes(latency: &HashMap<&'static str, LatencyExtremes>) -> Option<LatencyExtremes> {
    let min_us = latency.values().map(|e| e.min_us).min()?;
    let max_us = latency.values().map(|e| e.max_us).max()?;
    Some(LatencyExtremes { min_us, max_us })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal request-metrics table mirroring Goose's `raw_request_metrics_row`
    /// layout (nine plain `<td>` cells, whole-ms Min/Max, two-decimal Average).
    fn requests_html(rows: &str) -> String {
        format!(
            r#"<div class="requests">
            <h2>Request Metrics</h2>
            <table><thead><tr><th>Method</th></tr></thead><tbody>
            {rows}
            </tbody></table>
        </div>
        <div class="responses"><table><tbody>
        <tr>
        <td>POST</td>
        <td>validate</td>
        <td>1</td>
        <td>1</td>
        <td>1</td>
        <td>1</td>
        <td>1</td>
        <td>1</td>
        <td>1</td>
        <td>1</td>
    </tr>
        </tbody></table></div>"#
        )
    }

    fn row(method: &str, name: &str, min: &str, max: &str) -> String {
        format!(
            "<tr>\n        <td>{method}</td>\n        <td>{name}</td>\n        <td>100</td>\n        \
             <td>0</td>\n        <td>0.02</td>\n        <td>{min}</td>\n        <td>{max}</td>\n        \
             <td>50.00</td>\n        <td>0.00</td>\n    </tr>"
        )
    }

    #[test]
    fn min_max_are_replaced_with_submillisecond_values() {
        // Regression: Goose rounds a 90 µs fastest request to Min=1 ms and a
        // 1450 µs slowest to Max=1 ms; the rewrite must show 0.090 / 1.450.
        let html = requests_html(&row("POST", "validate", "1", "1"));
        let mut latency = HashMap::new();
        latency.insert(
            "validate",
            LatencyExtremes {
                min_us: 90,
                max_us: 1_450,
            },
        );
        let out = rewrite_request_extremes(&html, &latency);
        assert!(out.contains("<td>0.090</td>"), "min not rewritten: {out}");
        assert!(out.contains("<td>1.450</td>"), "max not rewritten: {out}");
        // The whole-ms originals are gone.
        assert!(!out.contains(&row("POST", "validate", "1", "1")));
    }

    #[test]
    fn aggregated_row_uses_overall_extremes() {
        let rows = format!(
            "{}\n{}\n{}",
            row("POST", "validate", "1", "7"),
            row("GET", "session_lookup", "1", "4"),
            row("", "Aggregated", "1", "5068"),
        );
        let html = requests_html(&rows);
        let mut latency = HashMap::new();
        latency.insert(
            "validate",
            LatencyExtremes {
                min_us: 180,
                max_us: 6_900,
            },
        );
        latency.insert(
            "session_lookup",
            LatencyExtremes {
                min_us: 420,
                max_us: 4_050,
            },
        );
        let out = rewrite_request_extremes(&html, &latency);
        // Aggregate min = min(180,420)=0.180 ms; max = max(6900,4050)=6.900 ms.
        assert!(out.contains("<td>0.180</td>"), "agg min: {out}");
        assert!(out.contains("<td>6.900</td>"), "agg max: {out}");
        // Per-journey cells rewritten too.
        assert!(out.contains("<td>4.050</td>"), "session max: {out}");
    }

    #[test]
    fn unknown_journey_keeps_goose_values() {
        // A row with no latency sample must be left byte-for-byte unchanged.
        let original = row("POST", "mystery", "3", "9");
        let html = requests_html(&original);
        let out = rewrite_request_extremes(&html, &HashMap::new());
        assert!(
            out.contains(&original),
            "unknown row must be untouched: {out}"
        );
    }

    #[test]
    fn cells_outside_the_requests_div_are_untouched() {
        // The lookalike nine-cell row in the responses div must NOT be rewritten:
        // only the requests table is in scope.
        let html = requests_html(&row("POST", "validate", "1", "1"));
        let mut latency = HashMap::new();
        latency.insert(
            "validate",
            LatencyExtremes {
                min_us: 90,
                max_us: 1_450,
            },
        );
        let out = rewrite_request_extremes(&html, &latency);
        // The responses-div block (all-`1` cells) survives intact.
        assert!(
            out.contains("<div class=\"responses\">"),
            "responses div present"
        );
        // Exactly one rewrite happened (the requests-table validate row), so the
        // sub-ms value appears once, not twice.
        assert_eq!(out.matches("<td>0.090</td>").count(), 1, "{out}");
    }

    #[test]
    fn no_requests_div_returns_input_unchanged() {
        let html = "<html><body>no metrics here</body></html>";
        let out = rewrite_request_extremes(html, &HashMap::new());
        assert_eq!(out, html);
    }

    #[test]
    fn format_ms_keeps_microsecond_precision() {
        assert_eq!(format_ms(90), "0.090");
        assert_eq!(format_ms(1_450), "1.450");
        assert_eq!(format_ms(5_068_000), "5068.000");
        assert_eq!(format_ms(0), "0.000");
    }
}
