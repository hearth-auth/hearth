//! Microsecond-resolution rewrites of the Goose HTML report (HEA-1788 board
//! follow-up).
//!
//! Goose measures every response time in **whole milliseconds** internally, so
//! its rendered tables round Hearth's sub-ms hot-path latencies out of
//! existence: the `Min (ms)` / `Max (ms)` columns of the **Request Metrics**
//! table show `1` for a 90 µs request, and every column of the **Response Time
//! Metrics** percentile table collapses to `1`. Our [`crate::latency`] registry
//! measures each journey at microsecond resolution (min/max *and* a histogram),
//! and these functions rewrite the rendered HTML so both tables show the real
//! figures.
//!
//! Each rewrite is scoped to the specific `<table>` inside its section `<div>`
//! (found by locating the first `<table>` after the section marker and its
//! closing `</table>`), so the echarts `<script>` blocks and every other table —
//! transactions, scenarios, status codes — are left byte-for-byte intact.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::{Captures, Regex};

use crate::latency::{LatencyExtremes, LatencyPercentiles, PercentileSnapshot};

/// Formats a microsecond value as milliseconds with microsecond precision (three
/// decimals) — exact for our `u64` µs samples and unit-matched to the report's
/// `(ms)` columns, so a sub-ms figure no longer rounds to a whole ms.
fn format_ms(us: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let ms = us as f64 / 1000.0;
    format!("{ms:.3}")
}

/// Byte range of the first `<table>…</table>` inside the section `<div
/// class="{div_class}">`. Goose nests an echarts `<div class="graph">` (with its
/// own `</div>`) *before* the metrics table, so scoping by the first `</div>`
/// after the section marker stops short of the table — this scopes to the table
/// itself instead. `None` if the section or its table is absent.
fn table_region(report: &str, div_class: &str) -> Option<(usize, usize)> {
    let marker = format!(r#"<div class="{div_class}">"#);
    let div = report.find(&marker)?;
    let after = div + marker.len();
    let table_start = after + report[after..].find("<table>")?;
    let table_end = table_start + report[table_start..].find("</table>")? + "</table>".len();
    Some((table_start, table_end))
}

/// Matches one nine-cell **request-metrics** row: `<tr>` then exactly nine plain
/// `<td>…</td>` cells then `</tr>`. Transaction rows open with `<td colspan="2">`
/// and response rows carry ten cells, so neither matches — only request rows do.
fn request_row_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
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

/// Matches one ten-cell **response-time (percentile)** row: `<tr>`, a method and
/// name cell, then eight percentile cells (50/60/70/80/90/95/99/100), then
/// `</tr>`. Nine-cell request rows and `colspan` transaction rows do not match.
fn percentile_row_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let pattern = concat!(
            r"(?s)<tr>\s*<td>(?P<method>[^<]*)</td>\s*<td>(?P<name>[^<]*)</td>\s*",
            r"<td>(?P<p50>[^<]*)</td>\s*<td>(?P<p60>[^<]*)</td>\s*<td>(?P<p70>[^<]*)</td>\s*",
            r"<td>(?P<p80>[^<]*)</td>\s*<td>(?P<p90>[^<]*)</td>\s*<td>(?P<p95>[^<]*)</td>\s*",
            r"<td>(?P<p99>[^<]*)</td>\s*<td>(?P<p100>[^<]*)</td>\s*</tr>",
        );
        Regex::new(pattern).expect("static percentile-row regex is valid")
    })
}

/// Rewrites the `Min (ms)` / `Max (ms)` cells of every request-metrics row in the
/// Goose HTML `report` using the microsecond `latency` extremes, keyed by journey
/// name. The synthetic `Aggregated` row uses the overall min/max across all
/// journeys. Rows whose name is absent from `latency` (and the aggregate when no
/// journey was recorded) are left exactly as Goose rendered them.
///
/// Pure and total: an HTML string with no requests table is returned unchanged.
#[must_use]
pub fn rewrite_request_extremes(
    report: &str,
    latency: &HashMap<&'static str, LatencyExtremes>,
) -> String {
    let Some((start, end)) = table_region(report, "requests") else {
        return report.to_string();
    };
    let agg = aggregate_extremes(latency);
    let rewritten = request_row_regex().replace_all(&report[start..end], |caps: &Captures| {
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

/// Rewrites every percentile cell (50/60/70/80/90/95/99/100) of the Response Time
/// Metrics table using the microsecond `percentiles` snapshot, keyed by journey
/// name; the `Aggregated` row uses the merged aggregate. Rows with no recorded
/// percentiles (unknown journey, or the aggregate when nothing was recorded) are
/// left exactly as Goose rendered them.
///
/// Pure and total: an HTML string with no responses table is returned unchanged.
#[must_use]
pub fn rewrite_response_percentiles(report: &str, percentiles: &PercentileSnapshot) -> String {
    let Some((start, end)) = table_region(report, "responses") else {
        return report.to_string();
    };
    let rewritten = percentile_row_regex().replace_all(&report[start..end], |caps: &Captures| {
        let name = &caps["name"];
        let pct = if name == "Aggregated" {
            percentiles.aggregate
        } else {
            percentiles.per_journey.get(name).copied()
        };
        match pct {
            Some(p) => format_percentile_row(&caps["method"], name, p),
            // Unknown journey (or empty aggregate): keep Goose's original cells.
            None => caps[0].to_string(),
        }
    });
    format!("{}{}{}", &report[..start], rewritten, &report[end..])
}

/// Matches the Goose report's overview `<p>Users: <span>N</span></p>` line — the
/// single most-prominent number at the top of the report. `N` is the Goose
/// *load-generator concurrency* (`--users`), which readers repeatedly misread as
/// "N users were seeded" (the board's recurring "why 200 users?" complaint). The
/// capture lets us relabel it and, when known, state the resident corpus.
fn users_line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)<p>Users:\s*<span>(?P<n>\d+)</span>\s*</p>")
            .expect("static users-line regex is valid")
    })
}

/// Relabels the Goose overview's `<p>Users: <span>N</span></p>` line so the
/// most-visible number in the report can no longer be misread as the seeded
/// population: `N` is the **load-generator concurrency** (`--users`), not the
/// corpus. When `resident_corpus_size` is known it is stated alongside, making
/// the seeded-accounts-under-test count equally prominent (HEA-1788 board
/// follow-up — "it's still saying 200 users").
///
/// Pure and total: an HTML string with no such line is returned unchanged.
#[must_use]
pub fn rewrite_users_label(report: &str, resident_corpus_size: Option<u64>) -> String {
    users_line_regex()
        .replace(report, |caps: &Captures| {
            let n = &caps["n"];
            match resident_corpus_size {
                Some(size) => format!(
                    "<p>Load-generator users (concurrency): <span>{n}</span> \
                     &mdash; resident corpus under test: <span>{}</span> seeded accounts</p>",
                    group_thousands(size),
                ),
                None => {
                    format!("<p>Load-generator users (concurrency): <span>{n}</span></p>")
                }
            }
        })
        .into_owned()
}

/// Matches the Goose report's dedicated `<div class="users">` section heading
/// `<h2>User Metrics</h2>`. Goose plots **load-generator concurrency** here — the
/// number of active `--users` over the run, whose graph peaks at the configured
/// concurrency (e.g. 200) — under a heading that reads as the seeded population.
/// This is the section the board keeps reporting as "still showing 200 users":
/// the earlier fix only relabeled the top-of-report overview line, not this one.
/// The capture preserves the opening `<div>` so only the heading is rewritten.
fn user_metrics_heading_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)(?P<pre><div class="users">\s*)<h2>User Metrics</h2>"#)
            .expect("static user-metrics-heading regex is valid")
    })
}

/// Relabels the Goose `User Metrics` section heading (the `<div class="users">`
/// block) so its graph — which peaks at the load-generator concurrency
/// (`--users`) — can no longer be misread as the seeded population, and inserts a
/// clarifying note. When `resident_corpus_size` is known the seeded-accounts
/// count is stated alongside (HEA-1788 board follow-up — "the User Metrics
/// section is still showing 200 users"). The echarts graph itself is untouched:
/// its concurrency-over-time data is correct.
///
/// Pure and total: an HTML string with no such section is returned unchanged.
#[must_use]
pub fn rewrite_user_metrics_label(report: &str, resident_corpus_size: Option<u64>) -> String {
    user_metrics_heading_regex()
        .replace(report, |caps: &Captures| {
            let pre = &caps["pre"];
            let note = match resident_corpus_size {
                Some(size) => format!(
                    "<p>Active load-generator users (concurrency) over time &mdash; this graph \
                     peaks at the configured <code>--users</code> value, <strong>not</strong> the \
                     seeded population. Resident corpus under test: <span>{}</span> seeded \
                     accounts.</p>",
                    group_thousands(size),
                ),
                None => {
                    "<p>Active load-generator users (concurrency) over time &mdash; this graph \
                         peaks at the configured <code>--users</code> value, <strong>not</strong> \
                         the seeded population.</p>"
                        .to_string()
                }
            };
            format!("{pre}<h2>Load-generator concurrency (active users)</h2>\n            {note}")
        })
        .into_owned()
}

/// Formats an integer with comma thousands separators (e.g. `1200000` →
/// `"1,200,000"`) so a seven-figure corpus reads clearly in the report header.
fn group_thousands(n: u64) -> String {
    let digits = n.to_string();
    let bytes = digits.as_bytes();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// Renders a ten-cell percentile row with our microsecond figures formatted as
/// milliseconds, matching Goose's cell layout.
fn format_percentile_row(method: &str, name: &str, p: LatencyPercentiles) -> String {
    format!(
        "<tr>\n            <td>{method}</td>\n            <td>{name}</td>\n            \
         <td>{p50}</td>\n            <td>{p60}</td>\n            <td>{p70}</td>\n            \
         <td>{p80}</td>\n            <td>{p90}</td>\n            <td>{p95}</td>\n            \
         <td>{p99}</td>\n            <td>{p100}</td>\n        </tr>",
        p50 = format_ms(p.p50_us),
        p60 = format_ms(p.p60_us),
        p70 = format_ms(p.p70_us),
        p80 = format_ms(p.p80_us),
        p90 = format_ms(p.p90_us),
        p95 = format_ms(p.p95_us),
        p99 = format_ms(p.p99_us),
        p100 = format_ms(p.p100_us),
    )
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

    /// Full Goose section layout: a nested echarts `<div class="graph">` (with its
    /// own `<div id=…></div>` and `<script>`) precedes the metrics table — the
    /// exact structure whose stray `</div>` defeated the earlier scoping.
    fn requests_html(rows: &str) -> String {
        format!(
            r#"<div class="requests">
            <h2>Request Metrics</h2>
            <div class="graph">
                <div id="graph-rps" style="width: 1000px; height:500px; background: white;"></div>
                <script type="text/javascript">var x = [["a",1]];</script>
            </div>
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

    /// Response section with the nested graph div and a ten-cell percentile row.
    fn responses_html(rows: &str) -> String {
        format!(
            r#"<div class="responses">
            <h2>Response Time Metrics</h2>
            <div class="graph">
                <div id="graph-avg-response-time"></div>
                <script>var d = [["t",1.5]];</script>
            </div>
            <table><thead><tr><th>Method</th></tr></thead><tbody>
            {rows}
            </tbody></table>
        </div>"#
        )
    }

    fn request_row(method: &str, name: &str, min: &str, max: &str) -> String {
        format!(
            "<tr>\n        <td>{method}</td>\n        <td>{name}</td>\n        <td>100</td>\n        \
             <td>0</td>\n        <td>0.02</td>\n        <td>{min}</td>\n        <td>{max}</td>\n        \
             <td>50.00</td>\n        <td>0.00</td>\n    </tr>"
        )
    }

    fn percentile_row(method: &str, name: &str, cells: [&str; 8]) -> String {
        format!(
            "<tr>\n            <td>{method}</td>\n            <td>{name}</td>\n            \
             <td>{}</td>\n            <td>{}</td>\n            <td>{}</td>\n            \
             <td>{}</td>\n            <td>{}</td>\n            <td>{}</td>\n            \
             <td>{}</td>\n            <td>{}</td>\n        </tr>",
            cells[0], cells[1], cells[2], cells[3], cells[4], cells[5], cells[6], cells[7],
        )
    }

    fn pct(v: u64) -> LatencyPercentiles {
        LatencyPercentiles {
            p50_us: v,
            p60_us: v,
            p70_us: v,
            p80_us: v,
            p90_us: v,
            p95_us: v,
            p99_us: v,
            p100_us: v,
        }
    }

    #[test]
    fn min_max_are_replaced_with_submillisecond_values() {
        // Regression: Goose rounds a 90 µs fastest request to Min=1 ms and a
        // 1450 µs slowest to Max=1 ms; the rewrite must show 0.090 / 1.450 —
        // and it must survive the nested graph div that broke the old scoping.
        let html = requests_html(&request_row("POST", "validate", "1", "1"));
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
        assert!(!out.contains(&request_row("POST", "validate", "1", "1")));
    }

    #[test]
    fn aggregated_row_uses_overall_extremes() {
        let rows = format!(
            "{}\n{}\n{}",
            request_row("POST", "validate", "1", "7"),
            request_row("GET", "session_lookup", "1", "4"),
            request_row("", "Aggregated", "1", "5068"),
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
        assert!(out.contains("<td>0.180</td>"), "agg min: {out}");
        assert!(out.contains("<td>6.900</td>"), "agg max: {out}");
        assert!(out.contains("<td>4.050</td>"), "session max: {out}");
    }

    #[test]
    fn unknown_journey_keeps_goose_values() {
        let original = request_row("POST", "mystery", "3", "9");
        let html = requests_html(&original);
        let out = rewrite_request_extremes(&html, &HashMap::new());
        assert!(
            out.contains(&original),
            "unknown row must be untouched: {out}"
        );
    }

    #[test]
    fn request_rewrite_ignores_the_responses_table() {
        // The lookalike nine-cell row in the responses div must NOT be rewritten:
        // scoping is confined to the requests table.
        let html = requests_html(&request_row("POST", "validate", "1", "1"));
        let mut latency = HashMap::new();
        latency.insert(
            "validate",
            LatencyExtremes {
                min_us: 90,
                max_us: 1_450,
            },
        );
        let out = rewrite_request_extremes(&html, &latency);
        assert_eq!(out.matches("<td>0.090</td>").count(), 1, "{out}");
    }

    #[test]
    fn no_requests_table_returns_input_unchanged() {
        let html = "<html><body>no metrics here</body></html>";
        assert_eq!(rewrite_request_extremes(html, &HashMap::new()), html);
    }

    #[test]
    fn percentiles_are_replaced_with_submillisecond_values() {
        // Regression (board follow-up): Goose renders a sub-ms journey's whole
        // percentile row as `1`; the rewrite must show real µs figures.
        let html = responses_html(&percentile_row(
            "GET",
            "session_lookup",
            ["1", "1", "1", "1", "1", "1", "1", "4"],
        ));
        let mut snap = PercentileSnapshot {
            per_journey: HashMap::new(),
            aggregate: None,
        };
        snap.per_journey.insert(
            "session_lookup",
            LatencyPercentiles {
                p50_us: 12,
                p60_us: 15,
                p70_us: 18,
                p80_us: 24,
                p90_us: 40,
                p95_us: 60,
                p99_us: 120,
                p100_us: 4_000,
            },
        );
        let out = rewrite_response_percentiles(&html, &snap);
        assert!(out.contains("<td>0.012</td>"), "p50 not rewritten: {out}");
        assert!(out.contains("<td>0.120</td>"), "p99 not rewritten: {out}");
        assert!(out.contains("<td>4.000</td>"), "p100 not rewritten: {out}");
        // The flat all-`1` row is gone.
        assert!(!out.contains(&percentile_row(
            "GET",
            "session_lookup",
            ["1", "1", "1", "1", "1", "1", "1", "4"]
        )));
    }

    #[test]
    fn percentile_aggregated_row_uses_aggregate() {
        let html = responses_html(&percentile_row(
            "",
            "Aggregated",
            ["1", "1", "1", "1", "370", "1,000", "2,000", "5,000"],
        ));
        let snap = PercentileSnapshot {
            per_journey: HashMap::new(),
            aggregate: Some(pct(2_500)),
        };
        let out = rewrite_response_percentiles(&html, &snap);
        assert!(out.contains("<td>2.500</td>"), "aggregate row: {out}");
        assert!(
            !out.contains("<td>1,000</td>"),
            "goose comma value gone: {out}"
        );
    }

    #[test]
    fn percentile_unknown_journey_is_untouched() {
        let original = percentile_row("POST", "mystery", ["1", "2", "3", "4", "5", "6", "7", "8"]);
        let html = responses_html(&original);
        let snap = PercentileSnapshot {
            per_journey: HashMap::new(),
            aggregate: None,
        };
        let out = rewrite_response_percentiles(&html, &snap);
        assert!(
            out.contains(&original),
            "unknown row must be untouched: {out}"
        );
    }

    #[test]
    fn no_responses_table_returns_input_unchanged() {
        let html = "<html><body>nothing here</body></html>";
        let snap = PercentileSnapshot {
            per_journey: HashMap::new(),
            aggregate: None,
        };
        assert_eq!(rewrite_response_percentiles(html, &snap), html);
    }

    #[test]
    fn format_ms_keeps_microsecond_precision() {
        assert_eq!(format_ms(90), "0.090");
        assert_eq!(format_ms(1_450), "1.450");
        assert_eq!(format_ms(5_068_000), "5068.000");
        assert_eq!(format_ms(0), "0.000");
    }

    #[test]
    fn group_thousands_separates_every_three_digits() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(200), "200");
        assert_eq!(group_thousands(1_000), "1,000");
        assert_eq!(group_thousands(1_200_000), "1,200,000");
        assert_eq!(group_thousands(12_345_678), "12,345,678");
    }

    /// The Goose overview line as rendered at the top of every report.
    fn overview_users_line(n: &str) -> String {
        format!("        <div class=\"info\">\n            <p>Users: <span>{n}</span> </p>\n")
    }

    #[test]
    fn users_label_relabels_and_states_resident_corpus() {
        let html = overview_users_line("200");
        let out = rewrite_users_label(&html, Some(1_200_000));
        // The bare "Users: 200" that reads as a seeded population is gone.
        assert!(
            !out.contains("<p>Users: <span>200</span>"),
            "bare Users line must be relabeled: {out}"
        );
        assert!(
            out.contains("Load-generator users (concurrency): <span>200</span>"),
            "concurrency relabel missing: {out}"
        );
        assert!(
            out.contains("resident corpus under test: <span>1,200,000</span> seeded accounts"),
            "resident corpus not surfaced: {out}"
        );
    }

    #[test]
    fn users_label_relabels_without_corpus_when_unknown() {
        let html = overview_users_line("200");
        let out = rewrite_users_label(&html, None);
        assert!(
            out.contains("Load-generator users (concurrency): <span>200</span></p>"),
            "concurrency relabel missing: {out}"
        );
        assert!(
            !out.contains("resident corpus"),
            "no corpus clause when size unknown: {out}"
        );
    }

    #[test]
    fn users_label_no_line_returns_input_unchanged() {
        let html = "<html><body>no overview here</body></html>";
        assert_eq!(rewrite_users_label(html, Some(999)), html);
    }

    /// The Goose `User Metrics` section as rendered (heading + echarts graph div).
    fn user_metrics_section(graph: &str) -> String {
        format!(
            "        <div class=\"users\">\n        <h2>User Metrics</h2>\n            {graph}\n        </div>"
        )
    }

    #[test]
    fn user_metrics_heading_relabeled_and_states_corpus() {
        // Regression (board follow-up): the "User Metrics" section — whose graph
        // peaks at the --users concurrency — kept reading as "200 users".
        let graph = r#"<div class="graph"><div id="graph-users"></div><script>var u=[["t",200]];</script></div>"#;
        let html = user_metrics_section(graph);
        let out = rewrite_user_metrics_label(&html, Some(1_200_000));
        // The bare "User Metrics" heading that reads as a seeded population is gone.
        assert!(
            !out.contains("<h2>User Metrics</h2>"),
            "User Metrics heading must be relabeled: {out}"
        );
        assert!(
            out.contains("<h2>Load-generator concurrency (active users)</h2>"),
            "concurrency relabel missing: {out}"
        );
        assert!(
            out.contains("Resident corpus under test: <span>1,200,000</span> seeded accounts"),
            "resident corpus not surfaced: {out}"
        );
        // The echarts graph is left byte-for-byte intact.
        assert!(out.contains(graph), "graph must be untouched: {out}");
    }

    #[test]
    fn user_metrics_heading_relabeled_without_corpus_when_unknown() {
        let graph = r#"<div class="graph"><div id="graph-users"></div></div>"#;
        let html = user_metrics_section(graph);
        let out = rewrite_user_metrics_label(&html, None);
        assert!(
            out.contains("<h2>Load-generator concurrency (active users)</h2>"),
            "concurrency relabel missing: {out}"
        );
        assert!(
            !out.contains("Resident corpus"),
            "no corpus clause when size unknown: {out}"
        );
        assert!(out.contains(graph), "graph must be untouched: {out}");
    }

    #[test]
    fn user_metrics_no_section_returns_input_unchanged() {
        let html = "<html><body>no user metrics section</body></html>";
        assert_eq!(rewrite_user_metrics_label(html, Some(999)), html);
    }
}
