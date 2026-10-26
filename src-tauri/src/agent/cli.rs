//! `wbm`: argument parsing and output. Every command becomes one call into
//! [`super::tools`], the same table the MCP server serves, so the two cannot disagree.
//!
//! Exit codes: 0 ok, 1 failed, 2 bad usage, 3 no database, 4 unsupported database, 5 not found.
//! With `--json` the result (or `{"error": {"code", "message"}}`) goes to stdout and nothing
//! else is printed there.

use super::tools::{self, Access};
use super::{default_db_path, mcp, AgentError, Ctx};
use serde_json::{json, Map, Value};
use std::io::Write;
use std::path::PathBuf;

pub const HELP: &str = "\
wbm - read the Wi-Fi Bluetooth Monitor's data and make a few safe edits

USAGE
  wbm [--db PATH] [--json] <command> [options]

READ
  status                         is the app running, how fresh, permissions, network, counts
  alerts [--since 24h] [--all] [--limit N]
  networks [--limit N]           Wi-Fi access points in the latest stored scan
  ble [--trackers] [--limit N]   Bluetooth LE devices in the latest stored scan
  devices [--network KEY] [--limit N]   remembered LAN devices
  places                         remembered places
  history [--since 6h] [--full] [--limit N]
  mine list | trusted list | watchlist list

EDIT (the only things wbm can change)
  alert dismiss ID
  mine add KIND HASH [--label TEXT]      KIND: wifiAp wifiGroup ble lan; HASH from a read command
  mine remove KIND HASH
  trusted add SSID [--security MODE]
  trusted remove SSID
  watchlist add ssid|vendor PATTERN [--match exact|contains]
  watchlist remove ID

OTHER
  mcp                            serve these tools over MCP on stdio
  tools                          list the tools (same list MCP serves)
  help, --version

OPTIONS
  --json     machine-readable output with stable field names (docs/agents.md)
  --db PATH  database file (default: ~/Library/Application Support/com.anomali007.wifibtmonitor/store.sqlite3)

wbm never scans, never sweeps and never changes a setting. Those are done in the app.

EXIT CODES  0 ok, 1 failed, 2 bad usage, 3 no database, 4 unsupported database, 5 not found
";

/// Leftover tokens for one command, consumed as they are used.
struct Rest(Vec<String>);

impl Rest {
    fn flag(&mut self, name: &str) -> Result<Option<String>, AgentError> {
        let Some(i) = self.0.iter().position(|t| t == name) else {
            return Ok(None);
        };
        if i + 1 >= self.0.len() || self.0[i + 1].starts_with("--") {
            return Err(AgentError::Usage(format!("{name} needs a value")));
        }
        let v = self.0.remove(i + 1);
        self.0.remove(i);
        Ok(Some(v))
    }

    fn switch(&mut self, name: &str) -> bool {
        match self.0.iter().position(|t| t == name) {
            Some(i) => {
                self.0.remove(i);
                true
            }
            None => false,
        }
    }

    fn limit(&mut self) -> Result<Option<i64>, AgentError> {
        self.flag("--limit")?
            .map(|v| {
                v.parse::<i64>()
                    .map_err(|_| AgentError::Usage("--limit must be a number".into()))
            })
            .transpose()
    }

    /// Take exactly `n` positional words; anything else left over is a usage error.
    fn words(mut self, n: usize, what: &str) -> Result<Vec<String>, AgentError> {
        if let Some(f) = self.0.iter().find(|t| t.starts_with("--")) {
            return Err(AgentError::Usage(format!("unknown option {f}")));
        }
        if self.0.len() != n {
            return Err(AgentError::Usage(format!("expected {what}")));
        }
        Ok(std::mem::take(&mut self.0))
    }
}

fn put(args: &mut Map<String, Value>, k: &str, v: Option<impl Into<Value>>) {
    if let Some(v) = v {
        args.insert(k.into(), v.into());
    }
}

/// Turn the command words into (tool name, arguments).
fn parse_command(words: Vec<String>) -> Result<(&'static str, Value), AgentError> {
    let mut it = words.into_iter();
    let cmd = it
        .next()
        .ok_or_else(|| AgentError::Usage("no command given; try `wbm help`".into()))?;
    let mut rest = Rest(it.collect());
    let mut a = Map::new();
    let tool: &'static str = match cmd.as_str() {
        "status" => {
            rest.words(0, "no arguments")?;
            "status"
        }
        "alerts" => {
            put(&mut a, "since", rest.flag("--since")?);
            if rest.switch("--all") {
                a.insert("includeDismissed".into(), json!(true));
            }
            put(&mut a, "limit", rest.limit()?);
            rest.words(0, "no positional arguments")?;
            "alerts"
        }
        "alert" => {
            let sub = pop(&mut rest, "alert dismiss ID")?;
            if sub != "dismiss" {
                return Err(AgentError::Usage(format!("unknown subcommand alert {sub}")));
            }
            let w = rest.words(1, "alert dismiss ID")?;
            a.insert("id".into(), json!(w[0]));
            "dismiss_alert"
        }
        "networks" => {
            put(&mut a, "limit", rest.limit()?);
            rest.words(0, "no positional arguments")?;
            "networks"
        }
        "ble" => {
            if rest.switch("--trackers") {
                a.insert("trackersOnly".into(), json!(true));
            }
            put(&mut a, "limit", rest.limit()?);
            rest.words(0, "no positional arguments")?;
            "ble"
        }
        "devices" => {
            put(&mut a, "networkKey", rest.flag("--network")?);
            put(&mut a, "limit", rest.limit()?);
            rest.words(0, "no positional arguments")?;
            "lan_devices"
        }
        "places" => {
            rest.words(0, "no arguments")?;
            "places"
        }
        "history" => {
            put(&mut a, "since", rest.flag("--since")?);
            if rest.switch("--full") {
                a.insert("full".into(), json!(true));
            }
            put(&mut a, "limit", rest.limit()?);
            rest.words(0, "no positional arguments")?;
            "history"
        }
        "mine" => match pop(&mut rest, "mine list|add|remove")?.as_str() {
            "list" => {
                rest.words(0, "mine list")?;
                "mine_list"
            }
            "add" => {
                put(&mut a, "label", rest.flag("--label")?);
                let w = rest.words(2, "mine add KIND HASH")?;
                a.insert("kind".into(), json!(w[0]));
                a.insert("idHash".into(), json!(w[1]));
                "mine_add"
            }
            "remove" => {
                let w = rest.words(2, "mine remove KIND HASH")?;
                a.insert("kind".into(), json!(w[0]));
                a.insert("idHash".into(), json!(w[1]));
                "mine_remove"
            }
            other => {
                return Err(AgentError::Usage(format!(
                    "unknown subcommand mine {other}"
                )))
            }
        },
        "trusted" => match pop(&mut rest, "trusted list|add|remove")?.as_str() {
            "list" => {
                rest.words(0, "trusted list")?;
                "trusted_list"
            }
            "add" => {
                put(&mut a, "security", rest.flag("--security")?);
                let w = rest.words(1, "trusted add SSID")?;
                a.insert("ssid".into(), json!(w[0]));
                "trusted_add"
            }
            "remove" => {
                let w = rest.words(1, "trusted remove SSID")?;
                a.insert("ssid".into(), json!(w[0]));
                "trusted_remove"
            }
            other => {
                return Err(AgentError::Usage(format!(
                    "unknown subcommand trusted {other}"
                )))
            }
        },
        "watchlist" => match pop(&mut rest, "watchlist list|add|remove")?.as_str() {
            "list" => {
                rest.words(0, "watchlist list")?;
                "watchlist_list"
            }
            "add" => {
                put(&mut a, "match", rest.flag("--match")?);
                let w = rest.words(2, "watchlist add ssid|vendor PATTERN")?;
                a.insert("kind".into(), json!(w[0]));
                a.insert("pattern".into(), json!(w[1]));
                "watchlist_add"
            }
            "remove" => {
                let w = rest.words(1, "watchlist remove ID")?;
                let id: i64 = w[0]
                    .parse()
                    .map_err(|_| AgentError::Usage("ID must be a number".into()))?;
                a.insert("id".into(), json!(id));
                "watchlist_remove"
            }
            other => {
                return Err(AgentError::Usage(format!(
                    "unknown subcommand watchlist {other}"
                )))
            }
        },
        other => {
            return Err(AgentError::Usage(format!(
                "unknown command {other:?}; try `wbm help`"
            )))
        }
    };
    Ok((tool, Value::Object(a)))
}

fn pop(rest: &mut Rest, what: &str) -> Result<String, AgentError> {
    if rest.0.is_empty() {
        return Err(AgentError::Usage(format!("expected {what}")));
    }
    Ok(rest.0.remove(0))
}

/// Run `wbm`. Returns the process exit code. `default_db` is used when `--db` is absent.
pub fn run(
    args: &[String],
    default_db: Option<PathBuf>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let mut json_out = false;
    let mut db: Option<PathBuf> = None;
    let mut words: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_out = true,
            "--db" => {
                i += 1;
                match args.get(i) {
                    Some(p) if !p.starts_with("--") => db = Some(PathBuf::from(p)),
                    _ => {
                        return fail(
                            json_out,
                            &AgentError::Usage("--db needs a path".into()),
                            out,
                            err,
                        )
                    }
                }
            }
            "--help" | "-h" | "help" if words.is_empty() => {
                let _ = out.write_all(HELP.as_bytes());
                return 0;
            }
            "--version" | "-V" if words.is_empty() => {
                let _ = writeln!(out, "wbm {}", env!("CARGO_PKG_VERSION"));
                return 0;
            }
            _ => words.push(args[i].clone()),
        }
        i += 1;
    }

    match words.first().map(String::as_str) {
        Some("mcp") => {
            if words.len() > 1 {
                return fail(
                    json_out,
                    &AgentError::Usage("mcp takes no arguments".into()),
                    out,
                    err,
                );
            }
            let ctx = Ctx::new(db.or(default_db).unwrap_or_default());
            return match mcp::serve_stdio(ctx) {
                Ok(()) => 0,
                Err(e) => {
                    let _ = writeln!(err, "wbm: {e}");
                    1
                }
            };
        }
        Some("tools") => {
            if words.len() > 1 {
                return fail(
                    json_out,
                    &AgentError::Usage("tools takes no arguments".into()),
                    out,
                    err,
                );
            }
            return print_tools(json_out, out);
        }
        _ => {}
    }

    let (tool, targs) = match parse_command(words) {
        Ok(x) => x,
        Err(e) => return fail(json_out, &e, out, err),
    };
    let Some(db) = db.or(default_db) else {
        return fail(
            json_out,
            &AgentError::Usage("cannot find your home directory; pass --db PATH".into()),
            out,
            err,
        );
    };
    match tools::call(&Ctx::new(db), tool, &targs) {
        Ok(v) => {
            if json_out {
                let _ = writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&v).unwrap_or_default()
                );
            } else {
                let _ = out.write_all(render(tool, &v).as_bytes());
            }
            0
        }
        Err(e) => fail(json_out, &e, out, err),
    }
}

/// Entry point for the binary: real args, real stdio, the app's usual database.
pub fn main_entry() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(
        &args,
        default_db_path(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}

fn fail(json_out: bool, e: &AgentError, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if json_out {
        let v = json!({"error": {"code": e.code(), "message": e.message()}});
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&v).unwrap_or_default()
        );
    } else {
        let _ = writeln!(err, "wbm: {}", e.message());
    }
    e.exit_code()
}

fn print_tools(json_out: bool, out: &mut dyn Write) -> i32 {
    if json_out {
        let v: Vec<Value> = tools::specs()
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "readOnly": s.read_only(),
                    "description": s.description,
                    "inputSchema": (s.schema)(),
                })
            })
            .collect();
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&json!({"tools": v})).unwrap_or_default()
        );
    } else {
        for s in tools::specs() {
            let kind = match s.access {
                Access::Read => "read",
                Access::Add | Access::Remove => "edit",
            };
            let _ = writeln!(
                out,
                "{:<18} {:<5} {}",
                s.name,
                kind,
                one_line(s.description)
            );
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Human output
// ---------------------------------------------------------------------------

/// The start of a description that fits one terminal line, cut at a word.
fn one_line(description: &str) -> String {
    const MAX: usize = 78;
    if description.chars().count() <= MAX {
        return description.to_string();
    }
    let cut: String = description.chars().take(MAX).collect();
    let cut = cut.rsplit_once(' ').map_or(cut.as_str(), |(head, _)| head);
    format!("{}...", cut.trim_end_matches([',', ';', ':', '.']))
}

/// `2026-10-25 14:03Z` from Unix milliseconds.
pub fn fmt_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn cell(v: &Value, key: &str) -> String {
    let x = &v[key];
    match x {
        Value::Null => "-".into(),
        Value::String(s) => {
            // Hashes are long; the full value is in --json.
            if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
                s[..12].to_string()
            } else {
                s.clone()
            }
        }
        Value::Bool(b) => if *b { "yes" } else { "no" }.into(),
        Value::Number(n) => {
            if (key.ends_with("At")
                || key.ends_with("Seen")
                || key == "firstSeen"
                || key == "lastSeen")
                && n.as_i64().is_some_and(|t| t > 1_000_000_000_000)
            {
                fmt_time(n.as_i64().unwrap_or(0))
            } else {
                n.to_string()
            }
        }
        Value::Array(a) => a
            .iter()
            .map(|e| e.as_str().map_or_else(|| e.to_string(), str::to_string))
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => x.to_string(),
    }
}

/// A plain aligned table. Empty input prints a one-line "none".
fn table(rows: &[Value], cols: &[(&str, &str)], none: &str) -> String {
    if rows.is_empty() {
        return format!("{none}\n");
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| cols.iter().map(|(_, k)| cell(r, k)).collect())
        .collect();
    let widths: Vec<usize> = cols
        .iter()
        .enumerate()
        .map(|(i, (h, _))| {
            cells
                .iter()
                .map(|c| c[i].chars().count())
                .chain([h.chars().count()])
                .max()
                .unwrap_or(0)
                .min(40)
        })
        .collect();
    let line = |vals: Vec<String>| {
        let mut s = String::new();
        for (i, v) in vals.iter().enumerate() {
            let t: String = v.chars().take(widths[i]).collect();
            if i + 1 == vals.len() {
                s.push_str(&t);
            } else {
                s.push_str(&format!("{t:<w$}  ", w = widths[i]));
            }
        }
        s.push('\n');
        s
    };
    let mut out = line(cols.iter().map(|(h, _)| (*h).to_string()).collect());
    for c in cells {
        out.push_str(&line(c));
    }
    out
}

fn rows<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v[key].as_array().map_or(&[], Vec::as_slice)
}

fn render(tool: &str, v: &Value) -> String {
    match tool {
        "status" => render_status(v),
        "alerts" => {
            let mut s = table(
                rows(v, "alerts"),
                &[
                    ("id", "id"),
                    ("severity", "severity"),
                    ("kind", "kind"),
                    ("last seen", "lastSeen"),
                    ("dismissed", "dismissed"),
                    ("title", "title"),
                ],
                "No alerts.",
            );
            if v["truncated"] == json!(true) {
                s.push_str("(more alerts exist; raise --limit)\n");
            }
            s
        }
        "dismiss_alert" => format!("Dismissed alert {}.\n", cell(&v["alert"], "id")),
        "networks" => with_scan_header(
            v,
            "networks",
            table(
                rows(v, "networks"),
                &[
                    ("ssid", "ssid"),
                    ("bssid hash", "bssidHash"),
                    ("rssi", "rssi"),
                    ("ch", "channel"),
                    ("security", "security"),
                    ("vendor", "vendor"),
                    ("trusted", "trusted"),
                    ("mine", "mine"),
                ],
                "No stored scan yet.",
            ),
        ),
        "ble" => with_scan_header(
            v,
            "devices",
            table(
                rows(v, "devices"),
                &[
                    ("name", "name"),
                    ("hash", "peripheralHash"),
                    ("rssi", "rssi"),
                    ("tracker", "tracker"),
                    ("owner", "ownerState"),
                    ("mine", "mine"),
                ],
                "No Bluetooth devices in the latest scan.",
            ),
        ),
        "lan_devices" => table(
            rows(v, "devices"),
            &[
                ("hash", "macHash"),
                ("vendor", "vendor"),
                ("hostname", "hostname"),
                ("services", "services"),
                ("last seen", "lastSeen"),
                ("mine", "mine"),
            ],
            "No LAN devices stored.",
        ),
        "places" => table(
            rows(v, "places"),
            &[
                ("id", "id"),
                ("label", "label"),
                ("first seen", "firstSeen"),
                ("last seen", "lastSeen"),
            ],
            "No places yet.",
        ),
        "history" => table(
            rows(v, "scans"),
            &[
                ("scanned at", "scannedAt"),
                ("wifi", "wifiCount"),
                ("ble", "bleCount"),
            ],
            "No scans in that window.",
        ),
        "mine_list" => table(
            rows(v, "mine"),
            &[
                ("kind", "kind"),
                ("hash", "idHash"),
                ("label", "label"),
                ("added", "addedAt"),
            ],
            "Nothing marked as yours.",
        ),
        "mine_add" => "Marked as yours.\n".into(),
        "mine_remove" => removed(v, "Removed from Mine."),
        "trusted_list" => {
            let counted: Vec<Value> = rows(v, "trusted")
                .iter()
                .map(|t| {
                    let mut t = t.clone();
                    t["knownAps"] = json!(t["knownBssidHashes"].as_array().map_or(0, Vec::len));
                    t
                })
                .collect();
            table(
                &counted,
                &[
                    ("ssid", "ssid"),
                    ("security", "expectedSecurity"),
                    ("known APs", "knownAps"),
                ],
                "No trusted networks.",
            )
        }
        "trusted_add" => {
            if v["added"] == json!(true) {
                format!("Trusted {}.\n", cell(&v["trusted"], "ssid"))
            } else {
                "Already trusted; nothing changed.\n".into()
            }
        }
        "trusted_remove" => removed(v, "No longer trusted."),
        "watchlist_list" => table(
            rows(v, "watchlist"),
            &[
                ("id", "id"),
                ("kind", "kind"),
                ("pattern", "pattern"),
                ("match", "match"),
            ],
            "Watchlist is empty.",
        ),
        "watchlist_add" => {
            if v["added"] == json!(true) {
                format!("Added watchlist rule {}.\n", cell(&v["watch"], "id"))
            } else {
                format!(
                    "That rule already exists (id {}).\n",
                    cell(&v["watch"], "id")
                )
            }
        }
        "watchlist_remove" => removed(v, "Removed."),
        _ => format!("{v}\n"),
    }
}

fn removed(v: &Value, yes: &str) -> String {
    if v["removed"] == json!(true) {
        format!("{yes}\n")
    } else {
        "Was not there; nothing changed.\n".into()
    }
}

fn with_scan_header(v: &Value, list: &str, body: String) -> String {
    let Some(at) = v["scannedAt"].as_i64() else {
        return body;
    };
    let total = v["total"].as_i64().unwrap_or(0);
    let shown = v[list].as_array().map_or(0, Vec::len);
    let mut s = format!(
        "Scan at {} ({}s ago), {} {}{}\n",
        fmt_time(at),
        v["ageSecs"].as_i64().unwrap_or(0),
        total,
        list,
        if (shown as i64) < total {
            format!(", showing {shown}")
        } else {
            String::new()
        }
    );
    s.push_str(&body);
    s
}

fn render_status(v: &Value) -> String {
    let mut s = String::new();
    let fresh = v["freshness"].as_str().unwrap_or("?");
    s.push_str(&format!("App: {fresh}\n"));
    s.push_str(&format!("{}\n", v["message"].as_str().unwrap_or("")));
    let snap = &v["snapshot"];
    if snap.is_object() {
        s.push_str(&format!(
            "Last scan: {}\n",
            snap["lastScanAt"].as_i64().map_or("-".into(), fmt_time)
        ));
        s.push_str(&format!(
            "Permissions: bluetooth {}, location {}\n",
            cell(&snap["permissions"], "bluetooth"),
            cell(&snap["permissions"], "location")
        ));
        s.push_str(&format!("Neighbor helper: {}\n", cell(snap, "helper")));
        if snap["network"].is_object() {
            let n = &snap["network"];
            s.push_str(&format!(
                "Network: {} (ap {}, group {}){}\n",
                cell(n, "ssid"),
                cell(n, "bssidHash"),
                cell(n, "groupId"),
                if n["isMine"] == json!(true) {
                    ", mine"
                } else {
                    ""
                }
            ));
        } else {
            s.push_str("Network: none (not on Wi-Fi, or the name is withheld)\n");
        }
        s.push_str(&format!(
            "Last cycle: {} wifi, {} ble, {} errors, {} new alerts\n",
            snap["scan"]["wifi"],
            snap["scan"]["ble"],
            snap["scan"]["errors"],
            snap["scan"]["newAlerts"]
        ));
    }
    let c = &v["counts"];
    s.push_str(&format!(
        "Stored: {} alerts ({} dismissed), {} mine, {} watchlist, {} places, {} LAN devices, {} scans\n",
        c["alertsActive"], c["alertsDismissed"], c["mine"], c["watchlist"], c["places"], c["lanDevices"], c["scans"]
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_formatting_matches_known_dates() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00Z");
        assert_eq!(fmt_time(1_700_000_000_000), "2023-11-14 22:13Z");
        assert_eq!(fmt_time(1_782_000_000_000), "2026-06-21 00:00Z");
        assert_eq!(fmt_time(951_782_400_000), "2000-02-29 00:00Z");
    }

    fn parse(s: &str) -> Result<(&'static str, Value), AgentError> {
        parse_command(s.split_whitespace().map(String::from).collect())
    }

    #[test]
    fn commands_map_to_tools_and_arguments() {
        assert_eq!(parse("status").unwrap().0, "status");
        let (t, a) = parse("alerts --since 24h --all --limit 5").unwrap();
        assert_eq!(t, "alerts");
        assert_eq!(
            a,
            json!({"since": "24h", "includeDismissed": true, "limit": 5})
        );
        let (t, a) = parse("mine add ble abc --label Mine").unwrap();
        assert_eq!(
            (t, a),
            (
                "mine_add",
                json!({"kind": "ble", "idHash": "abc", "label": "Mine"})
            )
        );
        let (t, a) = parse("watchlist add ssid Net-A --match exact").unwrap();
        assert_eq!(t, "watchlist_add");
        assert_eq!(
            a,
            json!({"kind": "ssid", "pattern": "Net-A", "match": "exact"})
        );
        assert_eq!(parse("watchlist remove 3").unwrap().1, json!({"id": 3}));
        assert_eq!(
            parse("devices --network k").unwrap().1,
            json!({"networkKey": "k"})
        );
    }

    #[test]
    fn bad_usage_is_rejected() {
        for bad in [
            "",
            "nope",
            "status extra",
            "alerts --bogus",
            "alerts --since",
            "alert dismiss",
            "alert list x",
            "mine add ble",
            "mine",
            "watchlist remove x",
            "networks --all",
        ] {
            assert!(matches!(parse(bad), Err(AgentError::Usage(_))), "{bad:?}");
        }
    }
}
