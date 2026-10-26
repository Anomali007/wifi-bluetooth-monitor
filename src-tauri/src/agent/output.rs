//! The output layer. Every tool result passes through here, once, so no tool has to remember
//! to do it.
//!
//! Network names, Bluetooth names, hostnames and service types are broadcast by anyone nearby
//! and land in a model's context, where a name such as "Ignore previous instructions" is an
//! injection attempt. This layer:
//! - strips control, bidirectional-override and zero-width characters from those fields,
//! - caps their length (SSID 32 bytes, hostname 63, services 16 entries of 64 bytes, ...),
//! - for machine consumers (`--json`, MCP) wraps each one as `{"untrusted": "..."}` so the
//!   data/instruction boundary is in the structure itself, and
//! - caps the whole response at [`MAX_RESPONSE_BYTES`] (128 KB: an MCP result carries the JSON
//!   twice, as structured content and as a text copy, so the wire stays under 256 KB), dropping rows from the longest list
//!   and saying so with `"truncated": true`.

use crate::labels::clean;
use serde_json::{json, Map, Value};

/// A response larger than this is cut down (and flagged), whatever the tool.
pub const MAX_RESPONSE_BYTES: usize = 128 * 1024;

/// Fields whose text comes from other people's devices (or from an agent), with their length
/// cap in bytes. Matching is by key name anywhere in the result.
pub const TEXT_FIELDS: &[(&str, usize)] = &[
    ("ssid", 32),
    ("subjectSsid", 32),
    ("name", 64),
    ("hostname", 63),
    ("vendor", 64),
    ("title", 200),
    ("detail", 600),
    ("label", 64),
    ("pattern", 64),
    ("possiblySameAs", 64),
];

/// List-valued fields: (key, most entries, longest entry in bytes).
pub const LIST_FIELDS: &[(&str, usize, usize)] = &[("services", 16, 64)];

fn wrap(s: String) -> Value {
    json!({ "untrusted": s })
}

fn text_cap(key: &str) -> Option<usize> {
    TEXT_FIELDS.iter().find(|(k, _)| *k == key).map(|(_, n)| *n)
}

fn list_cap(key: &str) -> Option<(usize, usize)> {
    LIST_FIELDS
        .iter()
        .find(|(k, _, _)| *k == key)
        .map(|(_, a, b)| (*a, *b))
}

/// Clean and cap every attacker-controlled field in `v`; wrap them when `mark` is set.
pub fn sanitize(v: &mut Value, mark: bool) {
    match v {
        Value::Object(m) => sanitize_object(m, mark),
        Value::Array(a) => a.iter_mut().for_each(|x| sanitize(x, mark)),
        _ => {}
    }
}

fn sanitize_object(m: &mut Map<String, Value>, mark: bool) {
    for (key, val) in m.iter_mut() {
        if let (Some(cap), Value::String(s)) = (text_cap(key), &*val) {
            let c = clean(s, cap);
            *val = if mark { wrap(c) } else { Value::String(c) };
        } else if let (Some((most, each)), Value::Array(items)) = (list_cap(key), &mut *val) {
            items.truncate(most);
            for item in items.iter_mut() {
                if let Value::String(s) = &*item {
                    let c = clean(s, each);
                    *item = if mark { wrap(c) } else { Value::String(c) };
                }
            }
        } else {
            sanitize(val, mark);
        }
    }
}

fn size(v: &Value) -> usize {
    serde_json::to_string(v).map_or(usize::MAX, |s| s.len())
}

/// Path to the array with the most serialized bytes, as keys (objects) and indexes (arrays).
fn heaviest_array(v: &Value) -> Option<(Vec<Step>, usize)> {
    fn go(v: &Value, path: &mut Vec<Step>, best: &mut Option<(Vec<Step>, usize)>) {
        match v {
            Value::Array(a) => {
                if a.len() > 1 {
                    let sz = size(v);
                    if best.as_ref().is_none_or(|(_, b)| sz > *b) {
                        *best = Some((path.clone(), sz));
                    }
                }
                for (i, x) in a.iter().enumerate() {
                    path.push(Step::Index(i));
                    go(x, path, best);
                    path.pop();
                }
            }
            Value::Object(m) => {
                for (k, x) in m {
                    path.push(Step::Key(k.clone()));
                    go(x, path, best);
                    path.pop();
                }
            }
            _ => {}
        }
    }
    let mut best = None;
    go(v, &mut Vec::new(), &mut best);
    best
}

#[derive(Clone)]
enum Step {
    Key(String),
    Index(usize),
}

fn at_mut<'a>(v: &'a mut Value, path: &[Step]) -> Option<&'a mut Value> {
    let mut cur = v;
    for s in path {
        cur = match (s, cur) {
            (Step::Key(k), Value::Object(m)) => m.get_mut(k)?,
            (Step::Index(i), Value::Array(a)) => a.get_mut(*i)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Keep a response under `max` bytes by halving the heaviest list until it fits. Sets the
/// top-level `"truncated": true` when anything was dropped. Lists of scans keep the newest.
pub fn cap_size(v: &mut Value, max: usize) {
    let mut cut = false;
    while size(v) > max {
        let Some((path, _)) = heaviest_array(v) else {
            break;
        };
        let newest_last = matches!(path.last(), Some(Step::Key(k)) if k == "scans");
        let Some(Value::Array(a)) = at_mut(v, &path) else {
            break;
        };
        let drop = a.len().div_ceil(2);
        if newest_last {
            a.drain(..drop);
        } else {
            a.truncate(a.len() - drop);
        }
        cut = true;
    }
    if cut {
        if let Value::Object(m) = v {
            m.insert("truncated".into(), json!(true));
        }
    }
}

/// The whole output stage.
pub fn finish(mut v: Value, mark: bool) -> Value {
    sanitize(&mut v, mark);
    cap_size(&mut v, MAX_RESPONSE_BYTES);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_fields_are_cleaned_capped_and_wrapped() {
        let long = "x".repeat(100);
        let v = json!({
            "networks": [{"ssid": format!("Net\u{200B}-A\u{202E}{long}"), "rssi": -40, "bssidHash": "ab"}],
            "devices": [{"hostname": long, "name": null, "services": (0..40).map(|i| format!("_s{i}.\u{0007}_tcp")).collect::<Vec<_>>()}],
        });
        let out = finish(v, true);
        let ssid = out["networks"][0]["ssid"]["untrusted"].as_str().unwrap();
        assert!(ssid.len() <= 32 && ssid.starts_with("Net-A"), "{ssid}");
        assert_eq!(out["networks"][0]["rssi"], -40, "numbers are left alone");
        assert_eq!(
            out["networks"][0]["bssidHash"], "ab",
            "hashes are left alone"
        );
        assert_eq!(
            out["devices"][0]["hostname"]["untrusted"]
                .as_str()
                .unwrap()
                .len(),
            63
        );
        assert!(out["devices"][0]["name"].is_null(), "null stays null");
        let services = out["devices"][0]["services"].as_array().unwrap();
        assert_eq!(services.len(), 16);
        assert_eq!(services[0]["untrusted"], "_s0._tcp");
    }

    #[test]
    fn unmarked_output_is_plain_but_still_clean() {
        let out = finish(
            json!({"alerts": [{"title": "T\u{200B}x", "detail": "d"}]}),
            false,
        );
        assert_eq!(out["alerts"][0]["title"], "Tx");
    }

    #[test]
    fn an_oversized_response_is_cut_and_flagged() {
        let rows: Vec<Value> = (0..5_000)
            .map(|i| json!({"ssid": format!("Net-{i}"), "pad": "p".repeat(200)}))
            .collect();
        let before = size(&json!({"networks": rows}));
        assert!(before > MAX_RESPONSE_BYTES);
        let out = finish(json!({"networks": rows}), true);
        assert!(size(&out) <= MAX_RESPONSE_BYTES);
        assert_eq!(out["truncated"], true);
        assert!(!out["networks"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_small_response_is_untouched_by_the_cap() {
        let out = finish(
            json!({"networks": [{"rssi": 1}, {"rssi": 2}], "total": 2}),
            true,
        );
        assert!(out.get("truncated").is_none());
        assert_eq!(out["networks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn truncating_scans_keeps_the_newest() {
        let scans: Vec<Value> = (0..400)
            .map(|i| json!({"scannedAt": i, "pad": "p".repeat(1000)}))
            .collect();
        let out = finish(json!({"scans": scans}), false);
        let kept = out["scans"].as_array().unwrap();
        assert_eq!(kept.last().unwrap()["scannedAt"], 399);
        assert_eq!(out["truncated"], true);
    }
}
