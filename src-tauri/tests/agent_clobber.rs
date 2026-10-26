//! The running app and an agent write the same database. The app holds settings in memory (the
//! settings page edits a draft and saves the WHOLE object); an agent adds a trusted network in
//! between. The app's next save must not erase it, and an agent edit must not change any other
//! setting. Synthetic data only, temp databases only.

use app_lib::model::{AlertToggles, Security, Settings, TrustedNetwork};
use app_lib::store::{OpenMode, Store};
use tempfile::TempDir;

fn net(ssid: &str) -> TrustedNetwork {
    TrustedNetwork {
        ssid: ssid.into(),
        known_bssid_hashes: vec!["aa".repeat(32)],
        expected_security: Security::Wpa2Personal,
    }
}

/// Two handles on one file: `app` (what the running app holds) and `agent` (a `wbm` process).
fn two_handles() -> (TempDir, Store, Store) {
    let dir = TempDir::new().unwrap();
    let app = Store::open(dir.path()).unwrap();
    let agent = Store::open_db_file(&dir.path().join("store.sqlite3"), OpenMode::Edit).unwrap();
    (dir, app, agent)
}

fn ssids(s: &Settings) -> Vec<&str> {
    s.trusted_networks.iter().map(|t| t.ssid.as_str()).collect()
}

#[test]
fn app_save_does_not_clobber_an_agent_added_trusted_network() {
    let (_d, mut app, mut agent) = two_handles();
    // The app loads its settings (the settings page draft is based on this).
    let mut draft = app.get_settings().unwrap();

    // An agent trusts a network while the page is open.
    agent
        .update_trusted_networks(|list| list.push(net("Net-A")))
        .unwrap();

    // The user changes an unrelated setting on the stale draft and saves the whole object.
    draft.scan_interval_secs = 90;
    app.set_settings(&draft).unwrap();

    let now = app.get_settings().unwrap();
    assert_eq!(
        now.scan_interval_secs, 90,
        "the user's own change must land"
    );
    assert_eq!(ssids(&now), ["Net-A"], "the agent's edit must survive");
}

#[test]
fn app_removal_of_one_network_keeps_the_agents_new_one() {
    let (_d, mut app, mut agent) = two_handles();
    agent
        .update_trusted_networks(|l| l.push(net("Net-A")))
        .unwrap();
    let mut draft = app.get_settings().unwrap();
    assert_eq!(ssids(&draft), ["Net-A"]);

    agent
        .update_trusted_networks(|l| l.push(net("Net-B")))
        .unwrap();

    // The user removes Net-A on a draft that never saw Net-B.
    draft.trusted_networks.retain(|t| t.ssid != "Net-A");
    app.set_settings(&draft).unwrap();

    assert_eq!(ssids(&app.get_settings().unwrap()), ["Net-B"]);
}

#[test]
fn agent_removal_survives_an_untouched_app_draft() {
    let (_d, mut app, mut agent) = two_handles();
    agent
        .update_trusted_networks(|l| l.extend([net("Net-A"), net("Net-B")]))
        .unwrap();
    let mut draft = app.get_settings().unwrap();
    agent
        .update_trusted_networks(|l| l.retain(|t| t.ssid != "Net-A"))
        .unwrap();

    draft.notify = false;
    app.set_settings(&draft).unwrap();

    let now = app.get_settings().unwrap();
    assert_eq!(
        ssids(&now),
        ["Net-B"],
        "a removal by the agent is not undone"
    );
    assert!(!now.notify);
}

#[test]
fn a_fresh_draft_saves_exactly_what_it_says() {
    // No concurrent edit: the app's save is authoritative, including emptying the list.
    let (_d, mut app, mut agent) = two_handles();
    agent
        .update_trusted_networks(|l| l.push(net("Net-A")))
        .unwrap();
    let mut draft = app.get_settings().unwrap();
    draft.trusted_networks.clear();
    app.set_settings(&draft).unwrap();
    assert!(app.get_settings().unwrap().trusted_networks.is_empty());
}

#[test]
fn agent_trusted_edit_changes_nothing_else() {
    let (_d, mut app, mut agent) = two_handles();
    let custom = Settings {
        scan_interval_secs: 45,
        retention_hours: 12,
        notify: false,
        lan_active_sweep: true,
        lan_neighbor_helper: true,
        alert_toggles: AlertToggles {
            new_device: true,
            ..AlertToggles::default()
        },
        ..Settings::default()
    };
    app.set_settings(&custom).unwrap();
    let before = app.get_settings().unwrap();

    agent
        .update_trusted_networks(|l| l.push(net("Net-A")))
        .unwrap();

    let after = app.get_settings().unwrap();
    assert_eq!(ssids(&after), ["Net-A"]);
    let mut expect = before.clone();
    expect.trusted_networks = after.trusted_networks.clone();
    expect.revision = after.revision;
    assert_eq!(after, expect, "only trustedNetworks may differ");
    assert!(after.lan_active_sweep && after.lan_neighbor_helper);
}

#[test]
fn concurrent_writers_lose_nothing() {
    // Two threads, each its own connection, add different networks 20 times.
    let dir = TempDir::new().unwrap();
    let _app = Store::open(dir.path()).unwrap();
    let db = dir.path().join("store.sqlite3");
    let handles: Vec<_> = ["A", "B"]
        .into_iter()
        .map(|tag| {
            let db = db.clone();
            std::thread::spawn(move || {
                for i in 0..20 {
                    let mut s = Store::open_db_file(&db, OpenMode::Edit).unwrap();
                    s.update_trusted_networks(|l| l.push(net(&format!("Net-{tag}{i}"))))
                        .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let n = Store::open_db_file(&db, OpenMode::Edit)
        .unwrap()
        .get_settings()
        .unwrap()
        .trusted_networks
        .len();
    assert_eq!(n, 40, "every concurrent edit must land");
}
