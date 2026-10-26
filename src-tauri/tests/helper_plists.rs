//! M4: `scripts/render-helper-plists.sh` bakes the builder's data folder into the bundled
//! launchd plists. It must refuse paths that would corrupt the substitution, XML-escape what it
//! accepts, and the runtime must be able to read the result back (`helper::check_bundle`).
//! Synthetic home folders only.

use std::path::{Path, PathBuf};
use std::process::Command;

use app_lib::lan::helper::{check_bundle, standard_out_path, BundleCheck, ARP_PLIST, NDP_PLIST};

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/render-helper-plists.sh")
}

/// Run the script with `home` as `$HOME`, rendering into a fresh temp folder.
fn render(home: &str) -> (bool, tempfile::TempDir) {
    let out = tempfile::tempdir().unwrap();
    let status = Command::new("bash")
        .arg(script())
        .env("HOME", home)
        .env("RENDER_OUT_DIR", out.path())
        .output()
        .unwrap();
    (status.status.success(), out)
}

fn rendered_files(dir: &Path) -> usize {
    std::fs::read_dir(dir).unwrap().count()
}

#[test]
fn paths_that_would_corrupt_the_substitution_are_refused_and_leave_nothing() {
    for bad in [
        "/Users/a&b",
        "/Users/a#b",
        "/Users/a<b",
        "/Users/a\\b",
        "/Users/a\nb",
    ] {
        let (ok, out) = render(bad);
        assert!(!ok, "{bad:?} must be refused");
        assert_eq!(rendered_files(out.path()), 0, "{bad:?} left output behind");
    }
}

#[test]
fn an_awkward_but_legal_home_round_trips_through_the_runtime_check() {
    // Space, apostrophe, quote and > are legal in a path and are XML-escaped on the way in.
    let home = "/Users/Test O'Brien \"x\" a>b";
    let (ok, out) = render(home);
    assert!(ok, "legal path rejected");
    assert_eq!(rendered_files(out.path()), 2);
    let data = Path::new(home).join("Library/Application Support/com.anomali007.wifibtmonitor");
    for p in [ARP_PLIST, NDP_PLIST] {
        let text = std::fs::read_to_string(out.path().join(p)).unwrap();
        assert!(
            !text.contains("a>b\"") || text.contains("&gt;"),
            "not escaped: {text}"
        );
        let got = standard_out_path(&text).unwrap();
        assert!(got.starts_with(data.to_str().unwrap()), "{got}");
    }
    // The runtime recognises its own build, and a different user's data folder as foreign.
    assert_eq!(check_bundle(out.path(), &data), BundleCheck::Match);
    let other =
        Path::new("/Users/someone-else/Library/Application Support/com.anomali007.wifibtmonitor");
    assert_eq!(check_bundle(out.path(), other), BundleCheck::Mismatch);
}

#[test]
fn a_plain_home_renders_two_valid_plists() {
    let (ok, out) = render("/Users/synthetic");
    assert!(ok);
    assert_eq!(rendered_files(out.path()), 2);
}

/// L4 + L6 wiring in `lib.rs`, which has no unit-testable seam: the data folder is locked
/// (0700) BEFORE the database is created in it, and quitting stops the launchd jobs.
#[test]
fn startup_locks_the_folder_before_the_database_and_quit_stops_the_jobs() {
    let lib =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    let prepare = lib.find("helper::prepare_dir(").expect("prepare_dir call");
    let open = lib.find("Store::open(").expect("Store::open call");
    assert!(
        prepare < open,
        "the folder must be locked before the database exists"
    );
    let exit = lib.find("RunEvent::Exit").expect("an Exit handler");
    let quit = lib.find("helper::on_quit()").expect("on_quit call");
    assert!(exit < quit, "on_quit runs from the Exit event");
    // NEGATIVE CONTROL: the check really compares positions (the reverse order is false).
    assert!(!(open < prepare));
}
