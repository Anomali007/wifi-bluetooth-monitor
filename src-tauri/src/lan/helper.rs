//! The opt-in background item: two launchd jobs, registered through `SMAppService`, that run
//! Apple's own `/usr/sbin/arp -an` and `/usr/sbin/ndp -an` once a minute and write their
//! output into this app's private data folder. macOS 27 shows the neighbor tables to those
//! platform binaries when launchd starts them, but not to a third-party app or to anything
//! the app spawns, so the app never spawns a process: it reads the files the jobs write.
//!
//! The plists live in the bundle (`Contents/Library/LaunchAgents/`, templates in
//! `src-tauri/helper/`). Registering needs the user's approval in System Settings, Login Items.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

pub const ARP_PLIST: &str = "com.anomali007.wifibtmonitor.arp.plist";
pub const NDP_PLIST: &str = "com.anomali007.wifibtmonitor.ndp.plist";
pub const ARP_OUT: &str = "neighbors-arp.out";
pub const NDP_OUT: &str = "neighbors-ndp.out";

/// Output older than this is not shown as current.
pub const MAX_AGE: Duration = Duration::from_secs(180);
/// Only the tail of a file is read (a launchd job appends, so a closed app lets it grow).
pub const MAX_READ: u64 = 256 * 1024;
/// A file larger than this is truncated even when nothing reads it.
pub const MAX_FILE: u64 = 1024 * 1024;

/// What the settings page shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HelperStatus {
    /// Not registered.
    Off,
    /// Registered and approved.
    Enabled,
    /// Registered, waiting for the user in System Settings, Login Items.
    NeedsApproval,
    /// The plists are not in this build (an unbundled or old build).
    Unavailable,
}

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Remember the app-data folder (called once from `setup`).
pub fn set_data_dir(dir: &Path) {
    let _ = DATA_DIR.set(dir.to_path_buf());
}

pub fn data_dir() -> Option<&'static Path> {
    DATA_DIR.get().map(PathBuf::as_path)
}

/// Why a file gave nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// No file (not approved yet, or not running).
    Missing,
    /// Nothing written within [`MAX_AGE`].
    Stale,
}

/// The last non-empty text per tool and when launchd wrote it. The app empties a file as soon
/// as it has read it, so the next scan can find it empty until the job runs again; this keeps
/// the rows across that gap, for no longer than [`MAX_AGE`] from when they were written.
#[derive(Debug, Clone, Default)]
pub struct Cache {
    arp: Option<(SystemTime, String)>,
    ndp: Option<(SystemTime, String)>,
}

/// Read one output file. Missing or older than [`MAX_AGE`] is a [`Freshness`] error (and an old
/// file is emptied). Fresh text is returned (tail of at most [`MAX_READ`] bytes), cached, and
/// the file is emptied at once. An empty fresh file returns the cached text if it is still
/// within the window. Never logs the content.
pub fn fetch(
    path: &Path,
    now: SystemTime,
    slot: &mut Option<(SystemTime, String)>,
) -> Result<String, Freshness> {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(meta) = std::fs::metadata(path) else {
        *slot = None;
        return Err(Freshness::Missing);
    };
    let wrote = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let age = |t: SystemTime| now.duration_since(t).unwrap_or(Duration::ZERO);
    if age(wrote) > MAX_AGE {
        if meta.len() > 0 {
            truncate(path);
        }
        *slot = None;
        return Err(Freshness::Stale);
    }
    let mut text = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let len = meta.len();
        if len > MAX_READ {
            let _ = f.seek(SeekFrom::Start(len - MAX_READ));
        }
        let mut bytes = Vec::new();
        let _ = f.take(MAX_READ).read_to_end(&mut bytes);
        text = String::from_utf8_lossy(&bytes).into_owned();
        if len > MAX_READ {
            // Drop the partial first line.
            if let Some(i) = text.find('\n') {
                text.drain(..=i);
            }
        }
    }
    if !text.trim().is_empty() {
        truncate(path);
        *slot = Some((wrote, text.clone()));
        return Ok(text);
    }
    if let Some((t, cached)) = slot.as_ref() {
        if age(*t) <= MAX_AGE {
            return Ok(cached.clone());
        }
    }
    *slot = None;
    Err(Freshness::Stale)
}

/// The runner the scan uses: it reads the two files the launchd jobs write and spawns nothing.
pub struct FileRunner {
    dir: Option<PathBuf>,
    enabled: bool,
    now: SystemTime,
    cache: std::cell::RefCell<Cache>,
}

impl FileRunner {
    pub fn new(dir: Option<&Path>, enabled: bool, now: SystemTime, cache: Cache) -> Self {
        FileRunner {
            dir: dir.map(Path::to_path_buf),
            enabled,
            now,
            cache: std::cell::RefCell::new(cache),
        }
    }

    pub fn into_cache(self) -> Cache {
        self.cache.into_inner()
    }
}

impl super::systools::Runner for FileRunner {
    fn run(&self, tool: super::systools::Tool) -> Result<String, super::systools::ToolFailure> {
        use super::systools::{Tool, ToolFailure};
        if !self.enabled {
            return Err(ToolFailure::HelperOff(tool));
        }
        let Some(dir) = self.dir.as_deref() else {
            return Err(ToolFailure::NoOutput(tool));
        };
        let mut cache = self.cache.borrow_mut();
        let (name, slot) = match tool {
            Tool::Arp => (ARP_OUT, &mut cache.arp),
            Tool::Ndp => (NDP_OUT, &mut cache.ndp),
        };
        fetch(&dir.join(name), self.now, slot).map_err(|f| match f {
            Freshness::Missing => ToolFailure::NoOutput(tool),
            Freshness::Stale => ToolFailure::Stale(tool),
        })
    }
}

/// Make the data folder private (0700) so the output files, which launchd creates readable,
/// cannot be listed or read by other accounts; bound the files left over from a closed app.
pub fn prepare_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    set_data_dir(dir);
    cap(&dir.join(ARP_OUT));
    cap(&dir.join(NDP_OUT));
}

/// Turn the background item on or off, deleting the output files when off.
pub fn apply(on: bool) {
    if on {
        if let Err(e) = register() {
            log::info!("lan: helper register failed: {e}");
        }
    } else {
        if let Err(e) = unregister() {
            log::info!("lan: helper unregister failed: {e}");
        }
        if let Some(dir) = data_dir() {
            delete_outputs(dir);
        }
    }
}

/// At launch: make the registration match the setting (the setting is the source of truth).
pub fn reconcile(on: bool, dir: &Path) {
    let st = status();
    match (on, st) {
        (true, HelperStatus::Off) => apply(true),
        (false, HelperStatus::Enabled | HelperStatus::NeedsApproval) => apply(false),
        (false, _) => delete_outputs(dir),
        _ => {}
    }
}

/// Empty a file in place (launchd holds it open, so truncate rather than delete).
pub fn truncate(path: &Path) {
    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
        let _ = f.set_len(0);
    }
}

/// Truncate a file that has grown past [`MAX_FILE`], whatever its age.
pub fn cap(path: &Path) {
    if std::fs::metadata(path)
        .map(|m| m.len() > MAX_FILE)
        .unwrap_or(false)
    {
        truncate(path);
    }
}

/// Delete both output files.
pub fn delete_outputs(dir: &Path) {
    for n in [ARP_OUT, NDP_OUT] {
        let _ = std::fs::remove_file(dir.join(n));
    }
}

#[cfg(target_os = "macos")]
mod sm {
    use super::*;
    use objc2_foundation::NSString;
    use objc2_service_management::{SMAppService, SMAppServiceStatus};

    fn service(plist: &str) -> objc2::rc::Retained<SMAppService> {
        // SAFETY: plain class method with an NSString argument.
        unsafe { SMAppService::agentServiceWithPlistName(&NSString::from_str(plist)) }
    }

    fn map(s: SMAppServiceStatus) -> HelperStatus {
        match s {
            SMAppServiceStatus::Enabled => HelperStatus::Enabled,
            SMAppServiceStatus::RequiresApproval => HelperStatus::NeedsApproval,
            SMAppServiceStatus::NotFound => HelperStatus::Unavailable,
            _ => HelperStatus::Off,
        }
    }

    pub fn status() -> HelperStatus {
        let a = map(unsafe { service(super::ARP_PLIST).status() });
        let n = map(unsafe { service(super::NDP_PLIST).status() });
        match (a, n) {
            (HelperStatus::Unavailable, _) | (_, HelperStatus::Unavailable) => {
                HelperStatus::Unavailable
            }
            (HelperStatus::NeedsApproval, _) | (_, HelperStatus::NeedsApproval) => {
                HelperStatus::NeedsApproval
            }
            (HelperStatus::Enabled, HelperStatus::Enabled) => HelperStatus::Enabled,
            _ => HelperStatus::Off,
        }
    }

    /// Register both jobs; returns the resulting status or an error text (no paths).
    pub fn register() -> Result<HelperStatus, String> {
        for p in [super::ARP_PLIST, super::NDP_PLIST] {
            let s = service(p);
            if let Err(e) = unsafe { s.registerAndReturnError() } {
                // "Operation not permitted" while approval is pending still leaves a
                // registered, approval-pending item; report the status instead of failing.
                let st = status();
                if st == HelperStatus::NeedsApproval {
                    return Ok(st);
                }
                return Err(format!("register failed: {}", e.localizedDescription()));
            }
        }
        Ok(status())
    }

    pub fn unregister() -> Result<(), String> {
        let mut err = None;
        for p in [super::ARP_PLIST, super::NDP_PLIST] {
            if let Err(e) = unsafe { service(p).unregisterAndReturnError() } {
                if unsafe { service(p).status() } != SMAppServiceStatus::NotRegistered {
                    err = Some(format!("unregister failed: {}", e.localizedDescription()));
                }
            }
        }
        err.map_or(Ok(()), Err)
    }

    pub fn open_login_items() {
        unsafe { SMAppService::openSystemSettingsLoginItems() };
    }
}

#[cfg(target_os = "macos")]
pub use sm::{open_login_items, register, status, unregister};

#[cfg(not(target_os = "macos"))]
pub fn status() -> HelperStatus {
    HelperStatus::Unavailable
}
#[cfg(not(target_os = "macos"))]
pub fn register() -> Result<HelperStatus, String> {
    Err("not supported on this platform".into())
}
#[cfg(not(target_os = "macos"))]
pub fn unregister() -> Result<(), String> {
    Ok(())
}
#[cfg(not(target_os = "macos"))]
pub fn open_login_items() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::systools::{read_tool, Runner, Tool, ToolFailure};

    const ARP: &str = "? (10.0.0.2) at 2:0:0:0:0:1 on en0 ifscope [ethernet]\n? (10.0.0.3) at 2:0:0:0:0:2 on en0 ifscope [ethernet]\n";
    const ARP_OTHER_IF: &str = "? (10.0.0.9) at 2:0:0:0:0:9 on en5 ifscope [ethernet]\n";
    const NDP: &str = "Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\nfd00::2                         2:0:0:0:0:1        en0 23h59m50s S\n";

    fn write(dir: &Path, name: &str, text: &str, age: Duration, now: SystemTime) {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_modified(now - age).unwrap();
    }

    fn runner(dir: &Path, enabled: bool, now: SystemTime, c: Cache) -> FileRunner {
        FileRunner::new(Some(dir), enabled, now, c)
    }

    #[test]
    fn plists_run_exactly_arp_and_ndp_with_an() {
        for (file, prog) in [
            ("com.anomali007.wifibtmonitor.arp.plist.in", "/usr/sbin/arp"),
            ("com.anomali007.wifibtmonitor.ndp.plist.in", "/usr/sbin/ndp"),
        ] {
            let text = std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("helper")
                    .join(file),
            )
            .unwrap();
            let args = plist_strings_after(&text, "ProgramArguments");
            assert_eq!(args, vec![prog.to_string(), "-an".to_string()], "{file}");
            assert!(text.contains("<key>AssociatedBundleIdentifiers</key>"));
            assert!(text.contains("<string>com.anomali007.wifibtmonitor</string>"));
            assert!(!text.contains("/bin/sh") && !text.contains("/usr/bin/env"));
        }
    }

    /// The `<string>` items of the `<array>` that follows `key`.
    fn plist_strings_after(text: &str, key: &str) -> Vec<String> {
        let after = &text[text.find(&format!("<key>{key}</key>")).unwrap()..];
        let arr = &after[after.find("<array>").unwrap()..after.find("</array>").unwrap()];
        arr.split("<string>")
            .skip(1)
            .map(|p| p.split("</string>").next().unwrap().to_string())
            .collect()
    }

    #[test]
    fn fresh_output_is_read_then_emptied_and_parses_to_rows() {
        let d = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        write(d.path(), ARP_OUT, ARP, Duration::from_secs(10), now);
        let r = runner(d.path(), true, now, Cache::default());
        let got = read_tool(&r, Tool::Arp);
        assert_eq!((got.failure, got.rows.len()), (None, 2), "must yield rows");
        assert_eq!(
            std::fs::metadata(d.path().join(ARP_OUT)).unwrap().len(),
            0,
            "emptied at once"
        );
    }

    #[test]
    fn negative_control_other_interface_yields_no_wifi_rows() {
        let d = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        write(d.path(), ARP_OUT, ARP_OTHER_IF, Duration::from_secs(1), now);
        let got = read_tool(&runner(d.path(), true, now, Cache::default()), Tool::Arp);
        assert_eq!(got.rows.len(), 1);
        assert!(
            crate::lan::systools::arp_entries(&got.rows, "en0", 11).is_empty(),
            "0 Wi-Fi rows"
        );
    }

    #[test]
    fn stale_file_is_ignored_and_emptied() {
        let d = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        write(
            d.path(),
            ARP_OUT,
            ARP,
            MAX_AGE + Duration::from_secs(5),
            now,
        );
        let r = runner(d.path(), true, now, Cache::default());
        assert_eq!(r.run(Tool::Arp), Err(ToolFailure::Stale(Tool::Arp)));
        assert_eq!(std::fs::metadata(d.path().join(ARP_OUT)).unwrap().len(), 0);
        // NEGATIVE CONTROL: the same bytes just inside the window are shown.
        write(
            d.path(),
            ARP_OUT,
            ARP,
            MAX_AGE - Duration::from_secs(5),
            now,
        );
        assert!(runner(d.path(), true, now, Cache::default())
            .run(Tool::Arp)
            .is_ok());
    }

    #[test]
    fn rows_survive_the_gap_after_emptying_but_not_past_the_window() {
        let d = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        write(d.path(), NDP_OUT, NDP, Duration::from_secs(20), now);
        let r = runner(d.path(), true, now, Cache::default());
        assert!(r.run(Tool::Ndp).unwrap().contains("fd00::2"));
        let cache = r.into_cache();
        // Next scan: the file is empty (and freshly touched by our truncate).
        let later = now + Duration::from_secs(60);
        write(d.path(), NDP_OUT, "", Duration::ZERO, later);
        let r = runner(d.path(), true, later, cache.clone());
        assert!(
            r.run(Tool::Ndp).unwrap().contains("fd00::2"),
            "cached rows bridge the gap"
        );
        // Past the window the cache is dropped.
        let much_later = now + MAX_AGE + Duration::from_secs(30);
        write(d.path(), NDP_OUT, "", Duration::ZERO, much_later);
        let r = runner(d.path(), true, much_later, cache);
        assert_eq!(r.run(Tool::Ndp), Err(ToolFailure::Stale(Tool::Ndp)));
    }

    #[test]
    fn missing_and_disabled() {
        let d = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        assert_eq!(
            runner(d.path(), true, now, Cache::default()).run(Tool::Arp),
            Err(ToolFailure::NoOutput(Tool::Arp))
        );
        write(d.path(), ARP_OUT, ARP, Duration::ZERO, now);
        assert_eq!(
            runner(d.path(), false, now, Cache::default()).run(Tool::Arp),
            Err(ToolFailure::HelperOff(Tool::Arp))
        );
        // The file is untouched when the helper is off.
        assert!(std::fs::metadata(d.path().join(ARP_OUT)).unwrap().len() > 0);
    }

    #[test]
    fn oversized_file_reads_only_the_tail_and_cap_empties_it() {
        let d = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let mut big = String::new();
        while (big.len() as u64) < MAX_READ * 2 {
            big.push_str(ARP);
        }
        write(d.path(), ARP_OUT, &big, Duration::ZERO, now);
        let mut slot = None;
        let t = fetch(&d.path().join(ARP_OUT), now, &mut slot).unwrap();
        assert!(t.len() as u64 <= MAX_READ);
        assert!(t.starts_with("? (10.0.0."), "partial first line dropped");
        let mut huge = String::new();
        while (huge.len() as u64) <= MAX_FILE {
            huge.push_str(ARP);
        }
        write(d.path(), NDP_OUT, &huge, Duration::ZERO, now);
        cap(&d.path().join(NDP_OUT));
        assert_eq!(std::fs::metadata(d.path().join(NDP_OUT)).unwrap().len(), 0);
    }
}
