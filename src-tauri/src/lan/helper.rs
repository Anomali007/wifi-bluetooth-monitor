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
    let Some(mut f) = open_checked(path, false) else {
        *slot = None;
        return Err(Freshness::Missing);
    };
    let Ok(meta) = f.metadata() else {
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
    let len = meta.len();
    if len > MAX_READ {
        let _ = f.seek(SeekFrom::Start(len - MAX_READ));
    }
    let mut bytes = Vec::new();
    let _ = (&mut f).take(MAX_READ).read_to_end(&mut bytes);
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if len > MAX_READ {
        // Drop the partial first line.
        if let Some(i) = text.find('\n') {
            text.drain(..=i);
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

/// Create the data folder if needed and make it private (0700) so the output files, which
/// launchd creates readable, cannot be listed or read by other accounts; bound the files left
/// over from a closed app. Call this BEFORE anything is created inside it (the database).
pub fn prepare_dir(dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
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
    if on && st == HelperStatus::Unavailable {
        log::info!("lan: helper unavailable in this build (the bundled plists are not for this user's data folder)");
    }
    match launch_action(on, st) {
        Action::Register => apply(true),
        Action::Unregister => apply(false),
        Action::Nothing if !on => delete_outputs(dir),
        Action::Nothing => {}
    }
}

/// Whether a file at an output path is one we may read and empty: a regular file, owned by
/// this user, with a single link. Anything else (a planted symlink target's owner, a hard link
/// to someone else's file) is treated as missing, never truncated.
pub fn is_ours(regular: bool, uid: u32, euid: u32, nlink: u64) -> bool {
    regular && uid == euid && nlink == 1
}

/// Open an output file without following a final symlink or blocking on a FIFO, then check
/// (on the open descriptor, so there is no race) that it is [`is_ours`]. `None` = treat as missing.
#[cfg(unix)]
fn open_checked(path: &Path, write: bool) -> Option<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let m = f.metadata().ok()?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    is_ours(m.is_file(), m.uid(), euid, m.nlink()).then_some(f)
}

#[cfg(not(unix))]
fn open_checked(path: &Path, write: bool) -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(!write)
        .write(write)
        .open(path)
        .ok()
}

/// Empty a file in place (launchd holds it open, so truncate rather than delete). A link,
/// FIFO, or file that is not ours is left alone.
pub fn truncate(path: &Path) {
    if let Some(f) = open_checked(path, true) {
        let _ = f.set_len(0);
    }
}

/// Truncate a file that has grown past [`MAX_FILE`], whatever its age.
pub fn cap(path: &Path) {
    let big = open_checked(path, false)
        .and_then(|f| f.metadata().ok())
        .is_some_and(|m| m.len() > MAX_FILE);
    if big {
        truncate(path);
    }
}

/// Delete both output files.
pub fn delete_outputs(dir: &Path) {
    for n in [ARP_OUT, NDP_OUT] {
        let _ = std::fs::remove_file(dir.join(n));
    }
}

// -- Bundle check (M4) ----------------------------------------------------------------------

/// Whether the plists bundled with this build point at THIS user's data folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleCheck {
    /// Both plists write to this user's data folder.
    Match,
    /// A plist writes somewhere else: the build was made by another user (the plists bake in
    /// the builder's home folder), so the jobs could never deliver output to this app.
    Mismatch,
    /// No bundled plists to read (an unbundled run or an old build).
    Missing,
}

/// The `StandardOutPath` string of a launchd plist, XML-unescaped.
pub fn standard_out_path(plist: &str) -> Option<String> {
    let after =
        &plist[plist.find("<key>StandardOutPath</key>")? + "<key>StandardOutPath</key>".len()..];
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")? + start;
    Some(
        after[start..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

/// Compare both bundled plists' `StandardOutPath` with where this user's app writes.
pub fn check_bundle(plist_dir: &Path, data_dir: &Path) -> BundleCheck {
    let mut mismatch = false;
    for (plist, out) in [(ARP_PLIST, ARP_OUT), (NDP_PLIST, NDP_OUT)] {
        let Ok(text) = std::fs::read_to_string(plist_dir.join(plist)) else {
            return BundleCheck::Missing;
        };
        let Some(path) = standard_out_path(&text) else {
            return BundleCheck::Missing;
        };
        if Path::new(&path) != data_dir.join(out) {
            mismatch = true;
        }
    }
    if mismatch {
        BundleCheck::Mismatch
    } else {
        BundleCheck::Match
    }
}

/// `Contents/Library/LaunchAgents` of the running bundle (`Contents/MacOS/<exe>` -> up two).
pub fn bundled_plist_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.parent()?.join("Library").join("LaunchAgents"))
}

/// True when the bundled plists belong to this user (the only case in which the jobs can work).
fn bundle_usable() -> bool {
    match (bundled_plist_dir(), data_dir()) {
        (Some(p), Some(d)) => check_bundle(&p, d) == BundleCheck::Match,
        _ => false,
    }
}

// -- Lifecycle (L6) ---------------------------------------------------------------------------

/// What to do with the registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Register,
    Unregister,
    Nothing,
}

/// At launch: make the registration match the setting (the setting is the source of truth).
pub fn launch_action(on: bool, st: HelperStatus) -> Action {
    match (on, st) {
        (true, HelperStatus::Off) => Action::Register,
        (false, HelperStatus::Enabled | HelperStatus::NeedsApproval) => Action::Unregister,
        _ => Action::Nothing,
    }
}

/// On quit: unregister whatever is registered, so the launchd jobs stop appending to the data
/// folder while the app is closed.
pub fn quit_action(st: HelperStatus) -> Action {
    match st {
        HelperStatus::Enabled | HelperStatus::NeedsApproval => Action::Unregister,
        HelperStatus::Off | HelperStatus::Unavailable => Action::Nothing,
    }
}

/// The app is quitting: stop the launchd jobs (and delete what they wrote) so nothing keeps
/// appending to the data folder while the app is closed. The setting stays on; the next
/// launch registers again.
pub fn on_quit() {
    if quit_action(status()) == Action::Unregister {
        if let Err(e) = unregister() {
            log::info!("lan: helper unregister on quit failed: {e}");
        }
    }
    if let Some(dir) = data_dir() {
        delete_outputs(dir);
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
pub use sm::{open_login_items, unregister};

/// Registration state. A build whose plists point at another user's data folder reports
/// [`HelperStatus::Unavailable`] ("Unavailable in this build") instead of registering jobs
/// that could never deliver output here.
#[cfg(target_os = "macos")]
pub fn status() -> HelperStatus {
    if !bundle_usable() {
        return HelperStatus::Unavailable;
    }
    sm::status()
}

#[cfg(target_os = "macos")]
pub fn register() -> Result<HelperStatus, String> {
    if !bundle_usable() {
        return Err("unavailable in this build".to_string());
    }
    sm::register()
}

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

    // -- M4: the bundled plists must be this user's -------------------------------------------

    fn plist_for(out: &str) -> String {
        format!("<plist><dict><key>StandardOutPath</key><string>{out}</string></dict></plist>")
    }

    fn write_plists(dir: &Path, data: &str) {
        std::fs::write(dir.join(ARP_PLIST), plist_for(&format!("{data}/{ARP_OUT}"))).unwrap();
        std::fs::write(dir.join(NDP_PLIST), plist_for(&format!("{data}/{NDP_OUT}"))).unwrap();
    }

    #[test]
    fn standard_out_path_is_read_and_xml_unescaped() {
        assert_eq!(
            standard_out_path(&plist_for("/Users/a &amp; b/x.out")).as_deref(),
            Some("/Users/a & b/x.out")
        );
        assert_eq!(standard_out_path("<plist></plist>"), None);
    }

    #[test]
    fn a_bundle_built_for_another_users_home_is_unavailable_here() {
        let plists = tempfile::tempdir().unwrap();
        let mine = tempfile::tempdir().unwrap();
        write_plists(
            plists.path(),
            "/Users/builder-a/Library/Application Support/x",
        );
        assert_eq!(
            check_bundle(plists.path(), mine.path()),
            BundleCheck::Mismatch,
            "plists bake in the builder's data folder"
        );
        // NEGATIVE CONTROL: plists rendered for this very data folder match.
        write_plists(plists.path(), mine.path().to_str().unwrap());
        assert_eq!(check_bundle(plists.path(), mine.path()), BundleCheck::Match);
        // One plist wrong is still a mismatch.
        std::fs::write(
            plists.path().join(NDP_PLIST),
            plist_for(&format!("/Users/builder-a/{NDP_OUT}")),
        )
        .unwrap();
        assert_eq!(
            check_bundle(plists.path(), mine.path()),
            BundleCheck::Mismatch
        );
        // No plists at all (an unbundled run).
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            check_bundle(empty.path(), mine.path()),
            BundleCheck::Missing
        );
    }

    #[test]
    fn the_rendered_template_path_shape_matches_the_runtime_expectation() {
        // The template substitutes DATA_DIR + "/neighbors-*.out"; the runtime compares the same.
        for (file, out) in [
            ("com.anomali007.wifibtmonitor.arp.plist.in", ARP_OUT),
            ("com.anomali007.wifibtmonitor.ndp.plist.in", NDP_OUT),
        ] {
            let t = std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("helper")
                    .join(file),
            )
            .unwrap();
            let rendered = t.replace("@DATA_DIR@", "/Users/synthetic/data");
            assert_eq!(
                standard_out_path(&rendered).as_deref(),
                Some(format!("/Users/synthetic/data/{out}").as_str())
            );
        }
    }

    // -- L6: quit and launch ------------------------------------------------------------------

    #[test]
    fn quitting_unregisters_a_running_item_and_launch_registers_it_again() {
        assert_eq!(quit_action(HelperStatus::Enabled), Action::Unregister);
        assert_eq!(quit_action(HelperStatus::NeedsApproval), Action::Unregister);
        // NEGATIVE CONTROLS: nothing to undo when it is not registered.
        assert_eq!(quit_action(HelperStatus::Off), Action::Nothing);
        assert_eq!(quit_action(HelperStatus::Unavailable), Action::Nothing);
        // Setting on + unregistered at launch (because we unregistered on quit) = register.
        assert_eq!(launch_action(true, HelperStatus::Off), Action::Register);
        assert_eq!(launch_action(true, HelperStatus::Enabled), Action::Nothing);
        assert_eq!(
            launch_action(false, HelperStatus::Enabled),
            Action::Unregister
        );
        assert_eq!(
            launch_action(true, HelperStatus::Unavailable),
            Action::Nothing
        );
    }

    // -- L4: never follow a planted link, never truncate someone else's file --------------------

    #[cfg(unix)]
    #[test]
    fn a_symlinked_output_file_is_missing_and_its_target_is_untouched() {
        let d = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        let target = victim.path().join("precious.txt");
        std::fs::write(&target, "keep me").unwrap();
        let link = d.path().join(ARP_OUT);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let now = SystemTime::now();
        let mut slot = None;
        assert_eq!(fetch(&link, now, &mut slot), Err(Freshness::Missing));
        // Whatever the age, the target keeps its bytes (stale path, cap path and truncate).
        let old = std::fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .unwrap();
        old.set_modified(now - MAX_AGE - Duration::from_secs(60))
            .unwrap();
        assert_eq!(fetch(&link, now, &mut slot), Err(Freshness::Missing));
        truncate(&link);
        cap(&link);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me");
        // NEGATIVE CONTROL: a regular file at the same path is read normally.
        std::fs::remove_file(&link).unwrap();
        write(d.path(), ARP_OUT, ARP, Duration::from_secs(5), now);
        assert!(fetch(&link, now, &mut None).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_hard_linked_output_file_is_missing_and_the_other_name_is_untouched() {
        let d = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let precious = other.path().join("precious.txt");
        std::fs::write(&precious, ARP).unwrap();
        let out = d.path().join(NDP_OUT);
        std::fs::hard_link(&precious, &out).unwrap();
        let now = SystemTime::now();
        assert_eq!(fetch(&out, now, &mut None), Err(Freshness::Missing));
        truncate(&out);
        assert_eq!(std::fs::read_to_string(&precious).unwrap(), ARP);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_in_place_of_the_output_file_does_not_block_the_scan() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join(ARP_OUT);
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = fetch(&fifo, SystemTime::now(), &mut None);
            let _ = tx.send(r);
        });
        let got = rx
            .recv_timeout(Duration::from_secs(3))
            .expect("fetch blocked on a FIFO");
        assert_eq!(got, Err(Freshness::Missing));
    }

    #[test]
    fn only_a_regular_single_link_file_of_ours_is_trusted() {
        assert!(is_ours(true, 501, 501, 1));
        assert!(!is_ours(false, 501, 501, 1), "not a regular file");
        assert!(!is_ours(true, 0, 501, 1), "owned by someone else");
        assert!(!is_ours(true, 501, 501, 2), "hard-linked elsewhere");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_dir_creates_and_locks_the_folder() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("data");
        prepare_dir(&dir);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        // Loose permissions on an existing folder are tightened.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_dir(&dir);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
