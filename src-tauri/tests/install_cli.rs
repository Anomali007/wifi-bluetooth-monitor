//! `scripts/install-cli.sh`, run for real against temp directories with the freshly built
//! `wbm` (WBM_BUILT skips the cargo build). It must copy, refuse to clobber a foreign `wbm`
//! unless forced, and print both registrations with the path quoted.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/install-cli.sh")
}

fn run(bin_dir: &Path, args: &[&str]) -> Output {
    Command::new("bash")
        .arg(script())
        .args(args)
        .env("WBM_BIN_DIR", bin_dir)
        .env("WBM_BUILT", env!("CARGO_BIN_EXE_wbm"))
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("run install-cli.sh")
}

fn out(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn it_copies_the_binary_instead_of_linking_it_and_it_runs() {
    let d = TempDir::new().unwrap();
    let bin = d.path().join("bin");
    let o = run(&bin, &[]);
    assert!(o.status.success(), "{}", out(&o));
    let dest = bin.join("wbm");
    let meta = fs::symlink_metadata(&dest).unwrap();
    assert!(meta.file_type().is_file(), "a real file, not a link");
    assert!(!meta.file_type().is_symlink());
    assert_eq!(meta.permissions().mode() & 0o111, 0o111, "executable");
    assert_eq!(
        fs::read(&dest).unwrap(),
        fs::read(env!("CARGO_BIN_EXE_wbm")).unwrap()
    );
    assert!(Command::new(&dest)
        .arg("--version")
        .output()
        .unwrap()
        .status
        .success());
    // Re-running over our own install is fine.
    assert!(run(&bin, &[]).status.success());
}

#[test]
fn it_refuses_to_overwrite_a_wbm_it_did_not_install_unless_forced() {
    let d = TempDir::new().unwrap();
    let bin = d.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let dest = bin.join("wbm");
    fs::write(&dest, "#!/bin/sh\necho someone elses tool\n").unwrap();
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap();
    let o = run(&bin, &[]);
    assert!(!o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("--force"), "{}", out(&o));
    assert!(
        fs::read_to_string(&dest)
            .unwrap()
            .contains("someone elses tool"),
        "left alone"
    );
    // --force replaces it, and from then on it is ours.
    let o = run(&bin, &["--force"]);
    assert!(o.status.success(), "{}", out(&o));
    assert_eq!(
        fs::read(&dest).unwrap(),
        fs::read(env!("CARGO_BIN_EXE_wbm")).unwrap()
    );
    assert!(run(&bin, &[]).status.success());
    // A file swapped in after our install is foreign again.
    fs::write(&dest, "swapped").unwrap();
    assert!(!run(&bin, &[]).status.success());
    assert_eq!(fs::read_to_string(&dest).unwrap(), "swapped");
}

#[test]
fn it_replaces_the_symlink_the_first_version_made_but_not_other_links() {
    let d = TempDir::new().unwrap();
    let bin = d.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let dest = bin.join("wbm");
    // The first version linked ~/bin/wbm to <target>/release/wbm.
    let release = d.path().join("target/release");
    fs::create_dir_all(&release).unwrap();
    fs::write(release.join("wbm"), "old build").unwrap();
    symlink(release.join("wbm"), &dest).unwrap();
    let o = run(&bin, &[]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(!fs::symlink_metadata(&dest)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_to_string(release.join("wbm")).unwrap(),
        "old build",
        "the link target is untouched"
    );
    // A link somewhere else is somebody else's.
    let elsewhere = d.path().join("elsewhere");
    fs::write(&elsewhere, "x").unwrap();
    fs::remove_file(&dest).unwrap();
    symlink(&elsewhere, &dest).unwrap();
    let o = run(&bin, &[]);
    assert!(!o.status.success(), "{}", out(&o));
    assert!(fs::symlink_metadata(&dest)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn it_prints_both_registrations_with_the_path_quoted() {
    let d = TempDir::new().unwrap();
    let bin = d.path().join("my bin"); // a space in the path
    let o = run(&bin, &[]);
    assert!(o.status.success(), "{}", out(&o));
    let text = out(&o);
    let quoted = format!("{}/wbm", bin.display()).replace(' ', "\\ ");
    assert!(
        text.contains(&format!("claude mcp add wbm -- {quoted} mcp\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!("claude mcp add wbm -- {quoted} mcp --edits\n")),
        "{text}"
    );
    assert!(
        text.contains("Read-only") && text.contains("With edits"),
        "{text}"
    );
    assert!(text.contains("mcp__wbm__*"), "{text}");
    // The unquoted form (which would break) is not what is printed.
    assert!(
        !text.contains(&format!("-- {}/wbm mcp", bin.display())),
        "{text}"
    );
}

#[test]
fn it_rejects_unknown_options() {
    let d = TempDir::new().unwrap();
    let o = run(&d.path().join("bin"), &["--bogus"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(!d.path().join("bin").exists(), "nothing was created");
}
