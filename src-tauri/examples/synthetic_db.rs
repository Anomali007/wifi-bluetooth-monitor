//! Writes a small synthetic database (`Net-A`, `02:00:00:...`, `Vendor-A`) for trying `wbm`
//! without touching a real store:
//!
//! ```sh
//! cargo run --example synthetic_db -- /tmp/wbm-demo
//! wbm --db /tmp/wbm-demo/store.sqlite3 networks
//! ```
//!
//! The directory must not already hold a store; nothing here reads or writes the real one.

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let Some(dest) = std::env::args().nth(1) else {
        eprintln!("usage: synthetic_db <new directory>");
        std::process::exit(2);
    };
    let dest = std::path::PathBuf::from(dest);
    if dest.join("store.sqlite3").exists() {
        eprintln!(
            "{} already holds a store; refusing to touch it",
            dest.display()
        );
        std::process::exit(2);
    }
    let f = common::fixture();
    std::fs::create_dir_all(&dest).expect("create directory");
    for name in ["store.sqlite3", "salt.key"] {
        let from = f.dir.path().join(name);
        if from.exists() {
            std::fs::copy(&from, dest.join(name)).expect("copy");
        }
    }
    println!("wrote {}", dest.join("store.sqlite3").display());
}
