//! `wbm`: command-line and MCP access to the Wi-Fi Bluetooth Monitor's data. All behaviour
//! lives in `app_lib::agent`; see `docs/agents.md`.

fn main() {
    std::process::exit(app_lib::agent::cli::main_entry());
}
