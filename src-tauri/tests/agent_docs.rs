//! The docs must say what the code does. Each check reads `docs/agents.md` / `README.md` and
//! compares against the live tool table, so a change to the table that the docs miss fails.

use app_lib::agent::tools::{self, Access};
use std::fs;
use std::path::PathBuf;

fn read(rel: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(rel),
    )
    .unwrap()
}

#[test]
fn the_docs_table_matches_the_tool_table_row_for_row() {
    let docs = read("docs/agents.md");
    let mut rows = 0;
    for s in tools::specs() {
        let mode = match s.access {
            Access::Read => "read",
            Access::Add | Access::Remove => "edit, **direct**",
            Access::Propose => "edit, **proposal**",
        };
        let row = format!("| `{}` | {mode} |", s.name);
        assert!(docs.contains(&row), "docs/agents.md lacks the row {row}");
        rows += 1;
    }
    assert_eq!(rows, 17, "FLOOR: all seventeen rows were checked");
    // NEGATIVE CONTROL: a wrong mode would not match.
    assert!(!docs.contains("| `trusted_add` | edit, **direct** |"));
    assert!(!docs.contains("| `status` | edit"));
}

#[test]
fn the_docs_describe_the_split_the_proposals_and_the_caps() {
    let docs = read("docs/agents.md");
    let readme = read("README.md");
    for must in [
        "wbm mcp --edits",
        "10 read tools",
        "agent-requests",
        "agent_proposals",
        "24 hours",
        "**20**",
        "latest scan only",
        "more than one security mode",
        "persists while the finding continues",
        "{\"untrusted\":",
        "256 KB",
        "**50**",
        "last **64**",
        "rejected",
        "added_by = agent",
        "mcp__wbm__*",
        "destructiveHint: true",
        "subjectSsid",
        "COPIES the binary",
        "--force",
    ] {
        assert!(docs.contains(must), "docs/agents.md lacks {must:?}");
    }
    for must in [
        "--edits",
        "Agent requests",
        "untrusted",
        "mcp__wbm__*",
        "256 KB",
    ] {
        assert!(readme.contains(must), "README.md lacks {must:?}");
    }
}

#[test]
fn the_docs_no_longer_make_the_claims_that_stopped_being_true() {
    let docs = read("docs/agents.md");
    let readme = read("README.md");
    for stale in [
        "the only four things an agent can change",
        "reappears only if",
        "last 16 revisions",
        "links ~/bin/wbm",
        "release build, links",
        "optional `security` (a value from",
        "the merge keeps both sides rather than dropping anything",
        "`trusted_add` and `trusted_remove` rewrite only the trusted list",
        "dismiss_alert` | the alert is kept",
    ] {
        assert!(!docs.contains(stale), "docs/agents.md still says {stale:?}");
        assert!(!readme.contains(stale), "README.md still says {stale:?}");
    }
    assert!(!readme.contains("can make four kinds of edit"));
    // Each tool description agrees about dismissal.
    let d = tools::specs()
        .iter()
        .find(|s| s.name == "dismiss_alert")
        .unwrap()
        .description;
    assert!(d.contains("persists while the finding continues"));
    assert!(!d.contains("reappears only if"));
}

#[test]
fn every_proposal_tool_says_it_is_a_request_in_its_own_description() {
    let mut n = 0;
    for s in tools::specs()
        .iter()
        .filter(|s| s.access == Access::Propose)
    {
        assert!(
            s.description.contains("does NOT") && s.description.contains("pending"),
            "{} must say it only records a request",
            s.name
        );
        n += 1;
    }
    assert_eq!(n, 5);
}
