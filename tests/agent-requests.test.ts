// The Agent requests UI: its helpers, the mock backend's contract for the four new commands
// (the Rust side is tests/agent_proposals.rs), and the stale-settings refusal.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import {
  decideAgentProposal,
  getSettings,
  listAgentAudit,
  listAgentProposals,
  setSettings,
  undoAgentChange,
} from "../lib/api";
import {
  AGENT_REQUESTS_ID,
  expiresIn,
  isStaleSettingsError,
  requestCountLabel,
  toolLabel,
} from "../lib/agent-requests";

const original = process.env.NEXT_PUBLIC_WBM_MOCK;
beforeEach(() => {
  process.env.NEXT_PUBLIC_WBM_MOCK = "1";
});
afterEach(() => {
  if (original === undefined) delete process.env.NEXT_PUBLIC_WBM_MOCK;
  else process.env.NEXT_PUBLIC_WBM_MOCK = original;
});

describe("helpers", () => {
  it("expiry reads in minutes, then hours, then expired", () => {
    const now = 1_000_000_000;
    expect(expiresIn(now + 5 * 60_000, now)).toBe("expires in 5 min");
    expect(expiresIn(now + 61 * 60_000, now)).toBe("expires in 1 h");
    expect(expiresIn(now + 23 * 3_600_000, now)).toBe("expires in 23 h");
    expect(expiresIn(now, now)).toBe("expired");
    expect(expiresIn(now - 1, now)).toBe("expired");
  });

  it("labels and counts", () => {
    expect(toolLabel("trusted_add")).toBe("Trust a network");
    expect(toolLabel("dismiss_alert")).toBe("Dismiss an alert");
    expect(toolLabel("something_else")).toBe("Change");
    expect(requestCountLabel(1)).toBe("1 agent request waiting");
    expect(requestCountLabel(3)).toBe("3 agent requests waiting");
  });

  it("recognises the stale-settings refusal and nothing else", () => {
    const msg =
      "store error: Settings changed elsewhere since this page loaded them; reload and try again.";
    expect(isStaleSettingsError(msg)).toBe(true);
    expect(isStaleSettingsError(new Error(msg))).toBe(true);
    expect(isStaleSettingsError("Save failed")).toBe(false);
    expect(isStaleSettingsError("settings changed")).toBe(false);
    expect(isStaleSettingsError(undefined)).toBe(false);
  });
});

describe("mock backend: proposals, decisions, audit, undo", () => {
  it("lists pending requests described by the app, with a reason when blocked", async () => {
    const list = await listAgentProposals();
    expect(list.length).toBe(2);
    for (const p of list) {
      expect(p.expiresAt - p.createdAt).toBe(24 * 3_600_000);
      expect(p.summary.length).toBeGreaterThan(10);
      // Names are quoted data.
      expect(p.summary).toMatch(/“[^“”]+”/);
    }
    const blocked = list.find((p) => p.blocked);
    expect(blocked?.warnings[0]).toMatch(/evil-twin/);
  });

  it("approving a blocked request is refused and it stays listed", async () => {
    const blocked = (await listAgentProposals()).find((p) => p.blocked)!;
    await expect(decideAgentProposal(blocked.id, true, blocked.digest)).rejects.toMatch(
      /security modes/,
    );
    expect((await listAgentProposals()).some((p) => p.id === blocked.id)).toBe(true);
  });

  it("rejecting clears it without an audit entry; approving applies, audits and can be undone", async () => {
    const before = (await listAgentAudit()).total;
    const blocked = (await listAgentProposals()).find((p) => p.blocked)!;
    const r = await decideAgentProposal(blocked.id, false);
    expect(r).toMatchObject({ status: "rejected", changed: false });
    expect((await listAgentAudit()).total).toBe(before);

    const ok = (await listAgentProposals())[0];
    // Approving without the digest the person was shown, or with a stale one, is refused.
    await expect(decideAgentProposal(ok.id, true)).rejects.toMatch(/changed since you read it/);
    await expect(decideAgentProposal(ok.id, true, "stale")).rejects.toMatch(/changed since/);
    const d = await decideAgentProposal(ok.id, true, ok.digest);
    expect(d).toMatchObject({ status: "approved", changed: true });
    const audit = (await listAgentAudit(50)).entries;
    expect(audit.length).toBe(before + 1);
    // The direct seed entry is pinned above the approved one.
    expect(audit[0].via).toBe("direct");
    const approved = audit.find((a) => a.proposalId === ok.id)!;
    expect(approved).toMatchObject({ addedBy: "agent", via: "proposal", undone: false });
    await expect(decideAgentProposal(ok.id, true, ok.digest)).rejects.toMatch(/no longer exists/);

    await undoAgentChange(approved.id);
    expect((await listAgentAudit(50)).entries.find((a) => a.id === approved.id)?.undone).toBe(true);
    await expect(undoAgentChange(approved.id)).rejects.toMatch(/already undone/);
  });
});

describe("mock backend: settings revision", () => {
  it("an unchanged save writes nothing; a changed one bumps the revision", async () => {
    const s = await getSettings();
    expect((await setSettings(s)).revision).toBe(s.revision);
    const saved = await setSettings({ ...s, notify: !s.notify });
    expect(saved.revision).toBe(s.revision + 1);
  });

  it("?mock=stale plays the refusal once, with the current values, then saves normally", async () => {
    vi.stubGlobal("window", { location: { search: "?mock=stale" } });
    try {
      const s = await getSettings();
      await expect(setSettings({ ...s, scanIntervalSecs: 77 })).rejects.toSatisfy(
        isStaleSettingsError,
      );
      const now = await getSettings();
      expect(now.scanIntervalSecs).toBe(s.scanIntervalSecs);
      expect(now.revision).toBe(s.revision + 1);
      expect((await setSettings({ ...now, scanIntervalSecs: 77 })).scanIntervalSecs).toBe(77);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("audit paging", () => {
  it("pins direct, not-undone changes first and reports the total", async () => {
    const page = await listAgentAudit(1);
    expect(page.entries.length).toBe(1);
    expect(page.total).toBeGreaterThan(1);
    expect(page.pinned).toBeGreaterThanOrEqual(1);
    expect(page.entries[0]).toMatchObject({ via: "direct", undone: false });
  });
});

describe("the UI is wired", () => {
  const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");

  it("the Settings section has the stable id and the page renders it first", () => {
    expect(AGENT_REQUESTS_ID).toBe("agent-requests");
    const section = read("components/settings/agent-requests-section.tsx");
    expect(section).toContain(`id="${AGENT_REQUESTS_ID}"`);
    expect(section).toContain("Approve");
    expect(section).toContain("Reject");
    expect(section).toContain("Undo");
    const page = read("app/settings/page.tsx");
    expect(page).toContain("<AgentRequestsSection />");
    expect(page.indexOf("<AgentRequestsSection />")).toBeLessThan(
      page.indexOf("<TrustedNetworksSection"),
    );
  });

  it("the Dashboard shows the count and links to the section", () => {
    expect(read("app/page.tsx")).toContain("<AgentRequestsBadge />");
    expect(read("components/agent-requests-badge.tsx")).toContain("#${AGENT_REQUESTS_ID}");
  });

  it("agent-supplied text is never rendered as markup or an instruction", () => {
    const section = read("components/settings/agent-requests-section.tsx");
    expect(section).not.toMatch(/dangerouslySetInnerHTML|innerHTML/);
    // The webview decides; the page only ever calls the typed wrappers.
    expect(section).not.toMatch(/invoke\(/);
    // Approve sends the digest of the request as it was shown.
    expect(section).toContain("p.digest");
    expect(section).toContain("Show more");
  });
});
