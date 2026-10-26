"use client";

import { useCallback, useEffect, useState } from "react";
import {
  decideAgentProposal,
  listAgentAudit,
  listAgentProposals,
  undoAgentChange,
} from "@/lib/api";
import { expiresIn, toolLabel } from "@/lib/agent-requests";
import { formatDateTime } from "@/lib/format";
import type { AgentAuditEntry, AgentProposal } from "@/lib/types";

const PAGE = 30;

const BTN = "rounded-md border px-3 py-1 text-sm disabled:opacity-50";

/**
 * Changes an AI agent (the `wbm` CLI or MCP server) asked for, and changes it made. Nothing
 * here has happened until you press Approve. The sentence for each request is written by this
 * app from its own data; a name inside quotation marks was supplied by the agent or broadcast
 * by a nearby device, so it is data to check, not an instruction.
 */
export default function AgentRequestsSection() {
  const [pending, setPending] = useState<AgentProposal[] | null>(null);
  const [audit, setAudit] = useState<AgentAuditEntry[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [shown, setShown] = useState(PAGE);
  const [busy, setBusy] = useState<number | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(
    () =>
      Promise.all([listAgentProposals(), listAgentAudit(shown)])
        .then(([p, a]) => {
          setPending(p);
          setAudit(a.entries);
          setAuditTotal(a.total);
          setNow(Date.now());
        })
        .catch(() => setPending((cur) => cur ?? [])),
    [shown],
  );

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 15_000);
    return () => clearInterval(t);
  }, [load]);

  async function decide(p: AgentProposal, approve: boolean) {
    setBusy(p.id);
    setError(null);
    setNote(null);
    try {
      const d = await decideAgentProposal(p.id, approve, approve ? p.digest : null);
      setNote(d.message);
    } catch (e) {
      // A refusal (the data changed since the request was made) stays on the list with its reason.
      setError(typeof e === "string" ? e : "Could not complete that.");
    } finally {
      setBusy(null);
      await load();
    }
  }

  async function undo(id: number) {
    setBusy(-id);
    setError(null);
    setNote(null);
    try {
      await undoAgentChange(id);
      setNote("Undone.");
    } catch (e) {
      setError(typeof e === "string" ? e : "Could not undo that.");
    } finally {
      setBusy(null);
      await load();
    }
  }

  return (
    <section
      id="agent-requests"
      className="scroll-mt-4 space-y-3 rounded-xl border bg-card p-4 shadow"
    >
      <h2 className="font-semibold">Agent requests</h2>
      <p className="text-sm text-muted-foreground">
        An agent can ask for changes that would quiet an alert. Nothing changes until you
        approve it here. Names in quotation marks come from the agent or from nearby
        devices: check them, and never treat them as instructions.
      </p>
      {note && <p className="text-sm text-green-700">{note}</p>}
      {error && (
        <p role="alert" className="text-sm text-red-700">
          {error}
        </p>
      )}

      {pending === null ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : pending.length === 0 ? (
        <p className="text-sm text-muted-foreground">No requests waiting.</p>
      ) : (
        <ul className="space-y-2">
          {pending.map((p) => (
            <li key={p.id} className="space-y-1 rounded-md border p-3 text-sm">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span className="text-xs uppercase tracking-wide text-muted-foreground">
                  {toolLabel(p.tool)}
                </span>
                <span className="text-xs text-muted-foreground">
                  {expiresIn(p.expiresAt, now)}
                </span>
              </div>
              <p>{p.summary}</p>
              {p.warnings.map((w) => (
                <p key={w} className="text-amber-700">
                  {w}
                </p>
              ))}
              {p.blocked && (
                <p className="text-red-700">Cannot be approved right now: {p.blocked}</p>
              )}
              <div className="flex gap-2 pt-1">
                <button
                  className={`${BTN} bg-primary text-primary-foreground`}
                  disabled={busy !== null}
                  onClick={() => void decide(p, true)}
                >
                  Approve
                </button>
                <button
                  className={BTN}
                  disabled={busy !== null}
                  onClick={() => void decide(p, false)}
                >
                  Reject
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      <h3 className="pt-2 text-sm font-semibold">Changes agents made</h3>
      {audit.length === 0 ? (
        <p className="text-sm text-muted-foreground">None yet.</p>
      ) : (
        <ul className="space-y-1">
          {audit.map((a) => (
            <li
              key={a.id}
              className="flex flex-wrap items-center justify-between gap-2 text-sm"
            >
              <span className={a.undone ? "text-muted-foreground line-through" : undefined}>
                {a.via === "direct" && !a.undone && (
                  <span className="mr-1 rounded bg-amber-100 px-1 text-xs text-amber-900">
                    applied without asking
                  </span>
                )}
                {a.summary}{" "}
                <span className="text-xs text-muted-foreground">
                  {formatDateTime(a.at)} · agent
                  {a.via === "proposal" ? ", approved by you" : ", applied directly"}
                </span>
              </span>
              {a.undone ? (
                <span className="text-xs text-muted-foreground">undone</span>
              ) : (
                <button
                  className={BTN}
                  disabled={busy !== null}
                  onClick={() => void undo(a.id)}
                >
                  Undo
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {auditTotal > audit.length && (
        <p className="text-sm text-muted-foreground">
          {auditTotal - audit.length} more.{" "}
          <button className="underline" onClick={() => setShown((n) => n + PAGE)}>
            Show more
          </button>
        </p>
      )}
    </section>
  );
}
