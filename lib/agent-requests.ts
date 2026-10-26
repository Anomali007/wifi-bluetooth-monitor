import type { Millis } from "./types";

/** DOM id of the Settings section; the Dashboard links to `/settings#agent-requests`. */
export const AGENT_REQUESTS_ID = "agent-requests";

/** `expires in 23 h`, `expires in 5 min`, or `expired`. */
export function expiresIn(expiresAt: Millis, now: Millis): string {
  const ms = expiresAt - now;
  if (ms <= 0) return "expired";
  const min = Math.ceil(ms / 60_000);
  if (min < 60) return `expires in ${min} min`;
  return `expires in ${Math.floor(min / 60)} h`;
}

/** What kind of request a tool name stands for, in plain words. */
export function toolLabel(tool: string): string {
  switch (tool) {
    case "trusted_add":
      return "Trust a network";
    case "trusted_remove":
      return "Stop trusting a network";
    case "mine_add":
      return "Mark a device as mine";
    case "mine_remove":
      return "Remove a device from Mine";
    case "dismiss_alert":
      return "Dismiss an alert";
    case "watchlist_add":
      return "Add a watchlist rule";
    case "watchlist_remove":
      return "Remove a watchlist rule";
    default:
      return "Change";
  }
}

/** `1 agent request waiting`, `3 agent requests waiting`. */
export function requestCountLabel(n: number): string {
  return `${n} agent request${n === 1 ? "" : "s"} waiting`;
}

/**
 * True when a settings save was refused because the stored settings changed under the page
 * (for example an agent edit, once the page's base version was no longer remembered). The
 * page must reload, not retry.
 */
export function isStaleSettingsError(e: unknown): boolean {
  const text = typeof e === "string" ? e : e instanceof Error ? e.message : "";
  return /settings changed elsewhere/i.test(text) && /reload/i.test(text);
}

export const STALE_SETTINGS_NOTICE =
  "Settings changed elsewhere (an agent or another window). This page was reloaded with the current values; make your change again and save.";
