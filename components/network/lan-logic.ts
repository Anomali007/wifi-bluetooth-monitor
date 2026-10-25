import type { HelperStatus, LanDevice, NetworkInfo, Settings } from "@/lib/types";

/**
 * Why "Sweep now" would be refused, or null when it may run. Same order and wording as the
 * backend gate (`lan::gate::sweep_gate`), so the page can explain before the user clicks.
 * The backend remains the authority; this only explains. (A network larger than a /23 is still
 * swept, but only with the single IPv6 packet; the backend skips the per-address IPv4 pass.)
 */
export function sweepBlockedReason(
  network: NetworkInfo | null,
  settings: Pick<Settings, "lanActiveSweep"> | null,
): string | null {
  if (!settings || !settings.lanActiveSweep) {
    return "The active sweep is switched off in Settings.";
  }
  if (!network || !network.networkKey) {
    return "Not joined to a Wi-Fi network that can be identified (Location access may be missing).";
  }
  if (!network.isMine) {
    return "This access point is not marked as yours. Mark it as mine first.";
  }
  return null;
}

/**
 * The status line shown when neighbor tables could not be read at all (Apple's built-in `arp`
 * and `ndp` unavailable and macOS hiding the tables from apps), or null when they were.
 */
export function neighborStatus(network: Pick<NetworkInfo, "neighborNote"> | null): string | null {
  const note = network?.neighborNote?.trim();
  return note ? `Showing announced devices only: ${note}.` : null;
}

/** Badge text for how the list was gathered. */
export function modeLabel(network: NetworkInfo | null): string {
  return network?.mode === "sweep" ? "Passive + sweep" : "Passive";
}

/** Where a device came from, in words. */
export function sourceLabel(d: Pick<LanDevice, "source">): string {
  switch (d.source) {
    case "neighbor":
      return "Neighbor table";
    case "announced":
      return "Announced";
    case "both":
      return "Both";
    default:
      return "Earlier version";
  }
}

/** Display name for a LAN device: its announced hostname, else a vendor-based fallback. */
export function deviceName(d: LanDevice): string {
  if (d.hostname) return d.hostname.replace(/\.local$/i, "");
  return d.vendor ? `${d.vendor} device` : "Unnamed device";
}

/** Service types without the leading underscore and protocol: `_http._tcp` -> `http`. */
export function serviceLabel(s: string): string {
  return s.replace(/\._(tcp|udp)$/i, "").replace(/^_/, "");
}

/** Plain-language state of the background item. Pure, so it is unit-tested. */
export function helperStatusLine(status: HelperStatus | null, wanted: boolean): string {
  if (status === "enabled") return "On: the background item is running.";
  if (status === "needsApproval")
    return "Needs your approval: turn it on in System Settings, General, Login Items.";
  if (status === "unavailable") return "Not available in this build.";
  return wanted ? "Press Save to turn it on." : "Off.";
}
