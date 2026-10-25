import type { LanDevice, NetworkInfo, Settings } from "@/lib/types";

/**
 * Why "Sweep now" would be refused, or null when it may run. Same order and wording as the
 * backend gate (`lan::gate::sweep_gate`), so the page can explain before the user clicks.
 * The backend remains the authority; this only explains. The sweep is one IPv6 packet on the
 * link, so the network's IPv4 size no longer matters.
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
