import type { LanDevice, NetworkInfo, Settings } from "@/lib/types";

/** Widest subnet the sweep runs on (a /23 is 512 addresses). Mirrors `lan::gate::MIN_PREFIX`. */
export const MIN_SWEEP_PREFIX = 23;
/** Narrowest subnet with another host to sweep. Mirrors `lan::gate::MAX_PREFIX`. */
export const MAX_SWEEP_PREFIX = 30;

/** Prefix length from CIDR text (`192.0.2.0/24` -> 24), or null if it does not parse. */
export function subnetPrefix(cidr: string | null): number | null {
  if (!cidr) return null;
  const m = /^\d{1,3}(?:\.\d{1,3}){3}\/(\d{1,2})$/.exec(cidr);
  if (!m) return null;
  const n = Number(m[1]);
  return n >= 0 && n <= 32 ? n : null;
}

/**
 * Why "Sweep now" would be refused, or null when it may run. Same order and wording as the
 * backend gate (`lan::gate::sweep_gate`), so the page can explain before the user clicks.
 * The backend remains the authority; this only explains.
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
  const prefix = subnetPrefix(network.subnet);
  if (prefix === null) return "The Wi-Fi interface has no IPv4 address yet.";
  if (prefix < MIN_SWEEP_PREFIX) {
    return "This network is larger than a /23 (512 addresses); the sweep only runs on small networks.";
  }
  if (prefix > MAX_SWEEP_PREFIX) return "This network has no other addresses to sweep.";
  return null;
}

/** Badge text for how the list was gathered. */
export function modeLabel(network: NetworkInfo | null): string {
  return network?.mode === "sweep" ? "Passive + sweep" : "Passive";
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
