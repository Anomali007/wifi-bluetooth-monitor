"use client";

import { SECURITY_LABEL, securityStrength } from "@/lib/format";
import type { TrustedNetwork, WifiObservation } from "@/lib/types";
import type { SectionProps } from "./section";

export default function TrustedNetworksSection({
  draft,
  set,
  wifi,
}: SectionProps & { wifi: WifiObservation[] }) {
  // Current visible networks that can be trusted: named ones, grouped by SSID.
  const candidates = new Map<string, TrustedNetwork>();
  for (const w of wifi) {
    if (!w.ssid) continue;
    const cur = candidates.get(w.ssid) ?? {
      ssid: w.ssid,
      knownBssidHashes: [],
      expectedSecurity: w.security,
    };
    // Expect the strongest mode seen for this name, so a stray weaker AP cannot lower the bar.
    if (securityStrength(w.security) > securityStrength(cur.expectedSecurity)) {
      cur.expectedSecurity = w.security;
    }
    if (w.bssidHash && !cur.knownBssidHashes.includes(w.bssidHash)) {
      cur.knownBssidHashes.push(w.bssidHash);
    }
    candidates.set(w.ssid, cur);
  }
  const trustedSsids = new Set(draft.trustedNetworks.map((t) => t.ssid));

  return (
    <section id="trusted-networks" className="scroll-mt-4 space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Trusted networks</h2>
      <p className="text-sm text-muted-foreground">
        If a trusted name shows up from unfamiliar hardware or weaker security,
        you get an alert. Access points you mark as mine count as familiar.
      </p>
      {draft.trustedNetworks.length === 0 && (
        <p className="text-sm text-muted-foreground">None yet.</p>
      )}
      <ul className="space-y-1">
        {draft.trustedNetworks.map((t) => (
          <li key={t.ssid} className="flex items-center justify-between text-sm">
            <span>
              {t.ssid}{" "}
              <span className="text-muted-foreground">
                ({SECURITY_LABEL[t.expectedSecurity]}, {t.knownBssidHashes.length}{" "}
                known access point{t.knownBssidHashes.length === 1 ? "" : "s"})
              </span>
            </span>
            <button
              onClick={() =>
                set({
                  trustedNetworks: draft.trustedNetworks.filter(
                    (x) => x.ssid !== t.ssid,
                  ),
                })
              }
              className="rounded-md border px-2 py-0.5 hover:bg-accent"
            >
              Remove
            </button>
          </li>
        ))}
      </ul>
      <div>
        <h3 id="trusted-add" className="mb-1 text-sm font-medium">Add from current scan</h3>
        {candidates.size === 0 ? (
          <p className="text-sm text-muted-foreground">
            No named networks in the latest scan (Location permission may be
            missing).
          </p>
        ) : (
          <ul className="space-y-1">
            {Array.from(candidates.values()).map((c) => (
              <li key={c.ssid} className="flex items-center justify-between text-sm">
                <span>
                  {c.ssid}{" "}
                  <span className="text-muted-foreground">
                    ({SECURITY_LABEL[c.expectedSecurity]})
                  </span>
                </span>
                <button
                  disabled={trustedSsids.has(c.ssid)}
                  onClick={() =>
                    set({ trustedNetworks: [...draft.trustedNetworks, c] })
                  }
                  className="rounded-md border px-2 py-0.5 hover:bg-accent disabled:opacity-40"
                >
                  {trustedSsids.has(c.ssid) ? "Trusted" : "Trust"}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
