/**
 * One registry for everything findable on the Settings page. The palette searches it, and
 * tests/settings-registry.test.ts fails when a control in components/settings has no entry, or an
 * entry names an id that is not in those files. Add the entry in the same change as the control.
 *
 * An id is the DOM id on the control (or section). Choosing a result goes to /settings#<id>.
 * Search only ever navigates here; it never changes a setting.
 */
export interface SettingEntry {
  id: string;
  label: string;
  section: string;
  description: string;
  keywords: string[];
}

const TN = "Trusted networks";
const MINE = "Mine";
const PLACES = "Places";
const WATCH = "Watchlist";
const LAN = "Network devices";
const SCAN = "Scanning";
const ALERTS = "Alerts";

export const SETTINGS_REGISTRY: readonly SettingEntry[] = [
  {
    id: "agent-requests",
    label: "Agent requests",
    section: "Agent requests",
    description: "Approve or reject changes an AI agent asked for, and undo changes agents made.",
    keywords: ["agent", "agents", "ai", "mcp", "wbm", "approve", "approval", "proposal", "request", "undo", "audit"],
  },
  {
    id: "trusted-networks",
    label: TN,
    section: TN,
    description: "Get an alert if a trusted name shows up from unfamiliar hardware or weaker security.",
    keywords: ["trust", "trusted", "evil twin", "impostor", "imposter", "fake network", "lookalike", "known network", "ssid", "home wifi"],
  },
  {
    id: "trusted-add",
    label: "Add a trusted network from the current scan",
    section: TN,
    description: "Pick a visible network name to trust.",
    keywords: ["trust a network", "add trusted", "mark trusted", "evil twin", "impostor"],
  },
  {
    id: "mine",
    label: MINE,
    section: MINE,
    description: "Access points and devices you marked as yours are left out of tracking and new-device alerts.",
    keywords: ["my devices", "mine", "own", "rename", "unmark", "ignore", "exclude", "allowlist"],
  },
  {
    id: "places",
    label: PLACES,
    section: PLACES,
    description: "Places are remembered as a set of nearby Wi-Fi hashes, never coordinates. Rename or forget them.",
    keywords: ["location", "where", "rename place", "forget place", "home", "work"],
  },
  {
    id: "place-retention-days",
    label: "Keep places and network devices for (days)",
    section: PLACES,
    description: "How long places, sightings and network devices are kept.",
    keywords: ["retention", "delete", "expire", "purge", "how long", "data age", "privacy"],
  },
  {
    id: "watchlist",
    label: WATCH,
    section: WATCH,
    description: "Get an alert when a network name or hardware vendor you list shows up.",
    keywords: ["watch", "watch for", "alert on name", "blocklist", "pattern", "vendor", "ssid"],
  },
  {
    id: "watchlist-kind",
    label: "Watch for (network name or vendor)",
    section: WATCH,
    description: "Choose whether the new entry matches a network name or a hardware vendor.",
    keywords: ["watch", "ssid", "vendor", "kind"],
  },
  {
    id: "watchlist-match",
    label: "Match mode (contains or exact)",
    section: WATCH,
    description: "Contains matches part of a name; exact means the same name.",
    keywords: ["watch", "exact", "contains", "partial"],
  },
  {
    id: "watchlist-pattern",
    label: "Watchlist pattern",
    section: WATCH,
    description: "The network name or vendor to watch for.",
    keywords: ["watch", "add watch", "name", "vendor"],
  },
  {
    id: "network-devices",
    label: LAN,
    section: LAN,
    description: "Devices on the network you are joined to, and the two opt-in switches that find more of them.",
    keywords: ["lan", "local network", "router", "devices on my network", "neighbors"],
  },
  {
    id: "lan-neighbor-helper",
    label: "Read the full device list",
    section: LAN,
    description: "Adds a background item that runs Apple's arp and ndp every minute. Off by default.",
    keywords: ["arp", "ndp", "neighbor", "neighbour", "neighbor table", "background item", "login item", "launchd", "helper", "device list"],
  },
  {
    id: "lan-active-sweep",
    label: "Find quiet devices with an active sweep",
    section: LAN,
    description: "Sends small packets to your own network to find devices that have not announced themselves. Off by default.",
    keywords: ["sweep", "scan network", "scan lan", "ping", "probe", "active scan", "udp", "transmit", "quiet devices", "discover"],
  },
  {
    id: "scanning",
    label: SCAN,
    section: SCAN,
    description: "How often the app scans, how long it listens for Bluetooth, and how long it keeps history.",
    keywords: ["scan", "frequency", "timing"],
  },
  {
    id: "scan-interval-secs",
    label: "Scan interval (seconds)",
    section: SCAN,
    description: "Time between automatic scans.",
    keywords: ["how often", "frequency", "polling", "refresh rate", "period"],
  },
  {
    id: "ble-scan-secs",
    label: "Bluetooth listen time per scan (seconds)",
    section: SCAN,
    description: "How long each scan listens for Bluetooth devices.",
    keywords: ["ble", "bluetooth", "duration", "listen"],
  },
  {
    id: "retention-hours",
    label: "Keep history for (hours)",
    section: SCAN,
    description: "How long scan history is stored.",
    keywords: ["retention", "history", "delete", "storage", "data age", "purge"],
  },
  {
    id: "alerts",
    label: ALERTS,
    section: ALERTS,
    description: "Choose which kinds of alert you get and how sensitive tracker detection is.",
    keywords: ["notifications", "alert types", "toggles"],
  },
  {
    id: "alert-evil-twin",
    label: "Evil twin (same name, different hardware)",
    section: ALERTS,
    description: "Alert when a network name appears from a second set of hardware.",
    keywords: ["impostor", "imposter", "fake network", "rogue access point", "twin"],
  },
  {
    id: "alert-open-lookalike",
    label: "Open lookalike of a secured network",
    section: ALERTS,
    description: "Alert when an open network copies the name of a secured one.",
    keywords: ["impostor", "downgrade", "fake network", "open network", "lookalike"],
  },
  {
    id: "alert-trusted-network-changed",
    label: "Trusted network changed",
    section: ALERTS,
    description: "Alert when a trusted network shows unfamiliar hardware or weaker security.",
    keywords: ["trust", "trusted", "changed"],
  },
  {
    id: "alert-persistent-tracker",
    label: "Possible tracker nearby (persistent)",
    section: ALERTS,
    description: "Alert when a tracker-like Bluetooth device stays near you.",
    keywords: ["airtag", "tile", "stalker", "tracking", "find my", "bluetooth"],
  },
  {
    id: "alert-new-device",
    label: "New device nearby (noisy)",
    section: ALERTS,
    description: "Alert for every new Bluetooth or Wi-Fi device. Off by default because it is noisy.",
    keywords: ["new", "unknown device", "noisy"],
  },
  {
    id: "alert-followed-across-places",
    label: "Possible device following you across places",
    section: ALERTS,
    description: "Alert when the same device shows up at more than one of your places.",
    keywords: ["following", "stalker", "tracking", "stalking", "multiple places"],
  },
  {
    id: "alert-watchlist",
    label: "Watchlist match",
    section: ALERTS,
    description: "Alert when something on your watchlist shows up.",
    keywords: ["watch", "watchlist", "ssid", "vendor"],
  },
  {
    id: "alert-new-lan-device",
    label: "New device on a network you marked as yours",
    section: ALERTS,
    description: "Alert when an unfamiliar device joins a network you marked as mine.",
    keywords: ["lan", "intruder", "new device", "mine", "home network"],
  },
  {
    id: "tracker-min-scans",
    label: "Tracker: minimum scans",
    section: ALERTS,
    description: "How many scans a device must appear in before it counts as a possible tracker.",
    keywords: ["tracker", "sensitivity", "threshold", "airtag"],
  },
  {
    id: "tracker-min-minutes",
    label: "Tracker: minimum minutes",
    section: ALERTS,
    description: "How long a device must stay nearby before it counts as a possible tracker.",
    keywords: ["tracker", "sensitivity", "threshold", "duration", "airtag"],
  },
  {
    id: "notify",
    label: "Show desktop notifications for new alerts",
    section: ALERTS,
    description: "Pop up a macOS notification when a new alert is created.",
    keywords: ["notification", "notify", "popup", "banner", "desktop", "sound"],
  },
];

export function settingHref(id: string): string {
  return `/settings#${id}`;
}

/**
 * Registry problems for a set of ids found in the Settings source: controls with no entry, and
 * entries whose id is not in the source. `controlIds` are the ids of controls and sections;
 * `allIds` is every id present (controls, sections and other anchors).
 */
export function registryGaps(
  controlIds: readonly string[],
  allIds: readonly string[],
  registry: readonly SettingEntry[] = SETTINGS_REGISTRY,
): { missingEntries: string[]; danglingEntries: string[]; duplicates: string[] } {
  const entryIds = registry.map((e) => e.id);
  const entrySet = new Set(entryIds);
  const present = new Set(allIds);
  const seen = new Set<string>();
  const duplicates: string[] = [];
  for (const id of entryIds) {
    if (seen.has(id)) duplicates.push(id);
    seen.add(id);
  }
  return {
    missingEntries: controlIds.filter((id) => !entrySet.has(id)),
    danglingEntries: entryIds.filter((id) => !present.has(id)),
    duplicates,
  };
}
