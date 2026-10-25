/**
 * TypeScript mirror of src-tauri/src/model.rs. FROZEN after Phase 0: change both files
 * together, integrator only. Rust serialises camelCase; enums are string unions;
 * every timestamp is Unix milliseconds.
 */

/** Unix time in milliseconds. */
export type Millis = number;

/** Push event names (model::EVENT_SCAN / EVENT_ALERT). */
export const EVENT_SCAN = "wbm://scan";
export const EVENT_ALERT = "wbm://alert";

export type Security =
  | "open"
  | "wep"
  | "wpaPersonal"
  | "wpa2Personal"
  | "wpa3Personal"
  | "wpaEnterprise"
  | "wpa2Enterprise"
  | "wpa3Enterprise"
  | "owe"
  | "unknown";

export type TrackerKind =
  | "appleFindMy"
  | "tile"
  | "samsungSmartTag"
  | "chipolo"
  | "pebblebee"
  | "googleFindMy"
  | "unknownTracker";

/**
 * Find My style adverts only. "separated" may alert; "nearOwner" is an owner's own accessory
 * (or an Apple device) and never does. Mirror of `OwnerState` in model.rs.
 */
export type OwnerState = "separated" | "nearOwner";

export interface WifiObservation {
  /** null when macOS withholds it (no Location permission) or the network is hidden. */
  ssid: string | null;
  /** Salted SHA-256 of the BSSID; null when withheld. */
  bssidHash: string | null;
  /** dBm */
  rssi: number;
  channel: number | null;
  security: Security;
  seenAt: Millis;
  /** Short vendor from the BSSID's OUI; "Private address" when locally administered; null if unknown. */
  vendor: string | null;
  /** Salted hash shared by the radios of one physical access point in one scan; null if withheld. */
  groupId: string | null;
}

export interface BleObservation {
  name: string | null;
  /** Salted SHA-256 of the CoreBluetooth peripheral UUID. */
  peripheralHash: string;
  /** dBm */
  rssi: number | null;
  /** Non-null only for an alertable signature; nearby-owner Find My adverts are null. */
  tracker: TrackerKind | null;
  /** Find My style adverts only; null otherwise and for rows stored before this existed. */
  ownerState: OwnerState | null;
  /** Manufacturer company identifier, e.g. 0x004C = 76 (Apple). */
  manufacturerId: number | null;
  seenAt: Millis;
}

export type PermissionStatus =
  | "granted"
  | "denied"
  | "notDetermined"
  | "restricted"
  | "unknown";

export interface PermissionState {
  bluetooth: PermissionStatus;
  location: PermissionStatus;
}

export type ScanSource = "wifi" | "ble" | "store" | "detect";
export type ScanErrorCode =
  | "permissionDenied"
  | "unavailable"
  | "timeout"
  | "failed";

export interface ScanError {
  source: ScanSource;
  code: ScanErrorCode;
  message: string;
}

export interface ScanResult {
  scannedAt: Millis;
  wifi: WifiObservation[];
  ble: BleObservation[];
  errors: ScanError[];
  permissions: PermissionState;
}

export interface ScanSnapshot {
  scannedAt: Millis;
  wifi: WifiObservation[];
  ble: BleObservation[];
}

/** Ascending by scannedAt; last element is the newest scan. */
export interface History {
  scans: ScanSnapshot[];
}

export type AlertKind =
  | "evilTwin"
  | "openLookalike"
  | "trustedNetworkChanged"
  | "persistentTracker"
  | "newDevice"
  | "followedAcrossPlaces"
  | "watchlist"
  | "newLanDevice";

export type Severity = "info" | "low" | "medium" | "high";

export interface Alert {
  id: string;
  kind: AlertKind;
  severity: Severity;
  title: string;
  detail: string;
  firstSeen: Millis;
  lastSeen: Millis;
  /** Hash of what the alert is about; never a raw identifier. */
  subjectHash: string;
  dismissed: boolean;
}

export interface TrustedNetwork {
  ssid: string;
  knownBssidHashes: string[];
  expectedSecurity: Security;
}

export interface AlertToggles {
  evilTwin: boolean;
  openLookalike: boolean;
  trustedNetworkChanged: boolean;
  persistentTracker: boolean;
  newDevice: boolean;
  /** default true */
  followedAcrossPlaces: boolean;
  /** default true; does nothing until the watchlist has entries */
  watchlist: boolean;
  /** default true; only fires on networks whose access point is marked mine */
  newLanDevice: boolean;
}

export interface Settings {
  trustedNetworks: TrustedNetwork[];
  /** default 60 */
  scanIntervalSecs: number;
  /** default 10 */
  bleScanSecs: number;
  /** default 24 */
  retentionHours: number;
  /** default true */
  notify: boolean;
  alertToggles: AlertToggles;
  /** default 5 */
  trackerMinScans: number;
  /** default 20 */
  trackerMinMinutes: number;
  /** Days places, place sightings and LAN devices are kept. default 14 */
  placeRetentionDays: number;
  /** Opt-in LAN sweep (one zero-byte UDP datagram per host), only while the joined access point is mine. default false */
  lanActiveSweep: boolean;
}

// ---- Places, Mine, watchlist, LAN (mirror of the v2 section of model.rs) ----

export interface Place {
  id: number;
  /** null shows as "Place N" */
  label: string | null;
  /** Member BSSID hashes. */
  members: string[];
  firstSeen: Millis;
  lastSeen: Millis;
}

export type SightingKind = "wifi" | "ble" | "lan";

export interface PlaceSighting {
  kind: SightingKind;
  idHash: string;
  placeId: number;
  firstSeen: Millis;
  lastSeen: Millis;
  scans: number;
}

export type MineKind = "wifiAp" | "wifiGroup" | "ble" | "lan";

export interface MineEntry {
  kind: MineKind;
  idHash: string;
  label: string | null;
  addedAt: Millis;
}

export type WatchKind = "ssid" | "vendor";
export type WatchMatch = "exact" | "contains";

export interface WatchlistEntry {
  id: number;
  kind: WatchKind;
  pattern: string;
  /** Serialised as `match` (Rust field `match_mode`). */
  match: WatchMatch;
  addedAt: Millis;
}

export interface LanDevice {
  networkKey: string;
  macHash: string;
  vendor: string | null;
  /** mDNS hostname, if announced. */
  hostname: string | null;
  /** mDNS service types, e.g. "_http._tcp". */
  services: string[];
  firstSeen: Millis;
  lastSeen: Millis;
  /** Live only, from the current neighbor/ARP tables or mDNS; never persisted. */
  ip: string | null;
  mine: boolean;
  /**
   * How it was learned: in the neighbor table ("neighbor"), heard announcing itself over mDNS
   * with no hardware address ("announced"), or both. Null only for rows from before v4.
   */
  source: LanSource | null;
}

export type LanSource = "neighbor" | "announced" | "both";

export type LanMode = "passive" | "sweep";

export interface NetworkInfo {
  networkKey: string | null;
  ssid: string | null;
  bssidHash: string | null;
  groupId: string | null;
  /** CIDR, e.g. "192.0.2.0/24" */
  subnet: string | null;
  /** The joined access point (or its radio group) is in Mine. */
  isMine: boolean;
  /** lanActiveSweep is on AND isMine: a sweep may run. */
  sweepEnabled: boolean;
  mode: LanMode;
  lastSweepAt: Millis | null;
}

export const DEFAULT_SETTINGS: Settings = {
  trustedNetworks: [],
  scanIntervalSecs: 60,
  bleScanSecs: 10,
  retentionHours: 24,
  notify: true,
  alertToggles: {
    evilTwin: true,
    openLookalike: true,
    trustedNetworkChanged: true,
    persistentTracker: true,
    newDevice: false,
    followedAcrossPlaces: true,
    watchlist: true,
    newLanDevice: true,
  },
  trackerMinScans: 5,
  trackerMinMinutes: 20,
  placeRetentionDays: 14,
  lanActiveSweep: false,
};
