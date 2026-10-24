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
  | "newDevice";

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
  },
  trackerMinScans: 5,
  trackerMinMinutes: 20,
};
