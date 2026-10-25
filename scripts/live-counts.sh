#!/usr/bin/env bash
# Prints COUNTS ONLY from the app's local SQLite store: no SSIDs, names or hashes.
# Usage: scripts/live-counts.sh [path/to/store.sqlite3]
# Default: ~/Library/Application Support/com.anomali007.wifibtmonitor/store.sqlite3
# Opens the database read-only, so it is safe to run while the app is running.
set -euo pipefail
DB="${1:-$HOME/Library/Application Support/com.anomali007.wifibtmonitor/store.sqlite3}"
[ -f "$DB" ] || { echo "no database at the app-data path (has the app run?)" >&2; exit 1; }

q() { sqlite3 -readonly -cmd '.timeout 3000' "$DB" "$1"; }

echo "scans stored:               $(q 'SELECT COUNT(*) FROM scans;')"
echo "distinct Wi-Fi networks:    $(q "SELECT COUNT(DISTINCT COALESCE(bssid_hash, ssid)) FROM wifi_sightings WHERE bssid_hash IS NOT NULL OR (ssid IS NOT NULL AND ssid <> '');")"
echo "wifi sightings:             $(q 'SELECT COUNT(*) FROM wifi_sightings;')"
echo "share with a non-nil SSID:  $(q "SELECT CASE WHEN COUNT(*)=0 THEN 'n/a' ELSE printf('%.1f%%', 100.0*SUM(ssid IS NOT NULL AND ssid <> '')/COUNT(*)) END FROM wifi_sightings;")"
echo "distinct BLE devices:       $(q 'SELECT COUNT(DISTINCT peripheral_hash) FROM ble_sightings;')"
echo "trackers by kind (distinct ids):"
rows=$(q "SELECT REPLACE(tracker, '\"', ''), COUNT(DISTINCT peripheral_hash) FROM ble_sightings WHERE tracker IS NOT NULL GROUP BY tracker ORDER BY 1;" | tr '|' ' ')
if [ -n "$rows" ]; then printf '%s\n' "$rows" | sed 's/^/  /'; else echo "  none"; fi
echo "alerts by kind:"
rows=$(q "SELECT REPLACE(kind, '\"', ''), COUNT(*) FROM alerts GROUP BY kind ORDER BY 1;" | tr '|' ' ')
if [ -n "$rows" ]; then printf '%s\n' "$rows" | sed 's/^/  /'; else echo "  none"; fi
echo "--- v2 (counts only) ---"
echo "wifi sightings with a vendor:        $(q "SELECT COUNT(*) FROM wifi_sightings WHERE vendor IS NOT NULL;")"
echo "  of which 'Private address':        $(q "SELECT COUNT(*) FROM wifi_sightings WHERE vendor = 'Private address';")"
echo "radio groups with more than 1 radio: $(q "SELECT COUNT(*) FROM (SELECT group_id FROM wifi_sightings WHERE group_id IS NOT NULL GROUP BY scan_at, group_id HAVING COUNT(DISTINCT bssid_hash) > 1 ) ;")  (group-in-scan instances)"
echo "distinct radio groups (any size):    $(q "SELECT COUNT(DISTINCT group_id) FROM wifi_sightings WHERE group_id IS NOT NULL;")"
echo "places:                              $(q 'SELECT COUNT(*) FROM places;')"
echo "place sightings (wifi/ble/lan):      $(q "SELECT COALESCE(SUM(kind LIKE '%wifi%'),0) || '/' || COALESCE(SUM(kind LIKE '%ble%'),0) || '/' || COALESCE(SUM(kind LIKE '%lan%'),0) FROM place_sightings;")"
echo "mine entries:                        $(q 'SELECT COUNT(*) FROM mine;')"
echo "watchlist entries:                   $(q 'SELECT COUNT(*) FROM watchlist;')"
echo "LAN devices (all):                   $(q 'SELECT COUNT(*) FROM lan_devices;')"
echo "LAN devices with an mDNS hostname:   $(q "SELECT COUNT(*) FROM lan_devices WHERE hostname IS NOT NULL AND hostname <> '';")"
echo "LAN devices with a vendor:           $(q "SELECT COUNT(*) FROM lan_devices WHERE vendor IS NOT NULL;")"
echo "distinct LAN networks:               $(q 'SELECT COUNT(DISTINCT network_key) FROM lan_devices;')"
