"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  dismissAlert,
  getAlerts,
  getPermissions,
  getSettings,
  onAlert,
  onScan,
  scanNow,
  setSettings,
} from "@/lib/api";
import type { Alert, PermissionState, ScanResult, Settings } from "@/lib/types";

interface MonitorState {
  scan: ScanResult | null;
  permissions: PermissionState | null;
  alerts: Alert[];
  settings: Settings | null;
  scanning: boolean;
  /** Last command failure (IPC errors arrive as strings). */
  error: string | null;
  refresh: () => Promise<void>;
  dismiss: (id: string) => Promise<void>;
  saveSettings: (s: Settings) => Promise<void>;
}

const Ctx = createContext<MonitorState | null>(null);

function msg(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : "Unknown error";
}

export function MonitorProvider({ children }: { children: React.ReactNode }) {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [permissions, setPermissions] = useState<PermissionState | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [settings, setSettingsState] = useState<Settings | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const busy = useRef(false);

  const loadAlerts = useCallback(async () => {
    try {
      setAlerts(await getAlerts(false));
    } catch (e) {
      setError(msg(e));
    }
  }, []);

  const refresh = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    setScanning(true);
    try {
      const r = await scanNow();
      setScan(r);
      setPermissions(r.permissions);
      setError(null);
      await loadAlerts();
    } catch (e) {
      setError(msg(e));
    } finally {
      busy.current = false;
      setScanning(false);
    }
  }, [loadAlerts]);

  useEffect(() => {
    let alive = true;
    const unsubs: Array<() => void> = [];
    (async () => {
      try {
        const [p, s] = await Promise.all([getPermissions(), getSettings()]);
        if (!alive) return;
        setPermissions(p);
        setSettingsState(s);
      } catch (e) {
        if (alive) setError(msg(e));
      }
      await loadAlerts();
      // Push events from the backend scan loop. Guarded: outside Tauri (plain browser)
      // listen() throws, and the page still works via the manual Scan button.
      try {
        const u1 = await onScan((r) => {
          setScan(r);
          setPermissions(r.permissions);
          void loadAlerts();
        });
        const u2 = await onAlert(() => void loadAlerts());
        if (alive) unsubs.push(u1, u2);
        else {
          u1();
          u2();
        }
      } catch {
        /* no event bridge available */
      }
      if (alive) void refresh();
    })();
    return () => {
      alive = false;
      unsubs.forEach((u) => u());
    };
  }, [loadAlerts, refresh]);

  const dismiss = useCallback(
    async (id: string) => {
      try {
        await dismissAlert(id);
        await loadAlerts();
      } catch (e) {
        setError(msg(e));
      }
    },
    [loadAlerts],
  );

  const saveSettings = useCallback(async (s: Settings) => {
    try {
      setSettingsState(await setSettings(s));
      setError(null);
    } catch (e) {
      setError(msg(e));
      throw e;
    }
  }, []);

  const value = useMemo(
    () => ({
      scan,
      permissions,
      alerts,
      settings,
      scanning,
      error,
      refresh,
      dismiss,
      saveSettings,
    }),
    [scan, permissions, alerts, settings, scanning, error, refresh, dismiss, saveSettings],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useMonitor(): MonitorState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useMonitor outside MonitorProvider");
  return v;
}
