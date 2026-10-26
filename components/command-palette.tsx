"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { rowsFrom } from "@/components/device-table";
import { useMonitor } from "@/components/monitor-provider";
import { listLanDevices, listPlaces } from "@/lib/api";
import {
  ACTIONS,
  PAGES,
  SETTING_ITEMS,
  dataItems,
  search,
  type PaletteItem,
} from "@/lib/palette-items";
import { placeName } from "@/components/mine-state";
import { reveal } from "@/lib/reveal";
import { cn } from "@/lib/utils";
import type { LanDevice, Place } from "@/lib/types";

/** The nav button opens the palette by dispatching this on window. */
export const OPEN_PALETTE_EVENT = "wbm:open-palette";

function typingInField(el: Element | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  return el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName);
}

export default function CommandPalette() {
  const router = useRouter();
  const { scan, alerts, refresh } = useMonitor();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [places, setPlaces] = useState<Place[]>([]);
  const [lan, setLan] = useState<LanDevice[]>([]);
  const returnFocus = useRef<HTMLElement | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const uid = useId();
  const listId = `${uid}-list`;
  const optId = (i: number) => `${uid}-opt-${i}`;

  const openPalette = useCallback(() => {
    returnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setQuery("");
    setActive(0);
    setOpen(true);
  }, []);

  const close = useCallback((restoreFocus: boolean) => {
    setOpen(false);
    if (restoreFocus) {
      const el = returnFocus.current;
      // After the dialog unmounts, so the browser does not move focus back to <body>.
      window.setTimeout(() => el?.focus(), 0);
    }
  }, []);

  // Global shortcuts: Cmd/Ctrl+K anywhere, "/" when no field has focus.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (open) close(true);
        else openPalette();
        return;
      }
      if (
        e.key === "/" &&
        !e.metaKey &&
        !e.ctrlKey &&
        !e.altKey &&
        !open &&
        !typingInField(document.activeElement)
      ) {
        e.preventDefault();
        openPalette();
      }
    };
    const onOpen = () => openPalette();
    window.addEventListener("keydown", onKey);
    window.addEventListener(OPEN_PALETTE_EVENT, onOpen);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener(OPEN_PALETTE_EVENT, onOpen);
    };
  }, [open, close, openPalette]);

  // Places and network devices are not in the monitor context; load them when the palette opens.
  useEffect(() => {
    if (!open) return;
    let live = true;
    listPlaces().then((p) => live && setPlaces(p), () => {});
    listLanDevices().then((d) => live && setLan(d), () => {});
    return () => {
      live = false;
    };
  }, [open]);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const items: PaletteItem[] = useMemo(() => {
    const rows = scan ? rowsFrom(scan.wifi, scan.ble) : [];
    return [
      ...PAGES,
      ...ACTIONS,
      ...SETTING_ITEMS,
      ...dataItems({
        wifi: rows
          .filter((r) => r.type === "Wi-Fi" && !r.name.startsWith("("))
          .map((r) => ({ ssid: r.name, vendor: r.vendor, rowKey: r.key })),
        ble: rows
          .filter((r) => r.type === "Bluetooth" && r.name !== "Unnamed device")
          .map((r) => ({ name: r.name, rowKey: r.key })),
        lan,
        places: places.map((p) => ({ id: p.id, label: placeName(p) })),
        alerts,
      }),
    ];
  }, [scan, lan, places, alerts]);

  const sections = useMemo(() => search(query, items), [query, items]);
  const flat = useMemo(() => sections.flatMap((s) => s.items), [sections]);

  useEffect(() => {
    document.getElementById(optId(active))?.scrollIntoView({ block: "nearest" });
    // optId is stable per uid
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, open]);

  const choose = (item: PaletteItem) => {
    if (item.action === "scan-now") {
      close(true);
      void refresh();
      return;
    }
    // Navigating moves focus to the target, so do not pull it back to where it was.
    close(false);
    if (item.href) {
      router.push(item.href);
      if (item.target) reveal(item.target);
    }
  };

  const onInputKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (flat.length) setActive((a) => (a + 1) % flat.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (flat.length) setActive((a) => (a - 1 + flat.length) % flat.length);
    } else if (e.key === "Home" && e.ctrlKey) {
      setActive(0);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const item = flat[active];
      if (item) choose(item);
    } else if (e.key === "Escape") {
      e.preventDefault();
      close(true);
    } else if (e.key === "Tab") {
      e.preventDefault(); // the dialog has one tab stop
    }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 px-4 pt-[12vh]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) close(true);
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Search"
        className="w-full max-w-xl overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-lg"
      >
        <input
          ref={inputRef}
          role="combobox"
          aria-expanded={flat.length > 0}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={flat.length > 0 ? optId(active) : undefined}
          aria-label="Search settings, pages and devices"
          placeholder="Search settings, pages, devices..."
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={onInputKey}
          autoComplete="off"
          spellCheck={false}
          className="w-full border-b bg-transparent px-4 py-3 text-sm outline-none placeholder:text-muted-foreground"
        />
        <div
          id={listId}
          role="listbox"
          aria-label="Results"
          className="max-h-[50vh] overflow-y-auto p-2"
        >
          {sections.map((s) => (
            <div key={s.group} role="group" aria-labelledby={`${uid}-g-${s.group}`} className="mb-1">
              <div
                id={`${uid}-g-${s.group}`}
                role="presentation"
                className="px-2 py-1 text-xs font-medium text-muted-foreground"
              >
                {s.title}
              </div>
              {s.items.map((item) => {
                const i = flat.indexOf(item);
                return (
                  <div
                    key={item.id}
                    id={optId(i)}
                    role="option"
                    aria-selected={i === active}
                    onMouseMove={() => i !== active && setActive(i)}
                    onClick={() => choose(item)}
                    className={cn(
                      "flex cursor-pointer items-baseline justify-between gap-3 rounded-md px-2 py-1.5 text-sm",
                      i === active && "bg-accent text-accent-foreground",
                    )}
                  >
                    <span className="truncate">{item.label}</span>
                    {item.hint && (
                      <span className="shrink-0 text-xs text-muted-foreground">{item.hint}</span>
                    )}
                  </div>
                );
              })}
            </div>
          ))}
          {flat.length === 0 && (
            <p className="px-2 py-6 text-center text-sm text-muted-foreground">
              No results for &ldquo;{query}&rdquo;
            </p>
          )}
        </div>
        <div className="flex gap-4 border-t px-4 py-2 text-xs text-muted-foreground">
          <span>Up and down to move</span>
          <span>Enter to open</span>
          <span>Esc to close</span>
        </div>
        <p role="status" className="sr-only">
          {query.trim() === "" ? "" : `${flat.length} result${flat.length === 1 ? "" : "s"}`}
        </p>
      </div>
    </div>
  );
}
