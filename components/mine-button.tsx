"use client";

import type { MineKind } from "@/lib/types";

export interface MineTarget {
  kind: MineKind;
  idHash: string;
  /** The device rotates its address (e.g. Apple BLE), so a mark will not last. */
  rotatingAddress: boolean;
}

/**
 * STUB (WP-AB owns): "Mark as mine" / "Mine" toggle for a device-table row. Renders nothing
 * until WP-AB builds it; device-table.tsx already places it in the last cell.
 */
export default function MineButton({ target }: { target: MineTarget }) {
  void target;
  return null;
}
