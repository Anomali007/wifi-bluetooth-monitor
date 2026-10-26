import type { Settings } from "@/lib/types";

/** Props every settings section that edits the draft receives from app/settings/page.tsx. */
export interface SectionProps {
  draft: Settings;
  set: (patch: Partial<Settings>) => void;
}
