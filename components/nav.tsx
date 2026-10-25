"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useMonitor } from "./monitor-provider";

const LINKS = [
  { href: "/", label: "Dashboard" },
  { href: "/alerts", label: "Alerts" },
  { href: "/history", label: "History" },
  { href: "/network", label: "Network" },
  { href: "/settings", label: "Settings" },
];

export default function Nav() {
  const path = usePathname() ?? "/";
  const { alerts } = useMonitor();
  const active = (href: string) =>
    href === "/" ? path === "/" : path.startsWith(href);
  return (
    <nav className="border-b bg-card">
      <div className="container mx-auto flex items-center gap-1 px-4 py-2">
        <span className="mr-4 font-semibold">Network Security Monitor</span>
        {LINKS.map((l) => (
          <Link
            key={l.href}
            href={l.href}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm hover:bg-accent",
              active(l.href) && "bg-accent font-medium",
            )}
          >
            {l.label}
            {l.href === "/alerts" && alerts.length > 0 && (
              <span className="ml-1.5 rounded-full bg-destructive px-1.5 py-0.5 text-xs text-destructive-foreground">
                {alerts.length}
              </span>
            )}
          </Link>
        ))}
        <span className="ml-auto text-xs text-muted-foreground">
          Listen-only: nothing is transmitted
        </span>
      </div>
    </nav>
  );
}
