"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { listAgentProposals } from "@/lib/api";
import { AGENT_REQUESTS_ID, requestCountLabel } from "@/lib/agent-requests";

/** A small count of agent requests waiting for a decision; nothing when there are none. */
export default function AgentRequestsBadge() {
  const [count, setCount] = useState(0);
  useEffect(() => {
    let live = true;
    const load = () =>
      listAgentProposals()
        .then((p) => live && setCount(p.length))
        .catch(() => live && setCount(0));
    void load();
    const t = setInterval(load, 15_000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);
  if (count === 0) return null;
  return (
    <Link
      href={`/settings#${AGENT_REQUESTS_ID}`}
      className="rounded-full bg-amber-100 px-3 py-1 text-xs font-medium text-amber-900"
    >
      {requestCountLabel(count)}
    </Link>
  );
}
