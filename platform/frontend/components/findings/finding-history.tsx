"use client";

import React from "react";
import { History as HistoryIcon } from "lucide-react";
import { useFindingHistory } from "@/hooks/use-findings";
import { formatRelativeTime } from "@/lib/utils";
import type { FindingHistoryEntry } from "@/types";

interface FindingHistoryProps {
  findingId: string;
}

const ACTION_LABELS: Record<string, string> = {
  "finding.created": "Finding created",
  "finding.deleted": "Finding deleted",
  "finding.status_changed": "Finding updated",
};

const FIELD_LABELS: Record<string, string> = {
  status: "Status",
  severity: "Severity",
  false_positive: "False positive flag",
  suppressed: "Suppressed",
};

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "none";
  if (typeof value === "boolean") return value ? "true" : "false";
  return String(value).replace(/_/g, " ");
}

/** Builds a human-readable summary of what actually changed between before/after_state. */
function describeChange(entry: FindingHistoryEntry): string[] {
  const before = entry.before_state ?? {};
  const after = entry.after_state ?? {};
  const changes: string[] = [];

  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const key of keys) {
    const beforeVal = (before as Record<string, unknown>)[key];
    const afterVal = (after as Record<string, unknown>)[key];
    if (beforeVal === afterVal) continue;
    const label = FIELD_LABELS[key] || key;
    changes.push(`${label} changed from ${formatValue(beforeVal)} to ${formatValue(afterVal)}`);
  }
  return changes;
}

function HistoryEntryRow({ entry }: { entry: FindingHistoryEntry }) {
  const actionLabel = ACTION_LABELS[entry.action] || entry.action;
  const changes = describeChange(entry);

  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center pt-0.5">
        <div className="h-2 w-2 rounded-full bg-zinc-600" />
        <div className="w-px flex-1 bg-zinc-800 mt-1" />
      </div>
      <div className="flex-1 min-w-0 pb-3">
        <div className="flex items-baseline gap-2 flex-wrap">
          <span className="text-sm font-medium text-zinc-300">{actionLabel}</span>
          <span className="text-xs text-zinc-600">
            by {entry.user_name || "Unknown"} · {formatRelativeTime(entry.created_at)}
          </span>
        </div>
        {changes.length > 0 && (
          <ul className="mt-1 space-y-0.5">
            {changes.map((c, i) => (
              <li key={i} className="text-sm text-zinc-400 leading-relaxed">
                {c}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export function FindingHistory({ findingId }: FindingHistoryProps) {
  const { data, isLoading } = useFindingHistory(findingId);
  const entries = data?.items ?? [];

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-zinc-300 flex items-center gap-1.5">
        <HistoryIcon className="h-4 w-4 text-zinc-500" />
        History {entries.length > 0 && <span className="text-zinc-500">({entries.length})</span>}
      </h3>

      {isLoading ? (
        <p className="text-sm text-zinc-600 py-2">Loading history...</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-zinc-600 py-2">No recorded history for this finding.</p>
      ) : (
        <div>
          {entries.map((entry, i) => (
            <div key={entry.id} className={i === entries.length - 1 ? "[&_.w-px]:hidden" : ""}>
              <HistoryEntryRow entry={entry} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
