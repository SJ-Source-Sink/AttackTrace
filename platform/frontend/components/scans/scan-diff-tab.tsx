"use client";

import React from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ScanDiff } from "@/types";

interface ScanDiffTabProps {
  diff: ScanDiff;
}

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400 border-red-700/50 bg-red-950/40",
  high: "text-orange-400 border-orange-700/50 bg-orange-950/40",
  medium: "text-yellow-400 border-yellow-700/50 bg-yellow-950/40",
  low: "text-blue-400 border-blue-700/50 bg-blue-950/40",
  info: "text-zinc-400 border-zinc-700/50 bg-zinc-900/40",
};

function SectionHeader({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="flex items-center gap-2 mb-2">
      <span className={cn("text-sm font-semibold", color)}>{label}</span>
      <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">{count}</span>
    </div>
  );
}

export function ScanDiffTab({ diff }: ScanDiffTabProps) {
  const hasChanges =
    diff.new_assets.length > 0 ||
    diff.removed_assets.length > 0 ||
    diff.new_findings.length > 0 ||
    diff.resolved_findings.length > 0;

  if (!hasChanges && !diff.previous_scan_id) {
    return (
      <div className="py-12 text-center text-sm text-zinc-500">
        This is the first scan for this target — no previous scan to compare against.
      </div>
    );
  }

  if (!hasChanges) {
    return (
      <div className="py-12 text-center text-sm text-zinc-500">
        No changes detected compared to the previous scan.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary bar */}
      <div className="flex flex-wrap gap-4 rounded-lg border border-zinc-800 bg-zinc-900 p-3 text-sm">
        {diff.new_assets.length > 0 && (
          <span className="text-emerald-400">+{diff.new_assets.length} new assets</span>
        )}
        {diff.removed_assets.length > 0 && (
          <span className="text-red-400">-{diff.removed_assets.length} removed assets</span>
        )}
        {diff.new_findings.length > 0 && (
          <span className="text-orange-400">+{diff.new_findings.length} new findings</span>
        )}
        {diff.resolved_findings.length > 0 && (
          <span className="text-emerald-400">{diff.resolved_findings.length} resolved</span>
        )}
      </div>

      {/* New Assets */}
      {diff.new_assets.length > 0 && (
        <div>
          <SectionHeader label="New Assets" count={diff.new_assets.length} color="text-emerald-400" />
          <div className="rounded-lg border border-zinc-800 divide-y divide-zinc-800 overflow-hidden">
            {diff.new_assets.map((asset, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2.5 bg-emerald-950/10 hover:bg-emerald-950/20 transition-colors">
                <span className="text-emerald-500 text-xs font-bold">+</span>
                <Badge variant="secondary" className="text-[10px] capitalize shrink-0">{asset.type}</Badge>
                <span className="font-mono text-xs text-zinc-300 truncate">{asset.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Removed Assets */}
      {diff.removed_assets.length > 0 && (
        <div>
          <SectionHeader label="Removed Assets" count={diff.removed_assets.length} color="text-red-400" />
          <div className="rounded-lg border border-zinc-800 divide-y divide-zinc-800 overflow-hidden">
            {diff.removed_assets.map((asset, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2.5 bg-red-950/10 hover:bg-red-950/20 transition-colors">
                <span className="text-red-500 text-xs font-bold">-</span>
                <Badge variant="secondary" className="text-[10px] capitalize shrink-0">{asset.type}</Badge>
                <span className="font-mono text-xs text-zinc-400 line-through truncate">{asset.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* New Findings */}
      {diff.new_findings.length > 0 && (
        <div>
          <SectionHeader label="New Findings" count={diff.new_findings.length} color="text-orange-400" />
          <div className="rounded-lg border border-zinc-800 divide-y divide-zinc-800 overflow-hidden">
            {diff.new_findings.map((finding, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2.5 bg-orange-950/5 hover:bg-orange-950/10 transition-colors">
                <span className="text-orange-500 text-xs font-bold">+</span>
                <span
                  className={cn(
                    "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize shrink-0",
                    SEV_COLORS[finding.severity] ?? SEV_COLORS.info
                  )}
                >
                  {finding.severity}
                </span>
                <span className="text-sm text-zinc-300 truncate flex-1">{finding.title}</span>
                <span className="font-mono text-xs text-zinc-500 truncate max-w-[200px] shrink-0">{finding.asset}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Resolved Findings */}
      {diff.resolved_findings.length > 0 && (
        <div>
          <SectionHeader label="Resolved Findings" count={diff.resolved_findings.length} color="text-emerald-400" />
          <div className="rounded-lg border border-zinc-800 divide-y divide-zinc-800 overflow-hidden">
            {diff.resolved_findings.map((finding, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2.5 bg-emerald-950/5 hover:bg-emerald-950/10 transition-colors opacity-70">
                <span className="text-emerald-500 text-xs">✓</span>
                <span
                  className={cn(
                    "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize shrink-0",
                    SEV_COLORS[finding.severity] ?? SEV_COLORS.info
                  )}
                >
                  {finding.severity}
                </span>
                <span className="text-sm text-zinc-500 line-through truncate flex-1">{finding.title}</span>
                <span className="font-mono text-xs text-zinc-600 truncate max-w-[200px] shrink-0">{finding.asset}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
