"use client";

import React, { useState } from "react";
import { ShieldAlert, ChevronLeft, ChevronRight, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/shared/empty-state";
import { FindingRow } from "@/components/findings/finding-row";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useFindings } from "@/hooks/use-findings";
import type { FindingFilters, FindingSeverity, FindingStatus } from "@/types";

const SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: FindingStatus[] = ["open", "in_progress", "remediated", "accepted_risk", "false_positive"];
const PER_PAGE = 25;

export default function FindingsPage() {
  const [viewMode, setViewMode] = useState<'active' | 'suppressed'>('active');
  const [filters, setFilters] = useState<FindingFilters>({ statuses: ["open", "in_progress"] });
  const [kevOnly, setKevOnly] = useState(false);
  const [confidenceFilter, setConfidenceFilter] = useState("");
  const [page, setPage] = useState(1);

  // Build query params based on view mode + filters
  const activeQueryFilters: FindingFilters & { page?: number; per_page?: number } = viewMode === 'active'
    ? {
        ...filters,
        suppressed: false,
        kev_only: kevOnly || undefined,
        confidence: confidenceFilter || undefined,
        page,
        per_page: PER_PAGE,
      }
    : {
        suppressed: true,
        page,
        per_page: PER_PAGE,
      };

  const { data, isLoading } = useFindings(activeQueryFilters);
  const findings = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PER_PAGE);

  // Fetch suppressed count for the badge
  const { data: suppressedData } = useFindings({ suppressed: true, per_page: 1, page: 1 });
  const suppressedCount = suppressedData?.total ?? 0;

  const toggleSeverity = (severity: FindingSeverity) => {
    const current = filters.severities ?? [];
    const updated = current.includes(severity)
      ? current.filter((s) => s !== severity)
      : [...current, severity];
    setFilters((f) => ({ ...f, severities: updated.length > 0 ? updated : undefined }));
    setPage(1);
  };

  const toggleStatus = (status: FindingStatus) => {
    const current = filters.statuses ?? [];
    const updated = current.includes(status)
      ? current.filter((s) => s !== status)
      : [...current, status];
    setFilters((f) => ({ ...f, statuses: updated.length > 0 ? updated : undefined }));
    setPage(1);
  };

  const clearFilters = () => {
    setFilters({});
    setKevOnly(false);
    setConfidenceFilter("");
    setPage(1);
  };

  const hasFilters =
    (filters.severities?.length ?? 0) > 0 ||
    (filters.statuses?.length ?? 0) > 0 ||
    !!filters.has_cve ||
    kevOnly ||
    !!confidenceFilter;

  const SEVERITY_COLORS: Record<FindingSeverity, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-blue-400",
    info: "text-gray-400",
  };

  const handleViewModeChange = (mode: 'active' | 'suppressed') => {
    setViewMode(mode);
    setPage(1);
  };

  return (
    <div className="flex gap-6 h-full">
      {/* Filter sidebar — only show in active mode */}
      {viewMode === 'active' && (
        <div className="w-52 shrink-0 space-y-5 rounded-lg border border-zinc-800 bg-zinc-900 p-4 self-start">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-zinc-300">Filters</h3>
            {hasFilters && (
              <Button
                variant="ghost"
                size="sm"
                onClick={clearFilters}
                className="h-6 text-xs text-zinc-500 gap-1 px-2"
              >
                <X className="h-3 w-3" />
                Clear
              </Button>
            )}
          </div>

          {/* KEV Only toggle */}
          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Threat Intel</Label>
            <button
              onClick={() => { setKevOnly(!kevOnly); setPage(1); }}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors w-full justify-start ${
                kevOnly
                  ? 'bg-red-900/50 border-red-500/50 text-red-300'
                  : 'border-zinc-600 text-zinc-400 hover:border-red-500/50 hover:text-red-300'
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${kevOnly ? 'bg-red-400 animate-pulse' : 'bg-zinc-600'}`} />
              KEV Only
            </button>
          </div>

          <Separator />

          {/* Confidence filter */}
          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Confidence</Label>
            <select
              value={confidenceFilter}
              onChange={(e) => { setConfidenceFilter(e.target.value); setPage(1); }}
              className="w-full rounded-lg border border-zinc-600 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-300"
            >
              <option value="">All Confidence</option>
              <option value="certain">Certain</option>
              <option value="firm">Firm</option>
              <option value="tentative">Tentative</option>
            </select>
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Severity</Label>
            {SEVERITIES.map((severity) => (
              <div key={severity} className="flex items-center gap-2">
                <Checkbox
                  id={`sev-${severity}`}
                  checked={(filters.severities ?? []).includes(severity)}
                  onCheckedChange={() => toggleSeverity(severity)}
                />
                <label
                  htmlFor={`sev-${severity}`}
                  className={`text-sm cursor-pointer capitalize font-medium ${SEVERITY_COLORS[severity]}`}
                >
                  {severity}
                </label>
              </div>
            ))}
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Status</Label>
            {STATUSES.map((status) => (
              <div key={status} className="flex items-center gap-2">
                <Checkbox
                  id={`status-${status}`}
                  checked={(filters.statuses ?? []).includes(status)}
                  onCheckedChange={() => toggleStatus(status)}
                />
                <label
                  htmlFor={`status-${status}`}
                  className="text-sm cursor-pointer text-zinc-300 capitalize"
                >
                  {status.replace("_", " ")}
                </label>
              </div>
            ))}
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">CVE / CVSS</Label>
            <div className="flex items-center gap-2">
              <Checkbox
                id="has-cve"
                checked={!!filters.has_cve}
                onCheckedChange={(checked) => {
                  setFilters((f) => ({ ...f, has_cve: checked ? true : undefined }));
                  setPage(1);
                }}
              />
              <label htmlFor="has-cve" className="text-sm cursor-pointer text-zinc-300">
                Has CVE ID
              </label>
            </div>
          </div>
        </div>
      )}

      {/* Main content */}
      <div className="flex-1 min-w-0 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Findings</h1>
            <p className="text-sm text-zinc-400 mt-0.5">
              {total.toLocaleString()} findings {hasFilters && viewMode === 'active' && "matching filters"}
            </p>
          </div>
        </div>

        {/* Active / Suppressed tab bar */}
        <div className="flex gap-1 rounded-lg bg-gray-800/50 p-1 w-fit">
          <button
            onClick={() => handleViewModeChange('active')}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              viewMode === 'active'
                ? 'bg-gray-700 text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Active Findings
          </button>
          <button
            onClick={() => handleViewModeChange('suppressed')}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              viewMode === 'suppressed'
                ? 'bg-gray-700 text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Suppressed
            {suppressedCount > 0 && (
              <span className="ml-1.5 rounded-full bg-gray-600 px-1.5 py-0.5 text-xs">
                {suppressedCount}
              </span>
            )}
          </button>
        </div>

        {isLoading ? (
          <div className="rounded-lg border border-zinc-800 divide-y divide-zinc-800">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3">
                <div className="h-3.5 w-3.5 rounded bg-zinc-800 animate-pulse shrink-0" />
                <div className="h-6 w-20 rounded bg-zinc-800 animate-pulse shrink-0" />
                <div className="flex-1 space-y-1.5">
                  <div className="h-4 w-64 rounded bg-zinc-800 animate-pulse" />
                  <div className="h-3 w-40 rounded bg-zinc-800 animate-pulse" />
                </div>
                <div className="h-6 w-24 rounded bg-zinc-800 animate-pulse shrink-0" />
              </div>
            ))}
          </div>
        ) : findings.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert className="h-8 w-8" />}
            title={viewMode === 'suppressed' ? "No suppressed findings" : "No findings"}
            description={
              viewMode === 'suppressed'
                ? "No findings have been suppressed or marked as false positive."
                : "No findings match your current filters. Run a scan to discover vulnerabilities."
            }
          />
        ) : (
          <div className="rounded-lg border border-zinc-800 overflow-hidden divide-y divide-zinc-800">
            {findings.map((f) => (
              <FindingRow key={f.id} finding={f} />
            ))}
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-sm text-zinc-500">
            <span>
              Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of{" "}
              {total.toLocaleString()}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="h-8"
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-zinc-400">
                {page} / {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="h-8"
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </div>

    </div>
  );
}
