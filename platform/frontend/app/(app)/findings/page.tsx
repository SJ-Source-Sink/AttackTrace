"use client";

import React, { useState } from "react";
import { ShieldAlert, Filter, ChevronLeft, ChevronRight, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/empty-state";
import { FindingsTable } from "@/components/findings/findings-table";
import { FindingDetail } from "@/components/findings/finding-detail";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useFindings } from "@/hooks/use-findings";
import type { Finding, FindingFilters, FindingSeverity, FindingStatus } from "@/types";

const SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: FindingStatus[] = ["open", "in_progress", "remediated", "accepted_risk", "false_positive"];
const PER_PAGE = 25;

export default function FindingsPage() {
  const [filters, setFilters] = useState<FindingFilters>({ statuses: ["open", "in_progress"] });
  const [page, setPage] = useState(1);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const { data, isLoading } = useFindings({ ...filters, page, per_page: PER_PAGE });
  const findings = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PER_PAGE);

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
    setPage(1);
  };

  const hasFilters =
    (filters.severities?.length ?? 0) > 0 || (filters.statuses?.length ?? 0) > 0;

  const SEVERITY_COLORS: Record<FindingSeverity, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-blue-400",
    info: "text-gray-400",
  };

  return (
    <div className="flex gap-6 h-full">
      {/* Filter sidebar */}
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
      </div>

      {/* Main content */}
      <div className="flex-1 min-w-0 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Findings</h1>
            <p className="text-sm text-zinc-400 mt-0.5">
              {total.toLocaleString()} findings {hasFilters && "matching filters"}
            </p>
          </div>
        </div>

        {findings.length === 0 && !isLoading ? (
          <EmptyState
            icon={<ShieldAlert className="h-8 w-8" />}
            title="No findings"
            description="No findings match your current filters. Run a scan to discover vulnerabilities."
          />
        ) : (
          <FindingsTable
            findings={findings}
            isLoading={isLoading}
            onRowClick={setSelectedFinding}
          />
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

      {/* Slide-over panel for finding detail */}
      {selectedFinding && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-40 bg-black/50"
            onClick={() => setSelectedFinding(null)}
          />
          {/* Panel */}
          <div className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl border-l border-zinc-800 bg-zinc-950 shadow-2xl animate-slide-in">
            <FindingDetail
              finding={selectedFinding}
              onClose={() => setSelectedFinding(null)}
            />
          </div>
        </>
      )}
    </div>
  );
}
