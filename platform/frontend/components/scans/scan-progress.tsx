"use client";

import React from "react";
import { CheckCircle2, XCircle, Loader2, Circle, AlertTriangle, WifiOff } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useScanStream } from "@/lib/sse";
import type { RecentFinding } from "@/lib/sse";
import { useCancelScan } from "@/hooks/use-scans";
import { severityBgColor } from "@/lib/utils";
import type { FindingSeverity } from "@/types";

interface ScanProgressProps {
  scanId: string;
}

const PHASE_ORDER = ["discovery", "enumeration", "analysis", "enrichment", "reporting"];
const MODULE_LABELS: Record<string, string> = {
  infrastructure: "Infrastructure",
  cloud: "Cloud Assets",
  osint: "OSINT",
  web: "Web Scanning",
  enrichment: "Enrichment",
};

function ModuleStatusIcon({ status }: { status: string }) {
  switch (status) {
    case "running":
      return <Loader2 className="h-4 w-4 animate-spin text-blue-400" />;
    case "completed":
      return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    case "failed":
      return <XCircle className="h-4 w-4 text-red-400" />;
    case "skipped":
      return <Circle className="h-4 w-4 text-zinc-600" />;
    default:
      return <Circle className="h-4 w-4 text-zinc-700" />;
  }
}

export function ScanProgress({ scanId }: ScanProgressProps) {
  const {
    latestPhase,
    moduleStatuses,
    recentFindings,
    progress,
    isConnected,
    error,
    scanStatus,
    disconnect,
  } = useScanStream(scanId);

  const { mutate: cancelScan, isPending: isCancelling } = useCancelScan();

  const handleCancel = () => {
    cancelScan(scanId);
    disconnect();
  };

  const moduleEntries = Object.entries(moduleStatuses);
  const currentPhaseIdx = PHASE_ORDER.indexOf(latestPhase ?? "");

  return (
    <div className="space-y-4">
      {/* Connection status + Cancel */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {isConnected ? (
            <>
              <div className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
              <span className="text-sm text-blue-400">Live</span>
            </>
          ) : error ? (
            <>
              <WifiOff className="h-4 w-4 text-orange-400" />
              <span className="text-sm text-orange-400">Reconnecting...</span>
            </>
          ) : (
            <>
              <div className="h-2 w-2 rounded-full bg-zinc-500" />
              <span className="text-sm text-zinc-500">Disconnected</span>
            </>
          )}
        </div>
        <Button
          variant="destructive"
          size="sm"
          onClick={handleCancel}
          disabled={isCancelling || scanStatus === "completed"}
          className="h-7 text-xs"
        >
          {isCancelling ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            "Cancel Scan"
          )}
        </Button>
      </div>

      {/* Overall progress */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-zinc-300">
              {latestPhase ? `Phase: ${latestPhase}` : "Initializing..."}
            </span>
            <span className="text-sm font-bold text-zinc-100">{progress}%</span>
          </div>
          <Progress value={progress} className="h-2" />

          {/* Phase steps */}
          <div className="flex items-center gap-1 mt-4">
            {PHASE_ORDER.map((phase, idx) => {
              const isPast = idx < currentPhaseIdx;
              const isCurrent = idx === currentPhaseIdx;
              return (
                <React.Fragment key={phase}>
                  <div
                    className={`flex items-center gap-1 text-xs ${
                      isPast
                        ? "text-emerald-400"
                        : isCurrent
                          ? "text-blue-400"
                          : "text-zinc-600"
                    }`}
                  >
                    {isPast ? (
                      <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                    ) : isCurrent ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" />
                    ) : (
                      <Circle className="h-3.5 w-3.5 shrink-0" />
                    )}
                    <span className="hidden sm:inline capitalize">{phase}</span>
                  </div>
                  {idx < PHASE_ORDER.length - 1 && (
                    <div
                      className={`h-px flex-1 ${
                        isPast ? "bg-emerald-400/30" : "bg-zinc-800"
                      }`}
                    />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Module statuses */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300">Module Status</CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <div className="space-y-2">
              {Object.keys(MODULE_LABELS).map((moduleId) => {
                const status = moduleStatuses[moduleId];
                return (
                  <div
                    key={moduleId}
                    className="flex items-center justify-between py-1.5 border-b border-zinc-800/60 last:border-0"
                  >
                    <div className="flex items-center gap-2">
                      <ModuleStatusIcon status={status?.status ?? "pending"} />
                      <span className="text-sm text-zinc-300">
                        {MODULE_LABELS[moduleId]}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      {status?.findings_count !== undefined && status.findings_count > 0 && (
                        <span className="text-xs text-red-400 font-medium">
                          {status.findings_count} findings
                        </span>
                      )}
                      {status?.assets_count !== undefined && status.assets_count > 0 && (
                        <span className="text-xs text-zinc-500">
                          {status.assets_count} assets
                        </span>
                      )}
                      <span className="text-xs text-zinc-600 capitalize">
                        {status?.status ?? "pending"}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Live findings feed */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300">
              Live Findings Feed
              {recentFindings.length > 0 && (
                <span className="ml-2 text-xs font-normal text-zinc-500">
                  {recentFindings.length} found
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="h-64">
              {recentFindings.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-32 text-zinc-600">
                  <AlertTriangle className="h-6 w-6 mb-2" />
                  <p className="text-sm">Waiting for findings...</p>
                </div>
              ) : (
                <div className="divide-y divide-zinc-800/60">
                  {recentFindings.map((finding: RecentFinding, idx) => (
                    <div
                      key={`${finding.title}-${idx}`}
                      className="flex items-start gap-2 px-4 py-2.5 animate-fade-in"
                    >
                      <Badge
                        className={`text-[10px] py-0 h-5 mt-0.5 shrink-0 capitalize border ${severityBgColor(finding.severity as FindingSeverity)}`}
                      >
                        {finding.severity}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-zinc-300 leading-tight truncate">
                          {finding.title}
                        </p>
                        <p className="text-[10px] text-zinc-600 truncate mt-0.5">
                          {finding.affected_asset}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
