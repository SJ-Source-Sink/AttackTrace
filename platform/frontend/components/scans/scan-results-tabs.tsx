"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileDown, Loader2, Brain, TrendingDown, ChevronLeft, ChevronRight } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { useAssets } from "@/hooks/use-assets";
import { useFindings } from "@/hooks/use-findings";
import { aiApi, reportsApi } from "@/lib/api";
import { toast } from "sonner";

import { severityBgColor, formatDate } from "@/lib/utils";
import type { Scan, AISummarizeResponse, FindingSeverity } from "@/types";

interface ScanResultsTabsProps {
  scan: Scan;
}

function SummaryTab({ scan }: { scan: Scan }) {
  const { data: summary, isLoading } = useQuery({
    queryKey: ["ai", "summarize", scan.id],
    queryFn: () => aiApi.summarize(scan.id) as Promise<AISummarizeResponse>,
    staleTime: Infinity,
  });

  const riskColors: Record<string, string> = {
    low: "text-emerald-400",
    medium: "text-yellow-400",
    high: "text-orange-400",
    critical: "text-red-400",
  };

  return (
    <div className="space-y-4">
      {/* Stats overview */}
      {scan.findings_count && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Critical", value: scan.findings_count.critical ?? 0, color: "text-red-500" },
            { label: "High", value: scan.findings_count.high ?? 0, color: "text-orange-500" },
            { label: "Medium", value: scan.findings_count.medium ?? 0, color: "text-yellow-500" },
            { label: "Low", value: scan.findings_count.low ?? 0, color: "text-blue-400" },
          ].map((stat) => (
            <Card key={stat.label}>
              <CardContent className="p-4 text-center">
                <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
                <p className="text-xs text-zinc-500 mt-1">{stat.label}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* AI Executive Summary */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Brain className="h-4 w-4 text-blue-400" />
            AI Executive Summary
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-5/6" />
              <Skeleton className="h-4 w-4/5" />
            </div>
          ) : summary ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <span className="text-sm text-zinc-400">Overall Risk:</span>
                <span className={`font-semibold capitalize ${riskColors[summary.risk_level]}`}>
                  {summary.risk_level}
                </span>
              </div>
              <p className="text-sm text-zinc-300 leading-relaxed">{summary.summary}</p>
              {summary.key_findings.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                    Key Findings
                  </p>
                  <ul className="space-y-1">
                    {summary.key_findings.map((finding, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-sm text-zinc-300">
                        <TrendingDown className="h-3.5 w-3.5 text-red-400 mt-0.5 shrink-0" />
                        {finding}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {summary.recommendations.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                    Recommendations
                  </p>
                  <ul className="space-y-1">
                    {summary.recommendations.map((rec, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-sm text-zinc-300">
                        <span className="text-blue-400 shrink-0 text-xs mt-0.5">→</span>
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-zinc-500">AI summary not available.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function AssetsTab({ scanId }: { scanId: string }) {
  const [page, setPage] = useState(1);
  const PER_PAGE = 20;
  const { data, isLoading } = useAssets({ scan_id: scanId, page, per_page: PER_PAGE });
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-zinc-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900">
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Type</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Value</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Risk</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">First Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {isLoading
              ? Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 4 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <Skeleton className="h-4 w-full" />
                      </td>
                    ))}
                  </tr>
                ))
              : data?.items.map((asset) => (
                  <tr key={asset.id} className="hover:bg-zinc-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <Badge variant="secondary" className="text-xs capitalize">
                        {asset.asset_type}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-300 max-w-xs truncate">
                      {asset.value}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-16 rounded-full bg-zinc-800 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              asset.risk_score >= 70
                                ? "bg-red-500"
                                : asset.risk_score >= 40
                                  ? "bg-yellow-500"
                                  : "bg-emerald-500"
                            }`}
                            style={{ width: `${asset.risk_score}%` }}
                          />
                        </div>
                        <span className="text-xs text-zinc-400">{asset.risk_score}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-500">
                      {formatDate(asset.first_seen)}
                    </td>
                  </tr>
                ))}
          </tbody>
        </table>
      </div>
      {total > PER_PAGE && (
        <div className="flex items-center justify-between px-1">
          <span className="text-xs text-zinc-500">
            Page {page} of {totalPages} — {total} total
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              className="h-7 w-7 p-0"
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 w-7 p-0"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function FindingsTab({ scanId }: { scanId: string }) {
  const [page, setPage] = useState(1);
  const PER_PAGE = 20;
  const { data, isLoading } = useFindings({ scan_id: scanId, page, per_page: PER_PAGE });
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-zinc-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900">
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Severity</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Title</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Asset</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {isLoading
              ? Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 4 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <Skeleton className="h-4 w-full" />
                      </td>
                    ))}
                  </tr>
                ))
              : data?.items.map((finding) => (
                  <tr key={finding.id} className="hover:bg-zinc-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <Badge
                        className={`text-[10px] capitalize border ${severityBgColor(finding.severity as FindingSeverity)}`}
                      >
                        {finding.severity}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-sm text-zinc-300 max-w-xs truncate">
                      {finding.title}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-500 max-w-xs truncate">
                      {finding.asset_value}
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="secondary" className="text-xs capitalize">
                        {finding.status.replace("_", " ")}
                      </Badge>
                    </td>
                  </tr>
                ))}
          </tbody>
        </table>
      </div>
      {total > PER_PAGE && (
        <div className="flex items-center justify-between px-1">
          <span className="text-xs text-zinc-500">
            Page {page} of {totalPages} — {total} total
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              className="h-7 w-7 p-0"
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 w-7 p-0"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function ReportTab({ scanId }: { scanId: string }) {
  const queryClient = useQueryClient();
  const [generatingFormat, setGeneratingFormat] = useState<string | null>(null);

  const { data: reportsData, isLoading } = useQuery({
    queryKey: ["reports", scanId],
    queryFn: () => reportsApi.list(scanId) as Promise<{ items: Array<{ id: string; scan_id: string; name: string; format: string; size_bytes: number; created_at: string }>; total: number }>,
    staleTime: 30_000,
  });
  const reports = reportsData?.items ?? [];

  const generateMutation = useMutation({
    mutationFn: (format: string) => reportsApi.generate(scanId, format),
    onSuccess: () => {
      toast.success("Report generated", { description: "Ready to download below." });
      queryClient.invalidateQueries({ queryKey: ["reports", scanId] });
      setGeneratingFormat(null);
    },
    onError: (err: unknown) => {
      const msg = (err as { message?: string })?.message ?? "Generation failed";
      toast.error("Failed", { description: msg });
      setGeneratingFormat(null);
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        {(["html", "json"] as const).map((format) => (
          <Button
            key={format}
            variant="outline"
            size="sm"
            className="gap-1.5 uppercase text-xs"
            disabled={generateMutation.isPending}
            onClick={() => { setGeneratingFormat(format); generateMutation.mutate(format); }}
          >
            {generateMutation.isPending && generatingFormat === format ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <FileDown className="h-3.5 w-3.5" />
            )}
            {format}
          </Button>
        ))}
      </div>
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 2 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : reports.length > 0 ? (
        <div className="space-y-2">
          {reports.map((report) => (
            <div
              key={report.id}
              className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900 p-3"
            >
              <div>
                <p className="text-sm font-medium text-zinc-300">{report.name}</p>
                <p className="text-xs text-zinc-500">
                  {report.format.toUpperCase()} · {formatDate(report.created_at)}
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5"
                onClick={() =>
                  reportsApi.download(report.scan_id, report.name)
                    .catch((e) => toast.error("Download failed", { description: e.message }))
                }
              >
                <FileDown className="h-3.5 w-3.5" />
                Download
              </Button>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-zinc-500 py-4">No reports generated yet. Click HTML or JSON above to generate one.</p>
      )}
    </div>
  );
}

export function ScanResultsTabs({ scan }: ScanResultsTabsProps) {
  return (
    <Tabs defaultValue="summary">
      <TabsList className="mb-4">
        <TabsTrigger value="summary">Summary</TabsTrigger>
        <TabsTrigger value="assets">
          Assets
          {typeof scan.results_summary?.total_assets === "number" && (
            <span className="ml-1.5 text-xs opacity-70">{scan.results_summary.total_assets}</span>
          )}
        </TabsTrigger>
        <TabsTrigger value="findings">
          Findings
          {scan.findings_count && (
            <span className="ml-1.5 text-xs opacity-70">
              {Object.values(scan.findings_count).reduce((a: number, b) => a + (Number(b) || 0), 0)}
            </span>
          )}
        </TabsTrigger>
        <TabsTrigger value="report">Report</TabsTrigger>
      </TabsList>

      <TabsContent value="summary">
        <SummaryTab scan={scan} />
      </TabsContent>
      <TabsContent value="assets">
        <AssetsTab scanId={scan.id} />
      </TabsContent>
      <TabsContent value="findings">
        <FindingsTab scanId={scan.id} />
      </TabsContent>
      <TabsContent value="report">
        <ReportTab scanId={scan.id} />
      </TabsContent>
    </Tabs>
  );
}
