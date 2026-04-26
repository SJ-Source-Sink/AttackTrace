"use client";

import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileDown, Loader2, Brain, TrendingDown, ChevronLeft, ChevronRight, GitBranch, ExternalLink, ChevronDown, ChevronRight as ChevronRightIcon } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { useAssets } from "@/hooks/use-assets";
import { useFindings } from "@/hooks/use-findings";
import { aiApi, reportsApi, scansApi } from "@/lib/api";
import { ScanDiffTab } from "@/components/scans/scan-diff-tab";
import type { ScanDiff } from "@/types";
import { toast } from "sonner";

import { severityBgColor, formatDate } from "@/lib/utils";
import { KevBadge } from "@/components/findings/kev-badge";
import { ConfidenceBadge } from "@/components/findings/confidence-badge";
import type { Scan, AISummarizeResponse, FindingSeverity, Asset, Finding } from "@/types";

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
  const [viewMode, setViewMode] = useState<'active' | 'suppressed'>('active');
  const [kevOnly, setKevOnly] = useState(false);
  const [confidenceFilter, setConfidenceFilter] = useState("");
  const PER_PAGE = 20;

  const queryFilters = viewMode === 'active'
    ? {
        scan_id: scanId,
        suppressed: false,
        kev_only: kevOnly || undefined,
        confidence: confidenceFilter || undefined,
        page,
        per_page: PER_PAGE,
      }
    : { scan_id: scanId, suppressed: true, page, per_page: PER_PAGE };

  const { data, isLoading } = useFindings(queryFilters);
  const { data: suppressedData } = useFindings({ scan_id: scanId, suppressed: true, per_page: 1, page: 1 });
  const suppressedCount = suppressedData?.total ?? 0;
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  const handleViewModeChange = (mode: 'active' | 'suppressed') => {
    setViewMode(mode);
    setPage(1);
  };

  return (
    <div className="space-y-3">
      {/* Active / Suppressed tab bar */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex gap-1 rounded-lg bg-zinc-800/50 p-1 w-fit">
          <button
            onClick={() => handleViewModeChange('active')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
              viewMode === 'active'
                ? 'bg-zinc-700 text-white'
                : 'text-zinc-400 hover:text-white'
            }`}
          >
            Active
          </button>
          <button
            onClick={() => handleViewModeChange('suppressed')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
              viewMode === 'suppressed'
                ? 'bg-zinc-700 text-white'
                : 'text-zinc-400 hover:text-white'
            }`}
          >
            Suppressed
            {suppressedCount > 0 && (
              <span className="ml-1 rounded-full bg-zinc-600 px-1.5 py-0.5 text-[10px]">
                {suppressedCount}
              </span>
            )}
          </button>
        </div>

        {/* Filters — only in active mode */}
        {viewMode === 'active' && (
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => { setKevOnly(!kevOnly); setPage(1); }}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                kevOnly
                  ? 'bg-red-900/50 border-red-500/50 text-red-300'
                  : 'border-zinc-600 text-zinc-400 hover:border-red-500/50 hover:text-red-300'
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${kevOnly ? 'bg-red-400 animate-pulse' : 'bg-zinc-600'}`} />
              KEV Only
            </button>
            <select
              value={confidenceFilter}
              onChange={(e) => { setConfidenceFilter(e.target.value); setPage(1); }}
              className="rounded-lg border border-zinc-600 bg-zinc-800 px-3 py-1 text-xs text-zinc-300"
            >
              <option value="">All Confidence</option>
              <option value="certain">Certain</option>
              <option value="firm">Firm</option>
              <option value="tentative">Tentative</option>
            </select>
          </div>
        )}
      </div>

      <div className="rounded-lg border border-zinc-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900">
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Severity</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Title</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">CVE / CVSS</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Asset</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-400 uppercase">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {isLoading
              ? Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 5 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <Skeleton className="h-4 w-full" />
                      </td>
                    ))}
                  </tr>
                ))
              : data?.items.map((finding) => (
                  <tr key={finding.id} className="hover:bg-zinc-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1">
                        <Badge
                          className={`text-[10px] capitalize border ${severityBgColor(finding.severity as FindingSeverity)}`}
                        >
                          {finding.severity}
                        </Badge>
                        <ConfidenceBadge confidence={finding.confidence} />
                      </div>
                    </td>
                    <td className="px-4 py-3 max-w-xs">
                      <div className="flex flex-col gap-0.5">
                        <span className="text-sm text-zinc-300 line-clamp-2">{finding.title}</span>
                        <KevBadge kev_status={finding.kev_status} epss_score={finding.epss_score} />
                        {viewMode === 'suppressed' && finding.suppressed_reason && (
                          <span className="text-[10px] text-zinc-500 italic">
                            Reason: {finding.suppressed_reason}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-0.5">
                        {finding.cve_id ? (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="inline-flex items-center gap-0.5 text-[10px] text-blue-400 hover:underline"
                          >
                            {finding.cve_id}
                            <ExternalLink className="h-2.5 w-2.5" />
                          </a>
                        ) : null}
                        {finding.cvss_score != null ? (
                          <span className={`text-[10px] font-mono font-semibold ${
                            finding.cvss_score >= 9 ? "text-red-400" :
                            finding.cvss_score >= 7 ? "text-orange-400" :
                            finding.cvss_score >= 4 ? "text-yellow-400" : "text-blue-400"
                          }`}>
                            CVSS {finding.cvss_score.toFixed(1)}
                          </span>
                        ) : null}
                        {finding.epss_score != null ? (
                          <span className="text-[10px] text-orange-300">
                            EPSS {(finding.epss_score * 100).toFixed(1)}%
                          </span>
                        ) : (!finding.cvss_score && !finding.cve_id ? <span className="text-xs text-zinc-600">—</span> : null)}
                      </div>
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

function AttackChainTab({ scan }: { scan: Scan }) {
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set());
  const { data: assetsData, isLoading: assetsLoading } = useAssets({ scan_id: scan.id, per_page: 200, page: 1 });
  const { data: findingsData, isLoading: findingsLoading } = useFindings({ scan_id: scan.id, per_page: 200, page: 1 });

  const isLoading = assetsLoading || findingsLoading;

  const chain = useMemo(() => {
    const assets = assetsData?.items ?? [];
    const findings = findingsData?.items ?? [];

    // Group assets by type
    const domains = assets.filter((a) => a.asset_type === "domain");
    const subdomains = assets.filter((a) => a.asset_type === "subdomain");
    const ips = assets.filter((a) => a.asset_type === "ip");
    const webapps = assets.filter((a) => a.asset_type === "webapp");

    // Map finding asset_value → findings
    const findingsByAsset = new Map<string, Finding[]>();
    for (const f of findings) {
      const key = f.asset_value;
      if (!key) continue;
      if (!findingsByAsset.has(key)) findingsByAsset.set(key, []);
      findingsByAsset.get(key)!.push(f);
    }

    // Build tree: domain → matching subdomains → ips → webapps
    // Extract a root domain from a URL or hostname string
    const extractRootDomain = (val: string): string => {
      try {
        const host = val.includes("://") ? new URL(val).hostname : val;
        const parts = host.split(".");
        return parts.length >= 2 ? parts.slice(-2).join(".") : host;
      } catch {
        return val;
      }
    };

    const rootDomains = domains.length > 0
      ? domains
      : subdomains.length > 0
        ? [...new Set(subdomains.map((s) => extractRootDomain(s.value)))].map(
            (d) => ({ id: d, value: d, asset_type: "domain" } as Asset)
          )
        // Fallback: derive root domains from webapp URLs
        : [...new Set(webapps.map((w) => extractRootDomain(w.value)))].map(
            (d) => ({ id: d, value: d, asset_type: "domain" } as Asset)
          );

    return rootDomains.map((domain) => {
      const domainSubdomains = subdomains.filter(
        (s) => s.value === domain.value || s.value.endsWith(`.${domain.value}`)
      );
      const domainIps = ips;
      const domainWebapps = webapps.filter(
        (w) => extractRootDomain(w.value) === domain.value
      );

      const domainFindings = findingsByAsset.get(domain.value) ?? [];

      return {
        domain,
        subdomains: domainSubdomains.map((sub) => ({
          asset: sub,
          findings: findingsByAsset.get(sub.value) ?? [],
        })),
        ips: domainIps.map((ip) => ({
          asset: ip,
          findings: findingsByAsset.get(ip.value) ?? [],
        })),
        webapps: domainWebapps.map((w) => ({
          asset: w,
          findings: findingsByAsset.get(w.value) ?? [],
        })),
        directFindings: domainFindings,
        totalFindings: findings.length,
      };
    });
  }, [assetsData, findingsData]);

  const toggleDomain = (domainId: string) => {
    setExpandedDomains((prev) => {
      const next = new Set(prev);
      if (next.has(domainId)) next.delete(domainId);
      else next.add(domainId);
      return next;
    });
  };

  const SEV_COLOR: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-400",
    info: "bg-zinc-500",
  };

  const FindingDots = ({ findings }: { findings: Finding[] }) => {
    if (!findings.length) return null;
    const bySev = findings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    return (
      <div className="flex items-center gap-1">
        {Object.entries(bySev).map(([sev, count]) => (
          <span
            key={sev}
            className={`inline-flex items-center justify-center h-4 min-w-[16px] px-1 rounded-full text-[9px] font-bold text-white ${SEV_COLOR[sev] ?? "bg-zinc-500"}`}
            title={`${count} ${sev}`}
          >
            {count}
          </span>
        ))}
      </div>
    );
  };

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    );
  }

  if (chain.length === 0) {
    return (
      <div className="py-12 text-center text-sm text-zinc-500">
        No assets discovered yet. Run a scan to populate the attack chain.
      </div>
    );
  }

  const allFindings = findingsData?.items ?? [];
  const criticalCount = allFindings.filter((f) => f.severity === "critical").length;
  const highCount = allFindings.filter((f) => f.severity === "high").length;

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="flex items-center gap-4 p-3 rounded-lg bg-zinc-900 border border-zinc-800 text-sm">
        <div className="flex items-center gap-1.5">
          <GitBranch className="h-4 w-4 text-blue-400" />
          <span className="text-zinc-400">Attack Surface:</span>
        </div>
        <span className="text-zinc-300">{(assetsData?.items ?? []).length} assets</span>
        <span className="text-zinc-600">·</span>
        <span className="text-zinc-300">{allFindings.length} findings</span>
        {criticalCount > 0 && (
          <>
            <span className="text-zinc-600">·</span>
            <span className="text-red-400 font-semibold">{criticalCount} critical</span>
          </>
        )}
        {highCount > 0 && (
          <>
            <span className="text-zinc-600">·</span>
            <span className="text-orange-400 font-semibold">{highCount} high</span>
          </>
        )}
      </div>

      {/* Chain tree */}
      <div className="space-y-2">
        {chain.map(({ domain, subdomains, ips, webapps, directFindings }) => {
          const isExpanded = expandedDomains.has(domain.id ?? domain.value);
          const childCount = subdomains.length + ips.length + webapps.length;
          const allChildFindings = [
            ...directFindings,
            ...subdomains.flatMap((s) => s.findings),
            ...ips.flatMap((i) => i.findings),
            ...webapps.flatMap((w) => w.findings),
          ];

          return (
            <div key={domain.id ?? domain.value} className="rounded-lg border border-zinc-800 overflow-hidden">
              {/* Domain row */}
              <button
                type="button"
                className="w-full flex items-center gap-3 px-4 py-3 bg-zinc-900 hover:bg-zinc-800/60 transition-colors text-left"
                onClick={() => toggleDomain(domain.id ?? domain.value)}
              >
                {isExpanded
                  ? <ChevronDown className="h-4 w-4 text-zinc-500 shrink-0" />
                  : <ChevronRightIcon className="h-4 w-4 text-zinc-500 shrink-0" />
                }
                <span className="font-mono text-sm font-semibold text-zinc-200">{domain.value}</span>
                <Badge variant="secondary" className="text-[10px]">domain</Badge>
                {childCount > 0 && (
                  <span className="text-xs text-zinc-500">{childCount} child assets</span>
                )}
                <div className="ml-auto flex items-center gap-2">
                  <FindingDots findings={allChildFindings} />
                </div>
              </button>

              {/* Children */}
              {isExpanded && (
                <div className="border-t border-zinc-800 divide-y divide-zinc-800/60">
                  {subdomains.map(({ asset, findings }) => (
                    <div key={asset.id} className="flex items-center gap-3 px-4 py-2.5 pl-10 bg-zinc-950/40">
                      <span className="text-xs text-zinc-500">└</span>
                      <span className="font-mono text-xs text-zinc-300">{asset.value}</span>
                      <Badge variant="secondary" className="text-[10px]">subdomain</Badge>
                      {asset.risk_score > 0 && (
                        <span className={`text-[10px] ${asset.risk_score >= 70 ? "text-red-400" : asset.risk_score >= 40 ? "text-yellow-400" : "text-zinc-500"}`}>
                          risk {asset.risk_score}
                        </span>
                      )}
                      <div className="ml-auto">
                        <FindingDots findings={findings} />
                      </div>
                    </div>
                  ))}
                  {ips.map(({ asset, findings }) => (
                    <div key={asset.id} className="flex items-center gap-3 px-4 py-2.5 pl-10 bg-zinc-950/40">
                      <span className="text-xs text-zinc-500">└</span>
                      <span className="font-mono text-xs text-zinc-300">{asset.value}</span>
                      <Badge variant="secondary" className="text-[10px]">ip</Badge>
                      <div className="ml-auto">
                        <FindingDots findings={findings} />
                      </div>
                    </div>
                  ))}
                  {webapps.map(({ asset, findings }) => (
                    <div key={asset.id} className="flex items-center gap-3 px-4 py-2.5 pl-10 bg-zinc-950/40">
                      <span className="text-xs text-zinc-500">└</span>
                      <span className="font-mono text-xs text-zinc-300 truncate max-w-[300px]">{asset.value}</span>
                      <Badge variant="secondary" className="text-[10px]">webapp</Badge>
                      <div className="ml-auto">
                        <FindingDots findings={findings} />
                      </div>
                    </div>
                  ))}
                  {childCount === 0 && directFindings.length === 0 && (
                    <div className="px-10 py-3 text-xs text-zinc-600">No child assets discovered</div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
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

function ChangesTab({ scanId }: { scanId: string }) {
  const { data: diff, isLoading, isError } = useQuery({
    queryKey: ["scan", "diff", scanId],
    queryFn: () => scansApi.getDiff(scanId) as Promise<ScanDiff>,
    staleTime: 60_000,
    retry: false,
  });

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  if (isError || !diff) {
    return (
      <div className="py-12 text-center text-sm text-zinc-500">
        No change data available for this scan. Diffs are computed after scan completion.
      </div>
    );
  }

  return <ScanDiffTab diff={diff} />;
}

export function ScanResultsTabs({ scan }: ScanResultsTabsProps) {
  const { data: diffData } = useQuery({
    queryKey: ["scan", "diff", scan.id],
    queryFn: () => scansApi.getDiff(scan.id) as Promise<ScanDiff>,
    staleTime: 60_000,
    retry: false,
    enabled: scan.status === "completed",
  });

  const changeCount = diffData
    ? (diffData.new_assets?.length ?? 0) +
      (diffData.removed_assets?.length ?? 0) +
      (diffData.new_findings?.length ?? 0) +
      (diffData.resolved_findings?.length ?? 0)
    : 0;

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
        <TabsTrigger value="chain">Attack Chain</TabsTrigger>
        <TabsTrigger value="changes">
          Changes
          {changeCount > 0 && (
            <span className="ml-1.5 rounded-full bg-orange-600/80 px-1.5 py-0.5 text-[10px] font-semibold text-white">
              {changeCount}
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
      <TabsContent value="chain">
        <AttackChainTab scan={scan} />
      </TabsContent>
      <TabsContent value="changes">
        <ChangesTab scanId={scan.id} />
      </TabsContent>
      <TabsContent value="report">
        <ReportTab scanId={scan.id} />
      </TabsContent>
    </Tabs>
  );
}
