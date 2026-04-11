"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  GitFork, Play, Square, Download, ChevronDown, ChevronRight,
  CheckCircle2, XCircle, AlertTriangle, Info, Loader2,
  History, Plus, X, Globe, Shield, Copy, Database, PackageSearch,
  Search, Check,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { getAccessToken } from "@/lib/auth";
import { toast } from "sonner";
import { useSearchParams } from "next/navigation";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ─── Types ────────────────────────────────────────────────────────────────────

type TakeoverStatus = "VULNERABLE" | "NEEDS_REVIEW" | "NOT_VULNERABLE" | "ERROR" | "SCANNING";

interface TakeoverResult {
  hostname: string;
  status: TakeoverStatus;
  service: string | null;
  cname_chain: string[];
  reason: string;
  confidence: "confirmed" | "potential" | "low" | "";
  severity: "critical" | "high" | "medium" | "low" | "info" | "";
  remediation: string;
  ns_records?: string[];
  mx_records?: string[];
}

interface HistoryEntry {
  id: string;
  targets_count: number;
  started_at: string;
  vulnerable_count: number;
  needs_review_count: number;
  status: string;
}

// ─── Status config ────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<TakeoverStatus, {
  icon: React.ElementType;
  label: string;
  rowClass: string;
  badgeClass: string;
  iconClass: string;
}> = {
  VULNERABLE: {
    icon: XCircle,
    label: "Vulnerable",
    rowClass: "border-red-600/30 bg-red-600/5",
    badgeClass: "bg-red-600/15 text-red-400 border-red-600/30",
    iconClass: "text-red-400",
  },
  NEEDS_REVIEW: {
    icon: AlertTriangle,
    label: "Needs Review",
    rowClass: "border-orange-500/30 bg-orange-500/5",
    badgeClass: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    iconClass: "text-orange-400",
  },
  NOT_VULNERABLE: {
    icon: CheckCircle2,
    label: "Safe",
    rowClass: "border-zinc-800",
    badgeClass: "bg-zinc-500/10 text-zinc-500 border-zinc-700",
    iconClass: "text-zinc-500",
  },
  ERROR: {
    icon: Info,
    label: "Error",
    rowClass: "border-zinc-800",
    badgeClass: "bg-zinc-800 text-zinc-500 border-zinc-700",
    iconClass: "text-zinc-500",
  },
  SCANNING: {
    icon: Loader2,
    label: "Scanning…",
    rowClass: "border-zinc-800 opacity-60",
    badgeClass: "bg-zinc-800 text-zinc-500 border-zinc-700",
    iconClass: "text-zinc-500 animate-spin",
  },
};

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-600/10 text-red-400 border-red-600/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

// ─── ResultRow ────────────────────────────────────────────────────────────────

function ResultRow({ result }: { result: TakeoverResult }) {
  const [expanded, setExpanded] = useState(result.status === "VULNERABLE");
  const cfg = STATUS_CONFIG[result.status];
  const Icon = cfg.icon;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => toast.success("Copied"));
  };

  return (
    <div className={cn("rounded-lg border transition-colors", cfg.rowClass)}>
      <button
        className="w-full flex items-center gap-3 px-3 py-2.5 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <Icon className={cn("h-4 w-4 shrink-0", cfg.iconClass)} />

        {/* Hostname */}
        <span className="flex-1 font-mono text-sm text-zinc-200 truncate min-w-0">
          {result.hostname}
        </span>

        {/* Service badge */}
        {result.service && (
          <Badge variant="outline" className="text-[10px] py-0 h-4 text-zinc-400 shrink-0">
            {result.service}
          </Badge>
        )}

        {/* Severity */}
        {result.severity && result.status === "VULNERABLE" && (
          <Badge className={cn("text-[10px] border capitalize py-0 h-4 shrink-0", SEV_COLORS[result.severity])}>
            {result.severity}
          </Badge>
        )}

        {/* Status */}
        <span className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0 text-[10px] h-4 shrink-0", cfg.badgeClass)}>
          {cfg.label}
        </span>

        {/* Confidence */}
        {result.confidence && result.confidence !== "low" && result.status !== "NOT_VULNERABLE" && result.status !== "ERROR" && (
          <span className="text-[10px] text-zinc-600 shrink-0">
            {result.confidence}
          </span>
        )}

        {expanded
          ? <ChevronDown className="h-3.5 w-3.5 text-zinc-600 shrink-0" />
          : <ChevronRight className="h-3.5 w-3.5 text-zinc-600 shrink-0" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-zinc-800/60 space-y-3 pt-3">
          {/* Reason */}
          <div>
            <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Detection Reason</p>
            <p className="text-xs text-zinc-300">{result.reason}</p>
          </div>

          {/* CNAME chain */}
          {result.cname_chain && result.cname_chain.length > 0 && (
            <div>
              <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1.5">CNAME Chain</p>
              <div className="flex items-center gap-1.5 flex-wrap">
                {result.cname_chain.map((hop, i) => (
                  <React.Fragment key={i}>
                    <span className="font-mono text-[11px] text-zinc-300 bg-zinc-900 border border-zinc-800 rounded px-1.5 py-0.5">
                      {hop}
                    </span>
                    {i < result.cname_chain.length - 1 && (
                      <ChevronRight className="h-3 w-3 text-zinc-600" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {/* NS records */}
          {result.ns_records && result.ns_records.length > 0 && (
            <div>
              <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1.5">Nameservers</p>
              <div className="flex flex-wrap gap-1.5">
                {result.ns_records.map((ns) => (
                  <span key={ns} className="font-mono text-[11px] text-zinc-400 bg-zinc-900 border border-zinc-800 rounded px-1.5 py-0.5">
                    {ns}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          {result.remediation && result.status !== "NOT_VULNERABLE" && (
            <div>
              <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Remediation</p>
              <p className="text-xs text-zinc-400 leading-relaxed border-l-2 border-zinc-700 pl-3">
                {result.remediation}
              </p>
            </div>
          )}

          {/* Copy hostname */}
          <button
            className="flex items-center gap-1.5 text-[11px] text-zinc-600 hover:text-zinc-400 transition-colors"
            onClick={(e) => { e.stopPropagation(); copyToClipboard(result.hostname); }}
          >
            <Copy className="h-3 w-3" /> Copy hostname
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Asset Import Panel ───────────────────────────────────────────────────────

interface AssetItem { id: string; value: string; asset_type: string; risk_score: number }

function AssetImportPanel({ onImport }: { onImport: (hosts: string[]) => void }) {
  const [open, setOpen] = useState(false);
  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [typeFilter, setTypeFilter] = useState<"all" | "subdomain" | "domain">("all");

  const loadAssets = useCallback(async () => {
    if (assets.length > 0) return; // already loaded
    setLoading(true);
    try {
      const token = getAccessToken();
      // Fetch subdomains + domains only (takeover-relevant)
      const params = new URLSearchParams({ per_page: "500", page: "1" });
      const res = await fetch(`${API_BASE}/assets?${params}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error("Failed to load assets");
      const data = await res.json();
      const items: AssetItem[] = (data.items ?? []).filter(
        (a: AssetItem) => a.asset_type === "subdomain" || a.asset_type === "domain"
      );
      setAssets(items);
    } catch {
      toast.error("Could not load assets");
    } finally {
      setLoading(false);
    }
  }, [assets.length]);

  const toggleOpen = () => {
    if (!open) loadAssets();
    setOpen((v) => !v);
    setSelected(new Set());
  };

  const filtered = assets.filter((a) => {
    if (typeFilter !== "all" && a.asset_type !== typeFilter) return false;
    if (search && !a.value.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const toggleAll = () => {
    if (selected.size === filtered.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map((a) => a.value)));
    }
  };

  const handleImport = () => {
    if (selected.size === 0) { toast.error("Select at least one asset"); return; }
    onImport(Array.from(selected));
    setOpen(false);
    setSelected(new Set());
    toast.success(`Imported ${selected.size} asset${selected.size > 1 ? "s" : ""}`);
  };

  return (
    <div>
      <button
        type="button"
        onClick={toggleOpen}
        className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
      >
        <PackageSearch className="h-3.5 w-3.5" />
        Import from Assets
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
      </button>

      {open && (
        <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950 overflow-hidden">
          {/* Search + type filter */}
          <div className="p-2 border-b border-zinc-800 space-y-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-zinc-500" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter assets..."
                className="w-full pl-7 pr-3 py-1.5 text-xs bg-zinc-900 border border-zinc-800 rounded text-zinc-300 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div className="flex items-center gap-1">
              {(["all", "subdomain", "domain"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t)}
                  className={cn(
                    "px-2 py-0.5 rounded text-[10px] capitalize border transition-colors",
                    typeFilter === t
                      ? "bg-blue-600/20 text-blue-400 border-blue-600/40"
                      : "bg-zinc-900 text-zinc-500 border-zinc-800 hover:text-zinc-300"
                  )}
                >
                  {t}
                </button>
              ))}
              <span className="ml-auto text-[10px] text-zinc-600">{filtered.length} assets</span>
            </div>
          </div>

          {/* Asset list */}
          <div className="max-h-[220px] overflow-y-auto">
            {loading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-4 w-4 text-zinc-500 animate-spin" />
              </div>
            ) : filtered.length === 0 ? (
              <p className="py-6 text-center text-xs text-zinc-600">No matching assets found</p>
            ) : (
              <>
                {/* Select all row */}
                <button
                  type="button"
                  onClick={toggleAll}
                  className="w-full flex items-center gap-2 px-3 py-2 hover:bg-zinc-800/50 transition-colors border-b border-zinc-800/50 text-left"
                >
                  <div className={cn(
                    "h-3.5 w-3.5 rounded border flex items-center justify-center shrink-0",
                    selected.size === filtered.length && filtered.length > 0
                      ? "bg-blue-600 border-blue-600"
                      : "border-zinc-600"
                  )}>
                    {selected.size === filtered.length && filtered.length > 0 && (
                      <Check className="h-2.5 w-2.5 text-white" />
                    )}
                  </div>
                  <span className="text-[11px] text-zinc-400 font-medium">
                    {selected.size === filtered.length && filtered.length > 0 ? "Deselect all" : `Select all (${filtered.length})`}
                  </span>
                </button>

                {filtered.map((asset) => (
                  <button
                    key={asset.id}
                    type="button"
                    onClick={() => setSelected((prev) => {
                      const next = new Set(prev);
                      if (next.has(asset.value)) next.delete(asset.value);
                      else next.add(asset.value);
                      return next;
                    })}
                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-zinc-800/50 transition-colors border-b border-zinc-800/30 last:border-0 text-left"
                  >
                    <div className={cn(
                      "h-3.5 w-3.5 rounded border flex items-center justify-center shrink-0",
                      selected.has(asset.value) ? "bg-blue-600 border-blue-600" : "border-zinc-700"
                    )}>
                      {selected.has(asset.value) && <Check className="h-2.5 w-2.5 text-white" />}
                    </div>
                    <span className="font-mono text-[11px] text-zinc-300 flex-1 truncate">{asset.value}</span>
                    <Badge variant="secondary" className="text-[9px] py-0 h-3.5 shrink-0">
                      {asset.asset_type}
                    </Badge>
                    {asset.risk_score > 0 && (
                      <span className={cn(
                        "text-[9px] shrink-0",
                        asset.risk_score >= 70 ? "text-red-400" : asset.risk_score >= 40 ? "text-yellow-400" : "text-zinc-600"
                      )}>
                        {asset.risk_score}
                      </span>
                    )}
                  </button>
                ))}
              </>
            )}
          </div>

          {/* Import action */}
          <div className="p-2 border-t border-zinc-800 flex items-center justify-between">
            <span className="text-[10px] text-zinc-500">
              {selected.size > 0 ? `${selected.size} selected` : "Select assets above"}
            </span>
            <div className="flex gap-1.5">
              <button
                type="button"
                onClick={() => { setOpen(false); setSelected(new Set()); }}
                className="px-2 py-1 text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleImport}
                disabled={selected.size === 0}
                className="px-3 py-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-[10px] rounded transition-colors"
              >
                Add {selected.size > 0 ? selected.size : ""} to Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function TakeoverPage() {
  const searchParams = useSearchParams();
  const [targetsText, setTargetsText] = useState(() => {
    // Pre-populate from URL ?hosts= param (e.g. navigating from Assets page)
    if (typeof window !== "undefined") {
      const hosts = new URLSearchParams(window.location.search).get("hosts");
      if (hosts) return hosts.split(",").join("\n");
    }
    return "";
  });
  const [checkCname, setCheckCname] = useState(true);
  const [checkNs, setCheckNs] = useState(true);
  const [checkMx, setCheckMx] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<TakeoverResult[]>([]);
  const [scanningSet, setScanningSet] = useState<Set<string>>(new Set());
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [filterStatus, setFilterStatus] = useState<TakeoverStatus | "ALL">("ALL");
  const [services, setServices] = useState<{ service: string; count: number }[]>([]);

  const abortRef = useRef<AbortController | null>(null);

  // Handle hosts from URL params (e.g. from Assets page "Check Takeover" action)
  useEffect(() => {
    const hosts = searchParams.get("hosts");
    if (hosts && !targetsText) {
      setTargetsText(hosts.split(",").join("\n"));
    }
  }, [searchParams]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleAssetImport = useCallback((hosts: string[]) => {
    setTargetsText((prev) => {
      const existing = prev.split(/[\n,]/).map((t) => t.trim()).filter(Boolean);
      const newHosts = hosts.filter((h) => !existing.includes(h));
      return [...existing, ...newHosts].join("\n");
    });
  }, []);

  // Load known services from fingerprint DB
  useEffect(() => {
    const token = getAccessToken();
    fetch(`${API_BASE}/takeover/fingerprints`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then((r) => r.ok ? r.json() : [])
      .then((data: { service: string }[]) => {
        const counts = new Map<string, number>();
        data.forEach((d) => counts.set(d.service, (counts.get(d.service) || 0) + 1));
        setServices(Array.from(counts.entries()).map(([service, count]) => ({ service, count })));
      })
      .catch(() => {});

    const token2 = getAccessToken();
    fetch(`${API_BASE}/takeover/history`, {
      headers: token2 ? { Authorization: `Bearer ${token2}` } : {},
    })
      .then((r) => r.ok ? r.json() : [])
      .then((d) => { if (Array.isArray(d)) setHistory(d); })
      .catch(() => {});
  }, []);

  const startScan = useCallback(async () => {
    const lines = targetsText
      .split(/[\n,]/)
      .map((t) => t.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, ""))
      .filter(Boolean);

    if (lines.length === 0) {
      toast.error("Enter at least one hostname");
      return;
    }
    if (lines.length > 500) {
      toast.error("Maximum 500 targets per scan");
      return;
    }

    setIsScanning(true);
    setResults([]);
    setScanningSet(new Set(lines));
    setProgress({ done: 0, total: lines.length });

    abortRef.current = new AbortController();

    try {
      const token = getAccessToken();
      const res = await fetch(`${API_BASE}/takeover/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          targets: lines,
          check_cname: checkCname,
          check_ns: checkNs,
          check_mx: checkMx,
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Scan failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          const eventMatch = part.match(/^event: (\S+)/m);
          const dataMatch = part.match(/^data: ([\s\S]+)/m);
          if (!eventMatch || !dataMatch) continue;

          const event = eventMatch[1];
          let data: Record<string, unknown>;
          try { data = JSON.parse(dataMatch[1]); } catch { continue; }

          if (event === "start") {
            toast.success(`Scanning ${data.total} target(s)`);
          } else if (event === "result") {
            const r = data as unknown as TakeoverResult;
            setScanningSet((prev) => { const n = new Set(prev); n.delete(r.hostname); return n; });
            setResults((prev) => [...prev, r]);
            setProgress((p) => p ? { done: p.done + 1, total: p.total } : null);
            if (r.status === "VULNERABLE") {
              toast.error(`Vulnerable: ${r.hostname} → ${r.service}`, { duration: 4000 });
            }
          } else if (event === "complete") {
            setIsScanning(false);
            setScanningSet(new Set());
            const vulnCount = (data.vulnerable_count as number) ?? 0;
            const reviewCount = (data.needs_review_count as number) ?? 0;
            if (vulnCount > 0) {
              toast.error(`Scan complete — ${vulnCount} vulnerable, ${reviewCount} needs review`);
            } else {
              toast.success(`Scan complete — ${reviewCount > 0 ? reviewCount + " needs review" : "no vulnerabilities found"}`);
            }
            // Refresh history
            const t2 = getAccessToken();
            fetch(`${API_BASE}/takeover/history`, {
              headers: t2 ? { Authorization: `Bearer ${t2}` } : {},
            })
              .then((r2) => r2.ok ? r2.json() : [])
              .then((d) => { if (Array.isArray(d)) setHistory(d); })
              .catch(() => {});
          } else if (event === "error") {
            toast.error(`Error: ${data.message}`);
            setIsScanning(false);
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") {
        toast.error(`Scan failed: ${err.message}`);
      }
      setIsScanning(false);
    }
  }, [targetsText, checkCname, checkNs, checkMx]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanningSet(new Set());
    toast.info("Scan stopped");
  };

  const exportResults = () => {
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `takeover-results-${Date.now()}.json`;
    a.click();
  };

  const exportCsv = () => {
    const rows = [
      ["Hostname", "Status", "Service", "Severity", "Confidence", "CNAME Chain", "Reason"],
      ...results.map((r) => [
        r.hostname,
        r.status,
        r.service ?? "",
        r.severity ?? "",
        r.confidence ?? "",
        r.cname_chain?.join(" → ") ?? "",
        r.reason,
      ]),
    ];
    const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `takeover-results-${Date.now()}.csv`;
    a.click();
  };

  const filteredResults = filterStatus === "ALL"
    ? results
    : results.filter((r) => r.status === filterStatus);

  // Counts
  const counts = {
    VULNERABLE: results.filter((r) => r.status === "VULNERABLE").length,
    NEEDS_REVIEW: results.filter((r) => r.status === "NEEDS_REVIEW").length,
    NOT_VULNERABLE: results.filter((r) => r.status === "NOT_VULNERABLE").length,
    ERROR: results.filter((r) => r.status === "ERROR").length,
  };

  const totalScanned = results.length + scanningSet.size;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Takeover Checker"
        description="Detect dangling DNS, unclaimed services, and subdomain takeover vulnerabilities"
      >
        <div className="flex items-center gap-2">
          {results.length > 0 && (
            <>
              <Button variant="outline" size="sm" onClick={exportCsv} className="gap-1.5">
                <Download className="h-3.5 w-3.5" /> CSV
              </Button>
              <Button variant="outline" size="sm" onClick={exportResults} className="gap-1.5">
                <Download className="h-3.5 w-3.5" /> JSON
              </Button>
            </>
          )}
          <Button
            variant="outline" size="sm"
            onClick={() => setShowHistory(!showHistory)}
            className="gap-1.5"
          >
            <History className="h-3.5 w-3.5" /> History ({history.length})
          </Button>
        </div>
      </PageHeader>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">

        {/* ── Config Panel ── */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <GitFork className="h-4 w-4 text-blue-400" />
                Scan Targets
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">

              {/* Target input */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-zinc-400">Subdomains / Hostnames</Label>
                  <span className="text-[10px] text-zinc-600">
                    {targetsText.split(/[\n,]/).filter((t) => t.trim()).length} targets
                  </span>
                </div>
                <Textarea
                  placeholder={`sub1.example.com\nsub2.example.com\nblog.example.com`}
                  value={targetsText}
                  onChange={(e) => setTargetsText(e.target.value)}
                  disabled={isScanning}
                  rows={8}
                  className="font-mono text-xs resize-none"
                />
                <p className="text-[10px] text-zinc-600">
                  One per line, or comma-separated. Up to 500 targets.
                </p>
                {/* Import from asset inventory */}
                {!isScanning && (
                  <AssetImportPanel onImport={handleAssetImport} />
                )}
              </div>

              {/* Detection options */}
              <div className="space-y-2.5 rounded-lg border border-zinc-800 p-3">
                <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">Detection Layers</p>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-zinc-300">CNAME Chain Analysis</p>
                    <p className="text-[10px] text-zinc-600">Follow hops, detect dangling</p>
                  </div>
                  <Switch checked={checkCname} onCheckedChange={setCheckCname} disabled={isScanning} />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-zinc-300">NS Takeover</p>
                    <p className="text-[10px] text-zinc-600">Nameserver delegation check</p>
                  </div>
                  <Switch checked={checkNs} onCheckedChange={setCheckNs} disabled={isScanning} />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-zinc-300">MX Takeover</p>
                    <p className="text-[10px] text-zinc-600">Mail record check (slower)</p>
                  </div>
                  <Switch checked={checkMx} onCheckedChange={setCheckMx} disabled={isScanning} />
                </div>
              </div>

              {/* Run/Stop */}
              {isScanning ? (
                <Button onClick={stopScan} variant="destructive" className="w-full gap-2">
                  <Square className="h-4 w-4" /> Stop Scan
                </Button>
              ) : (
                <Button onClick={startScan} className="w-full gap-2">
                  <Play className="h-4 w-4" /> Start Takeover Scan
                </Button>
              )}
            </CardContent>
          </Card>

          {/* Fingerprint DB info */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold text-zinc-400 flex items-center gap-2">
                <Database className="h-3.5 w-3.5" />
                Fingerprint Database
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-[11px] text-zinc-500 mb-2">
                {services.length > 0 ? services.length : "40"}+ service signatures
              </p>
              <div className="space-y-1 max-h-[280px] overflow-y-auto">
                {services.length > 0 ? services.map((s) => (
                  <div key={s.service} className="flex items-center gap-2">
                    <div className="h-1.5 w-1.5 rounded-full bg-blue-400/60 shrink-0" />
                    <span className="text-[11px] text-zinc-500 truncate">{s.service}</span>
                  </div>
                )) : (
                  <p className="text-[11px] text-zinc-600 italic">Loading…</p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ── Results Panel ── */}
        <div className="lg:col-span-2 space-y-4">

          {/* Stats bar */}
          {(isScanning || results.length > 0) && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
              <div className="flex items-center gap-4 flex-wrap">
                {isScanning && (
                  <div className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
                    <span className="text-xs text-zinc-400">
                      {progress ? `${progress.done}/${progress.total} checked` : "Scanning…"}
                    </span>
                  </div>
                )}
                {!isScanning && results.length > 0 && (
                  <span className="text-xs text-zinc-400">{results.length} checked</span>
                )}

                {counts.VULNERABLE > 0 && (
                  <button
                    onClick={() => setFilterStatus(filterStatus === "VULNERABLE" ? "ALL" : "VULNERABLE")}
                    className={cn(
                      "flex items-center gap-1.5 rounded-md border px-2 py-1 transition-colors",
                      "bg-red-600/10 text-red-400 border-red-600/30",
                      filterStatus === "VULNERABLE" && "ring-1 ring-red-500"
                    )}
                  >
                    <XCircle className="h-3 w-3" />
                    <span className="text-[11px] font-medium">{counts.VULNERABLE} Vulnerable</span>
                  </button>
                )}

                {counts.NEEDS_REVIEW > 0 && (
                  <button
                    onClick={() => setFilterStatus(filterStatus === "NEEDS_REVIEW" ? "ALL" : "NEEDS_REVIEW")}
                    className={cn(
                      "flex items-center gap-1.5 rounded-md border px-2 py-1 transition-colors",
                      "bg-orange-500/10 text-orange-400 border-orange-500/30",
                      filterStatus === "NEEDS_REVIEW" && "ring-1 ring-orange-500"
                    )}
                  >
                    <AlertTriangle className="h-3 w-3" />
                    <span className="text-[11px] font-medium">{counts.NEEDS_REVIEW} Needs Review</span>
                  </button>
                )}

                {counts.NOT_VULNERABLE > 0 && (
                  <button
                    onClick={() => setFilterStatus(filterStatus === "NOT_VULNERABLE" ? "ALL" : "NOT_VULNERABLE")}
                    className={cn(
                      "flex items-center gap-1.5 rounded-md border px-2 py-1 transition-colors",
                      "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
                      filterStatus === "NOT_VULNERABLE" && "ring-1 ring-emerald-500"
                    )}
                  >
                    <CheckCircle2 className="h-3 w-3" />
                    <span className="text-[11px] font-medium">{counts.NOT_VULNERABLE} Safe</span>
                  </button>
                )}

                {filterStatus !== "ALL" && (
                  <button
                    onClick={() => setFilterStatus("ALL")}
                    className="text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
                  >
                    <X className="h-3 w-3 inline mr-1" />Clear filter
                  </button>
                )}
              </div>

              {/* Progress bar */}
              {isScanning && progress && (
                <div className="mt-2 h-1 bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500 transition-all duration-300"
                    style={{ width: `${(progress.done / progress.total) * 100}%` }}
                  />
                </div>
              )}
            </div>
          )}

          {/* Scanning placeholders */}
          {isScanning && scanningSet.size > 0 && (
            <div className="space-y-1">
              {Array.from(scanningSet).slice(0, 5).map((h) => (
                <div key={h} className="flex items-center gap-3 px-3 py-2 rounded-lg border border-zinc-800 opacity-50">
                  <Loader2 className="h-4 w-4 text-zinc-600 animate-spin shrink-0" />
                  <span className="font-mono text-xs text-zinc-500">{h}</span>
                  <span className="text-[10px] text-zinc-700">scanning…</span>
                </div>
              ))}
              {scanningSet.size > 5 && (
                <p className="text-[11px] text-zinc-600 pl-3">
                  +{scanningSet.size - 5} more scanning…
                </p>
              )}
            </div>
          )}

          {/* Results */}
          {filteredResults.length > 0 && (
            <div className="space-y-2">
              {filteredResults.map((r) => (
                <ResultRow key={r.hostname} result={r} />
              ))}
            </div>
          )}

          {/* Empty state */}
          {!isScanning && results.length === 0 && (
            <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
              <GitFork className="h-12 w-12" />
              <p className="text-sm">Enter subdomains and run a scan</p>
              <p className="text-xs text-zinc-700">
                CNAME chains · 40+ service fingerprints · NS/MX takeover · dangling DNS
              </p>
            </div>
          )}

          {!isScanning && results.length > 0 && filteredResults.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-600 space-y-2">
              <Shield className="h-8 w-8" />
              <p className="text-sm">No results match the current filter</p>
              <button
                className="text-xs text-blue-400 hover:text-blue-300"
                onClick={() => setFilterStatus("ALL")}
              >
                Show all
              </button>
            </div>
          )}
        </div>
      </div>

      {/* History */}
      {showHistory && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <History className="h-4 w-4 text-zinc-400" />
              Scan History
            </CardTitle>
          </CardHeader>
          <CardContent>
            {history.length === 0 ? (
              <p className="text-sm text-zinc-600 py-4 text-center">No past scans</p>
            ) : (
              <div className="space-y-2">
                {history.map((entry) => (
                  <div key={entry.id} className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 p-3">
                    <div className={cn(
                      "h-2 w-2 rounded-full shrink-0",
                      entry.vulnerable_count > 0 ? "bg-red-400" :
                      entry.needs_review_count > 0 ? "bg-orange-400" : "bg-emerald-400"
                    )} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-zinc-200">{entry.targets_count} targets checked</p>
                      <p className="text-[10px] text-zinc-500">{new Date(entry.started_at).toLocaleString()}</p>
                    </div>
                    <div className="text-right shrink-0 space-y-0.5">
                      {entry.vulnerable_count > 0 && (
                        <p className="text-xs text-red-400">{entry.vulnerable_count} vulnerable</p>
                      )}
                      {entry.needs_review_count > 0 && (
                        <p className="text-xs text-orange-400">{entry.needs_review_count} needs review</p>
                      )}
                      {entry.vulnerable_count === 0 && entry.needs_review_count === 0 && (
                        <p className="text-xs text-emerald-400">All safe</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
