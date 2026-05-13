"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  FolderOpen, Play, Square, CheckCircle2, XCircle, AlertTriangle,
  Shield, Loader2, Search, Clock, History, Trash2, ExternalLink,
  ChevronDown, ChevronRight, Info, FileWarning, Globe, Database,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ── Types ─────────────────────────────────────────────────────────────────────

type Severity = "critical" | "high" | "medium" | "info";

interface Finding {
  path: string;
  url: string;
  status_code: number;
  severity: Severity;
  category: string;
  size_bytes: number;
  content_preview: string;
  note: string;
}

interface ScanComplete {
  scan_id: string;
  target: string;
  total_checked: number;
  total_found: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
}

interface HistoryItem {
  id: string;
  target: string;
  started_at: string;
  completed_at: string;
  total_checked: number;
  total_found: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
}

interface HistoryDetail extends HistoryItem {
  findings: Finding[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SEV_STYLES: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  info:     "bg-blue-500/10 text-blue-400 border-blue-500/20",
};

const SEV_BORDER: Record<string, string> = {
  critical: "border-red-600/40 bg-red-600/5",
  high:     "border-orange-500/40 bg-orange-500/5",
  medium:   "border-yellow-500/40 bg-yellow-500/5",
  info:     "border-zinc-700/50 bg-zinc-900/20",
};

const CATEGORY_LABELS: Record<string, string> = {
  version_control:   "Version Control",
  environment_files: "Environment Files",
  backup_files:      "Backups",
  config_files:      "Config Files",
  credentials:       "Credentials",
  debug_info:        "Debug / Info",
  logs:              "Logs",
  cloud:             "Cloud Secrets",
  custom:            "Custom Paths",
};

const CATEGORIES = [
  { key: "check_git",         label: "Version Control",  desc: ".git, .svn, .hg configs" },
  { key: "check_env",         label: "Environment Files", desc: ".env, .env.local, .env.production" },
  { key: "check_backups",     label: "Backups",           desc: "backup.sql, site.tar.gz, .bak files" },
  { key: "check_configs",     label: "Config Files",      desc: "config.yml, docker-compose, Jenkinsfile" },
  { key: "check_credentials", label: "Credentials",       desc: "wp-config, secrets.yml, SSH keys" },
  { key: "check_debug",       label: "Debug / Info",      desc: "phpinfo, swagger, robots.txt" },
  { key: "check_logs",        label: "Logs",              desc: "error.log, access.log, laravel.log" },
  { key: "check_cloud",       label: "Cloud Secrets",     desc: ".aws/credentials, gcloud, service-account" },
];

// ── FindingCard ───────────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={cn("rounded-lg border transition-colors", SEV_BORDER[finding.severity] ?? SEV_BORDER.medium)}>
      <button
        className="w-full flex items-center gap-3 p-3 text-left"
        onClick={() => setExpanded(v => !v)}
      >
        {finding.severity === "critical" || finding.severity === "high"
          ? <XCircle className="h-4 w-4 text-red-400 shrink-0" />
          : finding.severity === "medium"
            ? <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0" />
            : <Info className="h-4 w-4 text-blue-400 shrink-0" />
        }
        <div className="flex-1 min-w-0 space-y-0.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-zinc-200 truncate">{finding.path}</span>
            <Badge className={cn("text-[10px] border h-4 py-0 capitalize shrink-0", SEV_STYLES[finding.severity])}>
              {finding.severity}
            </Badge>
            <Badge variant="outline" className="text-[10px] h-4 py-0 text-zinc-400 shrink-0">
              {CATEGORY_LABELS[finding.category] ?? finding.category}
            </Badge>
            {finding.status_code === 403 && (
              <Badge variant="outline" className="text-[10px] h-4 py-0 text-purple-400 border-purple-500/30">
                403 Forbidden
              </Badge>
            )}
          </div>
          <p className="text-[10px] text-zinc-500">{finding.note}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {finding.size_bytes > 0 && (
            <span className="text-[10px] text-zinc-600">{(finding.size_bytes / 1024).toFixed(1)}KB</span>
          )}
          {expanded ? <ChevronDown className="h-3.5 w-3.5 text-zinc-600" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-600" />}
        </div>
      </button>
      {expanded && (
        <div className="border-t border-zinc-800 px-3 pb-3 pt-2 space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-zinc-500 font-mono break-all">{finding.url}</span>
            <a
              href={finding.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-zinc-500 hover:text-blue-400"
              onClick={e => e.stopPropagation()}
            >
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
          {finding.content_preview && (
            <pre className="rounded bg-zinc-950 border border-zinc-800 px-2.5 py-2 text-[10px] font-mono text-zinc-400 whitespace-pre-wrap break-all max-h-32 overflow-y-auto">
              {finding.content_preview}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ── History Tab ───────────────────────────────────────────────────────────────

function HistoryTab({ onRestore }: { onRestore: (target: string) => void }) {
  const [items, setItems]               = useState<HistoryItem[]>([]);
  const [loading, setLoading]           = useState(false);
  const [detail, setDetail]             = useState<HistoryDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [deleting, setDeleting]         = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetchWithAuth(`${API_BASE}/exposure/history`);
      if (r.ok) {
        const d = await r.json();
        setItems(d.items ?? []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const openDetail = async (id: string) => {
    setLoadingDetail(true);
    try {
      const r = await fetchWithAuth(`${API_BASE}/exposure/history/${id}`);
      if (r.ok) setDetail(await r.json());
    } finally {
      setLoadingDetail(false);
    }
  };

  const deleteScan = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeleting(id);
    try {
      const r = await fetchWithAuth(`${API_BASE}/exposure/history/${id}`, { method: "DELETE" });
      if (r.ok) {
        setItems(p => p.filter(s => s.id !== id));
        if (detail?.id === id) setDetail(null);
        toast.success("Scan deleted");
      }
    } finally {
      setDeleting(null);
    }
  };

  if (detail) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setDetail(null)}
            className="text-xs text-zinc-500 hover:text-zinc-300 flex items-center gap-1"
          >
            <ChevronRight className="h-3 w-3 rotate-180" /> Back
          </button>
          <span className="font-mono text-xs text-blue-400">{detail.target}</span>
          <button
            onClick={() => { onRestore(detail.target); setDetail(null); }}
            className="ml-auto text-xs text-blue-400 hover:text-blue-300"
          >
            Restore target
          </button>
        </div>
        <div className="grid grid-cols-4 gap-3">
          {Object.entries(detail.by_severity ?? {}).map(([sev, count]) => (
            <div key={sev} className={cn("rounded-lg border p-3 text-center", SEV_BORDER[sev] ?? "border-zinc-800")}>
              <p className={cn("text-2xl font-bold", sev === "critical" ? "text-red-400" : sev === "high" ? "text-orange-400" : sev === "medium" ? "text-yellow-400" : "text-blue-400")}>{count}</p>
              <p className="text-[10px] text-zinc-500 capitalize mt-0.5">{sev}</p>
            </div>
          ))}
        </div>
        <div className="space-y-2">
          {(detail.findings ?? []).map((f, i) => (
            <FindingCard key={i} finding={f} />
          ))}
          {(detail.findings ?? []).length === 0 && (
            <div className="text-center py-10 text-zinc-600 text-sm">No exposed files found</div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-zinc-500">{items.length} scan{items.length !== 1 ? "s" : ""} on record</p>
        <button onClick={load} className="text-[10px] text-zinc-500 hover:text-zinc-300 flex items-center gap-1">
          <Clock className="h-3 w-3" /> Refresh
        </button>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-6 w-6 animate-spin text-zinc-600" />
        </div>
      )}

      {!loading && items.length === 0 && (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-16 text-center">
          <History className="h-10 w-10 text-zinc-700 mb-3" />
          <p className="text-sm font-medium text-zinc-500">No scan history yet</p>
          <p className="text-xs text-zinc-600 mt-1">Completed scans will appear here automatically.</p>
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="space-y-2">
          {items.map(scan => (
            <div
              key={scan.id}
              onClick={() => openDetail(scan.id)}
              className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-4 cursor-pointer transition-colors hover:border-zinc-600"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0 space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs text-blue-400 truncate">{scan.target}</span>
                    {loadingDetail && <Loader2 className="h-3 w-3 animate-spin text-zinc-500" />}
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-zinc-500">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(scan.completed_at).toLocaleString()}
                    </span>
                    <span>{scan.total_checked} paths checked</span>
                    <span>{scan.total_found} exposed</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {(scan.by_severity?.critical ?? 0) > 0 && (
                      <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 rounded px-1.5 py-0.5">
                        {scan.by_severity.critical} critical
                      </span>
                    )}
                    {(scan.by_severity?.high ?? 0) > 0 && (
                      <span className="text-[10px] bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded px-1.5 py-0.5">
                        {scan.by_severity.high} high
                      </span>
                    )}
                    {(scan.by_severity?.medium ?? 0) > 0 && (
                      <span className="text-[10px] bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded px-1.5 py-0.5">
                        {scan.by_severity.medium} medium
                      </span>
                    )}
                    {scan.total_found === 0 && (
                      <span className="text-[10px] text-emerald-400">No exposed files</span>
                    )}
                  </div>
                </div>
                <button
                  onClick={e => deleteScan(scan.id, e)}
                  disabled={deleting === scan.id}
                  className="shrink-0 text-zinc-600 hover:text-red-400 transition-colors p-1"
                >
                  {deleting === scan.id
                    ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    : <Trash2 className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ExposureScannerPage() {
  const [tab, setTab] = useState<"scan" | "history">("scan");

  // Config
  const [target, setTarget]       = useState(() => localStorage.getItem("exposure_target") ?? "");
  const [categories, setCategories] = useState<Record<string, boolean>>(() => {
    const saved = localStorage.getItem("exposure_categories");
    if (saved) { try { return JSON.parse(saved); } catch { /* ignore */ } }
    return Object.fromEntries(CATEGORIES.map(c => [c.key, true]));
  });
  const [customPaths, setCustomPaths] = useState(() => localStorage.getItem("exposure_custom_paths") ?? "");

  // Scan state
  const [isScanning, setIsScanning]   = useState(false);
  const [scanStatus, setScanStatus]   = useState<"idle" | "running" | "done" | "failed">("idle");
  const [checked, setChecked]         = useState(0);
  const [total, setTotal]             = useState(0);
  const [currentPath, setCurrentPath] = useState("");
  const [findings, setFindings]       = useState<Finding[]>([]);
  const [complete, setComplete]       = useState<ScanComplete | null>(null);
  const [currentCategory, setCurrentCategory] = useState<string>("");

  const abortRef = useRef<AbortController | null>(null);

  const toggleCategory = (key: string) =>
    setCategories(p => ({ ...p, [key]: !p[key] }));

  const startScan = useCallback(async () => {
    if (!target.trim()) { toast.error("Please enter a target URL"); return; }

    localStorage.setItem("exposure_target", target.trim());
    localStorage.setItem("exposure_categories", JSON.stringify(categories));
    localStorage.setItem("exposure_custom_paths", customPaths);

    setIsScanning(true);
    setScanStatus("running");
    setChecked(0);
    setTotal(0);
    setCurrentPath("");
    setFindings([]);
    setComplete(null);
    setCurrentCategory("");

    abortRef.current = new AbortController();

    const custom = customPaths
      .split("\n")
      .map(p => p.trim())
      .filter(Boolean);

    try {
      const res = await fetchWithAuth(`${API_BASE}/exposure/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          ...Object.fromEntries(CATEGORIES.map(c => [c.key, categories[c.key] ?? true])),
          custom_paths: custom,
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Scan failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }

      const reader  = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          const eventMatch = part.match(/^event:\s*(\S+)/m);
          const dataMatch  = part.match(/^data:\s*([\s\S]+)/m);
          if (!dataMatch) continue;
          const event = eventMatch?.[1] ?? "unknown";
          let data: Record<string, unknown>;
          try { data = JSON.parse(dataMatch[1]); } catch { continue; }

          if (event === "start") {
            setTotal(data.total_paths as number ?? 0);
          } else if (event === "progress") {
            setChecked(data.checked as number ?? 0);
            setTotal(data.total as number ?? 0);
            setCurrentPath(data.current_path as string ?? "");
          } else if (event === "finding") {
            const f = data as unknown as Finding;
            setFindings(p => [...p, f]);
            setCurrentCategory(f.category);
          } else if (event === "complete") {
            const d = data as unknown as ScanComplete;
            setComplete(d);
            setScanStatus("done");
            setIsScanning(false);
            toast.success(`Scan complete — ${d.total_found} exposed files found`);
          } else if (event === "error") {
            setScanStatus("failed");
            setIsScanning(false);
            toast.error(`Scan error: ${data.message}`);
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") {
        setScanStatus("failed");
        toast.error(`Scan failed: ${err.message}`);
      }
      setIsScanning(false);
    }
  }, [target, categories, customPaths]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  const progress = total > 0 ? Math.round((checked / total) * 100) : 0;

  const findingsByCategory = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    (acc[f.category] ??= []).push(f);
    return acc;
  }, {});

  const critCount   = findings.filter(f => f.severity === "critical").length;
  const highCount   = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;

  const handleRestore = (t: string) => {
    setTarget(t);
    setTab("scan");
    toast.success(`Restored: ${t}`);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Exposed Files Scanner"
        description="Check for accidentally exposed sensitive files: secrets, credentials, backups, configs, source control"
      >
        {isScanning && (
          <Button variant="destructive" size="sm" onClick={stopScan} className="gap-1.5">
            <Square className="h-3.5 w-3.5" /> Stop
          </Button>
        )}
      </PageHeader>

      {/* Tab switcher */}
      <div className="flex gap-1 rounded-lg border border-zinc-800 bg-zinc-900/50 p-1 w-fit">
        {([["scan", FolderOpen, "Scanner"], ["history", History, "History"]] as const).map(([id, Icon, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              tab === id ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {tab === "history" && <HistoryTab onRestore={handleRestore} />}

      {tab === "scan" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">

          {/* ── Config Panel ── */}
          <div className="space-y-4">

            {/* Target */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <Globe className="h-4 w-4 text-blue-400" /> Target
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Base URL</Label>
                  <Input
                    placeholder="https://target.com"
                    value={target}
                    onChange={e => setTarget(e.target.value)}
                    disabled={isScanning}
                    onKeyDown={e => e.key === "Enter" && !isScanning && startScan()}
                    className="font-mono text-xs"
                  />
                  <p className="text-[10px] text-zinc-600">Paths will be appended: https://target.com/.env</p>
                </div>
              </CardContent>
            </Card>

            {/* Categories */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <Database className="h-4 w-4 text-purple-400" /> Categories
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {CATEGORIES.map(cat => (
                  <label
                    key={cat.key}
                    className={cn(
                      "flex items-start gap-2.5 rounded-md border p-2.5 cursor-pointer transition-colors",
                      categories[cat.key]
                        ? "border-blue-500/30 bg-blue-500/5"
                        : "border-zinc-800 bg-zinc-900/30 hover:border-zinc-700"
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={categories[cat.key] ?? true}
                      onChange={() => toggleCategory(cat.key)}
                      disabled={isScanning}
                      className="mt-0.5 h-3.5 w-3.5 accent-blue-500"
                    />
                    <div>
                      <p className="text-xs font-medium text-zinc-300">{cat.label}</p>
                      <p className="text-[10px] text-zinc-600 mt-0.5">{cat.desc}</p>
                    </div>
                  </label>
                ))}
              </CardContent>
            </Card>

            {/* Custom paths */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <Search className="h-4 w-4 text-zinc-400" /> Custom Paths
                </CardTitle>
              </CardHeader>
              <CardContent>
                <textarea
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-2 text-xs font-mono text-zinc-300 placeholder-zinc-600 focus:outline-none focus:ring-1 focus:ring-blue-500 resize-none"
                  rows={4}
                  placeholder={"/admin/config.php\n/legacy/backup.zip\n/.secret"}
                  value={customPaths}
                  onChange={e => setCustomPaths(e.target.value)}
                  disabled={isScanning}
                />
                <p className="text-[10px] text-zinc-600 mt-1">One path per line</p>
              </CardContent>
            </Card>

            <Button
              className="w-full gap-2"
              onClick={startScan}
              disabled={isScanning}
            >
              {isScanning
                ? <><Loader2 className="h-4 w-4 animate-spin" /> Scanning...</>
                : <><Play className="h-4 w-4" /> Start Scan</>}
            </Button>
          </div>

          {/* ── Results Panel ── */}
          <div className="lg:col-span-2 space-y-4">

            {/* Progress */}
            {(isScanning || scanStatus === "done") && (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                    <Shield className="h-4 w-4 text-blue-400" />
                    {isScanning ? "Scanning..." : "Scan Complete"}
                    {isScanning && <Loader2 className="h-3.5 w-3.5 animate-spin text-zinc-500 ml-auto" />}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* Progress bar */}
                  <div>
                    <div className="flex justify-between text-[10px] text-zinc-500 mb-1">
                      <span>{checked} / {total} paths checked</span>
                      <span>{progress}%</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-zinc-800 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-blue-500 transition-all duration-300"
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                  </div>
                  {isScanning && currentPath && (
                    <p className="text-[10px] font-mono text-zinc-500">
                      Checking: <span className="text-zinc-400">{currentPath}</span>
                    </p>
                  )}

                  {/* Severity summary */}
                  {findings.length > 0 && (
                    <div className="flex gap-3 flex-wrap pt-1">
                      {critCount > 0 && (
                        <div className={cn("rounded border px-2.5 py-1.5", SEV_BORDER.critical)}>
                          <span className="text-sm font-bold text-red-400">{critCount}</span>
                          <span className="text-[10px] text-zinc-500 ml-1">critical</span>
                        </div>
                      )}
                      {highCount > 0 && (
                        <div className={cn("rounded border px-2.5 py-1.5", SEV_BORDER.high)}>
                          <span className="text-sm font-bold text-orange-400">{highCount}</span>
                          <span className="text-[10px] text-zinc-500 ml-1">high</span>
                        </div>
                      )}
                      {mediumCount > 0 && (
                        <div className={cn("rounded border px-2.5 py-1.5", SEV_BORDER.medium)}>
                          <span className="text-sm font-bold text-yellow-400">{mediumCount}</span>
                          <span className="text-[10px] text-zinc-500 ml-1">medium</span>
                        </div>
                      )}
                      {findings.length - critCount - highCount - mediumCount > 0 && (
                        <div className="rounded border border-zinc-700/50 bg-zinc-900/20 px-2.5 py-1.5">
                          <span className="text-sm font-bold text-blue-400">{findings.length - critCount - highCount - mediumCount}</span>
                          <span className="text-[10px] text-zinc-500 ml-1">info</span>
                        </div>
                      )}
                      {findings.length === 0 && !isScanning && (
                        <div className="flex items-center gap-2 text-emerald-400">
                          <CheckCircle2 className="h-4 w-4" />
                          <span className="text-sm font-medium">No exposed files found</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* By category summary */}
                  {complete && Object.keys(complete.by_category ?? {}).length > 0 && (
                    <div className="pt-1 border-t border-zinc-800">
                      <p className="text-[10px] text-zinc-500 mb-2">By category</p>
                      <div className="flex flex-wrap gap-1.5">
                        {Object.entries(complete.by_category).map(([cat, count]) => (
                          <span key={cat} className="text-[10px] rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-zinc-400">
                            {CATEGORY_LABELS[cat] ?? cat}: <span className="text-zinc-200 font-semibold">{count}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Findings grouped by category */}
            {Object.entries(findingsByCategory).map(([cat, catFindings]) => (
              <div key={cat} className="space-y-2">
                <div className="flex items-center gap-2">
                  <FileWarning className="h-4 w-4 text-zinc-500" />
                  <h3 className="text-xs font-semibold text-zinc-400">
                    {CATEGORY_LABELS[cat] ?? cat}
                  </h3>
                  <span className="text-[10px] text-zinc-600">{catFindings.length} finding{catFindings.length !== 1 ? "s" : ""}</span>
                </div>
                {catFindings.map((f, i) => (
                  <FindingCard key={i} finding={f} />
                ))}
              </div>
            ))}

            {/* Empty state */}
            {scanStatus === "idle" && findings.length === 0 && (
              <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-20 text-center">
                <FolderOpen className="h-12 w-12 text-zinc-700 mb-3" />
                <p className="text-sm font-medium text-zinc-500">Configure a target and start the scan</p>
                <p className="text-xs text-zinc-600 mt-1">
                  Checks {Object.values(CATEGORIES).length} categories of sensitive file paths
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
