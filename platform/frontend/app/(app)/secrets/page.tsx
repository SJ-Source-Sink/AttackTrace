"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Key, Play, Square, Download, RotateCcw, AlertCircle, CheckCircle2,
  History, Trash2, Clock, FileSearch, Shield, ShieldAlert, ShieldOff,
  ExternalLink, ChevronDown, ChevronUp, Globe, Github, Info,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ── Types ──────────────────────────────────────────────────────────────────────

interface SecretFinding {
  type: "secret" | "exposure";
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  url: string;
  match: string;
  line_number: number | null;
  context: string;
}

interface ScanStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  files_scanned: number;
}

interface ProgressEvent {
  phase: string;
  message: string;
  count: number;
}

interface HistoryEntry {
  id: string;
  target: string;
  scan_type: string;
  started_at: string;
  completed_at: string;
  stats: ScanStats;
  duration_seconds: number;
  findings?: SecretFinding[];
}

// ── Constants ──────────────────────────────────────────────────────────────────

const SCAN_TYPES = [
  { value: "url", label: "URL / Domain", desc: "Scan a website for exposed secrets in JS files" },
  { value: "github_org", label: "GitHub Organization", desc: "Scan all public repos for a GitHub org" },
  { value: "github_user", label: "GitHub User", desc: "Scan all public repos for a GitHub user" },
];

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string; border: string; icon: React.ComponentType<{ className?: string }> }> = {
  critical: {
    label: "Critical",
    color: "text-red-400",
    bg: "bg-red-950/40",
    border: "border-red-800/60",
    icon: ShieldOff,
  },
  high: {
    label: "High",
    color: "text-orange-400",
    bg: "bg-orange-950/40",
    border: "border-orange-800/60",
    icon: ShieldAlert,
  },
  medium: {
    label: "Medium",
    color: "text-yellow-400",
    bg: "bg-yellow-950/30",
    border: "border-yellow-800/50",
    icon: Shield,
  },
  low: {
    label: "Low",
    color: "text-blue-400",
    bg: "bg-blue-950/30",
    border: "border-blue-800/50",
    icon: Info,
  },
};

// ── Sub-components ─────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.low;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider", cfg.color, cfg.bg)}>
      {cfg.label}
    </span>
  );
}

function FindingCard({ finding }: { finding: SecretFinding }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = SEVERITY_CONFIG[finding.severity] ?? SEVERITY_CONFIG.low;
  const Icon = cfg.icon;

  return (
    <div className={cn("rounded-lg border p-3 space-y-2 transition-colors", cfg.bg, cfg.border)}>
      <div className="flex items-start gap-2">
        <Icon className={cn("h-4 w-4 mt-0.5 shrink-0", cfg.color)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-zinc-200">{finding.name}</span>
            <SeverityBadge severity={finding.severity} />
            {finding.type === "exposure" && (
              <Badge variant="outline" className="text-[10px] text-zinc-400 border-zinc-700">
                Exposed File
              </Badge>
            )}
          </div>
          <div className="mt-1 flex items-center gap-1.5 min-w-0">
            <code className="text-[11px] text-zinc-400 font-mono truncate max-w-[400px]" title={finding.url}>
              {finding.url}
            </code>
            <a
              href={finding.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-zinc-600 hover:text-zinc-400 shrink-0"
              onClick={(e) => e.stopPropagation()}
            >
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="shrink-0 text-zinc-600 hover:text-zinc-400"
        >
          {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </button>
      </div>

      <div className="flex items-center gap-3 ml-6">
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] text-zinc-500">Match:</span>
          <code className="text-[11px] font-mono text-amber-300 bg-amber-950/40 px-1.5 py-0.5 rounded">
            {finding.match}
          </code>
        </div>
        {finding.line_number != null && (
          <span className="text-[10px] text-zinc-500">Line {finding.line_number}</span>
        )}
      </div>

      {expanded && finding.context && (
        <div className="ml-6 rounded-md border border-zinc-800 bg-zinc-950 p-2">
          <p className="text-[10px] text-zinc-500 mb-1 uppercase tracking-wider">Context</p>
          <code className="text-[11px] font-mono text-zinc-400 whitespace-pre-wrap break-all">
            {finding.context}
          </code>
        </div>
      )}
    </div>
  );
}

function StatPill({ count, severity }: { count: number; severity: string }) {
  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.low;
  if (count === 0) return null;
  return (
    <div className={cn("flex items-center gap-1.5 rounded-md border px-2.5 py-1.5", cfg.bg, cfg.border)}>
      <span className={cn("text-sm font-bold tabular-nums", cfg.color)}>{count}</span>
      <span className={cn("text-xs", cfg.color)}>{cfg.label}</span>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function SecretsPage() {
  const [activeTab, setActiveTab] = useState<"scanner" | "history">("scanner");

  // Form state
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("url");
  const [githubToken, setGithubToken] = useState("");
  const [includeWayback, setIncludeWayback] = useState(true);
  const [maxJsFiles, setMaxJsFiles] = useState(100);

  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [findings, setFindings] = useState<SecretFinding[]>([]);
  const [progressLog, setProgressLog] = useState<ProgressEvent[]>([]);
  const [scanStats, setScanStats] = useState<ScanStats | null>(null);
  const [scanDuration, setScanDuration] = useState<number | null>(null);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);

  // History state
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selectedHistoryEntry, setSelectedHistoryEntry] = useState<HistoryEntry | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const progressEndRef = useRef<HTMLDivElement>(null);

  // Group findings by severity
  const findingsBySeverity = SEVERITY_ORDER.reduce((acc, sev) => {
    acc[sev] = findings.filter((f) => f.severity === sev);
    return acc;
  }, {} as Record<string, SecretFinding[]>);

  // Load history from API
  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await fetchWithAuth(`${API_BASE}/secrets/history`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.items ?? []);
      }
    } catch {
      toast.error("Failed to load history");
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "history") {
      loadHistory();
    }
  }, [activeTab, loadHistory]);

  // Load full history entry details
  const loadHistoryEntry = useCallback(async (entry: HistoryEntry) => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/secrets/history/${entry.id}`);
      if (res.ok) {
        const full = await res.json();
        setSelectedHistoryEntry(full);
      }
    } catch {
      toast.error("Failed to load scan details");
    }
  }, []);

  const deleteHistoryEntry = useCallback(async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const res = await fetchWithAuth(`${API_BASE}/secrets/history/${id}`, { method: "DELETE" });
      if (res.ok) {
        setHistory((prev) => prev.filter((h) => h.id !== id));
        if (selectedHistoryEntry?.id === id) setSelectedHistoryEntry(null);
        toast.success("Scan deleted");
      }
    } catch {
      toast.error("Failed to delete scan");
    }
  }, [selectedHistoryEntry]);

  const startScan = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target");
      return;
    }

    setIsScanning(true);
    setScanStatus("running");
    setFindings([]);
    setProgressLog([]);
    setScanStats(null);
    setScanDuration(null);
    setCurrentScanId(null);

    abortRef.current = new AbortController();

    try {
      const res = await fetchWithAuth(`${API_BASE}/secrets/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          scan_type: scanType,
          github_token: githubToken.trim() || null,
          include_wayback: includeWayback,
          max_js_files: maxJsFiles,
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
          const eventMatch = part.match(/^event: (\w+)/m);
          const dataMatch = part.match(/^data: ([\s\S]+)/m);
          if (!eventMatch || !dataMatch) continue;

          const event = eventMatch[1];
          let data: Record<string, unknown>;
          try {
            data = JSON.parse(dataMatch[1]);
          } catch {
            continue;
          }

          if (event === "start") {
            setCurrentScanId(data.scan_id as string);
          } else if (event === "progress") {
            const prog = data as unknown as ProgressEvent;
            setProgressLog((prev) => {
              const next = [...prev, prog];
              setTimeout(() => progressEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
              return next.slice(-200); // keep last 200 messages
            });
          } else if (event === "finding") {
            const finding = (data.data ?? data) as SecretFinding;
            setFindings((prev) => [...prev, finding]);
          } else if (event === "complete") {
            setScanStatus("completed");
            setIsScanning(false);
            setScanDuration(data.duration_seconds as number);
            setScanStats({
              critical: (data.critical as number) ?? 0,
              high: (data.high as number) ?? 0,
              medium: (data.medium as number) ?? 0,
              low: (data.low as number) ?? 0,
              files_scanned: (data.files_scanned as number) ?? 0,
            });
            const total = data.total_findings as number;
            if (total === 0) {
              toast.success("Scan complete — no secrets found");
            } else {
              toast.warning(`Scan complete — ${total} finding${total === 1 ? "" : "s"} detected`);
            }
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
        setIsScanning(false);
        toast.error(`Scan failed: ${err.message}`);
      } else if (err instanceof Error && err.name === "AbortError") {
        setIsScanning(false);
        setScanStatus("idle");
      }
    }
  }, [target, scanType, githubToken, includeWayback, maxJsFiles]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  const exportJSON = () => {
    const blob = new Blob(
      [JSON.stringify({ target, scan_type: scanType, findings, stats: scanStats }, null, 2)],
      { type: "application/json" }
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `secrets-${target.replace(/[^a-z0-9]/gi, "_")}-${Date.now()}.json`;
    a.click();
  };

  const totalFindings = findings.length;

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <PageHeader
        title="Secret Scanner"
        description="Detect exposed API keys, credentials, and sensitive files in web apps and GitHub repos"
      >
        <div className="flex items-center gap-2">
          {scanStatus === "completed" && findings.length > 0 && (
            <Button variant="outline" size="sm" onClick={exportJSON} className="gap-1.5">
              <Download className="h-3.5 w-3.5" /> Export JSON
            </Button>
          )}
        </div>
      </PageHeader>

      {/* Tab switcher */}
      <div className="flex gap-1 border-b border-zinc-800 pb-0">
        {(["scanner", "history"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              "px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px",
              activeTab === tab
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-zinc-500 hover:text-zinc-300"
            )}
          >
            {tab === "scanner" ? (
              <span className="flex items-center gap-1.5">
                <Key className="h-3.5 w-3.5" /> Scanner
              </span>
            ) : (
              <span className="flex items-center gap-1.5">
                <History className="h-3.5 w-3.5" /> History
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── SCANNER TAB ─────────────────────────────────────────────────────── */}
      {activeTab === "scanner" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Config panel */}
          <div className="space-y-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <Key className="h-4 w-4 text-amber-400" />
                  Scan Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Target */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Target</Label>
                  <Input
                    placeholder="https://example.com or myorg"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={isScanning}
                    onKeyDown={(e) => e.key === "Enter" && !isScanning && startScan()}
                    className="font-mono text-xs"
                  />
                  <p className="text-[10px] text-zinc-600">
                    {scanType === "url"
                      ? "Full URL or domain (e.g. https://app.example.com)"
                      : scanType === "github_org"
                      ? "GitHub organization name (e.g. google)"
                      : "GitHub username (e.g. torvalds)"}
                  </p>
                </div>

                {/* Scan type */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Scan Type</Label>
                  <Select value={scanType} onValueChange={setScanType} disabled={isScanning}>
                    <SelectTrigger className="text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SCAN_TYPES.map((t) => (
                        <SelectItem key={t.value} value={t.value}>
                          <div>
                            <p className="font-medium">{t.label}</p>
                            <p className="text-[10px] text-zinc-500">{t.desc}</p>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {/* GitHub token */}
                {(scanType === "github_org" || scanType === "github_user") && (
                  <div className="space-y-1.5">
                    <Label className="text-xs text-zinc-400">
                      GitHub Token <span className="text-zinc-600">(optional)</span>
                    </Label>
                    <Input
                      type="password"
                      placeholder="ghp_..."
                      value={githubToken}
                      onChange={(e) => setGithubToken(e.target.value)}
                      disabled={isScanning}
                      className="font-mono text-xs"
                    />
                    <p className="text-[10px] text-zinc-600">Increases rate limits for private orgs</p>
                  </div>
                )}

                {/* Wayback toggle */}
                {scanType === "url" && (
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs text-zinc-400">Include Wayback URLs</p>
                      <p className="text-[10px] text-zinc-600">Scan archived JS/JSON/config files</p>
                    </div>
                    <button
                      onClick={() => !isScanning && setIncludeWayback(!includeWayback)}
                      className={cn(
                        "relative w-9 h-5 rounded-full transition-colors",
                        includeWayback ? "bg-blue-600" : "bg-zinc-700"
                      )}
                    >
                      <span className={cn(
                        "absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform",
                        includeWayback ? "translate-x-4" : "translate-x-0.5"
                      )} />
                    </button>
                  </div>
                )}

                {/* Max JS files */}
                {scanType === "url" && (
                  <div className="space-y-1.5">
                    <Label className="text-xs text-zinc-400">Max JS Files</Label>
                    <Input
                      type="number"
                      min={1}
                      max={500}
                      value={maxJsFiles}
                      onChange={(e) => setMaxJsFiles(Math.max(1, Math.min(500, Number(e.target.value))))}
                      disabled={isScanning}
                      className="text-xs"
                    />
                    <p className="text-[10px] text-zinc-600">Maximum JS/config files to fetch and scan</p>
                  </div>
                )}

                {/* Action button */}
                {isScanning ? (
                  <Button onClick={stopScan} variant="destructive" className="w-full gap-2">
                    <Square className="h-4 w-4" /> Stop Scan
                  </Button>
                ) : (
                  <Button onClick={startScan} className="w-full gap-2">
                    <Play className="h-4 w-4" /> Start Scan
                  </Button>
                )}
              </CardContent>
            </Card>

            {/* Summary stats */}
            {scanStats && (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                    Scan Summary
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex flex-wrap gap-2">
                    {SEVERITY_ORDER.map((sev) => (
                      <StatPill key={sev} count={scanStats[sev]} severity={sev} />
                    ))}
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs">
                      <span className="text-zinc-500">Files scanned</span>
                      <span className="text-zinc-300 font-medium">{scanStats.files_scanned}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-zinc-500">Total findings</span>
                      <span className={cn("font-medium", totalFindings > 0 ? "text-red-400" : "text-emerald-400")}>
                        {totalFindings}
                      </span>
                    </div>
                    {scanDuration !== null && (
                      <div className="flex justify-between text-xs">
                        <span className="text-zinc-500">Duration</span>
                        <span className="text-zinc-300 font-medium">{scanDuration}s</span>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Status indicator */}
            {scanStatus !== "idle" && !scanStats && (
              <Card>
                <CardContent className="pt-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-zinc-500">Status</span>
                    <div className="flex items-center gap-1.5">
                      {scanStatus === "running" && (
                        <div className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
                      )}
                      {scanStatus === "completed" && <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />}
                      {scanStatus === "failed" && <AlertCircle className="h-3.5 w-3.5 text-red-400" />}
                      <span className={cn("text-xs font-medium capitalize",
                        scanStatus === "running" && "text-blue-400",
                        scanStatus === "completed" && "text-emerald-400",
                        scanStatus === "failed" && "text-red-400",
                      )}>
                        {scanStatus}
                      </span>
                    </div>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-zinc-500">Findings so far</span>
                    <span className={cn("font-medium", totalFindings > 0 ? "text-red-400" : "text-zinc-300")}>
                      {totalFindings}
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-zinc-500">Events received</span>
                    <span className="text-zinc-300 font-medium">{progressLog.length}</span>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Results panel */}
          <div className="lg:col-span-2 space-y-4">
            {/* Progress log */}
            {(isScanning || progressLog.length > 0) && (
              <div className="rounded-lg border border-zinc-800 bg-zinc-950">
                <div className="flex items-center justify-between border-b border-zinc-800 px-3 py-2">
                  <span className="text-xs text-zinc-500 font-mono flex items-center gap-1.5">
                    <FileSearch className="h-3.5 w-3.5" />
                    {isScanning ? "Scanning..." : "Scan log"}
                  </span>
                  {!isScanning && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setProgressLog([])}
                      className="h-6 w-6 p-0"
                    >
                      <RotateCcw className="h-3 w-3" />
                    </Button>
                  )}
                </div>
                <div className="h-48 overflow-y-auto p-3 space-y-0.5 font-mono text-xs">
                  {progressLog.map((p, i) => (
                    <div key={i} className="flex items-start gap-2 leading-5">
                      <span className={cn("shrink-0 text-[10px] uppercase px-1 rounded mt-0.5",
                        p.phase === "js_discovery" ? "text-blue-400 bg-blue-950/50" :
                        p.phase === "wayback" ? "text-purple-400 bg-purple-950/50" :
                        p.phase === "secret_scan" ? "text-amber-400 bg-amber-950/50" :
                        p.phase === "exposed_files" ? "text-red-400 bg-red-950/50" :
                        p.phase === "github_enum" ? "text-emerald-400 bg-emerald-950/50" :
                        "text-zinc-500 bg-zinc-800"
                      )}>
                        {p.phase.replace("_", " ")}
                      </span>
                      <span className="text-zinc-400 truncate">{p.message}</span>
                    </div>
                  ))}
                  {isScanning && (
                    <div className="flex items-center gap-2 text-blue-400">
                      <div className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                      <span>Scanning...</span>
                    </div>
                  )}
                  <div ref={progressEndRef} />
                </div>
              </div>
            )}

            {/* Findings by severity */}
            {totalFindings > 0 && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-red-400" />
                    Findings ({totalFindings})
                  </h3>
                  {currentScanId && (
                    <span className="text-[10px] text-zinc-600 font-mono">ID: {currentScanId}</span>
                  )}
                </div>

                {SEVERITY_ORDER.map((sev) => {
                  const group = findingsBySeverity[sev];
                  if (group.length === 0) return null;
                  const cfg = SEVERITY_CONFIG[sev];
                  return (
                    <div key={sev} className="space-y-2">
                      <div className="flex items-center gap-2">
                        <span className={cn("text-xs font-bold uppercase tracking-wider", cfg.color)}>
                          {cfg.label}
                        </span>
                        <span className={cn("text-xs rounded-full px-2 py-0.5 font-bold", cfg.bg, cfg.color)}>
                          {group.length}
                        </span>
                      </div>
                      <div className="space-y-2">
                        {group.map((f, i) => (
                          <FindingCard key={`${f.url}-${f.name}-${i}`} finding={f} />
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Empty/idle state */}
            {scanStatus === "idle" && progressLog.length === 0 && (
              <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
                <Key className="h-12 w-12" />
                <p className="text-sm">Configure a target and run a scan</p>
                <p className="text-xs text-zinc-700">Detects API keys, passwords, private keys, exposed .git, .env files, and more</p>
              </div>
            )}

            {/* Completed, no findings */}
            {scanStatus === "completed" && totalFindings === 0 && (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500 space-y-3">
                <CheckCircle2 className="h-10 w-10 text-emerald-500" />
                <p className="text-sm font-medium text-emerald-400">No secrets detected</p>
                <p className="text-xs text-zinc-600">
                  Scanned {scanStats?.files_scanned ?? 0} file{scanStats?.files_scanned !== 1 ? "s" : ""} — nothing suspicious found
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── HISTORY TAB ─────────────────────────────────────────────────────── */}
      {activeTab === "history" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
          {/* History list */}
          <div className="lg:col-span-2 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-zinc-300">Past Scans</h3>
              <Button
                variant="ghost"
                size="sm"
                onClick={loadHistory}
                disabled={historyLoading}
                className="gap-1.5 text-xs text-zinc-500"
              >
                <RotateCcw className={cn("h-3 w-3", historyLoading && "animate-spin")} />
                Refresh
              </Button>
            </div>

            {historyLoading ? (
              <div className="text-center py-8 text-zinc-600 text-sm">Loading...</div>
            ) : history.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-zinc-600 space-y-2">
                <History className="h-8 w-8" />
                <p className="text-sm">No scans yet</p>
              </div>
            ) : (
              <div className="space-y-2">
                {history.map((entry) => {
                  const total = entry.stats
                    ? (entry.stats.critical ?? 0) + (entry.stats.high ?? 0) +
                      (entry.stats.medium ?? 0) + (entry.stats.low ?? 0)
                    : 0;
                  const isSelected = selectedHistoryEntry?.id === entry.id;
                  return (
                    <div key={entry.id} className="relative group">
                      <button
                        className={cn(
                          "w-full flex items-start gap-3 rounded-lg border p-3 hover:border-zinc-700 transition-colors text-left",
                          isSelected
                            ? "border-blue-700 bg-blue-950/20"
                            : "border-zinc-800 bg-zinc-900"
                        )}
                        onClick={() => loadHistoryEntry(entry)}
                      >
                        <div className="shrink-0 mt-0.5">
                          {total === 0 ? (
                            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                          ) : (
                            <ShieldAlert className="h-4 w-4 text-red-400" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-mono text-zinc-200 truncate">{entry.target}</p>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <span className="text-[10px] text-zinc-500 capitalize">
                              {entry.scan_type.replace("_", " ")}
                            </span>
                            <span className="text-zinc-700">·</span>
                            <span className="text-[10px] text-zinc-500 flex items-center gap-1">
                              <Clock className="h-2.5 w-2.5" />
                              {new Date(entry.started_at).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          <p className={cn("text-xs font-bold", total > 0 ? "text-red-400" : "text-emerald-400")}>
                            {total} finding{total !== 1 ? "s" : ""}
                          </p>
                          {entry.stats?.critical > 0 && (
                            <p className="text-[10px] text-red-500">{entry.stats.critical} critical</p>
                          )}
                        </div>
                      </button>
                      <button
                        onClick={(e) => deleteHistoryEntry(entry.id, e)}
                        className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded text-zinc-600 hover:text-red-400"
                        title="Delete scan"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* History detail */}
          <div className="lg:col-span-3">
            {selectedHistoryEntry ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-semibold text-zinc-200 font-mono">{selectedHistoryEntry.target}</p>
                    <p className="text-xs text-zinc-500 capitalize">
                      {selectedHistoryEntry.scan_type?.replace("_", " ")} ·{" "}
                      {new Date(selectedHistoryEntry.started_at).toLocaleString()} ·{" "}
                      {selectedHistoryEntry.duration_seconds}s
                    </p>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      const blob = new Blob(
                        [JSON.stringify(selectedHistoryEntry, null, 2)],
                        { type: "application/json" }
                      );
                      const a = document.createElement("a");
                      a.href = URL.createObjectURL(blob);
                      a.download = `secrets-${selectedHistoryEntry.target.replace(/[^a-z0-9]/gi, "_")}.json`;
                      a.click();
                    }}
                    className="gap-1.5"
                  >
                    <Download className="h-3.5 w-3.5" /> Export
                  </Button>
                </div>

                {/* Stats summary */}
                {selectedHistoryEntry.stats && (
                  <div className="flex flex-wrap gap-2">
                    {SEVERITY_ORDER.map((sev) => (
                      <StatPill
                        key={sev}
                        count={selectedHistoryEntry.stats[sev] ?? 0}
                        severity={sev}
                      />
                    ))}
                    <div className="flex items-center gap-1.5 rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1.5">
                      <span className="text-sm font-bold tabular-nums text-zinc-300">
                        {selectedHistoryEntry.stats.files_scanned ?? 0}
                      </span>
                      <span className="text-xs text-zinc-500">files</span>
                    </div>
                  </div>
                )}

                {/* Findings grouped by severity */}
                {(selectedHistoryEntry.findings?.length ?? 0) === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-zinc-600 space-y-2">
                    <CheckCircle2 className="h-8 w-8 text-emerald-600" />
                    <p className="text-sm text-emerald-500">No findings in this scan</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {SEVERITY_ORDER.map((sev) => {
                      const group = (selectedHistoryEntry.findings ?? []).filter(
                        (f) => f.severity === sev
                      );
                      if (group.length === 0) return null;
                      const cfg = SEVERITY_CONFIG[sev];
                      return (
                        <div key={sev} className="space-y-2">
                          <div className="flex items-center gap-2">
                            <span className={cn("text-xs font-bold uppercase tracking-wider", cfg.color)}>
                              {cfg.label}
                            </span>
                            <span className={cn("text-xs rounded-full px-2 py-0.5 font-bold", cfg.bg, cfg.color)}>
                              {group.length}
                            </span>
                          </div>
                          <div className="space-y-2">
                            {group.map((f, i) => (
                              <FindingCard key={`${f.url}-${f.name}-${i}`} finding={f} />
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full py-20 text-zinc-600 space-y-2">
                <Globe className="h-8 w-8" />
                <p className="text-sm">Select a scan from the list to view results</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
