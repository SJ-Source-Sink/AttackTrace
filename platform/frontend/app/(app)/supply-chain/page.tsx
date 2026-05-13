"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Package, Upload, Play, Square, CheckCircle2, AlertTriangle,
  ChevronDown, ChevronUp, History, Trash2, ArrowLeft, Clock,
  Loader2, ShieldAlert, ShieldOff, ExternalLink, FileText, RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

interface SupplyFinding {
  package: string;
  version: string;
  ecosystem: string;
  vuln_id: string;
  cve: string;
  title: string;
  severity: Severity;
  cvss: string | null;
  fixed_versions: string[];
  references: string[];
  detail?: string;
}

interface ScanRecord {
  id: string;
  filename: string;
  ecosystem: string;
  deps_count: number;
  findings_count: number;
  severity_counts: Record<Severity, number>;
  findings: SupplyFinding[];
  started_at: string;
  completed_at: string;
  status: string;
}

const SEV_CONFIG: Record<Severity, { label: string; color: string; bg: string; border: string }> = {
  CRITICAL: { label: "Critical", color: "text-red-400", bg: "bg-red-950/40", border: "border-red-800/60" },
  HIGH:     { label: "High",     color: "text-orange-400", bg: "bg-orange-950/40", border: "border-orange-800/60" },
  MEDIUM:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-950/40", border: "border-yellow-800/60" },
  LOW:      { label: "Low",      color: "text-blue-400", bg: "bg-blue-950/40", border: "border-blue-800/60" },
  INFO:     { label: "Info",     color: "text-zinc-400", bg: "bg-zinc-800/40", border: "border-zinc-700/60" },
};

const SUPPORTED_FILES = ["package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml", "go.mod", "Cargo.toml"];

export default function SupplyChainPage() {
  const [tab, setTab] = useState<"scanner" | "history">("scanner");
  const [file, setFile] = useState<File | null>(null);
  const [checkConfusion, setCheckConfusion] = useState(true);
  const [running, setRunning] = useState(false);
  const [findings, setFindings] = useState<SupplyFinding[]>([]);
  const [progress, setProgress] = useState<string[]>([]);
  const [scanMeta, setScanMeta] = useState<{ depsCount: number; ecosystem: string } | null>(null);
  const [history, setHistory] = useState<ScanRecord[]>([]);
  const [historyDetail, setHistoryDetail] = useState<ScanRecord | null>(null);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const abortRef = useRef<AbortController | null>(null);

  const loadHistory = useCallback(async () => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/supply-chain/history`);
      const data = await res.json();
      setHistory(data.items ?? []);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { if (tab === "history") loadHistory(); }, [tab, loadHistory]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFile(e.target.files?.[0] ?? null);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setFile(e.dataTransfer.files[0] ?? null);
  };

  const startScan = async () => {
    if (!file) { toast.error("Please select a dependency file"); return; }
    setRunning(true);
    setFindings([]);
    setProgress([]);
    setScanMeta(null);
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      const form = new FormData();
      form.append("file", file);
      form.append("check_confusion", checkConfusion ? "true" : "false");

      const token = localStorage.getItem("access_token");
      const orgId = localStorage.getItem("org_id");
      const headers: Record<string, string> = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;
      if (orgId) headers["X-Org-ID"] = orgId;

      const res = await fetch(`${API_BASE}/supply-chain/scan`, {
        method: "POST",
        headers,
        body: form,
        signal: ctrl.signal,
      });
      if (!res.ok) { toast.error("Scan failed to start"); setRunning(false); return; }

      const reader = res.body!.getReader();
      const dec = new TextDecoder();
      let buf = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() ?? "";
        for (const part of parts) {
          const dataLine = part.split("\n").find(l => l.startsWith("data:"));
          if (!dataLine) continue;
          try {
            const evt = JSON.parse(dataLine.slice(5).trim());
            if (evt.event_type === "finding" || part.startsWith("event: finding")) {
              setFindings(prev => [...prev, evt.finding ?? evt]);
            } else if (part.startsWith("event: finding")) {
              // already handled
            } else if (part.startsWith("event: progress")) {
              setProgress(prev => [...prev, evt.message ?? ""]);
            } else if (part.startsWith("event: start")) {
              setProgress(prev => [...prev, `Started scan on ${evt.filename}`]);
            } else if (part.startsWith("event: complete")) {
              setScanMeta({ depsCount: evt.deps_count ?? 0, ecosystem: evt.ecosystem ?? "" });
              toast.success(`Scan complete — ${evt.findings_count} findings`);
              setRunning(false);
            } else if (part.startsWith("event: error")) {
              toast.error(evt.message ?? "Scan error");
              setRunning(false);
            }
            // parse SSE events by event: line
            const eventLine = part.split("\n").find(l => l.startsWith("event:"));
            const event = eventLine?.slice(6).trim();
            if (event === "finding") {
              const d = JSON.parse(dataLine.slice(5).trim());
              if (d.finding) setFindings(prev => [...prev, d.finding]);
            } else if (event === "progress") {
              const d = JSON.parse(dataLine.slice(5).trim());
              setProgress(prev => [...prev.slice(-19), d.message ?? ""]);
            } else if (event === "complete") {
              const d = JSON.parse(dataLine.slice(5).trim());
              setScanMeta({ depsCount: d.deps_count ?? 0, ecosystem: "" });
              setRunning(false);
            }
          } catch { /* ignore parse errors */ }
        }
      }
    } catch (e: unknown) {
      if ((e as { name?: string }).name !== "AbortError") toast.error("Scan connection lost");
      setRunning(false);
    }
  };

  const stopScan = () => { abortRef.current?.abort(); setRunning(false); };

  const toggleExpand = (id: string) => {
    setExpandedIds(prev => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  };

  const deleteHistory = async (id: string) => {
    await fetchWithAuth(`${API_BASE}/supply-chain/history/${id}`, { method: "DELETE" });
    setHistory(prev => prev.filter(h => h.id !== id));
    if (historyDetail?.id === id) setHistoryDetail(null);
  };

  const sevCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <PageHeader title="Supply Chain Scanner" description="Detect vulnerable dependencies and dependency confusion attacks via OSV.dev" />

      {/* Tabs */}
      <div className="px-6 pt-4">
        <div className="flex gap-1 border-b border-zinc-800 mb-6">
          {(["scanner", "history"] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors capitalize",
                tab === t ? "border-emerald-500 text-emerald-400" : "border-transparent text-zinc-400 hover:text-zinc-200"
              )}
            >
              {t === "history" ? <><History className="inline h-3.5 w-3.5 mr-1.5" />History</> : <><Package className="inline h-3.5 w-3.5 mr-1.5" />Scanner</>}
            </button>
          ))}
        </div>

        {/* ── Scanner Tab ─────────────────────────────────────────────────── */}
        {tab === "scanner" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Config */}
            <Card className="bg-zinc-900 border-zinc-800 lg:col-span-1">
              <CardHeader>
                <CardTitle className="text-sm text-zinc-300">Configuration</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* File drop */}
                <div>
                  <Label className="text-zinc-400 text-xs mb-2 block">Dependency File</Label>
                  <div
                    onDrop={handleDrop}
                    onDragOver={e => e.preventDefault()}
                    className="border-2 border-dashed border-zinc-700 rounded-lg p-6 text-center cursor-pointer hover:border-emerald-600 transition-colors"
                    onClick={() => document.getElementById("dep-file")?.click()}
                  >
                    <Upload className="h-8 w-8 text-zinc-500 mx-auto mb-2" />
                    <p className="text-xs text-zinc-400">
                      {file ? file.name : "Drop a dependency file or click to browse"}
                    </p>
                    <p className="text-xs text-zinc-600 mt-1">{SUPPORTED_FILES.join(", ")}</p>
                    <input id="dep-file" type="file" className="hidden" onChange={handleFileChange} />
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-zinc-300 text-sm">Check Dependency Confusion</Label>
                    <p className="text-xs text-zinc-500 mt-0.5">Detect internal packages on public registries</p>
                  </div>
                  <Switch checked={checkConfusion} onCheckedChange={setCheckConfusion} />
                </div>
                <div className="flex gap-2">
                  <Button onClick={startScan} disabled={running || !file} className="flex-1 bg-emerald-600 hover:bg-emerald-700">
                    {running ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
                    {running ? "Scanning..." : "Start Scan"}
                  </Button>
                  {running && (
                    <Button onClick={stopScan} variant="outline" className="border-zinc-700 text-red-400 hover:bg-red-950/30">
                      <Square className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Results */}
            <div className="lg:col-span-2 space-y-4">
              {/* Stats */}
              {(findings.length > 0 || running) && (
                <div className="grid grid-cols-5 gap-3">
                  {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]).map(sev => (
                    <Card key={sev} className={cn("border", SEV_CONFIG[sev].bg, SEV_CONFIG[sev].border)}>
                      <CardContent className="p-3 text-center">
                        <p className={cn("text-xl font-bold", SEV_CONFIG[sev].color)}>{sevCounts[sev] ?? 0}</p>
                        <p className="text-xs text-zinc-400">{SEV_CONFIG[sev].label}</p>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}

              {/* Progress */}
              {progress.length > 0 && (
                <Card className="bg-zinc-900 border-zinc-800">
                  <CardContent className="p-3">
                    {progress.slice(-5).map((msg, i) => (
                      <p key={i} className="text-xs text-zinc-400 py-0.5">{msg}</p>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Findings */}
              {findings.length > 0 && (
                <Card className="bg-zinc-900 border-zinc-800">
                  <CardHeader className="py-3 px-4 border-b border-zinc-800">
                    <CardTitle className="text-sm text-zinc-200">{findings.length} Vulnerabilities Found</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0 divide-y divide-zinc-800 max-h-[600px] overflow-y-auto">
                    {findings.map((f, i) => {
                      const key = `${f.package}-${f.vuln_id}-${i}`;
                      const expanded = expandedIds.has(key);
                      const cfg = SEV_CONFIG[f.severity] ?? SEV_CONFIG.INFO;
                      return (
                        <div key={key} className="p-4">
                          <div className="flex items-start justify-between cursor-pointer" onClick={() => toggleExpand(key)}>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <Badge className={cn("text-xs", cfg.bg, cfg.color, cfg.border)}>{cfg.label}</Badge>
                                <span className="font-mono text-sm text-zinc-200">{f.package}</span>
                                {f.version && <span className="text-xs text-zinc-500">v{f.version}</span>}
                                <span className="text-xs text-zinc-600">[{f.ecosystem}]</span>
                              </div>
                              <p className="text-sm text-zinc-300 mt-1">{f.title}</p>
                              {f.cve && <span className="text-xs text-emerald-400 font-mono">{f.cve}</span>}
                            </div>
                            {expanded ? <ChevronUp className="h-4 w-4 text-zinc-500 flex-shrink-0" /> : <ChevronDown className="h-4 w-4 text-zinc-500 flex-shrink-0" />}
                          </div>
                          {expanded && (
                            <div className="mt-3 space-y-2 text-xs text-zinc-400 border-t border-zinc-800 pt-3">
                              {f.detail && <p>{f.detail}</p>}
                              {f.fixed_versions.length > 0 && (
                                <p className="text-green-400">Fix: upgrade to {f.fixed_versions.join(", ")}</p>
                              )}
                              {f.references.map((ref, ri) => (
                                <a key={ri} href={ref} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-blue-400 hover:underline">
                                  <ExternalLink className="h-3 w-3" />{ref}
                                </a>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </CardContent>
                </Card>
              )}

              {!running && findings.length === 0 && progress.length === 0 && (
                <div className="flex flex-col items-center justify-center h-48 text-zinc-600">
                  <Package className="h-12 w-12 mb-3 opacity-30" />
                  <p className="text-sm">Upload a dependency file and start scanning</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── History Tab ─────────────────────────────────────────────────── */}
        {tab === "history" && (
          <div>
            {historyDetail ? (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <Button variant="ghost" size="sm" onClick={() => setHistoryDetail(null)} className="text-zinc-400">
                    <ArrowLeft className="h-4 w-4 mr-1" /> Back
                  </Button>
                  <h2 className="text-lg font-semibold text-zinc-200">{historyDetail.filename}</h2>
                  <Badge className="text-xs bg-zinc-800 text-zinc-400">{historyDetail.ecosystem}</Badge>
                </div>
                <div className="grid grid-cols-5 gap-3">
                  {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]).map(sev => (
                    <Card key={sev} className={cn("border", SEV_CONFIG[sev].bg, SEV_CONFIG[sev].border)}>
                      <CardContent className="p-3 text-center">
                        <p className={cn("text-xl font-bold", SEV_CONFIG[sev].color)}>{historyDetail.severity_counts?.[sev] ?? 0}</p>
                        <p className="text-xs text-zinc-400">{SEV_CONFIG[sev].label}</p>
                      </CardContent>
                    </Card>
                  ))}
                </div>
                <Card className="bg-zinc-900 border-zinc-800">
                  <CardContent className="p-0 divide-y divide-zinc-800 max-h-[600px] overflow-y-auto">
                    {(historyDetail.findings ?? []).map((f, i) => {
                      const cfg = SEV_CONFIG[f.severity] ?? SEV_CONFIG.INFO;
                      return (
                        <div key={i} className="p-4 flex items-start gap-3">
                          <Badge className={cn("text-xs mt-0.5", cfg.bg, cfg.color, cfg.border)}>{cfg.label}</Badge>
                          <div>
                            <span className="font-mono text-sm text-zinc-200">{f.package}</span>
                            {f.version && <span className="text-xs text-zinc-500 ml-2">v{f.version}</span>}
                            <p className="text-sm text-zinc-300 mt-0.5">{f.title}</p>
                            {f.cve && <span className="text-xs text-emerald-400 font-mono">{f.cve}</span>}
                          </div>
                        </div>
                      );
                    })}
                  </CardContent>
                </Card>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h2 className="text-base font-semibold text-zinc-200">Scan History</h2>
                  <Button variant="ghost" size="sm" onClick={loadHistory} className="text-zinc-400">
                    <RefreshCw className="h-4 w-4 mr-1" /> Refresh
                  </Button>
                </div>
                {history.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-40 text-zinc-600">
                    <History className="h-10 w-10 mb-2 opacity-30" />
                    <p className="text-sm">No scan history yet</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {history.map(h => (
                      <Card key={h.id} className="bg-zinc-900 border-zinc-800 hover:border-zinc-700 transition-colors cursor-pointer" onClick={() => setHistoryDetail(h)}>
                        <CardContent className="p-4 flex items-center justify-between">
                          <div>
                            <div className="flex items-center gap-2">
                              <FileText className="h-4 w-4 text-emerald-400" />
                              <span className="font-medium text-zinc-200">{h.filename}</span>
                              <Badge className="text-xs bg-zinc-800 text-zinc-400">{h.ecosystem}</Badge>
                            </div>
                            <div className="flex gap-3 mt-1 text-xs text-zinc-500">
                              <span><Clock className="inline h-3 w-3 mr-1" />{new Date(h.started_at).toLocaleString()}</span>
                              <span>{h.deps_count} deps</span>
                              <span className={h.findings_count > 0 ? "text-red-400" : "text-green-400"}>
                                {h.findings_count} findings
                              </span>
                            </div>
                          </div>
                          <Button variant="ghost" size="sm" onClick={e => { e.stopPropagation(); deleteHistory(h.id); }} className="text-zinc-500 hover:text-red-400">
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
