"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Container, Play, Square, CheckCircle2, AlertTriangle, Shield,
  ChevronDown, ChevronUp, History, Trash2, ArrowLeft, Clock,
  Loader2, Server, Globe, Lock, RefreshCw, ExternalLink, RotateCcw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

interface ContainerFinding {
  category: string;
  title: string;
  severity: Severity;
  endpoint: string;
  detail: string;
  evidence?: string;
  remediation?: string;
}

interface ScanRecord {
  id: string;
  target: string;
  scan_type: string;
  findings_count: number;
  severity_counts: Record<Severity, number>;
  findings: ContainerFinding[];
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

export default function ContainerScannerPage() {
  const [tab, setTab] = useState<"scanner" | "history">("scanner");
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("kubernetes");
  const [checkK8s, setCheckK8s] = useState(true);
  const [checkRegistry, setCheckRegistry] = useState(true);
  const [running, setRunning] = useState(false);
  const [findings, setFindings] = useState<ContainerFinding[]>([]);
  const [progress, setProgress] = useState<string[]>([]);
  const [history, setHistory] = useState<ScanRecord[]>([]);
  const [historyDetail, setHistoryDetail] = useState<ScanRecord | null>(null);
  const [expandedIds, setExpandedIds] = useState<Set<number>>(new Set());
  const abortRef = useRef<AbortController | null>(null);

  const loadHistory = useCallback(async () => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/container/history`);
      const data = await res.json();
      setHistory(data.items ?? []);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { if (tab === "history") loadHistory(); }, [tab, loadHistory]);

  const startScan = async () => {
    if (!target.trim()) { toast.error("Enter a target host/URL"); return; }
    setRunning(true);
    setFindings([]);
    setProgress([]);
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      const res = await fetchWithAuth(`${API_BASE}/container/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), scan_type: scanType, check_k8s_ports: checkK8s, check_registry: checkRegistry }),
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
          const eventLine = part.split("\n").find(l => l.startsWith("event:"));
          const dataLine = part.split("\n").find(l => l.startsWith("data:"));
          if (!dataLine) continue;
          try {
            const evt = JSON.parse(dataLine.slice(5).trim());
            const event = eventLine?.slice(6).trim();
            if (event === "finding") {
              setFindings(prev => [...prev, evt.finding ?? evt]);
            } else if (event === "progress") {
              setProgress(prev => [...prev.slice(-19), evt.message ?? ""]);
            } else if (event === "complete") {
              toast.success(`Scan complete — ${evt.findings_count} findings`);
              setRunning(false);
            } else if (event === "error") {
              toast.error(evt.message ?? "Scan error");
              setRunning(false);
            }
          } catch { /* ignore */ }
        }
      }
    } catch (e: unknown) {
      if ((e as { name?: string }).name !== "AbortError") toast.error("Connection lost");
      setRunning(false);
    }
  };

  const stopScan = () => { abortRef.current?.abort(); setRunning(false); };

  const toggleExpand = (i: number) => {
    setExpandedIds(prev => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n; });
  };

  const deleteHistory = async (id: string) => {
    await fetchWithAuth(`${API_BASE}/container/history/${id}`, { method: "DELETE" });
    setHistory(prev => prev.filter(h => h.id !== id));
    if (historyDetail?.id === id) setHistoryDetail(null);
  };

  const restoreFromHistory = (h: ScanRecord) => {
    setTarget(h.target);
    setScanType(h.scan_type || "kubernetes");
    setTab("scanner");
    toast.success(`Restored: ${h.target}`);
  };

  const sevCounts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {} as Record<string, number>);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <PageHeader title="Container & K8s Scanner" description="Detect exposed Kubernetes APIs, open Docker registries, and container misconfigurations" />

      <div className="px-6 pt-4">
        <div className="flex gap-1 border-b border-zinc-800 mb-6">
          {(["scanner", "history"] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={cn("px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors",
                tab === t ? "border-cyan-500 text-cyan-400" : "border-transparent text-zinc-400 hover:text-zinc-200")}>
              {t === "history" ? <><History className="inline h-3.5 w-3.5 mr-1.5" />History</> : <><Container className="inline h-3.5 w-3.5 mr-1.5" />Scanner</>}
            </button>
          ))}
        </div>

        {tab === "scanner" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="bg-zinc-900 border-zinc-800 lg:col-span-1">
              <CardHeader><CardTitle className="text-sm text-zinc-300">Configuration</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label className="text-zinc-400 text-xs mb-1 block">Target Host / URL</Label>
                  <Input
                    value={target}
                    onChange={e => setTarget(e.target.value)}
                    placeholder="e.g. k8s.example.com or https://registry.example.com"
                    className="bg-zinc-800 border-zinc-700 text-zinc-100"
                  />
                </div>
                <div>
                  <Label className="text-zinc-400 text-xs mb-1 block">Scan Type</Label>
                  <select value={scanType} onChange={e => setScanType(e.target.value)}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-md px-3 py-2 text-sm text-zinc-100">
                    <option value="kubernetes">Kubernetes Cluster</option>
                    <option value="registry">Docker Registry</option>
                    <option value="both">Both</option>
                  </select>
                </div>
                <div className="flex items-center justify-between">
                  <Label className="text-zinc-300 text-sm">Check K8s Ports</Label>
                  <Switch checked={checkK8s} onCheckedChange={setCheckK8s} />
                </div>
                <div className="flex items-center justify-between">
                  <Label className="text-zinc-300 text-sm">Check Docker Registry</Label>
                  <Switch checked={checkRegistry} onCheckedChange={setCheckRegistry} />
                </div>
                <div className="flex gap-2">
                  <Button onClick={startScan} disabled={running || !target.trim()} className="flex-1 bg-cyan-600 hover:bg-cyan-700">
                    {running ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
                    {running ? "Scanning..." : "Start Scan"}
                  </Button>
                  {running && (
                    <Button onClick={stopScan} variant="outline" className="border-zinc-700 text-red-400">
                      <Square className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>

            <div className="lg:col-span-2 space-y-4">
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

              {progress.length > 0 && (
                <Card className="bg-zinc-900 border-zinc-800">
                  <CardContent className="p-3">
                    {progress.slice(-5).map((msg, i) => <p key={i} className="text-xs text-zinc-400 py-0.5">{msg}</p>)}
                  </CardContent>
                </Card>
              )}

              {findings.length > 0 && (
                <Card className="bg-zinc-900 border-zinc-800">
                  <CardHeader className="py-3 px-4 border-b border-zinc-800">
                    <CardTitle className="text-sm text-zinc-200">{findings.length} Findings</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0 divide-y divide-zinc-800 max-h-[600px] overflow-y-auto">
                    {findings.map((f, i) => {
                      const expanded = expandedIds.has(i);
                      const cfg = SEV_CONFIG[f.severity] ?? SEV_CONFIG.INFO;
                      return (
                        <div key={i} className="p-4">
                          <div className="flex items-start justify-between cursor-pointer" onClick={() => toggleExpand(i)}>
                            <div className="flex-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <Badge className={cn("text-xs", cfg.bg, cfg.color, cfg.border)}>{cfg.label}</Badge>
                                <span className="text-xs text-zinc-500 font-mono">{f.category}</span>
                              </div>
                              <p className="text-sm font-medium text-zinc-200 mt-1">{f.title}</p>
                              <p className="text-xs text-zinc-500 mt-0.5 font-mono">{f.endpoint}</p>
                            </div>
                            {expanded ? <ChevronUp className="h-4 w-4 text-zinc-500 flex-shrink-0" /> : <ChevronDown className="h-4 w-4 text-zinc-500 flex-shrink-0" />}
                          </div>
                          {expanded && (
                            <div className="mt-3 space-y-2 text-xs border-t border-zinc-800 pt-3">
                              <p className="text-zinc-400">{f.detail}</p>
                              {f.evidence && <p className="font-mono text-zinc-500 bg-zinc-800 rounded p-2">{f.evidence}</p>}
                              {f.remediation && <p className="text-green-400">Fix: {f.remediation}</p>}
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
                  <Container className="h-12 w-12 mb-3 opacity-30" />
                  <p className="text-sm">Enter a target and start scanning</p>
                </div>
              )}
            </div>
          </div>
        )}

        {tab === "history" && (
          <div>
            {historyDetail ? (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <Button variant="ghost" size="sm" onClick={() => setHistoryDetail(null)} className="text-zinc-400">
                    <ArrowLeft className="h-4 w-4 mr-1" /> Back
                  </Button>
                  <h2 className="text-lg font-semibold text-zinc-200">{historyDetail.target}</h2>
                  <Button
                    variant="outline"
                    size="sm"
                    className="ml-auto gap-1.5 border-zinc-700 text-cyan-400 hover:text-cyan-300"
                    onClick={() => restoreFromHistory(historyDetail)}
                  >
                    <RotateCcw className="h-3.5 w-3.5" /> Restore to Scanner
                  </Button>
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
                  <CardContent className="p-0 divide-y divide-zinc-800">
                    {(historyDetail.findings ?? []).map((f, i) => {
                      const cfg = SEV_CONFIG[f.severity] ?? SEV_CONFIG.INFO;
                      return (
                        <div key={i} className="p-4 flex items-start gap-3">
                          <Badge className={cn("text-xs mt-0.5", cfg.bg, cfg.color, cfg.border)}>{cfg.label}</Badge>
                          <div>
                            <p className="text-sm font-medium text-zinc-200">{f.title}</p>
                            <p className="text-xs text-zinc-500">{f.endpoint}</p>
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
                      <Card key={h.id} className="bg-zinc-900 border-zinc-800 hover:border-zinc-700 cursor-pointer" onClick={() => setHistoryDetail(h)}>
                        <CardContent className="p-4 flex items-center justify-between">
                          <div>
                            <div className="flex items-center gap-2">
                              <Container className="h-4 w-4 text-cyan-400" />
                              <span className="font-medium text-zinc-200">{h.target}</span>
                              <Badge className="text-xs bg-zinc-800 text-zinc-400">{h.scan_type}</Badge>
                            </div>
                            <div className="flex gap-3 mt-1 text-xs text-zinc-500">
                              <span><Clock className="inline h-3 w-3 mr-1" />{new Date(h.started_at).toLocaleString()}</span>
                              <span className={h.findings_count > 0 ? "text-red-400" : "text-green-400"}>{h.findings_count} findings</span>
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
