"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Swords, Play, Square, Download, ChevronDown, ChevronRight,
  Shield, AlertTriangle, Info, CheckCircle2, XCircle,
  History, Trash2, Plus, X, Loader2, ToggleLeft, ToggleRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const MODULES = [
  { id: "headers", label: "Security Headers", description: "Check for missing/misconfigured HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)" },
  { id: "redirect", label: "Open Redirect", description: "Test common redirect parameters for open redirect vulnerabilities" },
  { id: "xss", label: "XSS Scanner", description: "Test for reflected Cross-Site Scripting in URL parameters" },
  { id: "sqli", label: "SQL Injection", description: "Time-based and error-based SQL injection detection" },
  { id: "ssrf", label: "SSRF Prober", description: "Test URL parameters for Server-Side Request Forgery to cloud metadata and internal services" },
  { id: "graphql", label: "GraphQL Inspector", description: "Test for exposed GraphQL introspection and batch query abuse" },
  { id: "jwt", label: "JWT Analyzer", description: "Analyze JWT tokens for alg:none bypass, weak secrets, and info exposure" },
  { id: "auth_bypass", label: "Auth Bypass", description: "Test admin paths, HTTP method overrides, and header-based auth bypass" },
  { id: "takeover", label: "Takeover Detection", description: "Check for subdomain/service takeover fingerprints" },
];

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-600/10 text-red-400 border-red-600/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-zinc-500",
};

const SEV_BADGE_TEXT: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-zinc-400",
};

interface AttackFinding {
  id: string;
  module: string;
  test_name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  evidence: string;
  url: string;
  is_vulnerable: boolean;
  remediation: string;
}

interface ScanCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface HistoryEntry {
  id: string;
  target: string;
  started_at: string;
  total_findings: number;
  status: string;
}

interface FindingCardProps {
  finding: AttackFinding;
}

function FindingCard({ finding }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [remExpanded, setRemExpanded] = useState(false);
  const sev = finding.severity ?? "info";

  return (
    <div className={cn(
      "rounded-lg border transition-colors",
      sev === "critical" ? "border-red-600/20 bg-red-600/5" :
      sev === "high" ? "border-orange-500/20 bg-orange-500/5" :
      sev === "medium" ? "border-yellow-500/20" :
      "border-zinc-800"
    )}>
      <button
        className="w-full flex items-start gap-3 p-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={cn("mt-1 h-2 w-2 rounded-full shrink-0", SEV_DOT[sev] ?? "bg-zinc-500")} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-zinc-200">{finding.title}</span>
            <Badge className={cn("text-[10px] border capitalize py-0 h-4", SEV_COLORS[sev])}>
              {finding.severity}
            </Badge>
            <Badge variant="outline" className="text-[10px] py-0 h-4 text-zinc-500">
              {finding.module}
            </Badge>
            {finding.is_vulnerable ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-red-600/10 border border-red-600/30 px-2 py-0 text-[10px] text-red-400 h-4">
                <XCircle className="h-2.5 w-2.5" /> Vulnerable
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 px-2 py-0 text-[10px] text-emerald-400 h-4">
                <CheckCircle2 className="h-2.5 w-2.5" /> Not Vulnerable
              </span>
            )}
          </div>
          <p className="text-[10px] text-zinc-500 mt-0.5">{finding.test_name}</p>
          {finding.url && (
            <p className="text-xs text-zinc-500 font-mono mt-0.5 truncate">{finding.url}</p>
          )}
        </div>
        {expanded
          ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500 shrink-0 mt-0.5" />
          : <ChevronRight className="h-3.5 w-3.5 text-zinc-500 shrink-0 mt-0.5" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-zinc-800/60">
          {finding.description && (
            <div className="pt-3">
              <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Description</p>
              <p className="text-xs text-zinc-300">{finding.description}</p>
            </div>
          )}

          {finding.evidence && (
            <div>
              <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Evidence</p>
              <div className="rounded-md border border-zinc-800 bg-zinc-950 p-2 max-h-[200px] overflow-y-auto">
                <pre className="text-xs text-zinc-300 font-mono whitespace-pre-wrap break-all">{finding.evidence}</pre>
              </div>
            </div>
          )}

          {finding.remediation && (
            <div>
              <button
                className="flex items-center gap-1 text-[10px] text-zinc-500 uppercase tracking-wider hover:text-zinc-300 transition-colors"
                onClick={(e) => { e.stopPropagation(); setRemExpanded(!remExpanded); }}
              >
                {remExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                Remediation
              </button>
              {remExpanded && (
                <p className="text-xs text-zinc-300 mt-1 pl-3 border-l border-zinc-700">{finding.remediation}</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AttackSuitePage() {
  const [target, setTarget] = useState("");
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set(MODULES.map((m) => m.id)));
  const [authHeaders, setAuthHeaders] = useState<{ key: string; value: string }[]>([]);
  const [showAuthHeaders, setShowAuthHeaders] = useState(false);
  const [followRedirects, setFollowRedirects] = useState(true);
  const [timeout, setTimeout] = useState(30);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [progressMessages, setProgressMessages] = useState<{ module: string; message: string }[]>([]);
  const [showProgress, setShowProgress] = useState(true);
  const [findings, setFindings] = useState<AttackFinding[]>([]);
  const [counts, setCounts] = useState<ScanCounts>({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const progressEndRef = useRef<HTMLDivElement>(null);

  // Load history on mount
  useEffect(() => {
    fetchWithAuth(`${API_BASE}/attack-suite/scans`)
      .then((r) => r.ok ? r.json() : [])
      .then((data) => {
        if (Array.isArray(data)) setHistory(data);
      })
      .catch(() => {});
  }, []);

  const toggleModule = (id: string) => {
    setSelectedModules((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => setSelectedModules(new Set(MODULES.map((m) => m.id)));
  const deselectAll = () => setSelectedModules(new Set());

  const addAuthHeader = () => setAuthHeaders((prev) => [...prev, { key: "", value: "" }]);
  const removeAuthHeader = (i: number) => setAuthHeaders((prev) => prev.filter((_, idx) => idx !== i));
  const updateAuthHeader = (i: number, field: "key" | "value", val: string) => {
    setAuthHeaders((prev) => prev.map((h, idx) => idx === i ? { ...h, [field]: val } : h));
  };

  const startScan = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target URL");
      return;
    }
    if (selectedModules.size === 0) {
      toast.error("Please select at least one module");
      return;
    }

    setIsScanning(true);
    setScanStatus("running");
    setProgressMessages([]);
    setFindings([]);
    setCounts({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    setScanId(null);

    abortRef.current = new AbortController();

    const builtHeaders: Record<string, string> = {};
    for (const h of authHeaders) {
      if (h.key.trim()) builtHeaders[h.key.trim()] = h.value;
    }

    try {
      const res = await fetchWithAuth(`${API_BASE}/attack-suite/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          modules: Array.from(selectedModules),
          auth_headers: builtHeaders,
          follow_redirects: followRedirects,
          timeout,
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
          try {
            data = JSON.parse(dataMatch[1]);
          } catch {
            continue;
          }

          if (event === "start") {
            setScanId(data.scan_id as string);
            toast.success(`Scan started against ${data.target}`);
          } else if (event === "progress") {
            setProgressMessages((prev) => {
              const next = [...prev, { module: (data.module as string) ?? "", message: data.message as string }];
              window.setTimeout(() => progressEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
              return next;
            });
          } else if (event === "finding") {
            const f = data as unknown as AttackFinding;
            setFindings((prev) => [...prev, f]);
            if (f.is_vulnerable) {
              setCounts((prev) => ({
                ...prev,
                [f.severity]: (prev[f.severity] ?? 0) + 1,
              }));
            }
          } else if (event === "complete") {
            const completeCounts = data.counts as ScanCounts;
            if (completeCounts) setCounts(completeCounts);
            setScanStatus("completed");
            setIsScanning(false);
            toast.success(`Scan complete — ${data.total_findings ?? 0} finding(s)`);
            // Refresh history
            fetchWithAuth(`${API_BASE}/attack-suite/scans`)
              .then((r) => r.ok ? r.json() : [])
              .then((d) => { if (Array.isArray(d)) setHistory(d); })
              .catch(() => {});
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
  }, [target, selectedModules, authHeaders, followRedirects, timeout]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify({ scan_id: scanId, target, findings }, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `attack-suite-${target.replace(/[^a-z0-9]/gi, "_")}-${Date.now()}.json`;
    a.click();
  };

  // Group findings by module
  const findingsByModule = findings.reduce<Record<string, AttackFinding[]>>((acc, f) => {
    if (!acc[f.module]) acc[f.module] = [];
    acc[f.module].push(f);
    return acc;
  }, {});

  const totalVulnerable = findings.filter((f) => f.is_vulnerable).length;

  return (
    <div className="space-y-6">
      <PageHeader title="Attack Suite" description="Run web security attack modules against a target URL">
        <div className="flex items-center gap-2">
          {findings.length > 0 && (
            <Button variant="outline" size="sm" onClick={exportJSON} className="gap-1.5">
              <Download className="h-3.5 w-3.5" /> Export JSON
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowHistory(!showHistory)}
            className="gap-1.5"
          >
            <History className="h-3.5 w-3.5" /> History ({history.length})
          </Button>
        </div>
      </PageHeader>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Config Panel */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Swords className="h-4 w-4 text-blue-400" />
                Scan Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-5">
              {/* Target */}
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Target URL</Label>
                <Input
                  placeholder="https://example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={isScanning}
                  className="font-mono text-xs"
                />
              </div>

              {/* Modules */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-zinc-400">Modules</Label>
                  <div className="flex items-center gap-2">
                    <button
                      className="text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
                      onClick={selectAll}
                      disabled={isScanning}
                    >
                      Select All
                    </button>
                    <span className="text-zinc-700 text-[10px]">/</span>
                    <button
                      className="text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
                      onClick={deselectAll}
                      disabled={isScanning}
                    >
                      Deselect All
                    </button>
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-1.5">
                  {MODULES.map((mod) => (
                    <div
                      key={mod.id}
                      className={cn(
                        "flex items-start gap-2 rounded-md border p-2 cursor-pointer transition-colors",
                        selectedModules.has(mod.id)
                          ? "border-blue-600/30 bg-blue-600/5"
                          : "border-zinc-800 hover:border-zinc-700",
                        isScanning && "opacity-50 cursor-not-allowed"
                      )}
                      onClick={() => !isScanning && toggleModule(mod.id)}
                    >
                      <Checkbox
                        checked={selectedModules.has(mod.id)}
                        onCheckedChange={() => !isScanning && toggleModule(mod.id)}
                        className="mt-0.5"
                      />
                      <div className="min-w-0">
                        <p className="text-xs font-medium text-zinc-300">{mod.label}</p>
                        <p className="text-[10px] text-zinc-500 leading-tight mt-0.5">{mod.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Auth Headers */}
              <div className="space-y-2">
                <button
                  className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors w-full"
                  onClick={() => setShowAuthHeaders(!showAuthHeaders)}
                >
                  {showAuthHeaders ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                  Auth Headers
                  {authHeaders.length > 0 && (
                    <Badge variant="secondary" className="text-[10px] py-0 h-4 ml-auto">{authHeaders.length}</Badge>
                  )}
                </button>
                {showAuthHeaders && (
                  <div className="space-y-2 pl-4 border-l border-zinc-800">
                    {authHeaders.map((h, i) => (
                      <div key={i} className="flex items-center gap-1.5">
                        <Input
                          placeholder="Header-Name"
                          value={h.key}
                          onChange={(e) => updateAuthHeader(i, "key", e.target.value)}
                          disabled={isScanning}
                          className="font-mono text-xs h-7 text-[11px]"
                        />
                        <span className="text-zinc-600 text-xs">:</span>
                        <Input
                          placeholder="value"
                          value={h.value}
                          onChange={(e) => updateAuthHeader(i, "value", e.target.value)}
                          disabled={isScanning}
                          className="font-mono text-xs h-7 text-[11px]"
                        />
                        <button
                          onClick={() => removeAuthHeader(i)}
                          disabled={isScanning}
                          className="text-zinc-600 hover:text-zinc-300 transition-colors shrink-0"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                    <button
                      onClick={addAuthHeader}
                      disabled={isScanning}
                      className="flex items-center gap-1 text-[11px] text-zinc-500 hover:text-zinc-300 transition-colors"
                    >
                      <Plus className="h-3 w-3" /> Add header
                    </button>
                  </div>
                )}
              </div>

              {/* Follow Redirects */}
              <div className="flex items-center justify-between">
                <Label className="text-xs text-zinc-400">Follow Redirects</Label>
                <Switch
                  checked={followRedirects}
                  onCheckedChange={setFollowRedirects}
                  disabled={isScanning}
                />
              </div>

              {/* Timeout */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-zinc-400">Timeout</Label>
                  <span className="text-xs font-mono text-zinc-300">{timeout}s</span>
                </div>
                <Slider
                  min={5}
                  max={60}
                  step={5}
                  value={[timeout]}
                  onValueChange={([v]) => setTimeout(v)}
                  disabled={isScanning}
                  className="w-full"
                />
                <div className="flex justify-between text-[10px] text-zinc-600">
                  <span>5s</span>
                  <span>60s</span>
                </div>
              </div>

              {/* Run / Stop */}
              {isScanning ? (
                <Button onClick={stopScan} variant="destructive" className="w-full gap-2">
                  <Square className="h-4 w-4" /> Stop Scan
                </Button>
              ) : (
                <Button
                  onClick={startScan}
                  className="w-full gap-2"
                  disabled={selectedModules.size === 0}
                >
                  <Play className="h-4 w-4" /> Run Attack Suite
                </Button>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-2 space-y-4">
          {/* Severity counts status bar */}
          {(scanStatus !== "idle" || findings.length > 0) && (
            <div className="flex items-center gap-2 flex-wrap rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
              {isScanning && (
                <Loader2 className="h-4 w-4 text-blue-400 animate-spin shrink-0" />
              )}
              {!isScanning && scanStatus === "completed" && (
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
              )}
              {!isScanning && scanStatus === "failed" && (
                <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
              )}
              <span className="text-xs text-zinc-400 mr-2">
                {isScanning ? "Scanning…" : scanStatus === "completed" ? `${totalVulnerable} vulnerable` : "Scan failed"}
              </span>
              {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
                <div key={sev} className={cn("flex items-center gap-1.5 rounded-md border px-2 py-1", SEV_COLORS[sev])}>
                  <div className={cn("h-1.5 w-1.5 rounded-full", SEV_DOT[sev])} />
                  <span className="text-[11px] font-medium capitalize">{sev}</span>
                  <span className={cn("text-[11px] font-bold", SEV_BADGE_TEXT[sev])}>{counts[sev]}</span>
                </div>
              ))}
            </div>
          )}

          {/* Progress log */}
          {progressMessages.length > 0 && (
            <div className="rounded-lg border border-zinc-800">
              <button
                className="w-full flex items-center justify-between px-3 py-2 border-b border-zinc-800 hover:bg-zinc-800/30 transition-colors"
                onClick={() => setShowProgress(!showProgress)}
              >
                <span className="text-xs text-zinc-500 font-mono">progress log ({progressMessages.length})</span>
                {showProgress ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
              </button>
              {showProgress && (
                <div className="h-[180px] overflow-y-auto bg-zinc-950 rounded-b-lg p-3 space-y-0.5 font-mono">
                  {progressMessages.map((msg, i) => (
                    <div key={i} className="text-xs leading-5 flex items-start gap-2">
                      {msg.module && (
                        <span className="text-blue-400 shrink-0">[{msg.module}]</span>
                      )}
                      <span className="text-zinc-400">{msg.message}</span>
                    </div>
                  ))}
                  <div ref={progressEndRef} />
                </div>
              )}
            </div>
          )}

          {/* Findings */}
          {findings.length > 0 ? (
            <div className="space-y-4">
              {Object.entries(findingsByModule).map(([moduleName, moduleFix]) => {
                const moduleDef = MODULES.find((m) => m.id === moduleName);
                return (
                  <div key={moduleName}>
                    <div className="flex items-center gap-2 mb-2">
                      <Shield className="h-4 w-4 text-zinc-500" />
                      <h3 className="text-sm font-semibold text-zinc-300">
                        {moduleDef?.label ?? moduleName}
                      </h3>
                      <Badge variant="secondary" className="text-[10px] py-0 h-4">
                        {moduleFix.length}
                      </Badge>
                      <span className="text-[10px] text-zinc-600 ml-1">
                        {moduleFix.filter((f) => f.is_vulnerable).length} vulnerable
                      </span>
                    </div>
                    <div className="space-y-2">
                      {moduleFix.map((f) => (
                        <FindingCard key={f.id} finding={f} />
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            !isScanning && scanStatus === "idle" && (
              <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
                <Swords className="h-12 w-12" />
                <p className="text-sm">No findings yet — run a scan to discover vulnerabilities</p>
              </div>
            )
          )}

          {isScanning && findings.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500 space-y-3">
              <Loader2 className="h-8 w-8 animate-spin text-blue-400" />
              <p className="text-sm">Running attack modules against {target}…</p>
              <p className="text-xs">{progressMessages.length} events received</p>
            </div>
          )}
        </div>
      </div>

      {/* History Panel */}
      {showHistory && (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <History className="h-4 w-4 text-zinc-400" />
                Scan History
              </CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            {history.length === 0 ? (
              <p className="text-sm text-zinc-600 py-4 text-center">No past scans found</p>
            ) : (
              <div className="space-y-2">
                {history.map((entry) => (
                  <div
                    key={entry.id}
                    className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 p-3"
                  >
                    <div className={cn(
                      "h-2 w-2 rounded-full shrink-0",
                      entry.status === "completed" ? "bg-emerald-400" :
                      entry.status === "failed" ? "bg-red-400" :
                      "bg-zinc-500"
                    )} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono text-zinc-200 truncate">{entry.target}</p>
                      <p className="text-[10px] text-zinc-500">
                        {new Date(entry.started_at).toLocaleString()}
                      </p>
                    </div>
                    <div className="text-right shrink-0">
                      <p className="text-xs text-zinc-400">{entry.total_findings} findings</p>
                      <p className={cn("text-[10px] capitalize",
                        entry.status === "completed" ? "text-emerald-400" :
                        entry.status === "failed" ? "text-red-400" :
                        "text-zinc-500"
                      )}>{entry.status}</p>
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
