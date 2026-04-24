"use client";

import React, { useState, useRef, useCallback, useEffect, DragEvent } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldX,
  ShieldAlert,
  Network,
  Search,
  Upload,
  FileText,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Terminal,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ─── Types ───────────────────────────────────────────────────────────────────

interface WAFDetectResult {
  detected: boolean;
  vendor: string | null;
  confidence: number;
  blocked_malicious: boolean;
  indicators: string[];
  normal_code: number | null;
  malicious_code: number | null;
}

interface BypassProbeResult {
  technique: string;
  payload: string;
  status_code: number | null;
  result: "BYPASS" | "BLOCKED" | "UNCERTAIN" | "ERROR";
}

interface BypassSummary {
  bypassed: number;
  blocked: number;
  uncertain: number;
  total: number;
}

interface PortMapRow {
  host: string;
  port: number | string;
  protocol: string;
  state: string;
  service: string;
  firewall_interpretation: string;
}

interface RuleAnomaly {
  severity: "critical" | "high" | "medium" | "low";
  type: string;
  description: string;
  rule_text: string;
  line_number: number | null;
}

interface RuleAnalysisResult {
  format: string;
  total_rules: number;
  anomalies: RuleAnomaly[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const TOTAL_BYPASS_PROBES = 13;

const RESULT_BADGE: Record<string, { label: string; className: string }> = {
  BYPASS: { label: "BYPASS", className: "bg-red-500/20 text-red-400 border-red-500/40" },
  BLOCKED: { label: "BLOCKED", className: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40" },
  UNCERTAIN: { label: "UNCERTAIN", className: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40" },
  ERROR: { label: "ERROR", className: "bg-zinc-700/50 text-zinc-400 border-zinc-600/40" },
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/40",
};

const STATE_COLOR: Record<string, string> = {
  open: "text-emerald-400",
  filtered: "text-red-400",
  unfiltered: "text-yellow-400",
  closed: "text-zinc-500",
};

const FIREWALL_MODES = [
  { value: "acl_probe", label: "ACK Probe", desc: "Detects stateful vs stateless filtering" },
  { value: "fin_null_xmas", label: "FIN / NULL / XMAS", desc: "Bypasses stateless packet filters" },
  { value: "source_port", label: "Source Port Trust", desc: "Tests DNS port trust (port 53)" },
  { value: "fragmented", label: "Fragmented Packets", desc: "Fragment reassembly evasion test" },
  { value: "full_suite", label: "Full Suite", desc: "Runs all modes combined" },
];

async function sseStream(
  url: string,
  payload: unknown,
  onEvent: (eventType: string, data: unknown) => void,
  signal?: AbortSignal
): Promise<void> {
  const res = await fetchWithAuth(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Request failed" }));
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
      let eventType = "message";
      let dataStr = "";
      for (const line of part.split("\n")) {
        if (line.startsWith("event:")) eventType = line.slice(6).trim();
        if (line.startsWith("data:")) dataStr = line.slice(5).trim();
      }
      if (!dataStr) continue;
      const data = JSON.parse(dataStr);
      onEvent(eventType, data);
    }
  }
}

// ─── Tab 1: WAF Detection ─────────────────────────────────────────────────────

function WAFDetectionTab() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<WAFDetectResult | null>(null);

  const detect = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target URL");
      return;
    }
    setLoading(true);
    setResult(null);
    try {
      const res = await fetchWithAuth(`${API_BASE}/firewall/waf/detect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Detection failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }
      const data: WAFDetectResult = await res.json();
      setResult(data);
    } catch (err: unknown) {
      toast.error(`WAF detection failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [target]);

  return (
    <div className="space-y-6">
      {/* Input */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <Search className="h-4 w-4 text-blue-400" />
            Target URL
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <Input
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={loading}
              onKeyDown={(e) => e.key === "Enter" && !loading && detect()}
              className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm flex-1"
            />
            <Button onClick={detect} disabled={loading} className="gap-2 shrink-0">
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Shield className="h-4 w-4" />
              )}
              {loading ? "Detecting…" : "Detect WAF"}
            </Button>
          </div>
          <p className="text-xs text-zinc-600">
            Sends normal and malicious request probes to detect WAF vendor and behavior.
          </p>
        </CardContent>
      </Card>

      {/* Result */}
      {result && (
        <Card>
          <CardContent className="pt-6 space-y-5">
            {/* WAF detected badge */}
            <div className="flex items-center gap-4">
              {result.detected ? (
                <>
                  <ShieldX className="h-8 w-8 text-red-400 shrink-0" />
                  <div>
                    <Badge className="bg-red-500/20 text-red-400 border-red-500/40 text-sm px-3 py-1">
                      WAF Detected
                    </Badge>
                    {result.vendor && (
                      <p className="text-lg font-bold text-zinc-100 mt-1">{result.vendor}</p>
                    )}
                  </div>
                </>
              ) : (
                <>
                  <ShieldCheck className="h-8 w-8 text-emerald-400 shrink-0" />
                  <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/40 text-sm px-3 py-1">
                    No WAF Detected
                  </Badge>
                </>
              )}
              {result.blocked_malicious && (
                <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/40 ml-auto">
                  Malicious Request Blocked
                </Badge>
              )}
            </div>

            {/* Confidence bar */}
            {result.detected && (
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <span className="text-zinc-500 font-semibold uppercase tracking-wider">Confidence</span>
                  <span className="text-zinc-300 font-medium">{result.confidence}%</span>
                </div>
                <div className="h-2 rounded-full bg-zinc-800 overflow-hidden">
                  <div
                    className={cn(
                      "h-full rounded-full transition-all duration-700",
                      result.confidence >= 80
                        ? "bg-red-500"
                        : result.confidence >= 50
                        ? "bg-orange-500"
                        : "bg-yellow-500"
                    )}
                    style={{ width: `${result.confidence}%` }}
                  />
                </div>
              </div>
            )}

            {/* Response codes */}
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Normal Code</p>
                <p className="text-xl font-bold text-zinc-100 font-mono">
                  {result.normal_code ?? "—"}
                </p>
              </div>
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Malicious Code</p>
                <p
                  className={cn(
                    "text-xl font-bold font-mono",
                    result.malicious_code && result.malicious_code >= 400
                      ? "text-red-400"
                      : "text-zinc-100"
                  )}
                >
                  {result.malicious_code ?? "—"}
                </p>
              </div>
            </div>

            {/* Indicators */}
            {result.indicators && result.indicators.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                  Indicators Found
                </p>
                <ul className="space-y-1.5">
                  {result.indicators.map((ind, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-zinc-300">
                      <span className="mt-1.5 h-1.5 w-1.5 rounded-full bg-blue-400 shrink-0" />
                      {ind}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {result.indicators && result.indicators.length === 0 && (
              <p className="text-sm text-zinc-600">No specific indicators captured.</p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {!result && !loading && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
          <Shield className="h-12 w-12" />
          <p className="text-sm">Enter a target URL and click Detect WAF</p>
        </div>
      )}
    </div>
  );
}

// ─── Tab 2: WAF Bypass Probe ──────────────────────────────────────────────────

function WAFBypassTab() {
  const [target, setTarget] = useState("");
  const [path, setPath] = useState("/search");
  const [param, setParam] = useState("q");
  const [running, setRunning] = useState(false);
  const [probes, setProbes] = useState<BypassProbeResult[]>([]);
  const [summary, setSummary] = useState<BypassSummary | null>(null);
  const [progress, setProgress] = useState(0);
  const abortRef = useRef<AbortController | null>(null);

  const start = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target URL");
      return;
    }
    setRunning(true);
    setProbes([]);
    setSummary(null);
    setProgress(0);
    abortRef.current = new AbortController();

    try {
      await sseStream(
        `${API_BASE}/firewall/waf/bypass`,
        { target: target.trim(), path: path.trim() || "/search", param: param.trim() || "q" },
        (eventType, data) => {
          if (eventType === "probe") {
            const probe = data as BypassProbeResult;
            setProbes((prev) => {
              const next = [...prev, probe];
              setProgress(Math.min((next.length / TOTAL_BYPASS_PROBES) * 100, 100));
              return next;
            });
          } else if (eventType === "complete") {
            const d = data as BypassSummary & { probes?: BypassProbeResult[] };
            setSummary({ bypassed: d.bypassed, blocked: d.blocked, uncertain: d.uncertain, total: d.total });
            if (d.probes) setProbes(d.probes);
            setProgress(100);
            setRunning(false);
            toast.success(`Bypass probe complete — ${d.bypassed} technique(s) bypassed`);
          } else if (eventType === "error") {
            const e = data as { message: string };
            setRunning(false);
            toast.error(`Probe error: ${e.message}`);
          }
        },
        abortRef.current.signal
      );
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") {
        toast.error(`Bypass probe failed: ${err.message}`);
      }
      setRunning(false);
    }
  }, [target, path, param]);

  const stop = () => {
    abortRef.current?.abort();
    setRunning(false);
    toast.info("Probe stopped");
  };

  return (
    <div className="space-y-6">
      {/* Config */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <Zap className="h-4 w-4 text-yellow-400" />
            Bypass Probe Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-1 space-y-1.5">
              <Label className="text-xs text-zinc-400">Target URL</Label>
              <Input
                placeholder="https://example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={running}
                className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Path</Label>
              <Input
                placeholder="/search"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                disabled={running}
                className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Param Name</Label>
              <Input
                placeholder="q"
                value={param}
                onChange={(e) => setParam(e.target.value)}
                disabled={running}
                className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm"
              />
            </div>
          </div>

          <div className="flex gap-3">
            {running ? (
              <Button onClick={stop} variant="destructive" className="gap-2">
                <XCircle className="h-4 w-4" /> Stop Probe
              </Button>
            ) : (
              <Button onClick={start} className="gap-2">
                <Zap className="h-4 w-4" /> Start Bypass Probe
              </Button>
            )}
          </div>

          {/* Progress bar */}
          {(running || probes.length > 0) && (
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-zinc-500 font-semibold uppercase tracking-wider">Progress</span>
                <span className="text-zinc-400">
                  {probes.length} / {TOTAL_BYPASS_PROBES} probes
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-blue-500 transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Summary */}
      {summary && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: "Total", value: summary.total, className: "text-zinc-200" },
            { label: "Bypassed", value: summary.bypassed, className: "text-red-400" },
            { label: "Blocked", value: summary.blocked, className: "text-emerald-400" },
            { label: "Uncertain", value: summary.uncertain, className: "text-yellow-400" },
          ].map((s) => (
            <div
              key={s.label}
              className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 text-center"
            >
              <p className={cn("text-2xl font-bold font-mono", s.className)}>{s.value}</p>
              <p className="text-xs text-zinc-500 mt-0.5">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Probe results table */}
      {probes.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-zinc-400" />
              Probe Results
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="rounded-b-lg overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-zinc-900 border-b border-zinc-800">
                    <th className="px-4 py-2.5 text-left font-semibold text-zinc-400 uppercase tracking-wider">
                      Technique
                    </th>
                    <th className="px-4 py-2.5 text-left font-semibold text-zinc-400 uppercase tracking-wider">
                      Payload
                    </th>
                    <th className="px-4 py-2.5 text-left font-semibold text-zinc-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-4 py-2.5 text-left font-semibold text-zinc-400 uppercase tracking-wider">
                      Result
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {probes.map((probe, i) => {
                    const badge = RESULT_BADGE[probe.result] ?? RESULT_BADGE.ERROR;
                    return (
                      <tr
                        key={i}
                        className="animate-in fade-in slide-in-from-top-1 duration-200 hover:bg-zinc-800/30"
                      >
                        <td className="px-4 py-2.5 text-zinc-200 font-medium">{probe.technique}</td>
                        <td className="px-4 py-2.5 font-mono text-zinc-400 max-w-[200px] truncate" title={probe.payload}>
                          {probe.payload.length > 40 ? probe.payload.slice(0, 40) + "…" : probe.payload}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-zinc-300">
                          {probe.status_code ?? "—"}
                        </td>
                        <td className="px-4 py-2.5">
                          <Badge className={cn("text-[10px] px-2 py-0.5 border", badge.className)}>
                            {badge.label}
                          </Badge>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {probes.length === 0 && !running && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
          <Zap className="h-12 w-12" />
          <p className="text-sm">Configure probe settings and click Start Bypass Probe</p>
        </div>
      )}

      {running && probes.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-zinc-500 space-y-3">
          <Loader2 className="h-8 w-8 animate-spin text-blue-400" />
          <p className="text-sm">Launching bypass techniques…</p>
        </div>
      )}
    </div>
  );
}

// ─── Tab 3: Port Firewall Mapper ──────────────────────────────────────────────

function PortFirewallMapperTab() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("full_suite");
  const [running, setRunning] = useState(false);
  const [logLines, setLogLines] = useState<string[]>([]);
  const [portRows, setPortRows] = useState<PortMapRow[]>([]);
  const [completed, setCompleted] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logLines]);

  const start = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target host or IP");
      return;
    }
    setRunning(true);
    setLogLines([]);
    setPortRows([]);
    setCompleted(false);
    abortRef.current = new AbortController();

    try {
      await sseStream(
        `${API_BASE}/firewall/port-map`,
        { target: target.trim(), mode },
        (eventType, data) => {
          if (eventType === "output") {
            const d = data as { line: string };
            setLogLines((prev) => [...prev, d.line]);
          } else if (eventType === "complete") {
            const d = data as { results: PortMapRow[] };
            setPortRows(d.results ?? []);
            setRunning(false);
            setCompleted(true);
            toast.success(`Firewall map complete — ${d.results?.length ?? 0} entry/entries`);
          } else if (eventType === "error") {
            const e = data as { message: string };
            setRunning(false);
            toast.error(`Port map error: ${e.message}`);
          }
        },
        abortRef.current.signal
      );
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") {
        toast.error(`Port mapper failed: ${err.message}`);
      }
      setRunning(false);
    }
  }, [target, mode]);

  const stop = () => {
    abortRef.current?.abort();
    setRunning(false);
    toast.info("Scan stopped");
  };

  return (
    <div className="space-y-6">
      {/* Config */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <Network className="h-4 w-4 text-blue-400" />
            Firewall Scan Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Target Host / IP</Label>
              <Input
                placeholder="192.168.1.1 or example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={running}
                onKeyDown={(e) => e.key === "Enter" && !running && start()}
                className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Scan Mode</Label>
              <Select value={mode} onValueChange={setMode} disabled={running}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700 text-zinc-100 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FIREWALL_MODES.map((m) => (
                    <SelectItem key={m.value} value={m.value}>
                      <div>
                        <p className="font-medium">{m.label}</p>
                        <p className="text-[10px] text-zinc-500">{m.desc}</p>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Mode descriptions */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {FIREWALL_MODES.map((m) => (
              <button
                key={m.value}
                onClick={() => !running && setMode(m.value)}
                disabled={running}
                className={cn(
                  "rounded-md border px-3 py-2 text-left transition-colors",
                  mode === m.value
                    ? "border-blue-500/50 bg-blue-500/10"
                    : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700"
                )}
              >
                <p className={cn("text-xs font-semibold", mode === m.value ? "text-blue-300" : "text-zinc-300")}>
                  {m.label}
                </p>
                <p className="text-[10px] text-zinc-500 mt-0.5">{m.desc}</p>
              </button>
            ))}
          </div>

          <div className="flex gap-3">
            {running ? (
              <Button onClick={stop} variant="destructive" className="gap-2">
                <XCircle className="h-4 w-4" /> Stop Scan
              </Button>
            ) : (
              <Button onClick={start} className="gap-2">
                <Network className="h-4 w-4" /> Run Firewall Scan
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Live log terminal */}
      {logLines.length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-950">
          <div className="flex items-center gap-2 border-b border-zinc-800 px-3 py-2">
            <Terminal className="h-3.5 w-3.5 text-zinc-500" />
            <span className="text-xs text-zinc-500 font-mono">nmap output</span>
            {running && <Loader2 className="h-3 w-3 animate-spin text-blue-400 ml-auto" />}
          </div>
          <div className="h-64 overflow-y-auto p-3 space-y-0.5 font-mono text-xs">
            {logLines.map((line, i) => (
              <div
                key={i}
                className={cn(
                  "leading-5 whitespace-pre-wrap break-all",
                  line.toLowerCase().includes("open") ? "text-emerald-400" :
                  line.toLowerCase().includes("filtered") ? "text-red-400" :
                  line.toLowerCase().includes("error") || line.toLowerCase().includes("failed") ? "text-red-400" :
                  line.startsWith("Nmap") || line.startsWith("Starting") ? "text-blue-300 font-semibold" :
                  "text-zinc-400"
                )}
              >
                {line}
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        </div>
      )}

      {/* Results table */}
      {completed && portRows.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-zinc-400" />
              Firewall Map Results
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="rounded-b-lg overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-zinc-900 border-b border-zinc-800">
                    {["Host", "Port", "Protocol", "State", "Service", "Firewall Interpretation"].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left font-semibold text-zinc-400 uppercase tracking-wider whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {portRows.map((row, i) => (
                    <React.Fragment key={i}>
                      <tr className="hover:bg-zinc-800/30">
                        <td className="px-4 py-2.5 font-mono text-zinc-200">{row.host}</td>
                        <td className="px-4 py-2.5 font-mono font-semibold text-zinc-100">{row.port}</td>
                        <td className="px-4 py-2.5 text-zinc-500 uppercase">{row.protocol}</td>
                        <td className={cn("px-4 py-2.5 font-semibold capitalize", STATE_COLOR[row.state] ?? "text-zinc-400")}>
                          {row.state}
                        </td>
                        <td className="px-4 py-2.5 text-zinc-300">{row.service || "—"}</td>
                        <td className="px-4 py-2.5 text-zinc-500 italic max-w-xs">
                          {row.firewall_interpretation || "—"}
                        </td>
                      </tr>
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {completed && portRows.length === 0 && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 px-6 py-8 text-center">
          <CheckCircle2 className="h-6 w-6 text-emerald-400 mx-auto mb-2" />
          <p className="text-sm text-zinc-400">Scan complete. No port data returned.</p>
        </div>
      )}

      {!running && logLines.length === 0 && !completed && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
          <Network className="h-12 w-12" />
          <p className="text-sm">Enter a target and run the firewall scan</p>
        </div>
      )}
    </div>
  );
}

// ─── Tab 4: Rule Analyzer ─────────────────────────────────────────────────────

function RuleAnalyzerTab() {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RuleAnalysisResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) setFile(dropped);
  };

  const analyze = useCallback(async () => {
    if (!file) {
      toast.error("Please select a firewall config file");
      return;
    }
    setLoading(true);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetchWithAuth(`${API_BASE}/firewall/rules/analyze`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Analysis failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }
      const data: RuleAnalysisResult = await res.json();
      setResult(data);
      if (data.anomalies.length === 0) {
        toast.success("No anomalies detected — ruleset looks clean");
      } else {
        toast.warning(`Found ${data.anomalies.length} anomaly/anomalies in ruleset`);
      }
    } catch (err: unknown) {
      toast.error(`Rule analysis failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [file]);

  const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sortedAnomalies = result
    ? [...result.anomalies].sort(
        (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
      )
    : [];

  return (
    <div className="space-y-6">
      {/* Upload area */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <Upload className="h-4 w-4 text-purple-400" />
            Upload Firewall Config
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Drop zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={cn(
              "cursor-pointer rounded-lg border-2 border-dashed transition-colors px-6 py-12 text-center",
              dragging
                ? "border-blue-500 bg-blue-500/5"
                : file
                ? "border-emerald-500/50 bg-emerald-500/5"
                : "border-zinc-700 bg-zinc-900/40 hover:border-zinc-600 hover:bg-zinc-800/40"
            )}
          >
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={(e) => e.target.files?.[0] && setFile(e.target.files[0])}
              accept=".txt,.xml,.conf,.cfg,.acl,.log"
            />
            {file ? (
              <div className="flex flex-col items-center gap-2">
                <FileText className="h-8 w-8 text-emerald-400" />
                <p className="text-sm font-medium text-emerald-300">{file.name}</p>
                <p className="text-xs text-zinc-500">{(file.size / 1024).toFixed(1)} KB — click to change</p>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2">
                <Upload className="h-8 w-8 text-zinc-500" />
                <p className="text-sm font-medium text-zinc-300">Drop your firewall config here</p>
                <p className="text-xs text-zinc-500">or click to browse</p>
                <div className="flex gap-2 mt-2 flex-wrap justify-center">
                  {["iptables-save", "Cisco ACL", "pfSense XML"].map((fmt) => (
                    <span
                      key={fmt}
                      className="rounded-full border border-zinc-700 bg-zinc-800 px-2.5 py-0.5 text-[10px] text-zinc-400"
                    >
                      {fmt}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          <Button
            onClick={analyze}
            disabled={!file || loading}
            className="gap-2"
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Search className="h-4 w-4" />
            )}
            {loading ? "Analyzing…" : "Analyze Rules"}
          </Button>
        </CardContent>
      </Card>

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Summary bar */}
          <div className="flex items-center gap-3 flex-wrap">
            <Badge className="bg-purple-500/20 text-purple-300 border-purple-500/40 px-3 py-1">
              {result.format || "Unknown Format"}
            </Badge>
            <span className="text-sm text-zinc-400">
              <span className="font-semibold text-zinc-200">{result.total_rules}</span> rules parsed
            </span>
            <span className="text-sm text-zinc-400">
              <span
                className={cn(
                  "font-semibold",
                  sortedAnomalies.length > 0 ? "text-red-400" : "text-emerald-400"
                )}
              >
                {sortedAnomalies.length}
              </span>{" "}
              {sortedAnomalies.length === 1 ? "anomaly" : "anomalies"} found
            </span>
          </div>

          {/* No anomalies */}
          {sortedAnomalies.length === 0 && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-6 py-8 flex items-center gap-4">
              <CheckCircle2 className="h-8 w-8 text-emerald-400 shrink-0" />
              <div>
                <p className="text-sm font-semibold text-emerald-300">No anomalies detected</p>
                <p className="text-xs text-emerald-500/70 mt-0.5">
                  All {result.total_rules} rules look clean with no conflicts, redundancies, or over-permissive rules.
                </p>
              </div>
            </div>
          )}

          {/* Anomaly list */}
          {sortedAnomalies.length > 0 && (
            <div className="space-y-3">
              {sortedAnomalies.map((anomaly, i) => (
                <div
                  key={i}
                  className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <Badge className={cn("text-[10px] px-2 py-0.5 border capitalize", SEVERITY_BADGE[anomaly.severity])}>
                          {anomaly.severity}
                        </Badge>
                        <span className="text-sm font-semibold text-zinc-200 capitalize">
                          {anomaly.type.replace(/_/g, " ")}
                        </span>
                      </div>
                      <p className="text-sm text-zinc-400">{anomaly.description}</p>
                    </div>
                    {anomaly.line_number != null && (
                      <span className="text-xs text-zinc-600 font-mono shrink-0">
                        line {anomaly.line_number}
                      </span>
                    )}
                  </div>
                  {anomaly.rule_text && (
                    <div className="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2">
                      <code className="text-xs font-mono text-zinc-300 whitespace-pre-wrap break-all">
                        {anomaly.rule_text}
                      </code>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!result && !loading && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
          <FileText className="h-12 w-12" />
          <p className="text-sm">Upload a firewall config to analyze its rules</p>
        </div>
      )}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function FirewallPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Firewall & WAF Scanner"
        description="Detect WAF vendors, test bypass techniques, map firewall rules, and analyze rule configs"
      />

      <Tabs defaultValue="waf-detect" className="space-y-6">
        <TabsList className="bg-zinc-900 border border-zinc-800 p-1 gap-1">
          {[
            { value: "waf-detect", icon: ShieldX, label: "WAF Detection" },
            { value: "waf-bypass", icon: Zap, label: "WAF Bypass Probe" },
            { value: "port-map", icon: Network, label: "Port Firewall Mapper" },
            { value: "rule-analyzer", icon: FileText, label: "Rule Analyzer" },
          ].map(({ value, icon: Icon, label }) => (
            <TabsTrigger
              key={value}
              value={value}
              className="flex items-center gap-2 text-xs data-[state=active]:bg-zinc-800 data-[state=active]:text-zinc-100 text-zinc-400 px-3 py-1.5 rounded-md transition-colors"
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="waf-detect">
          <WAFDetectionTab />
        </TabsContent>

        <TabsContent value="waf-bypass">
          <WAFBypassTab />
        </TabsContent>

        <TabsContent value="port-map">
          <PortFirewallMapperTab />
        </TabsContent>

        <TabsContent value="rule-analyzer">
          <RuleAnalyzerTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
