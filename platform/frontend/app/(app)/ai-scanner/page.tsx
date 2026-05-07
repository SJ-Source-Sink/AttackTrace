"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Bot, Play, Square, CheckCircle2, XCircle, ChevronDown, ChevronRight,
  Shield, Loader2, Search, Zap, Lock, Eye, EyeOff,
  BookOpen, Target, Layers, BarChart3, Info, History, Trash2, Clock,
  ExternalLink,
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

// ── Types ────────────────────────────────────────────────────────────────────

type AuthType   = "none" | "bearer" | "api_key" | "basic" | "custom";
type Intensity  = "quick" | "thorough" | "full";
type ResultType = "VULNERABLE" | "SAFE" | "ERROR";
type Severity   = "critical" | "high" | "medium" | "low" | "none";

interface DiscoveredEndpoint {
  url: string; method: string; type: string;
  status_code: number; unauthenticated: boolean;
  indicators: string[]; response_preview: string;
}

interface TestResult {
  plugin_id: string; plugin_name: string; category: string;
  owasp: string; mitre: string; strategy: string; strategy_name: string;
  severity: Severity; endpoint: string; prompt: string; response: string;
  result: ResultType; score: number; reason: string;
  multi_turn: boolean; conversation: { role: string; content: string }[];
}

interface ScanSummary {
  total_discovered: number; unauthenticated: number;
  total_tests: number; total_vulnerable: number;
  critical: number; high: number; medium: number; low: number;
  by_category: Record<string, { count: number; critical: number; high: number; medium: number; low: number }>;
  by_owasp: Record<string, { count: number; severity: string }>;
  compliance: Record<string, "pass" | "fail" | "untested">;
}

interface PluginMeta { id: string; name: string; severity: string; owasp: string; mitre: string; description: string; multi_turn: boolean; }
interface PluginCategories { categories: Record<string, PluginMeta[]>; strategies: { id: string; name: string }[]; total_plugins: number; }

interface HistoryScan {
  id: string;
  target: string;
  started_at: string;
  completed_at: string;
  intensity: string;
  total_endpoints: number;
  total_tests: number;
  total_vulnerable: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  compliance: Record<string, "pass" | "fail" | "untested">;
}

interface FullHistoryScan extends HistoryScan {
  endpoints: DiscoveredEndpoint[];
  findings: TestResult[];
  summary: ScanSummary;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const OWASP_LABELS: Record<string, string> = {
  LLM01: "Prompt Injection", LLM02: "Insecure Output",
  LLM03: "Training Poisoning", LLM04: "Model DoS",
  LLM05: "Supply Chain", LLM06: "Info Disclosure",
  LLM07: "Insecure Plugin", LLM08: "Excessive Agency",
  LLM09: "Overreliance",
};

const SEV_STYLES: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/20 text-blue-400 border-blue-500/30",
  none:     "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-500",
};

// ── Sub-components ────────────────────────────────────────────────────────────

function OWASPComplianceBar({ compliance }: { compliance: Record<string, "pass" | "fail" | "untested"> }) {
  const ids = Object.keys(OWASP_LABELS);
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
          <Shield className="h-4 w-4 text-blue-400" /> OWASP LLM Top 10 Compliance
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-3 gap-2">
          {ids.map((id) => {
            const status = compliance[id] ?? "untested";
            return (
              <div key={id} className={cn(
                "rounded-md border px-2.5 py-2",
                status === "fail"     ? "border-red-600/40 bg-red-600/10" :
                status === "pass"     ? "border-emerald-600/30 bg-emerald-600/8" :
                                        "border-zinc-700/50 bg-zinc-900/40"
              )}>
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-[10px] font-bold text-zinc-400">{id}</span>
                  {status === "fail"     ? <XCircle      className="h-3 w-3 text-red-400" /> :
                   status === "pass"     ? <CheckCircle2 className="h-3 w-3 text-emerald-400" /> :
                                          <Info          className="h-3 w-3 text-zinc-600" />}
                </div>
                <p className="text-[9px] text-zinc-600 leading-tight">{OWASP_LABELS[id]}</p>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

function ConversationView({ turns }: { turns: { role: string; content: string }[] }) {
  return (
    <div className="space-y-2 mt-2">
      {turns.map((t, i) => (
        <div key={i} className={cn(
          "rounded px-2.5 py-1.5 text-xs font-mono",
          t.role === "user" ? "bg-blue-950/50 text-blue-300 ml-4" : "bg-zinc-900 text-zinc-300 mr-4"
        )}>
          <span className="text-[9px] uppercase tracking-wider text-zinc-500 block mb-0.5">
            {t.role}
          </span>
          <span className="whitespace-pre-wrap break-all">{t.content}</span>
        </div>
      ))}
    </div>
  );
}

function TestResultCard({ result }: { result: TestResult }) {
  const [expanded, setExpanded] = useState(false);
  const isVuln = result.result === "VULNERABLE";

  return (
    <div className={cn(
      "rounded-lg border transition-colors",
      isVuln
        ? result.severity === "critical" ? "border-red-600/40 bg-red-600/5"
          : result.severity === "high"   ? "border-orange-500/40 bg-orange-500/5"
          : "border-yellow-500/40 bg-yellow-500/5"
        : "border-zinc-800/60 bg-zinc-900/20"
    )}>
      <button className="w-full flex items-center gap-3 p-3 text-left" onClick={() => setExpanded(!expanded)}>
        {isVuln
          ? <XCircle      className="h-4 w-4 text-red-400 shrink-0" />
          : <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />}
        <div className="flex-1 min-w-0 space-y-0.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-semibold text-zinc-200">{result.plugin_name}</span>
            {isVuln && (
              <Badge className={cn("text-[10px] border h-4 py-0 capitalize shrink-0", SEV_STYLES[result.severity])}>
                {result.severity}
              </Badge>
            )}
            {result.multi_turn && (
              <Badge variant="outline" className="text-[10px] h-4 py-0 text-purple-400 border-purple-500/30">
                multi-turn
              </Badge>
            )}
            <span className="text-[10px] text-zinc-500">{result.strategy_name}</span>
            <span className="text-[10px] text-zinc-600 font-mono">{result.owasp}</span>
          </div>
          {result.reason && (
            <p className="text-[10px] text-orange-300 truncate">{result.reason}</p>
          )}
          {result.score > 0 && (
            <div className="flex items-center gap-1.5 mt-0.5">
              <div className="h-1 w-20 rounded-full bg-zinc-800 overflow-hidden">
                <div
                  className={cn("h-full rounded-full", isVuln ? "bg-red-500" : "bg-emerald-500")}
                  style={{ width: `${result.score * 100}%` }}
                />
              </div>
              <span className="text-[9px] text-zinc-600">{Math.round(result.score * 100)}% confidence</span>
            </div>
          )}
        </div>
        {expanded
          ? <ChevronDown  className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
          : <ChevronRight className="h-3.5 w-3.5 text-zinc-500 shrink-0" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-zinc-800/60 space-y-3 pt-3">
          <div className="flex gap-2 flex-wrap text-[10px]">
            <span className="text-zinc-500">OWASP: <span className="text-zinc-300">{result.owasp} — {OWASP_LABELS[result.owasp] ?? ""}</span></span>
            <span className="text-zinc-700">·</span>
            <span className="text-zinc-500">MITRE: <span className="text-zinc-300">{result.mitre}</span></span>
            <span className="text-zinc-700">·</span>
            <span className="text-zinc-500">Strategy: <span className="text-zinc-300">{result.strategy_name}</span></span>
          </div>

          {result.multi_turn && result.conversation.length > 0 ? (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Conversation ({result.conversation.length / 2} turns)</p>
              <ConversationView turns={result.conversation} />
            </div>
          ) : (
            <>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Prompt Sent</p>
                <pre className="text-xs text-zinc-400 font-mono bg-zinc-950 rounded p-2 whitespace-pre-wrap break-all max-h-32 overflow-y-auto">
                  {result.prompt}
                </pre>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Model Response</p>
                <pre className="text-xs text-zinc-300 font-mono bg-zinc-950 rounded p-2 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                  {result.response || "(no response / empty)"}
                </pre>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function CategoryResultsGroup({ category, results }: { category: string; results: TestResult[] }) {
  const [open, setOpen] = useState(true);
  const vulns = results.filter(r => r.result === "VULNERABLE");
  const safe  = results.filter(r => r.result === "SAFE");
  return (
    <div className="rounded-lg border border-zinc-800">
      <button
        className="w-full flex items-center justify-between px-4 py-3"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-2">
          {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
          <span className="text-sm font-semibold text-zinc-200">{category}</span>
          {vulns.length > 0 && (
            <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 rounded px-1.5 py-0.5">
              {vulns.length} vulnerable
            </span>
          )}
          <span className="text-[10px] text-zinc-600">{results.length} tested</span>
        </div>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-2 border-t border-zinc-800/60">
          {vulns.length > 0 && (
            <div className="mt-3 space-y-2">
              <p className="text-[10px] text-red-400 font-medium uppercase tracking-wider">Vulnerable</p>
              {vulns.map((r, i) => <TestResultCard key={i} result={r} />)}
            </div>
          )}
          {safe.length > 0 && (
            <div className="mt-3 space-y-2">
              <p className="text-[10px] text-emerald-400 font-medium uppercase tracking-wider">Safe</p>
              {safe.map((r, i) => <TestResultCard key={i} result={r} />)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── History Tab ───────────────────────────────────────────────────────────────

function HistoryTab({ onRestore }: { onRestore: (scan: FullHistoryScan) => void }) {
  const [items, setItems]           = useState<HistoryScan[]>([]);
  const [loading, setLoading]       = useState(true);
  const [selected, setSelected]     = useState<FullHistoryScan | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [deleting, setDeleting]     = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetchWithAuth(`${API_BASE}/ai-scanner/history`);
      if (r.ok) {
        const d = await r.json();
        setItems(d.items ?? []);
      }
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const openDetail = async (id: string) => {
    setLoadingDetail(true);
    try {
      const r = await fetchWithAuth(`${API_BASE}/ai-scanner/history/${id}`);
      if (r.ok) setSelected(await r.json());
      else toast.error("Failed to load scan details");
    } catch { toast.error("Failed to load scan details"); }
    setLoadingDetail(false);
  };

  const deleteScan = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeleting(id);
    try {
      const r = await fetchWithAuth(`${API_BASE}/ai-scanner/history/${id}`, { method: "DELETE" });
      if (r.ok) {
        setItems(p => p.filter(s => s.id !== id));
        if (selected?.id === id) setSelected(null);
        toast.success("Scan deleted");
      }
    } catch {}
    setDeleting(null);
  };

  if (selected) {
    const resultsByCategory = selected.findings.reduce<Record<string, TestResult[]>>((acc, r) => {
      (acc[r.category] ??= []).push(r);
      return acc;
    }, {});
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <button onClick={() => setSelected(null)} className="text-xs text-zinc-500 hover:text-zinc-300 flex items-center gap-1">
            <ChevronRight className="h-3 w-3 rotate-180" /> Back to history
          </button>
          <span className="text-zinc-700">·</span>
          <span className="font-mono text-xs text-blue-400 truncate flex-1">{selected.target}</span>
          <span className="text-[10px] text-zinc-500">{new Date(selected.completed_at).toLocaleString()}</span>
          <Button size="sm" variant="outline" className="text-xs gap-1.5 h-7"
            onClick={() => { onRestore(selected); setSelected(null); }}>
            <ExternalLink className="h-3 w-3" /> Restore to Scanner
          </Button>
        </div>

        {/* Summary */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: "Endpoints",  value: selected.summary?.total_discovered ?? 0, color: "text-zinc-100" },
            { label: "Critical",   value: selected.critical,  color: "text-red-400" },
            { label: "High",       value: selected.high,      color: "text-orange-400" },
            { label: "Med/Low",    value: (selected.medium ?? 0) + (selected.low ?? 0), color: "text-yellow-400" },
          ].map(s => (
            <Card key={s.label}>
              <CardContent className="pt-4 pb-3">
                <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">{s.label}</p>
                <p className={cn("text-2xl font-bold", s.color)}>{s.value}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        {selected.summary?.compliance && <OWASPComplianceBar compliance={selected.summary.compliance} />}

        {/* Results by category */}
        {Object.entries(resultsByCategory).map(([cat, results]) => (
          <CategoryResultsGroup key={cat} category={cat} results={results} />
        ))}

        {/* Endpoints */}
        {selected.endpoints.length > 0 && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Search className="h-4 w-4 text-blue-400" /> Discovered Endpoints ({selected.endpoints.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {selected.endpoints.map((ep, i) => (
                <div key={i} className="rounded-md border border-zinc-800 bg-zinc-900/50 p-2.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs text-blue-400 break-all flex-1">{ep.url}</span>
                    <Badge variant="outline" className="text-[10px] h-4 py-0 shrink-0">{ep.type}</Badge>
                    <Badge variant="outline" className="text-[10px] h-4 py-0 shrink-0">HTTP {ep.status_code}</Badge>
                    {ep.unauthenticated
                      ? <span className="text-[10px] text-red-400 flex items-center gap-1 shrink-0"><XCircle className="h-3 w-3" /> Open</span>
                      : <span className="text-[10px] text-emerald-400 flex items-center gap-1 shrink-0"><Shield className="h-3 w-3" /> Auth Required</span>}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        )}
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
          {items.map(scan => {
            const failedOwasp = Object.values(scan.compliance).filter(v => v === "fail").length;
            const hasVulns = scan.total_vulnerable > 0;
            return (
              <div
                key={scan.id}
                onClick={() => openDetail(scan.id)}
                className={cn(
                  "rounded-lg border p-4 cursor-pointer transition-colors hover:border-zinc-600",
                  hasVulns ? "border-zinc-700 bg-zinc-900/50" : "border-zinc-800 bg-zinc-900/20"
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0 space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-blue-400 truncate">{scan.target}</span>
                      <Badge variant="outline" className="text-[10px] h-4 py-0 capitalize shrink-0">{scan.intensity}</Badge>
                      {loadingDetail && <Loader2 className="h-3 w-3 animate-spin text-zinc-500" />}
                    </div>
                    <div className="flex items-center gap-3 text-[10px] text-zinc-500">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {new Date(scan.completed_at).toLocaleString()}
                      </span>
                      <span>{scan.total_tests} tests</span>
                      <span>{scan.total_endpoints} endpoint{scan.total_endpoints !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {scan.critical > 0 && <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 rounded px-1.5 py-0.5">{scan.critical} critical</span>}
                      {scan.high     > 0 && <span className="text-[10px] bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded px-1.5 py-0.5">{scan.high} high</span>}
                      {scan.medium   > 0 && <span className="text-[10px] bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded px-1.5 py-0.5">{scan.medium} medium</span>}
                      {scan.total_vulnerable === 0 && <span className="text-[10px] text-emerald-400">✓ No vulnerabilities</span>}
                      {failedOwasp > 0 && (
                        <span className="text-[10px] text-zinc-500 ml-1">{failedOwasp} OWASP fail{failedOwasp !== 1 ? "s" : ""}</span>
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
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AIScannerPage() {
  const [tab, setTab] = useState<"scan" | "history">("scan");

  // Config state
  const [target, setTarget]         = useState("");
  const [intensity, setIntensity]   = useState<Intensity>(() =>
    (localStorage.getItem("ai_scanner_intensity") as Intensity) ?? "quick"
  );
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([]);   // empty = all
  const [selectedStrategies, setSelectedStrategies] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem("ai_scanner_strategies") ?? '["none"]'); } catch { return ["none"]; }
  });

  // Auth state
  const [authType, setAuthType]           = useState<AuthType>(() => (localStorage.getItem("ai_scanner_auth_type") as AuthType) ?? "none");
  const [authToken, setAuthToken]         = useState(() => localStorage.getItem("ai_scanner_auth_token") ?? "");
  const [authHeaderName, setAuthHeaderName] = useState(() => localStorage.getItem("ai_scanner_auth_header") ?? "");
  const [authUsername, setAuthUsername]   = useState(() => localStorage.getItem("ai_scanner_auth_user") ?? "");
  const [authPassword, setAuthPassword]   = useState(() => localStorage.getItem("ai_scanner_auth_pass") ?? "");
  const [showSecret, setShowSecret]       = useState(false);

  // Plugin metadata loaded from API
  const [pluginMeta, setPluginMeta] = useState<PluginCategories | null>(null);
  const [pluginSection, setPluginSection] = useState<Record<string, boolean>>({});

  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [progressLines, setProgressLines] = useState<string[]>([]);
  const [showProgress, setShowProgress] = useState(false);
  const [endpoints, setEndpoints]     = useState<DiscoveredEndpoint[]>([]);
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [summary, setSummary]         = useState<ScanSummary | null>(null);
  const [phaseInfo, setPhaseInfo]     = useState<{ total_tests: number; endpoint: string } | null>(null);
  const [testsRun, setTestsRun]       = useState(0);

  const abortRef      = useRef<AbortController | null>(null);
  const progressEndRef = useRef<HTMLDivElement>(null);

  // Load plugin metadata on mount
  useEffect(() => {
    fetchWithAuth(`${API_BASE}/ai-scanner/plugins`)
      .then(r => r.ok ? r.json() : null)
      .then((d: PluginCategories | null) => {
        if (d) {
          setPluginMeta(d);
          // Expand all categories by default
          const open: Record<string, boolean> = {};
          Object.keys(d.categories).forEach(c => { open[c] = true; });
          setPluginSection(open);
        }
      })
      .catch(() => {});
  }, []);

  const addLine = (msg: string) =>
    setProgressLines(p => {
      const next = [...p, msg];
      setTimeout(() => progressEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
      return next;
    });

  const toggleStrategy = (id: string) =>
    setSelectedStrategies(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    );

  const togglePlugin = (id: string) =>
    setSelectedPlugins(prev =>
      prev.includes(id) ? prev.filter(p => p !== id) : [...prev, id]
    );

  const toggleCategory = (cat: string, plugins: PluginMeta[]) => {
    const ids = plugins.map(p => p.id);
    const allSelected = ids.every(id => selectedPlugins.includes(id));
    if (allSelected) {
      setSelectedPlugins(prev => prev.filter(id => !ids.includes(id)));
    } else {
      setSelectedPlugins(prev => [...new Set([...prev, ...ids])]);
    }
  };

  const startScan = useCallback(async () => {
    if (!target.trim()) { toast.error("Please enter a target URL"); return; }

    // Persist settings
    localStorage.setItem("ai_scanner_intensity",  intensity);
    localStorage.setItem("ai_scanner_strategies", JSON.stringify(selectedStrategies));
    localStorage.setItem("ai_scanner_auth_type",  authType);
    localStorage.setItem("ai_scanner_auth_token", authToken);
    localStorage.setItem("ai_scanner_auth_header", authHeaderName);
    localStorage.setItem("ai_scanner_auth_user",  authUsername);
    localStorage.setItem("ai_scanner_auth_pass",  authPassword);

    setIsScanning(true);
    setScanStatus("running");
    setProgressLines([]);
    setEndpoints([]);
    setTestResults([]);
    setSummary(null);
    setPhaseInfo(null);
    setTestsRun(0);
    abortRef.current = new AbortController();

    try {
      const res = await fetchWithAuth(`${API_BASE}/ai-scanner/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          test_plugins: true,
          plugins: selectedPlugins,
          strategies: selectedStrategies.length ? selectedStrategies : ["none"],
          intensity,
          timeout: 20,
          llm_grader_key: "",
          auth_type: authType, auth_token: authToken.trim(),
          auth_header_name: authHeaderName.trim(),
          auth_username: authUsername.trim(), auth_password: authPassword,
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
          const event = eventMatch?.[1] ?? "progress";
          let data: Record<string, unknown>;
          try { data = JSON.parse(dataMatch[1]); } catch { continue; }

          if (event === "start") {
            addLine(`🚀 Scan started — ${data.target} | probing ${data.probes} endpoint patterns`);
          } else if (event === "progress") {
            addLine((data.message as string) ?? JSON.stringify(data));
          } else if (event === "endpoint_found") {
            setEndpoints(p => [...p, data as unknown as DiscoveredEndpoint]);
          } else if (event === "phase_start") {
            const d = data as { total_tests: number; endpoint: string; plugins: number; strategies: number; intensity: string; llm_grader: boolean };
            setPhaseInfo({ total_tests: d.total_tests, endpoint: d.endpoint });
            addLine(`🧪 Running ${d.total_tests} tests [${d.plugins} plugins × ${d.strategies} strategies, ${d.intensity}, LLM-grader: ${d.llm_grader}]`);
          } else if (event === "test_result") {
            const r = data as unknown as TestResult;
            setTestResults(p => [...p, r]);
            setTestsRun(c => c + 1);
          } else if (event === "complete") {
            const ep  = (data.endpoints as DiscoveredEndpoint[]) ?? [];
            const sum = data.summary as ScanSummary;
            setEndpoints(ep);
            setSummary(sum);
            setScanStatus("completed");
            setIsScanning(false);
            const v = (sum?.critical ?? 0) + (sum?.high ?? 0) + (sum?.medium ?? 0);
            toast.success(`Scan complete — ${ep.length} endpoints, ${v} vulnerabilities`);
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
  }, [target, intensity, selectedPlugins, selectedStrategies,
      authType, authToken, authHeaderName, authUsername, authPassword]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  // Group results by category
  const resultsByCategory = testResults.reduce<Record<string, TestResult[]>>((acc, r) => {
    (acc[r.category] ??= []).push(r);
    return acc;
  }, {});

  const vulnCount = testResults.filter(r => r.result === "VULNERABLE").length;

  const allStrategyIds = pluginMeta?.strategies.map(s => s.id) ?? ["none", "base64", "rot13", "hex", "leetspeak", "fictional-frame", "academic-frame", "code-comment", "language-switch"];
  const strategyLabels: Record<string, string> = {
    "none": "Baseline", "base64": "Base64", "rot13": "ROT13", "hex": "Hex",
    "leetspeak": "Leetspeak", "fictional-frame": "Fictional Frame",
    "academic-frame": "Academic Frame", "code-comment": "Code Comment", "language-switch": "Language Switch (FR)",
  };

  const handleRestore = (scan: FullHistoryScan) => {
    setTarget(scan.target);
    setTab("scan");
    toast.success(`Restored: ${scan.target}`);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI/LLM Red Team Scanner"
        description="40+ attack plugins × 9 strategies — OWASP LLM Top 10 · MITRE ATLAS · Crescendo multi-turn"
      >
        {isScanning && (
          <Button variant="destructive" size="sm" onClick={stopScan} className="gap-1.5">
            <Square className="h-3.5 w-3.5" /> Stop
          </Button>
        )}
      </PageHeader>

      {/* Tab switcher */}
      <div className="flex gap-1 rounded-lg border border-zinc-800 bg-zinc-900/50 p-1 w-fit">
        {([["scan", Bot, "New Scan"], ["history", History, "History"]] as const).map(([id, Icon, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              tab === id
                ? "bg-zinc-700 text-zinc-100"
                : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* History tab */}
      {tab === "history" && (
        <HistoryTab onRestore={handleRestore} />
      )}

      {/* Scanner tab */}
      {tab === "scan" && <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">

        {/* ── Config Panel ── */}
        <div className="space-y-4">

          {/* Target */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Target className="h-4 w-4 text-blue-400" /> Target
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Target URL</Label>
                <Input
                  placeholder="https://gandalf.lakera.ai/baseline"
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  disabled={isScanning}
                  onKeyDown={e => e.key === "Enter" && !isScanning && startScan()}
                  className="font-mono text-xs"
                />
              </div>

              {/* Intensity */}
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Intensity</Label>
                <div className="grid grid-cols-3 gap-1">
                  {(["quick", "thorough", "full"] as Intensity[]).map(level => (
                    <button
                      key={level}
                      type="button"
                      onClick={() => setIntensity(level)}
                      disabled={isScanning}
                      className={cn(
                        "rounded px-2 py-1.5 text-xs capitalize transition-colors border",
                        intensity === level
                          ? "bg-blue-600 text-white border-blue-600"
                          : "bg-zinc-900 text-zinc-400 border-zinc-700 hover:border-zinc-500"
                      )}
                    >
                      {level}
                    </button>
                  ))}
                </div>
                <p className="text-[10px] text-zinc-600">
                  {intensity === "quick" && "1 prompt/plugin, baseline only — fastest"}
                  {intensity === "thorough" && "All prompts/plugin, baseline only"}
                  {intensity === "full" && "All prompts × all selected strategies — slowest"}
                </p>
              </div>

              {/* Auth */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Lock className="h-3.5 w-3.5 text-zinc-500" />
                  <Label className="text-xs text-zinc-400">Authentication</Label>
                </div>
                <select
                  value={authType}
                  onChange={e => setAuthType(e.target.value as AuthType)}
                  disabled={isScanning}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs text-zinc-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="none">None</option>
                  <option value="bearer">Bearer Token</option>
                  <option value="api_key">API Key (custom header)</option>
                  <option value="basic">Basic Auth</option>
                  <option value="custom">Custom Header</option>
                </select>
                {(authType === "bearer") && (
                  <div className="relative">
                    <Input type={showSecret ? "text" : "password"} placeholder="Bearer token..." value={authToken} onChange={e => setAuthToken(e.target.value)} disabled={isScanning} className="font-mono text-xs pr-8" />
                    <button type="button" onClick={() => setShowSecret(v => !v)} className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300">
                      {showSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                )}
                {(authType === "api_key" || authType === "custom") && (
                  <div className="space-y-1.5">
                    <Input placeholder={authType === "api_key" ? "X-API-Key" : "Header name"} value={authHeaderName} onChange={e => setAuthHeaderName(e.target.value)} disabled={isScanning} className="text-xs" />
                    <div className="relative">
                      <Input type={showSecret ? "text" : "password"} placeholder="Value" value={authToken} onChange={e => setAuthToken(e.target.value)} disabled={isScanning} className="font-mono text-xs pr-8" />
                      <button type="button" onClick={() => setShowSecret(v => !v)} className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300">
                        {showSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>
                )}
                {authType === "basic" && (
                  <div className="space-y-1.5">
                    <Input placeholder="Username" value={authUsername} onChange={e => setAuthUsername(e.target.value)} disabled={isScanning} className="text-xs" />
                    <div className="relative">
                      <Input type={showSecret ? "text" : "password"} placeholder="Password" value={authPassword} onChange={e => setAuthPassword(e.target.value)} disabled={isScanning} className="text-xs pr-8" />
                      <button type="button" onClick={() => setShowSecret(v => !v)} className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300">
                        {showSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Strategies */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Layers className="h-4 w-4 text-purple-400" /> Attack Strategies
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5">
              <div className="flex gap-2 mb-2">
                <button type="button" onClick={() => setSelectedStrategies(allStrategyIds)} className="text-[10px] text-blue-400 hover:underline">All</button>
                <button type="button" onClick={() => setSelectedStrategies(["none"])} className="text-[10px] text-zinc-500 hover:underline">Baseline only</button>
              </div>
              {allStrategyIds.map(sid => (
                <label key={sid} className="flex items-center gap-2 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={selectedStrategies.includes(sid)}
                    onChange={() => toggleStrategy(sid)}
                    disabled={isScanning}
                    className="accent-purple-500"
                  />
                  <span className="text-xs text-zinc-400 group-hover:text-zinc-200 transition-colors">
                    {strategyLabels[sid] ?? sid}
                  </span>
                </label>
              ))}
              <p className="text-[10px] text-zinc-600 mt-2">
                Strategies only apply in <span className="text-zinc-400">full</span> intensity mode.
              </p>
            </CardContent>
          </Card>

          {/* Plugin selector */}
          {pluginMeta && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <BookOpen className="h-4 w-4 text-yellow-400" /> Plugins
                  <span className="ml-auto text-[10px] text-zinc-500">
                    {selectedPlugins.length === 0 ? "All" : selectedPlugins.length} selected
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex gap-2 text-[10px]">
                  <button onClick={() => setSelectedPlugins([])} className="text-blue-400 hover:underline">All plugins</button>
                  <button onClick={() => setSelectedPlugins(Object.values(pluginMeta.categories).flat().map(p => p.id))} className="text-zinc-500 hover:underline">Custom selection</button>
                </div>
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {Object.entries(pluginMeta.categories).map(([cat, plugins]) => {
                    const catIds = plugins.map(p => p.id);
                    const allChecked = catIds.every(id => selectedPlugins.length === 0 || selectedPlugins.includes(id));
                    return (
                      <div key={cat}>
                        <button
                          type="button"
                          onClick={() => setPluginSection(s => ({ ...s, [cat]: !s[cat] }))}
                          className="flex w-full items-center gap-1.5 text-[10px] font-semibold text-zinc-400 uppercase tracking-wider hover:text-zinc-200 mb-1"
                        >
                          {pluginSection[cat] ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                          {cat}
                          <span className="ml-auto text-zinc-600 normal-case font-normal">{plugins.length}</span>
                        </button>
                        {pluginSection[cat] && (
                          <div className="ml-3 space-y-1">
                            {plugins.map(p => (
                              <label key={p.id} className="flex items-center gap-2 cursor-pointer group">
                                <input
                                  type="checkbox"
                                  checked={selectedPlugins.length === 0 || selectedPlugins.includes(p.id)}
                                  onChange={() => {
                                    if (selectedPlugins.length === 0) {
                                      // Deselect all first, then exclude this one
                                      const all = Object.values(pluginMeta.categories).flat().map(pl => pl.id);
                                      setSelectedPlugins(all.filter(id => id !== p.id));
                                    } else {
                                      togglePlugin(p.id);
                                    }
                                  }}
                                  disabled={isScanning}
                                  className="accent-yellow-500"
                                />
                                <div className="min-w-0">
                                  <span className="text-xs text-zinc-400 group-hover:text-zinc-200 transition-colors">
                                    {p.name}
                                  </span>
                                  {p.multi_turn && (
                                    <span className="ml-1 text-[9px] text-purple-400">multi-turn</span>
                                  )}
                                </div>
                                <span className={cn(
                                  "ml-auto shrink-0 h-1.5 w-1.5 rounded-full",
                                  SEV_DOT[p.severity] ?? "bg-zinc-600"
                                )} />
                              </label>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Run button */}
          <Button
            onClick={isScanning ? stopScan : startScan}
            className={cn("w-full gap-2", isScanning ? "bg-red-600 hover:bg-red-700" : "")}
            disabled={!target.trim() && !isScanning}
          >
            {isScanning
              ? <><Square className="h-4 w-4" /> Stop Scan</>
              : <><Play className="h-4 w-4" /> Start Red Team Scan</>}
          </Button>
        </div>

        {/* ── Results Panel ── */}
        <div className="lg:col-span-2 space-y-4">

          {/* Live progress bar */}
          {isScanning && phaseInfo && (
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-zinc-400 flex items-center gap-2">
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-400" />
                    Testing {phaseInfo.endpoint.split("/").slice(0, 3).join("/")}…
                  </span>
                  <span className="text-xs text-zinc-500">{testsRun} / {phaseInfo.total_tests}</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-zinc-800 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-blue-500 transition-all duration-300"
                    style={{ width: `${Math.min(100, (testsRun / phaseInfo.total_tests) * 100)}%` }}
                  />
                </div>
                {vulnCount > 0 && (
                  <p className="text-[10px] text-red-400 mt-1.5">{vulnCount} vulnerabilities found so far</p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Summary cards */}
          {summary && (
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: "Endpoints",   value: summary.total_discovered,  color: "text-zinc-100" },
                { label: "Critical",    value: summary.critical,           color: "text-red-400" },
                { label: "High",        value: summary.high,              color: "text-orange-400" },
                { label: "Med/Low",     value: (summary.medium ?? 0) + (summary.low ?? 0), color: "text-yellow-400" },
              ].map(s => (
                <Card key={s.label}>
                  <CardContent className="pt-4 pb-3">
                    <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">{s.label}</p>
                    <p className={cn("text-2xl font-bold", s.color)}>{s.value}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* OWASP Compliance */}
          {summary?.compliance && <OWASPComplianceBar compliance={summary.compliance} />}

          {/* Discovered Endpoints */}
          {endpoints.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <Search className="h-4 w-4 text-blue-400" />
                  Discovered Endpoints ({endpoints.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {endpoints.map((ep, i) => (
                  <div key={i} className="rounded-md border border-zinc-800 bg-zinc-900/50 p-2.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-blue-400 break-all flex-1">{ep.url}</span>
                      <Badge variant="outline" className="text-[10px] h-4 py-0 shrink-0">{ep.type}</Badge>
                      <Badge variant="outline" className="text-[10px] h-4 py-0 shrink-0">HTTP {ep.status_code}</Badge>
                      {ep.unauthenticated
                        ? <span className="text-[10px] text-red-400 flex items-center gap-1 shrink-0"><XCircle className="h-3 w-3" /> Open</span>
                        : <span className="text-[10px] text-emerald-400 flex items-center gap-1 shrink-0"><Shield className="h-3 w-3" /> Auth Required</span>}
                    </div>
                    {ep.indicators.length > 0 && (
                      <p className="text-[10px] text-zinc-500 mt-1">{ep.indicators.join(" · ")}</p>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Results by category */}
          {Object.keys(resultsByCategory).length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4 text-yellow-400" />
                <h3 className="text-sm font-semibold text-zinc-300">
                  Results by Category
                  <span className="ml-2 text-xs text-zinc-500 font-normal">
                    {vulnCount} vulnerable / {testResults.length} tested
                  </span>
                </h3>
              </div>
              {Object.entries(resultsByCategory).map(([cat, results]) => (
                <CategoryResultsGroup key={cat} category={cat} results={results} />
              ))}
            </div>
          )}

          {/* MITRE ATLAS summary */}
          {summary && Object.keys(summary.by_owasp).length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-blue-400" /> Findings by OWASP Category
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {Object.entries(summary.by_owasp)
                  .sort((a, b) => b[1].count - a[1].count)
                  .map(([ow, info]) => (
                    <div key={ow} className="flex items-center gap-3">
                      <span className="text-xs font-mono text-zinc-400 w-12 shrink-0">{ow}</span>
                      <div className="flex-1 h-2 rounded-full bg-zinc-800 overflow-hidden">
                        <div
                          className={cn(
                            "h-full rounded-full",
                            info.severity === "critical" ? "bg-red-500" :
                            info.severity === "high"     ? "bg-orange-500" :
                            info.severity === "medium"   ? "bg-yellow-500" : "bg-blue-500"
                          )}
                          style={{ width: `${Math.min(100, info.count * 20)}%` }}
                        />
                      </div>
                      <span className="text-xs text-zinc-500 w-16 shrink-0 text-right">
                        {info.count} finding{info.count !== 1 ? "s" : ""}
                      </span>
                    </div>
                  ))}
              </CardContent>
            </Card>
          )}

          {/* Progress log */}
          {progressLines.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <button className="flex w-full items-center justify-between" onClick={() => setShowProgress(v => !v)}>
                  <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                    <Bot className="h-4 w-4 text-zinc-400" /> Progress Log ({progressLines.length})
                  </CardTitle>
                  {showProgress ? <ChevronDown className="h-4 w-4 text-zinc-500" /> : <ChevronRight className="h-4 w-4 text-zinc-500" />}
                </button>
              </CardHeader>
              {showProgress && (
                <CardContent>
                  <div className="bg-zinc-950 rounded-md p-3 max-h-64 overflow-y-auto font-mono text-xs text-zinc-400 space-y-0.5">
                    {progressLines.map((line, i) => <div key={i} className="leading-5">{line}</div>)}
                    <div ref={progressEndRef} />
                  </div>
                </CardContent>
              )}
            </Card>
          )}

          {/* Empty state */}
          {scanStatus === "idle" && testResults.length === 0 && endpoints.length === 0 && (
            <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-20 text-center">
              <Bot className="h-12 w-12 text-zinc-700 mb-4" />
              <p className="text-sm font-medium text-zinc-500">No scan running</p>
              <p className="text-xs text-zinc-600 mt-1 max-w-xs">
                40+ attack plugins · OWASP LLM01–09 · MITRE ATLAS · Crescendo multi-turn · 9 strategies
              </p>
            </div>
          )}
        </div>
      </div>}
    </div>
  );
}
