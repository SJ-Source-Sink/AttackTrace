"use client";

import React, { useState, useRef, useCallback } from "react";
import {
  Code2,
  Play,
  Square,
  History,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  ShieldAlert,
  Globe,
  Key,
  Layers,
  FileCode2,
  Trash2,
  ExternalLink,
  Zap,
  CheckCircle2,
  Clock,
  Database,
  MessageSquare,
  Radio,
  Settings2,
  Variable,
  Bug,
  Shield,
  Shuffle,
  Link,
  Dices,
  Lock,
  BookOpen,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ─── Types ────────────────────────────────────────────────────────────────────

type FindingType =
  | "secret" | "dom_xss" | "dom_source" | "source_map" | "graphql"
  | "prototype_pollution" | "postmessage" | "websocket" | "service_worker" | "env_leak"
  | "security_header" | "sri_missing" | "library_vuln" | "open_redirect"
  | "jsonp" | "insecure_random" | "hardcoded_auth" | "confirmed_xss";
type Severity = "critical" | "high" | "medium" | "low" | "info";

interface JsFinding {
  type: FindingType;
  name: string;
  severity: Severity;
  file_url: string;
  match: string;
  line_number: number;
  recommendation: string;
  context?: string;
}

interface JsEndpoint {
  url: string;
  file: string;
  line: number;
}

interface ScanSummary {
  js_files_scanned: number;
  endpoints_found: number;
  secrets_found: number;
  dom_xss_sinks: number;
  source_maps_exposed: number;
  graphql_issues: number;
  prototype_pollution: number;
  env_leaks: number;
  security_headers: number;
  sri_missing: number;
  vulnerable_libs: number;
  open_redirects: number;
  hardcoded_auth: number;
  confirmed_xss: number;
  duration_seconds: number;
  error?: string;
}

interface HistoryRecord {
  id: string;
  target: string;
  started_at: string;
  completed_at: string;
  summary: ScanSummary;
  findings?: JsFinding[];
  endpoints?: JsEndpoint[];
}

// ─── Severity helpers ────────────────────────────────────────────────────────

const SEV_COLOR: Record<Severity | string, string> = {
  critical: "text-red-400 border-red-500/40 bg-red-500/10",
  high: "text-orange-400 border-orange-500/40 bg-orange-500/10",
  medium: "text-yellow-400 border-yellow-500/40 bg-yellow-500/10",
  low: "text-blue-400 border-blue-500/40 bg-blue-500/10",
  info: "text-zinc-400 border-zinc-500/40 bg-zinc-500/10",
};

const SEV_DOT: Record<Severity | string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-zinc-500",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
        SEV_COLOR[severity] ?? SEV_COLOR.info
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", SEV_DOT[severity] ?? SEV_DOT.info)} />
      {severity}
    </span>
  );
}

// ─── Finding type icon ────────────────────────────────────────────────────────

const FINDING_TYPE_META: Record<string, { icon: React.ElementType; color: string; label: string }> = {
  secret:             { icon: Key,          color: "text-red-400",     label: "Secret" },
  dom_xss:            { icon: Zap,          color: "text-orange-400",  label: "DOM XSS Sink" },
  dom_source:         { icon: AlertTriangle,color: "text-yellow-400",  label: "XSS Source" },
  source_map:         { icon: FileCode2,    color: "text-purple-400",  label: "Source Map" },
  graphql:            { icon: Database,     color: "text-pink-400",    label: "GraphQL" },
  prototype_pollution:{ icon: Bug,          color: "text-red-300",     label: "Proto Pollution" },
  postmessage:        { icon: MessageSquare,color: "text-cyan-400",    label: "PostMessage" },
  websocket:          { icon: Radio,        color: "text-emerald-400", label: "WebSocket" },
  service_worker:     { icon: Settings2,    color: "text-indigo-400",  label: "Service Worker" },
  env_leak:           { icon: Variable,     color: "text-amber-400",   label: "Env Leak" },
  security_header:    { icon: Shield,       color: "text-sky-400",     label: "Sec Header" },
  sri_missing:        { icon: Link,         color: "text-violet-400",  label: "Missing SRI" },
  library_vuln:       { icon: BookOpen,     color: "text-rose-400",    label: "Vuln Library" },
  open_redirect:      { icon: Shuffle,      color: "text-orange-300",  label: "Open Redirect" },
  jsonp:              { icon: Globe,        color: "text-teal-400",    label: "JSONP" },
  insecure_random:    { icon: Dices,        color: "text-yellow-300",  label: "Insecure Random" },
  hardcoded_auth:     { icon: Lock,         color: "text-red-500",     label: "Hardcoded Auth" },
  confirmed_xss:      { icon: Zap,          color: "text-red-400",     label: "Confirmed XSS" },
};

function FindingTypeIcon({ type }: { type: string }) {
  const meta = FINDING_TYPE_META[type];
  if (!meta) return <ShieldAlert className="h-3.5 w-3.5 text-zinc-400" />;
  const Icon = meta.icon;
  return <Icon className={cn("h-3.5 w-3.5 shrink-0", meta.color)} />;
}

function FindingTypeBadge({ type }: { type: string }) {
  const meta = FINDING_TYPE_META[type];
  if (!meta) return null;
  return (
    <span className={cn("text-[9px] font-semibold uppercase tracking-wider", meta.color)}>
      {meta.label}
    </span>
  );
}

// ─── Finding card ─────────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: JsFinding }) {
  const [open, setOpen] = useState(false);
  const isConfirmedXss = finding.type === "confirmed_xss";
  return (
    <div className={cn(
      "rounded-lg border bg-zinc-900/60",
      isConfirmedXss ? "border-red-500/50 bg-red-500/5 ring-1 ring-red-500/20" : "border-zinc-800"
    )}>
      <button
        className="w-full flex items-start gap-3 px-4 py-3 text-left"
        onClick={() => setOpen((p) => !p)}
      >
        <FindingTypeIcon type={finding.type} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            {isConfirmedXss && (
              <span className="inline-flex items-center gap-1 rounded bg-red-500/20 border border-red-500/40 px-1.5 py-0.5 text-[9px] font-bold uppercase text-red-400 tracking-wider">
                ⚡ CONFIRMED
              </span>
            )}
            <span className="text-sm font-semibold text-zinc-200">{finding.name}</span>
            <SeverityBadge severity={finding.severity} />
            <FindingTypeBadge type={finding.type} />
          </div>
          <p className="text-[11px] text-zinc-500 mt-0.5 font-mono truncate">
            {finding.file_url}
            {finding.line_number > 0 && (
              <span className="text-zinc-600"> :{finding.line_number}</span>
            )}
          </p>
        </div>
        {open ? (
          <ChevronDown className="h-4 w-4 text-zinc-500 shrink-0 mt-0.5" />
        ) : (
          <ChevronRight className="h-4 w-4 text-zinc-500 shrink-0 mt-0.5" />
        )}
      </button>
      {open && (
        <div className="border-t border-zinc-800 px-4 py-3 space-y-3">
          <div>
            <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Match</p>
            <code className="text-xs font-mono text-zinc-300 bg-zinc-800 px-2 py-1 rounded break-all">
              {finding.match}
            </code>
          </div>
          {finding.context && (
            <div>
              <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Code Context</p>
              <pre className="text-[11px] font-mono text-zinc-400 bg-zinc-800/60 px-3 py-2 rounded overflow-x-auto whitespace-pre-wrap max-h-32">
                {finding.context}
              </pre>
            </div>
          )}
          <div>
            <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Recommendation</p>
            <p className="text-xs text-zinc-400">{finding.recommendation}</p>
          </div>
          {finding.file_url.startsWith("http") && (
            <a
              href={finding.file_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[11px] text-blue-400 hover:underline"
            >
              Open file <ExternalLink className="h-3 w-3" />
            </a>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Endpoints grouped list ───────────────────────────────────────────────────

function EndpointsList({ endpoints }: { endpoints: JsEndpoint[] }) {
  const [expanded, setExpanded] = useState(true);

  // Group by path prefix (first 2 segments)
  const groups: Record<string, JsEndpoint[]> = {};
  for (const ep of endpoints) {
    const parts = ep.url.split("/").filter(Boolean);
    const prefix = parts.length > 0 ? `/${parts[0]}` : "/";
    groups[prefix] = groups[prefix] ?? [];
    groups[prefix].push(ep);
  }

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/60">
      <button
        className="w-full flex items-center justify-between px-4 py-3 text-left"
        onClick={() => setExpanded((p) => !p)}
      >
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-semibold text-zinc-200">
            Discovered Endpoints
          </span>
          <Badge variant="secondary" className="text-[10px]">
            {endpoints.length}
          </Badge>
        </div>
        {expanded ? (
          <ChevronDown className="h-4 w-4 text-zinc-500" />
        ) : (
          <ChevronRight className="h-4 w-4 text-zinc-500" />
        )}
      </button>
      {expanded && (
        <div className="border-t border-zinc-800 px-4 py-3 space-y-4 max-h-[400px] overflow-y-auto">
          {Object.entries(groups).map(([prefix, eps]) => (
            <div key={prefix}>
              <p className="text-[10px] text-zinc-500 font-mono uppercase tracking-wider mb-1.5">
                {prefix} ({eps.length})
              </p>
              <div className="space-y-1">
                {eps.slice(0, 20).map((ep, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 rounded bg-zinc-800/50 px-2 py-1.5"
                  >
                    <code className="text-xs font-mono text-emerald-400 flex-1 break-all">
                      {ep.url}
                    </code>
                    <span className="text-[10px] text-zinc-600 shrink-0 font-mono">
                      :{ep.line}
                    </span>
                  </div>
                ))}
                {eps.length > 20 && (
                  <p className="text-[10px] text-zinc-600 pl-2">
                    +{eps.length - 20} more…
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Summary strip ────────────────────────────────────────────────────────────

function SummaryStrip({ summary }: { summary: ScanSummary }) {
  const stats = [
    { label: "Confirmed XSS", value: summary.confirmed_xss ?? 0,   color: "text-red-400",     Icon: Zap },
    { label: "Secrets",      value: summary.secrets_found,        color: "text-red-300",     Icon: Key },
    { label: "Endpoints",    value: summary.endpoints_found,      color: "text-blue-400",    Icon: Globe },
    { label: "DOM XSS",      value: summary.dom_xss_sinks,        color: "text-orange-400",  Icon: AlertTriangle },
    { label: "Sec Headers",  value: summary.security_headers ?? 0,color: "text-sky-400",     Icon: Shield },
    { label: "Vuln Libs",    value: summary.vulnerable_libs ?? 0, color: "text-rose-400",    Icon: BookOpen },
    { label: "Missing SRI",  value: summary.sri_missing ?? 0,     color: "text-violet-400",  Icon: Link },
    { label: "Open Redirect",value: summary.open_redirects ?? 0,  color: "text-orange-300",  Icon: Shuffle },
    { label: "Auth Headers", value: summary.hardcoded_auth ?? 0,  color: "text-red-500",     Icon: Lock },
    { label: "Proto Pollut", value: summary.prototype_pollution ?? 0, color: "text-red-200", Icon: Bug },
    { label: "Env Leaks",    value: summary.env_leaks ?? 0,       color: "text-amber-400",   Icon: Variable },
    { label: "Source Maps",  value: summary.source_maps_exposed,  color: "text-purple-400",  Icon: FileCode2 },
    { label: "JS Files",     value: summary.js_files_scanned,     color: "text-zinc-300",    Icon: Layers },
  ];
  return (
    <div className="grid grid-cols-4 sm:grid-cols-8 gap-2">
      {stats.map(({ label, value, color, Icon }) => (
        <div
          key={label}
          className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2.5 flex flex-col items-center gap-1"
        >
          <Icon className={cn("h-4 w-4", color)} />
          <span className={cn("text-lg font-bold leading-none", color)}>{value}</span>
          <span className="text-[10px] text-zinc-500">{label}</span>
        </div>
      ))}
    </div>
  );
}

// ─── History tab ──────────────────────────────────────────────────────────────

function HistoryTab({
  history,
  onSelect,
  onDelete,
  loading,
}: {
  history: HistoryRecord[];
  onSelect: (r: HistoryRecord) => void;
  onDelete: (id: string) => void;
  loading: boolean;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20 text-zinc-600">
        <Clock className="h-5 w-5 animate-spin mr-2" /> Loading history…
      </div>
    );
  }

  if (history.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
        <History className="h-10 w-10" />
        <p className="text-sm">No scans yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {history.map((entry) => {
        const isExpanded = expanded === entry.id;
        const s = entry.summary ?? {};
        return (
          <div key={entry.id} className="rounded-lg border border-zinc-800 bg-zinc-900">
            <button
              className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-zinc-800/40 transition-colors"
              onClick={() => setExpanded(isExpanded ? null : entry.id)}
            >
              <Code2 className="h-4 w-4 text-blue-400 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-mono text-zinc-200 truncate">{entry.target}</p>
                <p className="text-[10px] text-zinc-500 mt-0.5">
                  {entry.started_at
                    ? new Date(entry.started_at).toLocaleString()
                    : "Unknown time"}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <div className="text-right space-y-0.5 hidden sm:block">
                  <p className="text-xs text-red-400">{s.secrets_found ?? 0} secrets</p>
                  <p className="text-xs text-blue-400">{s.endpoints_found ?? 0} endpoints</p>
                </div>
                {isExpanded ? (
                  <ChevronDown className="h-4 w-4 text-zinc-500" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-zinc-500" />
                )}
              </div>
            </button>

            {isExpanded && (
              <div className="border-t border-zinc-800 px-4 py-4 space-y-4">
                {s && <SummaryStrip summary={s as ScanSummary} />}

                {entry.findings && entry.findings.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-xs font-semibold text-zinc-400">Findings</p>
                    {entry.findings.slice(0, 10).map((f, i) => (
                      <FindingCard key={i} finding={f} />
                    ))}
                    {entry.findings.length > 10 && (
                      <p className="text-xs text-zinc-600 text-center">
                        +{entry.findings.length - 10} more findings
                      </p>
                    )}
                  </div>
                )}

                {entry.endpoints && entry.endpoints.length > 0 && (
                  <EndpointsList endpoints={entry.endpoints} />
                )}

                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    className="gap-1.5 text-xs"
                    onClick={() => onSelect(entry)}
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" /> Restore to Scanner
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="gap-1.5 text-xs text-red-400 hover:text-red-300"
                    onClick={() => onDelete(entry.id)}
                  >
                    <Trash2 className="h-3.5 w-3.5" /> Delete
                  </Button>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function JsScannerPage() {
  const [activeTab, setActiveTab] = useState<"scanner" | "history">("scanner");

  // Form
  const [target, setTarget] = useState("");
  const [maxDepth, setMaxDepth] = useState("2");
  const [maxFiles, setMaxFiles] = useState("50");
  const [includeSourceMaps, setIncludeSourceMaps] = useState(true);
  const [includeSubdomains, setIncludeSubdomains] = useState(false);

  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [progressMessages, setProgressMessages] = useState<string[]>([]);
  const [findings, setFindings] = useState<JsFinding[]>([]);
  const [endpoints, setEndpoints] = useState<JsEndpoint[]>([]);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [jsFilesProgress, setJsFilesProgress] = useState<{ current: number; total: number }>({ current: 0, total: 0 });
  const [discoveredUrls, setDiscoveredUrls] = useState<string[]>([]);

  // History
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const abortRef = useRef<AbortController | null>(null);
  const progressEndRef = useRef<HTMLDivElement>(null);

  // ── Load history when switching to History tab ──────────────────────────────

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await fetchWithAuth(`${API_BASE}/js-scanner/history`);
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

  const handleTabChange = (tab: "scanner" | "history") => {
    setActiveTab(tab);
    if (tab === "history") loadHistory();
  };

  // ── Delete history entry ────────────────────────────────────────────────────

  const deleteHistoryEntry = async (id: string) => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/js-scanner/history/${id}`, {
        method: "DELETE",
      });
      if (res.ok) {
        setHistory((prev) => prev.filter((r) => r.id !== id));
        toast.success("Scan record deleted");
      }
    } catch {
      toast.error("Failed to delete scan record");
    }
  };

  // ── Restore from history ────────────────────────────────────────────────────

  const restoreFromHistory = (record: HistoryRecord) => {
    setTarget(record.target);
    setFindings(record.findings ?? []);
    setEndpoints(record.endpoints ?? []);
    setSummary(record.summary ?? null);
    setActiveTab("scanner");
    toast.success("Restored scan results");
  };

  // ── Start scan ──────────────────────────────────────────────────────────────

  const startScan = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target URL");
      return;
    }

    // Normalize: add https:// if user typed a bare domain
    const normalizedTarget = /^https?:\/\//i.test(target.trim())
      ? target.trim()
      : `https://${target.trim()}`;
    if (normalizedTarget !== target.trim()) {
      setTarget(normalizedTarget);
    }

    setIsScanning(true);
    setProgressMessages([]);
    setFindings([]);
    setEndpoints([]);
    setSummary(null);
    setJsFilesProgress({ current: 0, total: 0 });
    setDiscoveredUrls([]);

    abortRef.current = new AbortController();

    try {
      const res = await fetchWithAuth(`${API_BASE}/js-scanner/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: normalizedTarget,
          max_depth: parseInt(maxDepth),
          max_files: parseInt(maxFiles),
          include_source_maps: includeSourceMaps,
          include_subdomains: includeSubdomains,
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Scan failed" }));
        throw new Error(
          typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail)
        );
      }

      if (!res.body) {
        throw new Error("Server returned no response body — streaming not supported");
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let completed = false;

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const parts = buffer.split("\n\n");
          buffer = parts.pop() ?? "";

          for (const part of parts) {
            if (!part.trim()) continue;
            const eventMatch = part.match(/^event: (\w+)/m);
            const dataMatch = part.match(/^data: (.+)/m);
            if (!eventMatch || !dataMatch) continue;

            const event = eventMatch[1];
            let data: Record<string, unknown>;
            try {
              data = JSON.parse(dataMatch[1]);
            } catch {
              continue;
            }

            if (event === "start") {
              setProgressMessages((prev) => [...prev, `Started scan on ${data.target}`]);
            } else if (event === "progress") {
              const msg = (data.message as string) ?? "";
              setProgressMessages((prev) => {
                const next = [...prev, msg];
                setTimeout(
                  () => progressEndRef.current?.scrollIntoView({ behavior: "smooth" }),
                  0
                );
                return next.slice(-100);
              });
              if (data.phase === "discovery" && Array.isArray(data.urls)) {
                setDiscoveredUrls(data.urls as string[]);
                setJsFilesProgress({ current: 0, total: (data.urls as string[]).length });
              }
              if (data.phase === "analysis") {
                setJsFilesProgress((prev) => ({ ...prev, current: prev.current + 1 }));
              }
            } else if (event === "finding") {
              setFindings((prev) => [...prev, data as unknown as JsFinding]);
            } else if (event === "endpoint") {
              setEndpoints((prev) => [
                ...prev,
                { url: data.url as string, file: data.file as string, line: (data.line as number) ?? 0 },
              ]);
            } else if (event === "complete") {
              completed = true;
              setSummary(data as unknown as ScanSummary);
              setIsScanning(false);
              if (data.error) {
                toast.error(`Scan failed: ${data.error}`);
              } else {
                toast.success(`Scan complete — ${data.js_files_scanned} files, ${data.secrets_found} secrets, ${data.endpoints_found} endpoints`);
              }
            } else if (event === "error") {
              completed = true;
              setIsScanning(false);
              toast.error(`Scan error: ${data.message}`);
            }
          }
        }
      } finally {
        reader.releaseLock();
        // Safety net: if stream closed without a complete/error event
        if (!completed) {
          setIsScanning(false);
          toast.warning("Scan stream ended unexpectedly");
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") {
        // user cancelled — already handled by stopScan
      } else {
        toast.error(`Scan failed: ${err instanceof Error ? err.message : String(err)}`);
      }
      setIsScanning(false);
    }
  }, [target, maxDepth, maxFiles, includeSourceMaps, includeSubdomains]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    toast.info("Scan stopped");
  };

  // ── Grouped findings ────────────────────────────────────────────────────────

  const secrets = findings.filter((f) => f.type === "secret");
  const domXss = findings.filter((f) => f.type === "dom_xss" || f.type === "dom_source");
  const sourceMaps = findings.filter((f) => f.type === "source_map");
  const graphqlFindings = findings.filter((f) => f.type === "graphql");
  const protoPollution = findings.filter((f) => f.type === "prototype_pollution");
  const postmessageFindings = findings.filter((f) => f.type === "postmessage");
  const websocketFindings = findings.filter((f) => f.type === "websocket");
  const swFindings = findings.filter((f) => f.type === "service_worker");
  const envLeaks = findings.filter((f) => f.type === "env_leak");

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <PageHeader
        title="JavaScript Analyzer"
        description="Discover endpoints, secrets, DOM XSS, prototype pollution, env leaks, postMessage issues, and more"
      />

      {/* Tab switcher */}
      <div className="flex gap-2 border-b border-zinc-800 pb-0">
        {(["scanner", "history"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => handleTabChange(tab)}
            className={cn(
              "px-4 py-2 text-sm font-medium capitalize border-b-2 -mb-px transition-colors",
              activeTab === tab
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-zinc-500 hover:text-zinc-300"
            )}
          >
            {tab === "scanner" ? (
              <span className="flex items-center gap-1.5">
                <Code2 className="h-3.5 w-3.5" /> Scanner
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
                  <Code2 className="h-4 w-4 text-blue-400" />
                  Scan Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Target */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Target URL</Label>
                  <Input
                    placeholder="https://example.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={isScanning}
                    onKeyDown={(e) => e.key === "Enter" && !isScanning && startScan()}
                    className="font-mono text-xs"
                  />
                  <p className="text-[10px] text-zinc-600">
                    Full URL including scheme
                  </p>
                </div>

                {/* Max depth */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Max Crawl Depth</Label>
                  <Select value={maxDepth} onValueChange={setMaxDepth} disabled={isScanning}>
                    <SelectTrigger className="text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 — Surface only</SelectItem>
                      <SelectItem value="2">2 — Standard (recommended)</SelectItem>
                      <SelectItem value="3">3 — Deep crawl</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Max files */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Max JS Files</Label>
                  <Select value={maxFiles} onValueChange={setMaxFiles} disabled={isScanning}>
                    <SelectTrigger className="text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="25">25 files</SelectItem>
                      <SelectItem value="50">50 files (recommended)</SelectItem>
                      <SelectItem value="100">100 files</SelectItem>
                      <SelectItem value="200">200 files</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Toggles */}
                <div className="space-y-2">
                  <ToggleOption
                    label="Check Source Maps"
                    description="Detect exposed .map files"
                    value={includeSourceMaps}
                    onChange={setIncludeSourceMaps}
                    disabled={isScanning}
                  />
                  <ToggleOption
                    label="Include Subdomains"
                    description="Follow JS from subdomain URLs"
                    value={includeSubdomains}
                    onChange={setIncludeSubdomains}
                    disabled={isScanning}
                  />
                </div>

                {isScanning ? (
                  <Button onClick={stopScan} variant="destructive" className="w-full gap-2">
                    <Square className="h-4 w-4" /> Stop Analysis
                  </Button>
                ) : (
                  <Button onClick={startScan} className="w-full gap-2">
                    <Play className="h-4 w-4" /> Analyze JavaScript
                  </Button>
                )}
              </CardContent>
            </Card>

            {/* Live stats */}
            {(isScanning || summary) && (
              <Card>
                <CardContent className="pt-4 space-y-2">
                  {jsFilesProgress.total > 0 && (
                    <div className="space-y-1">
                      <div className="flex justify-between text-[10px] text-zinc-500">
                        <span>Analyzing JS files</span>
                        <span>
                          {jsFilesProgress.current}/{jsFilesProgress.total}
                        </span>
                      </div>
                      <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded-full transition-all duration-300"
                          style={{
                            width: jsFilesProgress.total > 0
                              ? `${Math.min(100, (jsFilesProgress.current / jsFilesProgress.total) * 100)}%`
                              : "0%",
                          }}
                        />
                      </div>
                    </div>
                  )}
                  <StatRow label="Secrets" value={secrets.length} color="text-red-400" />
                  <StatRow label="Endpoints" value={endpoints.length} color="text-blue-400" />
                  <StatRow label="DOM XSS" value={domXss.length} color="text-orange-400" />
                  <StatRow label="Proto Pollution" value={protoPollution.length} color="text-red-300" />
                  <StatRow label="Env Leaks" value={envLeaks.length} color="text-amber-400" />
                  <StatRow label="Source Maps" value={sourceMaps.length} color="text-purple-400" />
                  {summary && (
                    <div className="pt-1 border-t border-zinc-800">
                      <StatRow
                        label="Duration"
                        value={`${summary.duration_seconds}s`}
                        color="text-zinc-400"
                      />
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>

          {/* Results panel */}
          <div className="lg:col-span-2 space-y-4">
            {/* Summary strip */}
            {summary && <SummaryStrip summary={summary} />}

            {/* Progress log */}
            {progressMessages.length > 0 && (
              <div className="rounded-lg border border-zinc-800 bg-zinc-950">
                <div className="flex items-center justify-between border-b border-zinc-800 px-3 py-2">
                  <span className="text-xs text-zinc-500 font-mono flex items-center gap-1.5">
                    {isScanning && (
                      <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                    )}
                    scan log
                  </span>
                </div>
                <div className="max-h-[160px] overflow-y-auto p-3 space-y-0.5">
                  {progressMessages.slice(-40).map((msg, i) => (
                    <div key={i} className="text-[11px] font-mono text-zinc-500 leading-5">
                      <span className="text-zinc-700">›</span> {msg}
                    </div>
                  ))}
                  <div ref={progressEndRef} />
                </div>
              </div>
            )}

            {/* Endpoints */}
            {endpoints.length > 0 && <EndpointsList endpoints={endpoints} />}

            {/* Secrets */}
            {secrets.length > 0 && (
              <FindingSection
                title="Secrets & Credentials"
                icon={<Key className="h-4 w-4 text-red-400" />}
                findings={secrets}
                color="text-red-400"
              />
            )}

            {/* DOM XSS */}
            {domXss.length > 0 && (
              <FindingSection
                title="DOM XSS Sinks"
                icon={<Zap className="h-4 w-4 text-orange-400" />}
                findings={domXss}
                color="text-orange-400"
              />
            )}

            {/* Source maps */}
            {sourceMaps.length > 0 && (
              <FindingSection
                title="Exposed Source Maps"
                icon={<FileCode2 className="h-4 w-4 text-purple-400" />}
                findings={sourceMaps}
                color="text-purple-400"
              />
            )}

            {/* GraphQL */}
            {graphqlFindings.length > 0 && (
              <FindingSection
                title="GraphQL Issues"
                icon={<Database className="h-4 w-4 text-pink-400" />}
                findings={graphqlFindings}
                color="text-pink-400"
              />
            )}

            {/* Prototype Pollution */}
            {protoPollution.length > 0 && (
              <FindingSection
                title="Prototype Pollution"
                icon={<Bug className="h-4 w-4 text-red-300" />}
                findings={protoPollution}
                color="text-red-300"
              />
            )}

            {/* Environment Leaks */}
            {envLeaks.length > 0 && (
              <FindingSection
                title="Environment Variable Leaks"
                icon={<Variable className="h-4 w-4 text-amber-400" />}
                findings={envLeaks}
                color="text-amber-400"
              />
            )}

            {/* PostMessage */}
            {postmessageFindings.length > 0 && (
              <FindingSection
                title="PostMessage Security"
                icon={<MessageSquare className="h-4 w-4 text-cyan-400" />}
                findings={postmessageFindings}
                color="text-cyan-400"
              />
            )}

            {/* WebSocket */}
            {websocketFindings.length > 0 && (
              <FindingSection
                title="WebSocket Security"
                icon={<Radio className="h-4 w-4 text-emerald-400" />}
                findings={websocketFindings}
                color="text-emerald-400"
              />
            )}

            {/* Service Worker */}
            {swFindings.length > 0 && (
              <FindingSection
                title="Service Worker"
                icon={<Settings2 className="h-4 w-4 text-indigo-400" />}
                findings={swFindings}
                color="text-indigo-400"
              />
            )}

            {/* Empty state */}
            {!isScanning && findings.length === 0 && endpoints.length === 0 && progressMessages.length === 0 && (
              <div className="flex flex-col items-center justify-center py-24 text-zinc-600 space-y-3">
                <Code2 className="h-12 w-12" />
                <p className="text-sm">Enter a target URL and click Analyze JavaScript</p>
                <p className="text-xs text-zinc-700">
                  Discovers endpoints, secrets, DOM XSS sinks, and source maps
                </p>
              </div>
            )}

            {isScanning && findings.length === 0 && endpoints.length === 0 && progressMessages.length > 0 && (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500 space-y-3">
                <Code2 className="h-8 w-8 animate-pulse text-blue-400" />
                <p className="text-sm">Crawling and analyzing JavaScript…</p>
                {discoveredUrls.length > 0 && (
                  <p className="text-xs text-zinc-600">
                    {discoveredUrls.length} JS files queued
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── HISTORY TAB ─────────────────────────────────────────────────────── */}
      {activeTab === "history" && (
        <HistoryTab
          history={history}
          onSelect={restoreFromHistory}
          onDelete={deleteHistoryEntry}
          loading={historyLoading}
        />
      )}
    </div>
  );
}

// ─── Small helpers ────────────────────────────────────────────────────────────

function StatRow({
  label,
  value,
  color,
}: {
  label: string;
  value: string | number;
  color: string;
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-zinc-500">{label}</span>
      <span className={cn("text-xs font-semibold", color)}>{value}</span>
    </div>
  );
}

function ToggleOption({
  label,
  description,
  value,
  onChange,
  disabled,
}: {
  label: string;
  description: string;
  value: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onChange(!value)}
      className={cn(
        "w-full flex items-start justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors",
        value
          ? "border-blue-500/40 bg-blue-500/5"
          : "border-zinc-800 bg-zinc-900/60",
        disabled && "opacity-50 cursor-not-allowed"
      )}
    >
      <div>
        <p className="text-xs font-medium text-zinc-300">{label}</p>
        <p className="text-[10px] text-zinc-600 mt-0.5">{description}</p>
      </div>
      <div
        className={cn(
          "relative mt-0.5 h-4 w-7 rounded-full transition-colors shrink-0",
          value ? "bg-blue-500" : "bg-zinc-700"
        )}
      >
        <span
          className={cn(
            "absolute top-0.5 h-3 w-3 rounded-full bg-white transition-transform",
            value ? "translate-x-3.5" : "translate-x-0.5"
          )}
        />
      </div>
    </button>
  );
}

function FindingSection({
  title,
  icon,
  findings,
  color,
}: {
  title: string;
  icon: React.ReactNode;
  findings: JsFinding[];
  color: string;
}) {
  const [open, setOpen] = useState(true);
  return (
    <div className="space-y-2">
      <button
        className="flex items-center gap-2 w-full text-left"
        onClick={() => setOpen((p) => !p)}
      >
        {icon}
        <span className={cn("text-sm font-semibold", color)}>{title}</span>
        <Badge variant="secondary" className="text-[10px] ml-1">
          {findings.length}
        </Badge>
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 text-zinc-600 ml-auto" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-zinc-600 ml-auto" />
        )}
      </button>
      {open && (
        <div className="space-y-2">
          {findings.map((f, i) => (
            <FindingCard key={i} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}
