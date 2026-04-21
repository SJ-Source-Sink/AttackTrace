"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Map,
  Play,
  Square,
  ChevronDown,
  ChevronUp,
  Clock,
  AlertTriangle,
  CheckCircle2,
  History,
  Shield,
  Zap,
  Link2,
  Terminal,
  BookOpen,
  AlertCircle,
  Layers,
  Target,
  Bug,
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

const INFRA_OPTIONS = [
  {
    value: "ad",
    label: "Active Directory",
    desc: "Domain controllers, Kerberos, LDAP, GPOs",
    icon: "🏢",
  },
  {
    value: "aws",
    label: "Amazon Web Services",
    desc: "IAM, S3, EC2, Lambda, CloudTrail",
    icon: "☁️",
  },
  {
    value: "azure",
    label: "Microsoft Azure",
    desc: "Entra ID, Storage, Functions, RBAC",
    icon: "🔷",
  },
  {
    value: "gcp",
    label: "Google Cloud Platform",
    desc: "IAM, GCS, Compute Engine, Cloud Run",
    icon: "🌐",
  },
  {
    value: "network",
    label: "Network Infrastructure",
    desc: "Routers, firewalls, switches, protocols",
    icon: "🔗",
  },
];

const RISK_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  info: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
};

const PHASE_COLORS: Record<string, string> = {
  reconnaissance: "bg-purple-500/10 text-purple-400",
  "initial-access": "bg-red-500/10 text-red-400",
  execution: "bg-orange-500/10 text-orange-400",
  persistence: "bg-yellow-500/10 text-yellow-400",
  "privilege-escalation": "bg-pink-500/10 text-pink-400",
  "defense-evasion": "bg-indigo-500/10 text-indigo-400",
  "credential-access": "bg-cyan-500/10 text-cyan-400",
  discovery: "bg-teal-500/10 text-teal-400",
  "lateral-movement": "bg-blue-500/10 text-blue-400",
  collection: "bg-emerald-500/10 text-emerald-400",
  exfiltration: "bg-rose-500/10 text-rose-400",
  impact: "bg-red-500/10 text-red-400",
};

interface Technique {
  id: string;
  mitre_id: string;
  name: string;
  phase: string;
  infrastructure: string;
  description: string;
  prerequisites: string[];
  tools: string[];
  commands: string[];
  detection: string;
  references: string[];
  next_techniques: string[];
  risk_level: string;
}

interface ChainStep {
  step_number: number;
  technique: Technique;
}

interface AttackChain {
  id: string;
  name: string;
  infrastructure: string;
  start_phase: string;
  end_phase: string;
  steps: ChainStep[];
}

interface CVE {
  cve_id: string;
  description: string;
  cvss_score: number;
  severity: string;
  affected_products: string[];
  exploitation_status: string;
  references: string[];
  published_date: string;
}

interface ThreatIntel {
  infrastructure: string;
  critical_cves: CVE[];
  [key: string]: unknown;
}

interface ScanResult {
  scan_id: string;
  infrastructure_type: string;
  infrastructure_label: string;
  technique_count: number;
  chain_steps: number;
  critical_cves: number;
  techniques: Technique[];
  attack_chain: AttackChain | null;
  threat_intel: ThreatIntel | null;
}

interface HistoryEntry {
  id: string;
  infrastructure_type: string;
  infrastructure_label: string;
  status: string;
  started_at: string;
  completed_at?: string;
  technique_count: number;
  chain_steps: number;
  critical_cves: number;
}

function TechniqueCard({ technique }: { technique: Technique }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-zinc-800 rounded-lg overflow-hidden">
      <button
        type="button"
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-zinc-800/30 transition-colors"
        onClick={() => setExpanded((e) => !e)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className="text-zinc-100 font-medium text-sm">{technique.name}</span>
            <Badge variant="outline" className="font-mono text-xs text-blue-400 border-blue-500/30">
              {technique.mitre_id}
            </Badge>
            <span
              className={cn(
                "text-xs px-2 py-0.5 rounded-full capitalize",
                PHASE_COLORS[technique.phase] ?? "bg-zinc-700 text-zinc-300"
              )}
            >
              {technique.phase.replace(/-/g, " ")}
            </span>
            <span
              className={cn(
                "text-xs px-2 py-0.5 rounded-full border capitalize font-medium",
                RISK_COLORS[technique.risk_level] ?? RISK_COLORS.info
              )}
            >
              {technique.risk_level}
            </span>
          </div>
          <p className="text-zinc-400 text-xs line-clamp-2">{technique.description}</p>
          {!expanded && technique.tools.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {technique.tools.slice(0, 4).map((tool) => (
                <span key={tool} className="text-xs bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded">
                  {tool}
                </span>
              ))}
              {technique.tools.length > 4 && (
                <span className="text-xs text-zinc-500">+{technique.tools.length - 4} more</span>
              )}
            </div>
          )}
        </div>
        <div className="shrink-0 mt-0.5">
          {expanded ? (
            <ChevronUp className="h-4 w-4 text-zinc-500" />
          ) : (
            <ChevronDown className="h-4 w-4 text-zinc-500" />
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-zinc-800 p-4 space-y-4 bg-zinc-900/40">
          {technique.prerequisites.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Prerequisites</p>
              <ul className="space-y-1">
                {technique.prerequisites.map((p, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-zinc-400">
                    <span className="text-zinc-600 mt-0.5">•</span>
                    {p}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {technique.tools.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Tools</p>
              <div className="flex flex-wrap gap-1.5">
                {technique.tools.map((tool) => (
                  <span key={tool} className="text-xs bg-zinc-800 border border-zinc-700 text-zinc-300 px-2 py-0.5 rounded">
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          )}

          {technique.commands.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Commands</p>
              <div className="bg-zinc-950 border border-zinc-800 rounded p-3 max-h-48 overflow-y-auto">
                {technique.commands.map((cmd, i) => (
                  <div
                    key={i}
                    className={cn(
                      "text-xs font-mono",
                      cmd.startsWith("#") ? "text-zinc-500 mt-2 first:mt-0" : "text-emerald-400 break-all"
                    )}
                  >
                    {cmd}
                  </div>
                ))}
              </div>
            </div>
          )}

          {technique.detection && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Detection</p>
              <p className="text-xs text-zinc-400">{technique.detection}</p>
            </div>
          )}

          {technique.next_techniques.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Leads To</p>
              <div className="flex flex-wrap gap-1.5">
                {technique.next_techniques.map((t) => (
                  <span key={t} className="text-xs font-mono bg-blue-500/10 border border-blue-500/20 text-blue-400 px-2 py-0.5 rounded">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {technique.references.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">References</p>
              <div className="space-y-0.5">
                {technique.references.map((ref) => (
                  <p key={ref} className="text-xs text-blue-400 truncate">{ref}</p>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CVECard({ cve }: { cve: CVE }) {
  const severityColor =
    cve.severity === "critical"
      ? "border-red-500/30 bg-red-500/5"
      : cve.severity === "high"
      ? "border-orange-500/30 bg-orange-500/5"
      : "border-yellow-500/30 bg-yellow-500/5";

  const scoreColor =
    cve.cvss_score >= 9
      ? "text-red-400"
      : cve.cvss_score >= 7
      ? "text-orange-400"
      : "text-yellow-400";

  return (
    <div className={cn("border rounded-lg p-4", severityColor)}>
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-sm font-semibold text-zinc-100">{cve.cve_id}</span>
          <Badge
            variant="outline"
            className={cn("text-xs capitalize", RISK_COLORS[cve.severity] ?? RISK_COLORS.info)}
          >
            {cve.severity}
          </Badge>
          {cve.exploitation_status === "in-the-wild" && (
            <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/20">
              In-the-Wild
            </Badge>
          )}
        </div>
        <span className={cn("text-lg font-bold shrink-0", scoreColor)}>
          {cve.cvss_score.toFixed(1)}
        </span>
      </div>
      <p className="text-sm text-zinc-300 mb-2">{cve.description}</p>
      <div className="flex flex-wrap gap-1 mt-2">
        {cve.affected_products.map((p) => (
          <span key={p} className="text-xs bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded">
            {p}
          </span>
        ))}
      </div>
      {cve.published_date && (
        <p className="text-xs text-zinc-500 mt-2">Published: {cve.published_date}</p>
      )}
    </div>
  );
}

export default function AttackMapperPage() {
  const [infraType, setInfraType] = useState("ad");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [phaseFilter, setPhaseFilter] = useState("");
  const [searchFilter, setSearchFilter] = useState("");

  const [isRunning, setIsRunning] = useState(false);
  const [progressLog, setProgressLog] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [activeTab, setActiveTab] = useState<"techniques" | "chain" | "intel">("techniques");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [techniqueSearch, setTechniqueSearch] = useState("");
  const [techniquePhaseFilter, setTechniquePhaseFilter] = useState("all");

  const abortRef = useRef<AbortController | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadHistory();
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [progressLog]);

  async function loadHistory() {
    try {
      const res = await fetchWithAuth(`${API_BASE}/attackmapper/scans`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.items ?? []);
      }
    } catch {
      // silently ignore
    }
  }

  const handleStop = useCallback(() => {
    abortRef.current?.abort();
    setIsRunning(false);
    setProgressLog((p) => [...p, "Scan aborted by user."]);
  }, []);

  const handleRun = useCallback(async () => {
    setIsRunning(true);
    setProgressLog([]);
    setResult(null);
    setActiveTab("techniques");

    abortRef.current = new AbortController();

    try {
      const token = localStorage.getItem("access_token");
      const res = await fetch(`${API_BASE}/attackmapper/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          infrastructure_type: infraType,
          category: categoryFilter || undefined,
          phase: phaseFilter || undefined,
          search: searchFilter || undefined,
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail ?? "Scan failed");
      }

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      let currentEvent = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          let eventType = currentEvent;
          let dataStr = "";

          for (const line of part.split("\n")) {
            if (line.startsWith("event: ")) {
              eventType = line.slice(7).trim();
            } else if (line.startsWith("data: ")) {
              dataStr = line.slice(6);
            }
          }

          if (!dataStr) continue;

          let payload: Record<string, unknown>;
          try {
            payload = JSON.parse(dataStr);
          } catch {
            continue;
          }

          if (eventType === "progress") {
            setProgressLog((p) => [...p, String(payload.message ?? "")]);
          } else if (eventType === "start") {
            setProgressLog((p) => [
              ...p,
              `Starting ${payload.infrastructure_label} attack path analysis...`,
            ]);
          } else if (eventType === "complete") {
            setResult(payload as unknown as ScanResult);
            setProgressLog((p) => [
              ...p,
              `Complete — ${payload.technique_count} techniques, ${payload.chain_steps} chain steps, ${payload.critical_cves} critical CVEs`,
            ]);
            loadHistory();
          } else if (eventType === "error") {
            toast.error(String(payload.message ?? "Scan error"));
            setProgressLog((p) => [...p, `Error: ${payload.message}`]);
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") {
        toast.error(err.message);
        setProgressLog((p) => [...p, `Error: ${err.message}`]);
      }
    } finally {
      setIsRunning(false);
    }
  }, [infraType, categoryFilter, phaseFilter, searchFilter]);

  // Filtered techniques for the techniques tab
  const filteredTechniques = (result?.techniques ?? []).filter((t) => {
    if (techniquePhaseFilter !== "all" && t.phase !== techniquePhaseFilter) return false;
    if (techniqueSearch) {
      const q = techniqueSearch.toLowerCase();
      return (
        t.name.toLowerCase().includes(q) ||
        t.mitre_id.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.tools.some((tool) => tool.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const uniquePhases = Array.from(new Set((result?.techniques ?? []).map((t) => t.phase)));

  const selectedInfra = INFRA_OPTIONS.find((o) => o.value === infraType);

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Attack Path Mapper"
        description="Visualize attack paths for AD, Cloud, and Network infrastructure mapped to MITRE ATT&CK"
      />

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* ── Left: Config panel ──────────────────────────────────────────── */}
        <div className="xl:col-span-1 space-y-4">
          <Card className="border-zinc-800 bg-zinc-900">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                <Layers className="h-4 w-4 text-blue-400" />
                Infrastructure Type
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {INFRA_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setInfraType(opt.value)}
                  className={cn(
                    "w-full flex items-start gap-3 p-3 rounded-lg border text-left transition-all",
                    infraType === opt.value
                      ? "border-blue-500/50 bg-blue-500/10"
                      : "border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800/50"
                  )}
                >
                  <span className="text-lg shrink-0">{opt.icon}</span>
                  <div className="min-w-0">
                    <p
                      className={cn(
                        "text-sm font-medium",
                        infraType === opt.value ? "text-blue-300" : "text-zinc-300"
                      )}
                    >
                      {opt.label}
                    </p>
                    <p className="text-xs text-zinc-500 mt-0.5">{opt.desc}</p>
                  </div>
                </button>
              ))}
            </CardContent>
          </Card>

          <Card className="border-zinc-800 bg-zinc-900">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-zinc-300">Filters (Optional)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Search Techniques</Label>
                <Input
                  placeholder="e.g. kerberoast, privilege escalation"
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="h-8 text-sm bg-zinc-950 border-zinc-700"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Phase Filter</Label>
                <Input
                  placeholder="e.g. reconnaissance, persistence"
                  value={phaseFilter}
                  onChange={(e) => setPhaseFilter(e.target.value)}
                  className="h-8 text-sm bg-zinc-950 border-zinc-700"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Category Filter</Label>
                <Input
                  placeholder="e.g. credential-access"
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="h-8 text-sm bg-zinc-950 border-zinc-700"
                />
              </div>
            </CardContent>
          </Card>

          <div className="flex gap-2">
            <Button
              onClick={handleRun}
              disabled={isRunning}
              className="flex-1 bg-blue-600 hover:bg-blue-500 text-white"
            >
              <Play className="h-4 w-4 mr-2" />
              {isRunning ? "Mapping..." : "Run Analysis"}
            </Button>
            {isRunning && (
              <Button
                variant="outline"
                onClick={handleStop}
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
              >
                <Square className="h-4 w-4" />
              </Button>
            )}
          </div>

          {/* History */}
          {history.length > 0 && (
            <Card className="border-zinc-800 bg-zinc-900">
              <button
                type="button"
                className="w-full flex items-center justify-between p-4"
                onClick={() => setShowHistory((s) => !s)}
              >
                <span className="flex items-center gap-2 text-sm font-medium text-zinc-300">
                  <History className="h-4 w-4 text-zinc-500" />
                  History ({history.length})
                </span>
                {showHistory ? (
                  <ChevronUp className="h-4 w-4 text-zinc-500" />
                ) : (
                  <ChevronDown className="h-4 w-4 text-zinc-500" />
                )}
              </button>
              {showHistory && (
                <div className="border-t border-zinc-800 divide-y divide-zinc-800 max-h-64 overflow-y-auto">
                  {history.map((h) => (
                    <div key={h.id} className="p-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm text-zinc-300 font-medium">
                          {h.infrastructure_label}
                        </span>
                        <Badge
                          variant="outline"
                          className={cn(
                            "text-xs",
                            h.status === "completed"
                              ? "text-emerald-400 border-emerald-500/20"
                              : h.status === "failed"
                              ? "text-red-400 border-red-500/20"
                              : "text-yellow-400 border-yellow-500/20"
                          )}
                        >
                          {h.status}
                        </Badge>
                      </div>
                      <div className="flex gap-3 mt-1 text-xs text-zinc-500">
                        <span>{h.technique_count} techniques</span>
                        <span>{h.chain_steps} steps</span>
                        <span>{h.critical_cves} CVEs</span>
                      </div>
                      <p className="text-xs text-zinc-600 mt-0.5">
                        {new Date(h.started_at).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}
        </div>

        {/* ── Right: Results ────────────────────────────────────────────────── */}
        <div className="xl:col-span-2 space-y-4">
          {/* Progress log */}
          {(isRunning || progressLog.length > 0) && (
            <Card className="border-zinc-800 bg-zinc-900">
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-2">
                  <Terminal className="h-3.5 w-3.5" />
                  Progress
                  {isRunning && (
                    <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3">
                <div className="bg-zinc-950 border border-zinc-800 rounded p-3 h-28 overflow-y-auto font-mono text-xs">
                  {progressLog.map((line, i) => (
                    <div
                      key={i}
                      className={cn(
                        line.startsWith("Error:") ? "text-red-400" : "text-zinc-300"
                      )}
                    >
                      <span className="text-zinc-600 mr-2">$</span>
                      {line}
                    </div>
                  ))}
                  <div ref={logEndRef} />
                </div>
              </CardContent>
            </Card>
          )}

          {/* Summary stats */}
          {result && (
            <div className="grid grid-cols-3 gap-3">
              <Card className="border-zinc-800 bg-zinc-900">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <Target className="h-4 w-4 text-blue-400" />
                    <span className="text-xs text-zinc-500">Techniques</span>
                  </div>
                  <p className="text-2xl font-bold text-zinc-100">{result.technique_count}</p>
                  <p className="text-xs text-zinc-500 mt-0.5">{result.infrastructure_label}</p>
                </CardContent>
              </Card>
              <Card className="border-zinc-800 bg-zinc-900">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <Link2 className="h-4 w-4 text-purple-400" />
                    <span className="text-xs text-zinc-500">Chain Steps</span>
                  </div>
                  <p className="text-2xl font-bold text-zinc-100">{result.chain_steps}</p>
                  <p className="text-xs text-zinc-500 mt-0.5">Full attack path</p>
                </CardContent>
              </Card>
              <Card className="border-zinc-800 bg-zinc-900">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <Bug className="h-4 w-4 text-red-400" />
                    <span className="text-xs text-zinc-500">Critical CVEs</span>
                  </div>
                  <p className="text-2xl font-bold text-zinc-100">{result.critical_cves}</p>
                  <p className="text-xs text-zinc-500 mt-0.5">Active threats</p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Tabs */}
          {result && (
            <Card className="border-zinc-800 bg-zinc-900">
              {/* Tab bar */}
              <div className="flex border-b border-zinc-800 px-4">
                {(
                  [
                    { key: "techniques", label: "Attack Techniques", icon: Shield, count: result.technique_count },
                    { key: "chain", label: "Full Attack Chain", icon: Link2, count: result.chain_steps },
                    { key: "intel", label: "Threat Intel", icon: AlertTriangle, count: result.critical_cves },
                  ] as const
                ).map(({ key, label, icon: Icon, count }) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setActiveTab(key)}
                    className={cn(
                      "flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors",
                      activeTab === key
                        ? "border-blue-500 text-blue-400"
                        : "border-transparent text-zinc-500 hover:text-zinc-300"
                    )}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    {label}
                    <span
                      className={cn(
                        "text-xs px-1.5 py-0.5 rounded-full",
                        activeTab === key ? "bg-blue-500/20 text-blue-400" : "bg-zinc-800 text-zinc-500"
                      )}
                    >
                      {count}
                    </span>
                  </button>
                ))}
              </div>

              <CardContent className="p-4">
                {/* ── Techniques tab ── */}
                {activeTab === "techniques" && (
                  <div className="space-y-3">
                    {/* Search + phase filter */}
                    <div className="flex gap-2">
                      <Input
                        placeholder="Search techniques, tools, MITRE IDs..."
                        value={techniqueSearch}
                        onChange={(e) => setTechniqueSearch(e.target.value)}
                        className="h-8 text-sm bg-zinc-950 border-zinc-700 flex-1"
                      />
                      <select
                        value={techniquePhaseFilter}
                        onChange={(e) => setTechniquePhaseFilter(e.target.value)}
                        className="h-8 text-sm bg-zinc-950 border border-zinc-700 rounded-md px-2 text-zinc-300"
                      >
                        <option value="all">All phases</option>
                        {uniquePhases.map((p) => (
                          <option key={p} value={p}>
                            {p.replace(/-/g, " ")}
                          </option>
                        ))}
                      </select>
                    </div>

                    {filteredTechniques.length === 0 ? (
                      <div className="text-center py-8 text-zinc-500 text-sm">
                        No techniques match your filter.
                      </div>
                    ) : (
                      <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                        {filteredTechniques.map((t) => (
                          <TechniqueCard key={t.id} technique={t} />
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* ── Full Chain tab ── */}
                {activeTab === "chain" && result.attack_chain && (
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="text-sm text-zinc-400">
                        <span className="text-zinc-300 font-medium">{result.attack_chain.name}</span>
                        <span className="mx-2 text-zinc-600">•</span>
                        <span className="capitalize">{result.attack_chain.start_phase.replace(/-/g, " ")}</span>
                        <span className="mx-1 text-zinc-600">→</span>
                        <span className="capitalize">{result.attack_chain.end_phase.replace(/-/g, " ")}</span>
                      </div>
                    </div>

                    <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
                      {result.attack_chain.steps.map((step) => (
                        <div key={step.step_number} className="flex gap-3">
                          {/* Step number connector */}
                          <div className="flex flex-col items-center">
                            <div className="h-6 w-6 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center shrink-0">
                              <span className="text-xs font-bold text-blue-400">{step.step_number}</span>
                            </div>
                            {step.step_number < result.attack_chain!.steps.length && (
                              <div className="w-px flex-1 bg-zinc-800 mt-1 mb-0 min-h-4" />
                            )}
                          </div>
                          <div className="flex-1 pb-2">
                            <TechniqueCard technique={step.technique} />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {activeTab === "chain" && !result.attack_chain && (
                  <div className="text-center py-8 text-zinc-500 text-sm">
                    No attack chain data available.
                  </div>
                )}

                {/* ── Threat Intel tab ── */}
                {activeTab === "intel" && result.threat_intel && (
                  <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
                    {result.threat_intel.critical_cves.length === 0 ? (
                      <div className="text-center py-8 text-zinc-500 text-sm">
                        No critical CVEs in the threat intelligence feed.
                      </div>
                    ) : (
                      result.threat_intel.critical_cves.map((cve) => (
                        <CVECard key={cve.cve_id} cve={cve} />
                      ))
                    )}
                  </div>
                )}

                {activeTab === "intel" && !result.threat_intel && (
                  <div className="text-center py-8 text-zinc-500 text-sm">
                    No threat intelligence data available.
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Empty state */}
          {!result && !isRunning && progressLog.length === 0 && (
            <Card className="border-zinc-800 bg-zinc-900 border-dashed">
              <CardContent className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="h-12 w-12 rounded-full bg-zinc-800 flex items-center justify-center">
                  <Map className="h-6 w-6 text-zinc-500" />
                </div>
                <p className="text-zinc-400 font-medium">Select an infrastructure type and run the analysis</p>
                <p className="text-zinc-600 text-sm text-center max-w-sm">
                  AttackMapper generates attack path visualizations mapped to MITRE ATT&CK with active threat intelligence
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
