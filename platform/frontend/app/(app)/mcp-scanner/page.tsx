"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Link2,
  Play,
  Square,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  Shield,
  Cpu,
  Search,
  Zap,
  Lock,
  Eye,
  Terminal,
  Globe,
  Database,
  Key,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type Phase = "discovery" | "sse_detection" | "enumeration" | "attack" | "intelligence";

interface MCPFinding {
  type: "finding";
  vuln_id: string;
  url: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  owasp: string;
  mitre?: string;
  detail?: string;
  tool_name?: string;
  evidence?: string;
  tool_count?: number;
  resource_count?: number;
  exposed_tools?: string[];
}

interface DiscoveredEndpoint {
  url: string;
  status: number;
  server_info: Record<string, unknown>;
}

interface ScanComplete {
  target: string;
  total_findings: number;
  endpoints_found: number;
  tools_enumerated: number;
  severity_counts: Record<Severity, number>;
  vuln_ids: string[];
  summary: string;
}

interface VulnCheck {
  name: string;
  severity: string;
  description: string;
  owasp: string;
  id?: string;
  mitre?: string;
}

interface VulnCatalog {
  discovery_probes: VulnCheck[];
  attack_modules: (VulnCheck & { payload_count: number })[];
  intelligence_checks: { name: string; severity: string }[];
}

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-zinc-700/50 text-zinc-400 border-zinc-600/30",
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const PHASE_LABELS: Record<string, string> = {
  discovery: "Discovery — probing MCP endpoint paths",
  sse_detection: "SSE Transport Detection",
  enumeration: "Enumeration — tools/resources/prompts",
  attack: "Attack Phase — path traversal, RCE, SSRF...",
  intelligence: "Intelligence — secrets, malicious tools, injection",
};

const PHASE_ICONS: Record<string, React.ReactNode> = {
  discovery: <Search className="h-3.5 w-3.5" />,
  sse_detection: <Zap className="h-3.5 w-3.5" />,
  enumeration: <Database className="h-3.5 w-3.5" />,
  attack: <Terminal className="h-3.5 w-3.5" />,
  intelligence: <Eye className="h-3.5 w-3.5" />,
};

const VULN_ICONS: Record<string, React.ReactNode> = {
  unauth_mcp_exposed: <Lock className="h-3.5 w-3.5" />,
  unauth_sse_transport: <Zap className="h-3.5 w-3.5" />,
  path_traversal: <Globe className="h-3.5 w-3.5" />,
  rce_eval: <Terminal className="h-3.5 w-3.5" />,
  ssrf: <Globe className="h-3.5 w-3.5" />,
  command_injection: <Terminal className="h-3.5 w-3.5" />,
  template_injection: <Terminal className="h-3.5 w-3.5" />,
  exposed_secret: <Key className="h-3.5 w-3.5" />,
  indirect_prompt_injection: <ShieldAlert className="h-3.5 w-3.5" />,
  tool_malicious_keywords: <AlertTriangle className="h-3.5 w-3.5" />,
  tool_typosquatting: <AlertTriangle className="h-3.5 w-3.5" />,
  tool_suspicious_keywords: <AlertTriangle className="h-3.5 w-3.5" />,
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge className={cn("text-[10px] border font-semibold", SEVERITY_STYLES[severity])}>
      {severity.toUpperCase()}
    </Badge>
  );
}

function FindingCard({ finding, index }: { finding: MCPFinding; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const icon = VULN_ICONS[finding.vuln_id] ?? <ShieldAlert className="h-3.5 w-3.5" />;

  return (
    <div className={cn(
      "rounded-lg border transition-colors",
      finding.severity === "critical" ? "border-red-500/30 bg-red-950/10" :
      finding.severity === "high" ? "border-orange-500/30 bg-orange-950/10" :
      finding.severity === "medium" ? "border-yellow-500/30 bg-yellow-950/10" :
      "border-zinc-700/50 bg-zinc-900/30"
    )}>
      <button
        className="w-full flex items-start gap-3 p-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={cn(
          "mt-0.5 rounded p-1",
          finding.severity === "critical" ? "bg-red-500/20 text-red-400" :
          finding.severity === "high" ? "bg-orange-500/20 text-orange-400" :
          finding.severity === "medium" ? "bg-yellow-500/20 text-yellow-400" :
          "bg-zinc-700/50 text-zinc-400"
        )}>
          {icon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs font-semibold text-zinc-200">{finding.title}</span>
          </div>
          <p className="text-[11px] text-zinc-500 mt-0.5 font-mono truncate">{finding.url}</p>
          {finding.owasp && (
            <span className="text-[10px] text-zinc-600">{finding.owasp}</span>
          )}
        </div>
        <div className="shrink-0 text-zinc-600">
          {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-3 border-t border-zinc-800/50 pt-3">
          <p className="text-xs text-zinc-300">{finding.description}</p>

          {finding.detail && (
            <div className="rounded bg-zinc-900 border border-zinc-800 p-2">
              <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Detail</p>
              <p className="text-xs font-mono text-zinc-300 break-all">{finding.detail}</p>
            </div>
          )}

          {finding.exposed_tools && finding.exposed_tools.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">
                Exposed Tools ({finding.tool_count ?? finding.exposed_tools.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {finding.exposed_tools.map((t) => (
                  <Badge key={t} variant="outline" className="text-[10px] font-mono py-0">{t}</Badge>
                ))}
              </div>
            </div>
          )}

          {finding.evidence && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Evidence</p>
              <pre className="text-[10px] font-mono text-zinc-400 bg-zinc-950 rounded p-2 overflow-x-auto max-h-32 whitespace-pre-wrap break-all">
                {finding.evidence}
              </pre>
            </div>
          )}

          <div className="rounded bg-emerald-950/20 border border-emerald-800/30 p-2">
            <p className="text-[10px] uppercase tracking-wider text-emerald-600 mb-1">Remediation</p>
            <p className="text-xs text-emerald-300">{finding.remediation}</p>
          </div>

          {finding.mitre && (
            <p className="text-[10px] text-zinc-600">
              <span className="font-semibold">MITRE ATLAS: </span>{finding.mitre}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export default function MCPScannerPage() {
  const [target, setTarget] = useState("");
  const [checkSse, setCheckSse] = useState(true);
  const [runAttacks, setRunAttacks] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [currentPhase, setCurrentPhase] = useState<string>("");
  const [findings, setFindings] = useState<MCPFinding[]>([]);
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [complete, setComplete] = useState<ScanComplete | null>(null);
  const [probeLog, setProbeLog] = useState<string[]>([]);
  const [showLog, setShowLog] = useState(false);
  const [catalog, setCatalog] = useState<VulnCatalog | null>(null);
  const [activeAttack, setActiveAttack] = useState<string>("");
  const abortRef = useRef<AbortController | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchWithAuth(`${API_BASE}/mcp-scanner/vulnerabilities`)
      .then((r) => r.ok ? r.json() : null)
      .then((data) => { if (data) setCatalog(data); })
      .catch(() => {});
  }, []);

  const addLog = (msg: string) => {
    setProbeLog((prev) => {
      const next = [...prev, msg];
      setTimeout(() => logEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
      return next;
    });
  };

  const startScan = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target URL");
      return;
    }

    setIsScanning(true);
    setScanStatus("running");
    setFindings([]);
    setEndpoints([]);
    setComplete(null);
    setProbeLog([]);
    setCurrentPhase("");
    setActiveAttack("");
    abortRef.current = new AbortController();

    try {
      const res = await fetchWithAuth(`${API_BASE}/mcp-scanner/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          check_sse: checkSse,
          run_attacks: runAttacks,
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
          const lines = part.trim().split("\n");
          let eventName = "";
          let dataStr = "";

          for (const line of lines) {
            if (line.startsWith("event: ")) eventName = line.slice(7).trim();
            else if (line.startsWith("data: ")) dataStr = line.slice(6).trim();
          }

          if (!dataStr) continue;

          let data: Record<string, unknown>;
          try { data = JSON.parse(dataStr); } catch { continue; }

          switch (eventName) {
            case "start":
              addLog(`[START] Scanning ${data.target} | ${data.checks} checks planned`);
              break;

            case "phase_start":
              setCurrentPhase(String(data.phase ?? ""));
              setActiveAttack("");
              addLog(`[PHASE] ${data.message ?? data.phase}`);
              break;

            case "attack_start":
              setActiveAttack(String(data.name ?? data.attack ?? ""));
              addLog(`[ATTACK] ${data.name} — probing tools...`);
              break;

            case "endpoint_found":
              setEndpoints((prev) => [...prev, data as unknown as DiscoveredEndpoint]);
              addLog(`[FOUND] MCP endpoint: ${data.url}`);
              toast.info(`MCP endpoint found: ${data.url}`, { duration: 3000 });
              break;

            case "probe":
              addLog(`[PROBE] ${data.url} → ${data.result ?? data.status}`);
              break;

            case "finding": {
              const f = data as unknown as MCPFinding;
              setFindings((prev) => [...prev, f]);
              addLog(`[${f.severity?.toUpperCase()}] ${f.title}`);
              if (f.severity === "critical") {
                toast.error(`Critical: ${f.title}`, { duration: 5000 });
              }
              break;
            }

            case "complete": {
              const c = data as unknown as ScanComplete;
              setComplete(c);
              setScanStatus("completed");
              setIsScanning(false);
              setCurrentPhase("");
              setActiveAttack("");
              addLog(`[DONE] ${c.summary}`);
              toast.success(c.summary);
              break;
            }

            case "error":
              setScanStatus("failed");
              setIsScanning(false);
              toast.error(`Error: ${data.message ?? data.error}`);
              break;
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
      }
    }
  }, [target, checkSse, runAttacks]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    setCurrentPhase("");
    toast.info("Scan stopped");
  };

  const sortedFindings = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const sevCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {} as Record<Severity, number>);

  return (
    <div className="space-y-6">
      <PageHeader
        title="MCP Scanner"
        description="Comprehensive Model Context Protocol security scanner — discovery, enumeration, attack, and intelligence phases"
      >
        {isScanning && (
          <Button variant="destructive" size="sm" onClick={stopScan} className="gap-1.5">
            <Square className="h-3.5 w-3.5" /> Stop
          </Button>
        )}
      </PageHeader>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* ── Config panel ──────────────────────────────────────────────── */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Shield className="h-4 w-4 text-blue-400" />
                Scan Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Target URL</Label>
                <Input
                  placeholder="http://localhost:3000"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={isScanning}
                  onKeyDown={(e) => e.key === "Enter" && !isScanning && startScan()}
                  className="font-mono text-xs"
                />
                <p className="text-[10px] text-zinc-600">
                  Base URL — scanner probes common MCP paths automatically
                </p>
              </div>

              <div className="space-y-3 rounded-md bg-zinc-800/30 border border-zinc-700/50 p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-medium text-zinc-300">SSE Transport Detection</p>
                    <p className="text-[10px] text-zinc-500">Probe for MCP over Server-Sent Events</p>
                  </div>
                  <Switch checked={checkSse} onCheckedChange={setCheckSse} disabled={isScanning} />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-medium text-zinc-300">Attack Phase</p>
                    <p className="text-[10px] text-zinc-500">Path traversal, RCE, SSRF, injection</p>
                  </div>
                  <Switch checked={runAttacks} onCheckedChange={setRunAttacks} disabled={isScanning} />
                </div>
              </div>

              <Button
                onClick={isScanning ? stopScan : startScan}
                className={cn("w-full gap-2", isScanning && "bg-red-600 hover:bg-red-700")}
                disabled={!target.trim() && !isScanning}
              >
                {isScanning ? (
                  <><Square className="h-4 w-4" /> Stop Scan</>
                ) : (
                  <><Play className="h-4 w-4" /> Start Scan</>
                )}
              </Button>

              {/* Live phase indicator */}
              {isScanning && (
                <div className="rounded-md border border-blue-500/30 bg-blue-950/20 p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
                    <span className="text-xs text-blue-400 font-medium">Scanning...</span>
                  </div>
                  {currentPhase && (
                    <div className="flex items-center gap-1.5 text-[11px] text-blue-300">
                      {PHASE_ICONS[currentPhase]}
                      <span>{PHASE_LABELS[currentPhase] ?? currentPhase}</span>
                    </div>
                  )}
                  {activeAttack && (
                    <p className="text-[10px] text-zinc-500 mt-1 pl-5">→ {activeAttack}</p>
                  )}
                </div>
              )}

              {scanStatus === "completed" && (
                <div className="flex items-center gap-2 text-xs text-emerald-400">
                  <CheckCircle2 className="h-4 w-4" /> Scan completed
                </div>
              )}
              {scanStatus === "failed" && (
                <div className="flex items-center gap-2 text-xs text-red-400">
                  <XCircle className="h-4 w-4" /> Scan failed
                </div>
              )}
            </CardContent>
          </Card>

          {/* Summary counts */}
          {(findings.length > 0 || complete) && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                  Findings Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {SEVERITY_ORDER.filter((s) => s !== "info").map((sev) => (
                  <div key={sev} className="flex items-center justify-between">
                    <SeverityBadge severity={sev} />
                    <span className="text-sm font-bold text-zinc-300">
                      {sevCounts[sev] ?? 0}
                    </span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Endpoints found */}
          {endpoints.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                  MCP Endpoints Found
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {endpoints.map((ep, i) => (
                  <div key={i} className="rounded bg-zinc-800/50 p-2">
                    <p className="text-[11px] font-mono text-blue-400 break-all">{ep.url}</p>
                    {ep.server_info && Object.keys(ep.server_info).length > 0 && (
                      <p className="text-[10px] text-zinc-500 mt-0.5">
                        {JSON.stringify(ep.server_info).slice(0, 80)}
                      </p>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Vulnerability catalog */}
          {catalog && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                  Vulnerability Catalog
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5">
                {catalog.attack_modules.map((a) => (
                  <div key={a.id} className="flex items-center gap-2">
                    <div className={cn(
                      "h-1.5 w-1.5 rounded-full shrink-0",
                      a.severity === "critical" ? "bg-red-500" : a.severity === "high" ? "bg-orange-500" : "bg-yellow-500"
                    )} />
                    <span className="text-[11px] text-zinc-400">{a.name}</span>
                    <span className="ml-auto text-[10px] text-zinc-600">{a.payload_count}p</span>
                  </div>
                ))}
                <div className="pt-1 border-t border-zinc-800 space-y-1">
                  {catalog.intelligence_checks.map((c) => (
                    <div key={c.name} className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full shrink-0 bg-purple-500" />
                      <span className="text-[11px] text-zinc-500">{c.name}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* ── Results panel ─────────────────────────────────────────────── */}
        <div className="lg:col-span-2 space-y-4">
          {/* Summary cards */}
          {complete && (
            <div className="grid grid-cols-3 gap-3">
              <Card>
                <CardContent className="pt-4 pb-3">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Findings</p>
                  <p className={cn(
                    "text-2xl font-bold",
                    complete.total_findings > 0 ? "text-red-400" : "text-emerald-400"
                  )}>
                    {complete.total_findings}
                  </p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4 pb-3">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Endpoints</p>
                  <p className="text-2xl font-bold text-zinc-100">{complete.endpoints_found}</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4 pb-3">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Tools Found</p>
                  <p className="text-2xl font-bold text-zinc-100">{complete.tools_enumerated}</p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Findings list */}
          {sortedFindings.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-orange-400" />
                  Security Findings ({sortedFindings.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {sortedFindings.map((f, i) => (
                  <FindingCard key={i} finding={f} index={i} />
                ))}
              </CardContent>
            </Card>
          )}

          {/* Live probe log */}
          {probeLog.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <button
                  className="flex w-full items-center justify-between"
                  onClick={() => setShowLog((v) => !v)}
                >
                  <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-zinc-400" />
                    Probe Log ({probeLog.length} entries)
                  </CardTitle>
                  {showLog ? <ChevronUp className="h-4 w-4 text-zinc-500" /> : <ChevronDown className="h-4 w-4 text-zinc-500" />}
                </button>
              </CardHeader>
              {showLog && (
                <CardContent>
                  <div className="bg-zinc-950 rounded-md p-3 max-h-64 overflow-y-auto font-mono text-xs">
                    {probeLog.map((line, i) => {
                      const color =
                        line.startsWith("[CRITICAL]") || line.startsWith("[critical]") ? "text-red-400" :
                        line.startsWith("[HIGH]") || line.startsWith("[high]") ? "text-orange-400" :
                        line.startsWith("[FOUND]") ? "text-blue-400" :
                        line.startsWith("[DONE]") ? "text-emerald-400" :
                        line.startsWith("[ATTACK]") ? "text-yellow-400" :
                        line.startsWith("[PHASE]") ? "text-purple-400" :
                        "text-zinc-500";
                      return (
                        <div key={i} className={cn("leading-5", color)}>{line}</div>
                      );
                    })}
                    <div ref={logEndRef} />
                  </div>
                </CardContent>
              )}
            </Card>
          )}

          {/* Empty state */}
          {scanStatus === "idle" && findings.length === 0 && (
            <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-16 text-center">
              <Cpu className="h-10 w-10 text-zinc-700 mb-3" />
              <p className="text-sm font-medium text-zinc-500">No scan running</p>
              <p className="text-xs text-zinc-600 mt-1 max-w-sm">
                Enter a target URL to scan for unauthenticated MCP servers, exposed tools, path traversal, RCE, SSRF, secrets, and prompt injection vulnerabilities.
              </p>
              {catalog && (
                <div className="mt-4 flex flex-wrap gap-2 justify-center">
                  {catalog.attack_modules.map((a) => (
                    <Badge key={a.id} variant="outline" className="text-[10px]">{a.name}</Badge>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Clean result when no findings */}
          {scanStatus === "completed" && findings.length === 0 && (
            <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-emerald-800/40 bg-emerald-950/10 py-12 text-center">
              <CheckCircle2 className="h-10 w-10 text-emerald-500 mb-3" />
              <p className="text-sm font-semibold text-emerald-400">No vulnerabilities found</p>
              <p className="text-xs text-zinc-500 mt-1">
                {complete?.endpoints_found === 0
                  ? "No MCP server endpoints detected at the target."
                  : "MCP server found but no exploitable vulnerabilities detected."}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
