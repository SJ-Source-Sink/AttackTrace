"use client";

import React, { useState, useRef, useCallback, useEffect, DragEvent } from "react";
import {
  Shield, ShieldCheck, ShieldX, ShieldAlert, Network, Search, Upload,
  FileText, Loader2, CheckCircle2, XCircle, AlertTriangle, Terminal, Zap,
  History, Trash2, Clock, ChevronDown, ChevronUp, Gauge, ArrowLeftRight,
  BarChart3, FileJson, AlertCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";
const HISTORY_KEY = "attacktrace:firewall:history";
const MAX_HISTORY = 30;

// ─── Types ───────────────────────────────────────────────────────────────────

interface WAFDetectResult {
  detected: boolean;
  vendor: string | null;
  confidence: number;
  blocked_malicious: boolean;
  indicators: string[];
  response_codes: { normal: number | null; malicious: number | null } | null;
  vendor_scores?: Record<string, number>;
  evidence_matrix?: Record<string, string[]>;
  phase_count?: number;
  probes_sent?: number;
  server_version?: string | null;
}

interface BypassProbeResult {
  technique: string;
  payload: string;
  status_code: number | null;
  result: "BYPASS" | "BLOCKED" | "UNCERTAIN" | "ERROR";
  category?: string;
}

interface BypassSummary {
  bypassed: number;
  blocked: number;
  uncertain: number;
  total: number;
  bypass_rate_by_category?: Record<string, number>;
  scan_id?: string;
}

interface BypassReport {
  overall_risk: "Critical" | "High" | "Medium" | "Low";
  bypass_rate: number;
  bypass_rate_by_category: Record<string, number>;
  most_effective_technique: string | null;
  remediation: Array<{ priority: "critical" | "high" | "medium" | "low"; action: string; rationale: string }>;
}

interface PortMapRow {
  host: string;
  port: number | string;
  protocol: string;
  state: string;
  service: string;
  firewall_interpretation: string;
  cve_advisories?: Array<{ id: string; cvss: number }>;
}

interface RuleAnomaly {
  severity: "critical" | "high" | "medium" | "low";
  type: string;
  description: string;
  rule_text: string;
  line_number: number | null;
  compliance?: string[];
}

interface RuleAnalysisResult {
  format: string;
  total_rules: number;
  anomalies: RuleAnomaly[];
}

interface BurstResult {
  burst_size: number;
  statuses: Record<string, number>;
  avg_ms: number;
  throttled: boolean;
}

interface RateLimitProfile {
  threshold_rps: number | null;
  reset_window_seconds: number | null;
  headers_exposed: string[];
  bypass_vectors: string[];
  bot_detection_type: "none" | "header_challenge" | "js_challenge" | "captcha" | "unknown";
  enforcement_type: "ip" | "session" | "global" | "unknown";
  total_requests_sent: number;
}

interface SmugglingProbeResult {
  probe_type: string;
  result: "TIMING_ANOMALY" | "RESPONSE_ANOMALY" | "NORMAL" | "ERROR";
  response_time_ms: number;
  baseline_ms: number;
  detail: string;
}

interface SmugglingComplete {
  desync_risk: "Critical" | "High" | "Medium" | "Low";
  anomalies_detected: number;
  probes_run: number;
  recommendation: string;
}

// ─── History Types ────────────────────────────────────────────────────────────

type FirewallScanType = "waf_detect" | "waf_bypass" | "port_map" | "rule_analyze" | "rate_limit" | "smuggling";

interface FirewallHistoryEntry {
  id: string;
  type: FirewallScanType;
  target: string;
  started_at: string;
  summary: string;
  waf_result?: WAFDetectResult;
  bypass_probes?: BypassProbeResult[];
  bypass_summary?: BypassSummary;
  port_rows?: PortMapRow[];
  rule_result?: RuleAnalysisResult;
  rate_limit_profile?: RateLimitProfile;
  smuggling_complete?: SmugglingComplete;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const RESULT_BADGE: Record<string, { label: string; className: string }> = {
  BYPASS:    { label: "BYPASS",    className: "bg-red-500/20 text-red-400 border-red-500/40" },
  BLOCKED:   { label: "BLOCKED",   className: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40" },
  UNCERTAIN: { label: "UNCERTAIN", className: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40" },
  ERROR:     { label: "ERROR",     className: "bg-zinc-700/50 text-zinc-400 border-zinc-600/40" },
};

const SMUGGLING_RESULT_BADGE: Record<string, { label: string; className: string }> = {
  TIMING_ANOMALY:   { label: "TIMING ANOMALY",   className: "bg-red-500/20 text-red-400 border-red-500/40" },
  RESPONSE_ANOMALY: { label: "RESPONSE ANOMALY", className: "bg-orange-500/20 text-orange-400 border-orange-500/40" },
  NORMAL:           { label: "NORMAL",           className: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40" },
  ERROR:            { label: "ERROR",            className: "bg-zinc-700/50 text-zinc-400 border-zinc-600/40" },
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/40",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/40",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
  low:      "bg-blue-500/20 text-blue-400 border-blue-500/40",
};

const RISK_BADGE: Record<string, string> = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/40",
  High:     "bg-orange-500/20 text-orange-400 border-orange-500/40",
  Medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
  Low:      "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
};

const STATE_COLOR: Record<string, string> = {
  open:       "text-emerald-400",
  filtered:   "text-red-400",
  unfiltered: "text-yellow-400",
  closed:     "text-zinc-500",
};

const FIREWALL_MODES = [
  { value: "acl_probe",       label: "ACK Probe",                  desc: "Detects stateful vs stateless filtering",    rootRequired: true },
  { value: "fin_null_xmas",   label: "FIN / NULL / XMAS",          desc: "Bypasses stateless packet filters",          rootRequired: true },
  { value: "source_port",     label: "Source Port Trust",          desc: "Tests DNS port trust (port 53)",             rootRequired: false },
  { value: "fragmented",      label: "Fragmented Packets",         desc: "Fragment reassembly evasion test",           rootRequired: true },
  { value: "full_suite",      label: "Full Suite",                 desc: "Runs all modes combined",                    rootRequired: true },
  { value: "service_version", label: "Service Version Detection",  desc: "Identifies service banners and versions",    rootRequired: false },
  { value: "decoy_scan",      label: "Decoy Scan",                 desc: "Uses decoy IPs to obscure scan origin",      rootRequired: true },
  { value: "udp_scan",        label: "UDP Firewall Probe",         desc: "Probes UDP ports for firewall behavior",     rootRequired: true },
];

const BYPASS_CATEGORIES = [
  { name: "SQLi",              color: "bg-red-500/20 text-red-400 border-red-500/40" },
  { name: "XSS",               color: "bg-orange-500/20 text-orange-400 border-orange-500/40" },
  { name: "Encoding",          color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40" },
  { name: "Verb Mutation",     color: "bg-blue-500/20 text-blue-400 border-blue-500/40" },
  { name: "Content Type",      color: "bg-purple-500/20 text-purple-400 border-purple-500/40" },
  { name: "Header Injection",  color: "bg-indigo-500/20 text-indigo-400 border-indigo-500/40" },
  { name: "Cloud",             color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40" },
];

const CLOUD_PROFILES = [
  { value: "auto",              label: "Auto-Detect" },
  { value: "cloudflare",        label: "Cloudflare" },
  { value: "aws_waf",           label: "AWS WAF" },
  { value: "azure_front_door",  label: "Azure Front Door" },
  { value: "akamai",            label: "Akamai" },
  { value: "gcp_cloud_armor",   label: "GCP Cloud Armor" },
];

const CVE_DATA: Record<string, Array<{ id: string; description: string; cvss: number }>> = {
  "Cloudflare":         [],
  "AWS WAF":            [],
  "Fortinet FortiWeb":  [
    { id: "CVE-2021-22123", description: "RCE via OS command injection", cvss: 9.8 },
    { id: "CVE-2022-22300", description: "Authentication bypass via crafted HTTP request", cvss: 7.6 },
  ],
  "F5 BIG-IP": [
    { id: "CVE-2022-1388",  description: "Authentication bypass leading to remote code execution", cvss: 9.8 },
    { id: "CVE-2023-46747", description: "SSRF escalating to unauthenticated RCE", cvss: 9.8 },
  ],
  "Citrix ADC/NetScaler": [
    { id: "CVE-2023-3519",  description: "Unauthenticated remote code execution in NSIP/SNIP", cvss: 9.8 },
    { id: "CVE-2023-4966",  description: "Sensitive session token disclosure (Citrix Bleed)", cvss: 9.4 },
  ],
  "Palo Alto": [
    { id: "CVE-2024-0012",  description: "Authentication bypass in PAN-OS management interface", cvss: 9.3 },
    { id: "CVE-2024-3393",  description: "Denial of service via crafted DNS packet", cvss: 8.7 },
  ],
};

const TYPE_META: Record<FirewallScanType, { label: string; color: string; icon: React.ReactNode }> = {
  waf_detect:   { label: "WAF Detect",    color: "text-blue-400 border-blue-500/30 bg-blue-500/10",       icon: <ShieldX className="h-3 w-3" /> },
  waf_bypass:   { label: "WAF Bypass",    color: "text-yellow-400 border-yellow-500/30 bg-yellow-500/10", icon: <Zap className="h-3 w-3" /> },
  port_map:     { label: "Port Map",      color: "text-purple-400 border-purple-500/30 bg-purple-500/10", icon: <Network className="h-3 w-3" /> },
  rule_analyze: { label: "Rule Analyzer", color: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10", icon: <FileText className="h-3 w-3" /> },
  rate_limit:   { label: "Rate Limit",    color: "text-orange-400 border-orange-500/30 bg-orange-500/10", icon: <Gauge className="h-3 w-3" /> },
  smuggling:    { label: "Smuggling",     color: "text-pink-400 border-pink-500/30 bg-pink-500/10",       icon: <ArrowLeftRight className="h-3 w-3" /> },
};

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

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
      onEvent(eventType, JSON.parse(dataStr));
    }
  }
}

// ─── Tab 1: WAF Detection ─────────────────────────────────────────────────────

function WAFDetectionTab({ onSave }: { onSave: (entry: FirewallHistoryEntry) => void }) {
  const [target, setTarget] = useState("");
  const [depth, setDepth] = useState<"quick" | "full">("full");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<WAFDetectResult | null>(null);
  const [phaseProgress, setPhaseProgress] = useState(0);

  const detect = useCallback(async () => {
    if (!target.trim()) { toast.error("Please enter a target URL"); return; }
    setLoading(true);
    setResult(null);
    setPhaseProgress(0);
    const startedAt = new Date().toISOString();
    try {
      const res = await fetchWithAuth(`${API_BASE}/firewall/waf/detect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), depth }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Detection failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }
      const data: WAFDetectResult = await res.json();
      setResult(data);
      onSave({
        id: crypto.randomUUID(),
        type: "waf_detect",
        target: target.trim(),
        started_at: startedAt,
        summary: data.detected
          ? `${data.vendor ?? "WAF"} detected — ${data.confidence}% confidence`
          : "No WAF detected",
        waf_result: data,
      });
    } catch (err: unknown) {
      toast.error(`WAF detection failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
      setPhaseProgress(100);
    }
  }, [target, depth, onSave]);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <Search className="h-4 w-4 text-blue-400" /> Target URL
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
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}
              {loading ? "Detecting…" : "Detect WAF"}
            </Button>
          </div>

          {/* Depth toggle */}
          <div className="flex items-center gap-3">
            <span className="text-xs text-zinc-500 font-semibold uppercase tracking-wider">Depth</span>
            <div className="flex rounded-md border border-zinc-700 overflow-hidden">
              {(["quick", "full"] as const).map((d) => (
                <button
                  key={d}
                  onClick={() => setDepth(d)}
                  disabled={loading}
                  className={cn(
                    "px-4 py-1.5 text-xs font-semibold capitalize transition-colors",
                    depth === d
                      ? "bg-blue-600 text-white"
                      : "bg-zinc-900 text-zinc-400 hover:bg-zinc-800"
                  )}
                >
                  {d === "quick" ? "Quick" : "Full"}
                </button>
              ))}
            </div>
            <span className="text-xs text-zinc-600">
              {depth === "quick" ? "Single probe pair (fast)" : "Multi-phase, 10+ probes (thorough)"}
            </span>
          </div>

          {loading && depth === "full" && (
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-zinc-500 font-semibold uppercase tracking-wider flex items-center gap-1.5">
                  <Loader2 className="h-3 w-3 animate-spin text-blue-400" /> Scanning…
                </span>
                <span className="text-zinc-400 font-mono">{phaseProgress}%</span>
              </div>
              <div className="h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-blue-500 transition-all duration-500 animate-pulse"
                  style={{ width: loading ? "60%" : `${phaseProgress}%` }}
                />
              </div>
            </div>
          )}

          <p className="text-xs text-zinc-600">Sends normal and malicious request probes to detect WAF vendor and behavior.</p>
        </CardContent>
      </Card>

      {result && <WAFDetectResultCard result={result} />}

      {!result && !loading && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
          <Shield className="h-12 w-12" />
          <p className="text-sm">Enter a target URL and click Detect WAF</p>
        </div>
      )}
    </div>
  );
}

function WAFDetectResultCard({ result }: { result: WAFDetectResult }) {
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const cves = result.vendor ? (CVE_DATA[result.vendor] ?? null) : null;

  return (
    <Card>
      <CardContent className="pt-6 space-y-5">
        <div className="flex items-center gap-4 flex-wrap">
          {result.detected ? (
            <>
              <ShieldX className="h-8 w-8 text-red-400 shrink-0" />
              <div>
                <Badge className="bg-red-500/20 text-red-400 border-red-500/40 text-sm px-3 py-1">WAF Detected</Badge>
                {result.vendor && <p className="text-lg font-bold text-zinc-100 mt-1">{result.vendor}</p>}
              </div>
            </>
          ) : (
            <>
              <ShieldCheck className="h-8 w-8 text-emerald-400 shrink-0" />
              <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/40 text-sm px-3 py-1">No WAF Detected</Badge>
            </>
          )}
          {result.blocked_malicious && (
            <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/40 ml-auto">Malicious Request Blocked</Badge>
          )}
          {result.server_version && (
            <Badge className="bg-zinc-700/50 text-zinc-300 border-zinc-600 font-mono text-xs">
              {result.server_version}
            </Badge>
          )}
        </div>

        {result.detected && (
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs">
              <span className="text-zinc-500 font-semibold uppercase tracking-wider">Confidence</span>
              <span className="text-zinc-300 font-medium">{result.confidence}%</span>
            </div>
            <div className="h-2 rounded-full bg-zinc-800 overflow-hidden">
              <div
                className={cn("h-full rounded-full transition-all duration-700",
                  result.confidence >= 80 ? "bg-red-500" : result.confidence >= 50 ? "bg-orange-500" : "bg-yellow-500")}
                style={{ width: `${result.confidence}%` }}
              />
            </div>
          </div>
        )}

        {/* Phase / probe stats */}
        {(result.phase_count != null || result.probes_sent != null) && (
          <div className="grid grid-cols-2 gap-3">
            {result.phase_count != null && (
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Phases Run</p>
                <p className="text-xl font-bold text-zinc-100 font-mono">{result.phase_count}</p>
              </div>
            )}
            {result.probes_sent != null && (
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Probes Sent</p>
                <p className="text-xl font-bold text-zinc-100 font-mono">{result.probes_sent}</p>
              </div>
            )}
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
            <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Normal Code</p>
            <p className="text-xl font-bold text-zinc-100 font-mono">{result.response_codes?.normal ?? "—"}</p>
          </div>
          <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
            <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Malicious Code</p>
            <p className={cn("text-xl font-bold font-mono", (result.response_codes?.malicious ?? 0) >= 400 ? "text-red-400" : "text-zinc-100")}>
              {result.response_codes?.malicious ?? "—"}
            </p>
          </div>
        </div>

        {result.indicators && result.indicators.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Indicators Found</p>
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

        {/* Evidence matrix accordion */}
        {result.evidence_matrix && Object.keys(result.evidence_matrix).length > 0 && (
          <div className="rounded-md border border-zinc-700 overflow-hidden">
            <button
              onClick={() => setEvidenceOpen((v) => !v)}
              className="w-full flex items-center justify-between px-4 py-2.5 bg-zinc-800/60 hover:bg-zinc-800 transition-colors"
            >
              <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider flex items-center gap-2">
                <BarChart3 className="h-3.5 w-3.5 text-blue-400" />
                Evidence Matrix ({Object.keys(result.evidence_matrix).length} phases)
              </span>
              {evidenceOpen ? <ChevronUp className="h-3.5 w-3.5 text-zinc-400" /> : <ChevronDown className="h-3.5 w-3.5 text-zinc-400" />}
            </button>
            {evidenceOpen && (
              <div className="divide-y divide-zinc-800">
                {Object.entries(result.evidence_matrix).map(([phase, items]) => (
                  <div key={phase} className="px-4 py-3 space-y-1.5">
                    <p className="text-xs font-semibold text-blue-300 capitalize">{phase.replace(/_/g, " ")}</p>
                    <ul className="space-y-1">
                      {(items as string[]).map((item, j) => (
                        <li key={j} className="text-xs text-zinc-400 flex items-start gap-2">
                          <span className="mt-1 h-1 w-1 rounded-full bg-zinc-600 shrink-0" />
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* CVE Advisory */}
        {cves !== null && (
          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1.5">
              <AlertCircle className="h-3.5 w-3.5 text-orange-400" /> CVE Advisory
            </p>
            {cves.length === 0 ? (
              <div className="flex items-center gap-2 rounded-md bg-emerald-500/10 border border-emerald-500/30 px-3 py-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                <span className="text-xs text-emerald-300">No known exploitable CVEs for this vendor</span>
              </div>
            ) : (
              <div className="space-y-2">
                {cves.map((cve) => (
                  <div key={cve.id} className="flex items-start gap-3 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2.5">
                    <Badge
                      className={cn(
                        "text-[10px] px-2 py-0.5 border shrink-0 font-mono",
                        cve.cvss >= 9 ? "bg-red-500/20 text-red-400 border-red-500/40" : "bg-orange-500/20 text-orange-400 border-orange-500/40"
                      )}
                    >
                      CVSS {cve.cvss}
                    </Badge>
                    <div>
                      <p className="text-xs font-semibold text-zinc-200 font-mono">{cve.id}</p>
                      <p className="text-xs text-zinc-400 mt-0.5">{cve.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Tab 2: WAF Bypass Probe ──────────────────────────────────────────────────

function BypassReportModal({ report, onClose }: { report: BypassReport; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-zinc-900 border border-zinc-700 rounded-xl max-w-lg w-full max-h-[85vh] overflow-y-auto shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800">
          <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
            <FileJson className="h-4 w-4 text-yellow-400" /> Bypass Report
          </h3>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300 transition-colors">
            <XCircle className="h-4 w-4" />
          </button>
        </div>
        <div className="p-5 space-y-5">
          <div className="flex items-center gap-3">
            <Badge className={cn("text-sm px-3 py-1 border", RISK_BADGE[report.overall_risk] ?? RISK_BADGE.Medium)}>
              {report.overall_risk} Risk
            </Badge>
            <span className="text-zinc-400 text-sm">
              <span className={cn("font-bold text-lg font-mono", report.bypass_rate > 50 ? "text-red-400" : report.bypass_rate > 25 ? "text-orange-400" : "text-emerald-400")}>
                {report.bypass_rate}%
              </span> bypass rate
            </span>
          </div>

          {report.most_effective_technique && (
            <div className="rounded-md bg-zinc-800 border border-zinc-700 px-3 py-2.5">
              <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Most Effective Technique</p>
              <p className="text-sm text-zinc-200 font-medium">{report.most_effective_technique}</p>
            </div>
          )}

          {Object.keys(report.bypass_rate_by_category).length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Bypass by Category</p>
              <div className="space-y-2">
                {Object.entries(report.bypass_rate_by_category).map(([cat, rate]) => (
                  <div key={cat} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-zinc-400">{cat}</span>
                      <span className={cn("font-mono font-semibold", rate > 50 ? "text-red-400" : rate > 25 ? "text-orange-400" : "text-emerald-400")}>{rate}%</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                      <div
                        className={cn("h-full rounded-full transition-all", rate > 50 ? "bg-red-500" : rate > 25 ? "bg-orange-500" : "bg-emerald-500")}
                        style={{ width: `${rate}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {report.remediation && report.remediation.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Remediation</p>
              <div className="space-y-2">
                {report.remediation.map((r, i) => (
                  <div key={i} className="rounded-md border border-zinc-700 bg-zinc-800/60 px-3 py-2.5 space-y-1">
                    <div className="flex items-center gap-2">
                      <Badge className={cn("text-[10px] px-1.5 py-0.5 border capitalize", SEVERITY_BADGE[r.priority] ?? SEVERITY_BADGE.low)}>
                        {r.priority}
                      </Badge>
                      <p className="text-xs font-semibold text-zinc-200">{r.action}</p>
                    </div>
                    <p className="text-xs text-zinc-500">{r.rationale}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function WAFBypassTab({ onSave }: { onSave: (entry: FirewallHistoryEntry) => void }) {
  const [target, setTarget] = useState("");
  const [path, setPath] = useState("/search");
  const [param, setParam] = useState("q");
  const [cloudProfile, setCloudProfile] = useState("auto");
  const [selectedCategories, setSelectedCategories] = useState<string[]>(BYPASS_CATEGORIES.map((c) => c.name));
  const [running, setRunning] = useState(false);
  const [probes, setProbes] = useState<BypassProbeResult[]>([]);
  const [summary, setSummary] = useState<BypassSummary | null>(null);
  const [progress, setProgress] = useState(0);
  const [totalProbes, setTotalProbes] = useState(0);
  const [completedScanId, setCompletedScanId] = useState<string | null>(null);
  const [bypassReport, setBypassReport] = useState<BypassReport | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const toggleCategory = (name: string) => {
    setSelectedCategories((prev) =>
      prev.includes(name) ? prev.filter((c) => c !== name) : [...prev, name]
    );
  };

  const categoriesPayload = selectedCategories.length === BYPASS_CATEGORIES.length || selectedCategories.length === 0
    ? null
    : selectedCategories;

  const start = useCallback(async () => {
    if (!target.trim()) { toast.error("Please enter a target URL"); return; }
    setRunning(true);
    setProbes([]);
    setSummary(null);
    setProgress(0);
    setTotalProbes(0);
    setCompletedScanId(null);
    setBypassReport(null);
    abortRef.current = new AbortController();
    const startedAt = new Date().toISOString();

    try {
      await sseStream(
        `${API_BASE}/firewall/waf/bypass`,
        {
          target: target.trim(),
          path: path.trim() || "/search",
          param: param.trim() || "q",
          cloud_profile: cloudProfile,
          categories: categoriesPayload,
        },
        (eventType, data) => {
          if (eventType === "start") {
            const d = data as { total_probes?: number };
            if (d.total_probes) setTotalProbes(d.total_probes);
          } else if (eventType === "probe") {
            const probe = data as BypassProbeResult;
            setProbes((prev) => {
              const next = [...prev, probe];
              setProgress((cur) => {
                const tot = totalProbes || 13;
                return Math.min((next.length / tot) * 100, 99);
              });
              return next;
            });
          } else if (eventType === "complete") {
            const d = data as BypassSummary & { probes?: BypassProbeResult[]; scan_id?: string };
            const finalProbes = d.probes ?? [];
            setSummary({
              bypassed: d.bypassed,
              blocked: d.blocked,
              uncertain: d.uncertain,
              total: d.total,
              bypass_rate_by_category: d.bypass_rate_by_category,
              scan_id: d.scan_id,
            });
            if (d.scan_id) setCompletedScanId(d.scan_id);
            if (finalProbes.length) setProbes(finalProbes);
            setProgress(100);
            setRunning(false);
            toast.success(`Bypass probe complete — ${d.bypassed} technique(s) bypassed`);
            onSave({
              id: crypto.randomUUID(),
              type: "waf_bypass",
              target: target.trim(),
              started_at: startedAt,
              summary: `${d.bypassed} bypassed / ${d.total} probes`,
              bypass_probes: finalProbes,
              bypass_summary: { bypassed: d.bypassed, blocked: d.blocked, uncertain: d.uncertain, total: d.total },
            });
          } else if (eventType === "error") {
            const e = data as { message: string };
            setRunning(false);
            toast.error(`Probe error: ${e.message}`);
          }
        },
        abortRef.current.signal
      );
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") toast.error(`Bypass probe failed: ${err.message}`);
      setRunning(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, path, param, cloudProfile, categoriesPayload, onSave]);

  const stop = () => { abortRef.current?.abort(); setRunning(false); toast.info("Probe stopped"); };

  const fetchReport = async () => {
    if (!completedScanId) return;
    setLoadingReport(true);
    try {
      const res = await fetchWithAuth(`${API_BASE}/firewall/bypass/report/${completedScanId}`);
      if (!res.ok) throw new Error("Failed to fetch report");
      const data: BypassReport = await res.json();
      setBypassReport(data);
    } catch (err: unknown) {
      toast.error(`Report fetch failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoadingReport(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <Zap className="h-4 w-4 text-yellow-400" /> Bypass Probe Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Cloud profile */}
          <div className="space-y-1.5">
            <Label className="text-xs text-zinc-400">Cloud Profile</Label>
            <Select value={cloudProfile} onValueChange={setCloudProfile} disabled={running}>
              <SelectTrigger className="bg-zinc-800 border-zinc-700 text-zinc-100 text-sm w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CLOUD_PROFILES.map((p) => (
                  <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-1 space-y-1.5">
              <Label className="text-xs text-zinc-400">Target URL</Label>
              <Input placeholder="https://example.com" value={target} onChange={(e) => setTarget(e.target.value)}
                disabled={running} className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Path</Label>
              <Input placeholder="/search" value={path} onChange={(e) => setPath(e.target.value)}
                disabled={running} className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Param Name</Label>
              <Input placeholder="q" value={param} onChange={(e) => setParam(e.target.value)}
                disabled={running} className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm" />
            </div>
          </div>

          {/* Category filter chips */}
          <div className="space-y-2">
            <Label className="text-xs text-zinc-400">Category Filter</Label>
            <div className="flex flex-wrap gap-2">
              {BYPASS_CATEGORIES.map((cat) => {
                const active = selectedCategories.includes(cat.name);
                return (
                  <button
                    key={cat.name}
                    onClick={() => toggleCategory(cat.name)}
                    disabled={running}
                    className={cn(
                      "px-2.5 py-1 rounded-full text-[11px] font-semibold border transition-all",
                      active ? cat.color : "bg-zinc-900 text-zinc-500 border-zinc-700 hover:border-zinc-600"
                    )}
                  >
                    {cat.name}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="flex gap-3">
            {running
              ? <Button onClick={stop} variant="destructive" className="gap-2"><XCircle className="h-4 w-4" /> Stop Probe</Button>
              : <Button onClick={start} className="gap-2"><Zap className="h-4 w-4" /> Start Bypass Probe</Button>}
            {!running && completedScanId && (
              <Button onClick={fetchReport} variant="outline" disabled={loadingReport} className="gap-2 border-zinc-700 text-zinc-300 hover:text-white">
                {loadingReport ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileJson className="h-4 w-4" />}
                Generate Report
              </Button>
            )}
          </div>
          {(running || probes.length > 0) && (
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-zinc-500 font-semibold uppercase tracking-wider">Progress</span>
                <span className="text-zinc-400">{probes.length} / {totalProbes || "?"} probes</span>
              </div>
              <div className="h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                <div className="h-full rounded-full bg-blue-500 transition-all duration-300" style={{ width: `${progress}%` }} />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {summary && <BypassSummaryGrid summary={summary} />}

      {/* Bypass rate by category bar chart */}
      {summary?.bypass_rate_by_category && Object.keys(summary.bypass_rate_by_category).length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-zinc-400" /> Bypass Rate by Category
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(summary.bypass_rate_by_category).map(([cat, rate]) => (
              <div key={cat} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-zinc-400">{cat}</span>
                  <span className={cn("font-mono font-semibold", rate > 50 ? "text-red-400" : rate > 25 ? "text-orange-400" : "text-emerald-400")}>{rate}%</span>
                </div>
                <div className="h-2 rounded-full bg-zinc-800 overflow-hidden">
                  <div
                    className={cn("h-full rounded-full transition-all duration-500", rate > 50 ? "bg-red-500" : rate > 25 ? "bg-orange-500" : "bg-emerald-500")}
                    style={{ width: `${rate}%` }}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {probes.length > 0 && <BypassProbeTable probes={probes} />}

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

      {bypassReport && <BypassReportModal report={bypassReport} onClose={() => setBypassReport(null)} />}
    </div>
  );
}

function BypassSummaryGrid({ summary }: { summary: BypassSummary }) {
  return (
    <div className="grid grid-cols-4 gap-3">
      {[
        { label: "Total",     value: summary.total,     className: "text-zinc-200" },
        { label: "Bypassed",  value: summary.bypassed,  className: "text-red-400" },
        { label: "Blocked",   value: summary.blocked,   className: "text-emerald-400" },
        { label: "Uncertain", value: summary.uncertain, className: "text-yellow-400" },
      ].map((s) => (
        <div key={s.label} className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 text-center">
          <p className={cn("text-2xl font-bold font-mono", s.className)}>{s.value}</p>
          <p className="text-xs text-zinc-500 mt-0.5">{s.label}</p>
        </div>
      ))}
    </div>
  );
}

function BypassProbeTable({ probes }: { probes: BypassProbeResult[] }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-zinc-400" /> Probe Results
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="rounded-b-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-zinc-900 border-b border-zinc-800">
                {["Technique", "Category", "Payload", "Status", "Result"].map((h) => (
                  <th key={h} className="px-4 py-2.5 text-left font-semibold text-zinc-400 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {probes.map((probe, i) => {
                const badge = RESULT_BADGE[probe.result] ?? RESULT_BADGE.ERROR;
                const catMeta = BYPASS_CATEGORIES.find((c) => c.name === probe.category);
                return (
                  <tr key={i} className="hover:bg-zinc-800/30">
                    <td className="px-4 py-2.5 text-zinc-200 font-medium">{probe.technique}</td>
                    <td className="px-4 py-2.5">
                      {probe.category ? (
                        <span className={cn("px-2 py-0.5 rounded-full text-[10px] font-semibold border", catMeta?.color ?? "text-zinc-400 border-zinc-700 bg-zinc-800")}>
                          {probe.category}
                        </span>
                      ) : <span className="text-zinc-600">—</span>}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-zinc-400 max-w-[200px] truncate" title={probe.payload}>
                      {probe.payload.length > 40 ? probe.payload.slice(0, 40) + "…" : probe.payload}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-zinc-300">{probe.status_code ?? "—"}</td>
                    <td className="px-4 py-2.5">
                      <Badge className={cn("text-[10px] px-2 py-0.5 border", badge.className)}>{badge.label}</Badge>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Tab 3: Port Firewall Mapper ──────────────────────────────────────────────

function PortFirewallMapperTab({ onSave }: { onSave: (entry: FirewallHistoryEntry) => void }) {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("full_suite");
  const [running, setRunning] = useState(false);
  const [logLines, setLogLines] = useState<string[]>([]);
  const [portRows, setPortRows] = useState<PortMapRow[]>([]);
  const [completed, setCompleted] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => { logEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logLines]);

  const start = useCallback(async () => {
    if (!target.trim()) { toast.error("Please enter a target host or IP"); return; }
    setRunning(true);
    setLogLines([]);
    setPortRows([]);
    setCompleted(false);
    abortRef.current = new AbortController();
    const startedAt = new Date().toISOString();

    try {
      await sseStream(
        `${API_BASE}/firewall/port-map`,
        { target: target.trim(), mode },
        (eventType, data) => {
          if (eventType === "output") {
            const d = data as { line: string };
            setLogLines((prev) => [...prev, d.line]);
          } else if (eventType === "complete") {
            const d = data as { all_hosts?: Array<{ host: string; ports: Array<{ port: number; protocol: string; state: string; service: string; firewall_interpretation: string; cve_advisories?: Array<{ id: string; cvss: number }> }> }> };
            const rows: PortMapRow[] = [];
            for (const host of d.all_hosts ?? []) {
              for (const p of host.ports ?? []) {
                rows.push({
                  host: host.host,
                  port: p.port,
                  protocol: p.protocol,
                  state: p.state,
                  service: p.service,
                  firewall_interpretation: p.firewall_interpretation ?? "",
                  cve_advisories: p.cve_advisories,
                });
              }
            }
            setPortRows(rows);
            setRunning(false);
            setCompleted(true);
            toast.success(`Firewall map complete — ${rows.length} port${rows.length !== 1 ? "s" : ""}`);
            onSave({
              id: crypto.randomUUID(),
              type: "port_map",
              target: target.trim(),
              started_at: startedAt,
              summary: `${rows.length} port${rows.length !== 1 ? "s" : ""} — mode: ${mode}`,
              port_rows: rows,
            });
          } else if (eventType === "error") {
            const e = data as { message: string };
            setRunning(false);
            toast.error(`Port map error: ${e.message}`);
          }
        },
        abortRef.current.signal
      );
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") toast.error(`Port mapper failed: ${err.message}`);
      setRunning(false);
    }
  }, [target, mode, onSave]);

  const stop = () => { abortRef.current?.abort(); setRunning(false); toast.info("Scan stopped"); };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <Network className="h-4 w-4 text-blue-400" /> Firewall Scan Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Target Host / IP</Label>
              <Input placeholder="192.168.1.1 or example.com" value={target}
                onChange={(e) => setTarget(e.target.value)} disabled={running}
                onKeyDown={(e) => e.key === "Enter" && !running && start()}
                className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Scan Mode</Label>
              <Select value={mode} onValueChange={setMode} disabled={running}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700 text-zinc-100 text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {FIREWALL_MODES.map((m) => (
                    <SelectItem key={m.value} value={m.value}>
                      <div><p className="font-medium">{m.label}</p><p className="text-[10px] text-zinc-500">{m.desc}</p></div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {FIREWALL_MODES.map((m) => (
              <button key={m.value} onClick={() => !running && setMode(m.value)} disabled={running}
                className={cn("rounded-md border px-3 py-2 text-left transition-colors",
                  mode === m.value ? "border-blue-500/50 bg-blue-500/10" : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700")}>
                <div className="flex items-center gap-1.5">
                  <p className={cn("text-xs font-semibold flex-1", mode === m.value ? "text-blue-300" : "text-zinc-300")}>{m.label}</p>
                  {m.rootRequired && <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/30">root</span>}
                </div>
                <p className="text-[10px] text-zinc-500 mt-0.5">{m.desc}</p>
              </button>
            ))}
          </div>

          {FIREWALL_MODES.find((m) => m.value === mode)?.rootRequired && (
            <div className="flex items-start gap-2 rounded-md border border-orange-500/30 bg-orange-500/10 px-3 py-2">
              <AlertTriangle className="h-4 w-4 text-orange-400 shrink-0 mt-0.5" />
              <p className="text-xs text-orange-300">
                This mode sends raw packets and requires <strong>root / sudo</strong> access to nmap.
              </p>
            </div>
          )}

          <div className="flex gap-3">
            {running
              ? <Button onClick={stop} variant="destructive" className="gap-2"><XCircle className="h-4 w-4" /> Stop Scan</Button>
              : <Button onClick={start} className="gap-2"><Network className="h-4 w-4" /> Run Firewall Scan</Button>}
          </div>
        </CardContent>
      </Card>

      {logLines.length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-950">
          <div className="flex items-center gap-2 border-b border-zinc-800 px-3 py-2">
            <Terminal className="h-3.5 w-3.5 text-zinc-500" />
            <span className="text-xs text-zinc-500 font-mono">nmap output</span>
            {running && <Loader2 className="h-3 w-3 animate-spin text-blue-400 ml-auto" />}
          </div>
          <div className="h-64 overflow-y-auto p-3 space-y-0.5 font-mono text-xs">
            {logLines.map((line, i) => (
              <div key={i} className={cn("leading-5 whitespace-pre-wrap break-all",
                line.toLowerCase().includes("open") ? "text-emerald-400" :
                line.toLowerCase().includes("filtered") ? "text-red-400" :
                line.toLowerCase().includes("error") || line.toLowerCase().includes("failed") ? "text-red-400" :
                line.startsWith("Nmap") || line.startsWith("Starting") ? "text-blue-300 font-semibold" : "text-zinc-400")}>
                {line}
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        </div>
      )}

      {completed && portRows.length > 0 && <PortMapTable rows={portRows} />}

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

function PortMapTable({ rows }: { rows: PortMapRow[] }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-zinc-400" /> Firewall Map Results
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="rounded-b-lg overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-zinc-900 border-b border-zinc-800">
                {["Host", "Port", "Protocol", "State", "Service", "Firewall Interpretation", "CVE"].map((h) => (
                  <th key={h} className="px-4 py-2.5 text-left font-semibold text-zinc-400 uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {rows.map((row, i) => {
                const hasCves = row.cve_advisories && row.cve_advisories.length > 0;
                const cveTitle = hasCves
                  ? row.cve_advisories!.map((c) => `${c.id} (CVSS: ${c.cvss})`).join("\n")
                  : "";
                return (
                  <tr key={i} className="hover:bg-zinc-800/30">
                    <td className="px-4 py-2.5 font-mono text-zinc-200">{row.host}</td>
                    <td className="px-4 py-2.5 font-mono font-semibold text-zinc-100">{row.port}</td>
                    <td className="px-4 py-2.5 text-zinc-500 uppercase">{row.protocol}</td>
                    <td className={cn("px-4 py-2.5 font-semibold capitalize", STATE_COLOR[row.state] ?? "text-zinc-400")}>{row.state}</td>
                    <td className="px-4 py-2.5 text-zinc-300">{row.service || "—"}</td>
                    <td className="px-4 py-2.5 text-zinc-500 italic max-w-xs">{row.firewall_interpretation || "—"}</td>
                    <td className="px-4 py-2.5">
                      {hasCves ? (
                        <span title={cveTitle} className="cursor-help inline-flex">
                          <AlertTriangle className="h-4 w-4 text-red-400" />
                        </span>
                      ) : (
                        <span className="text-zinc-600">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Tab 4: Rule Analyzer ─────────────────────────────────────────────────────

function buildComplianceSummary(anomalies: RuleAnomaly[]): Record<string, number> {
  const summary: Record<string, number> = {};
  for (const a of anomalies) {
    for (const tag of a.compliance ?? []) {
      const parts = tag.split("-");
      const framework = parts.slice(0, 2).join("-");
      summary[framework] = (summary[framework] ?? 0) + 1;
    }
  }
  return summary;
}

function RuleAnalyzerTab({ onSave }: { onSave: (entry: FirewallHistoryEntry) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RuleAnalysisResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault(); setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) setFile(dropped);
  };

  const analyze = useCallback(async () => {
    if (!file) { toast.error("Please select a firewall config file"); return; }
    setLoading(true);
    setResult(null);
    const startedAt = new Date().toISOString();
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetchWithAuth(`${API_BASE}/firewall/rules/analyze`, { method: "POST", body: formData });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Analysis failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }
      const data: RuleAnalysisResult = await res.json();
      data.anomalies = data.anomalies ?? [];
      setResult(data);
      if (data.anomalies.length === 0) toast.success("No anomalies detected — ruleset looks clean");
      else toast.warning(`Found ${data.anomalies.length} anomaly/anomalies in ruleset`);
      onSave({
        id: crypto.randomUUID(),
        type: "rule_analyze",
        target: file.name,
        started_at: startedAt,
        summary: `${data.total_rules} rules, ${data.anomalies.length} anomalies — ${data.format}`,
        rule_result: data,
      });
    } catch (err: unknown) {
      toast.error(`Rule analysis failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [file, onSave]);

  const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sortedAnomalies = result
    ? [...result.anomalies].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99))
    : [];

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <Upload className="h-4 w-4 text-purple-400" /> Upload Firewall Config
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={cn("cursor-pointer rounded-lg border-2 border-dashed transition-colors px-6 py-12 text-center",
              dragging ? "border-blue-500 bg-blue-500/5" :
              file ? "border-emerald-500/50 bg-emerald-500/5" :
              "border-zinc-700 bg-zinc-900/40 hover:border-zinc-600 hover:bg-zinc-800/40")}>
            <input ref={fileInputRef} type="file" className="hidden"
              onChange={(e) => e.target.files?.[0] && setFile(e.target.files[0])}
              accept=".txt,.xml,.conf,.cfg,.acl,.log,.json" />
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
                  {["iptables-save", "Cisco ACL", "pfSense XML", "AWS Security Groups (JSON)", "Azure NSG (JSON)"].map((fmt) => (
                    <span key={fmt} className="rounded-full border border-zinc-700 bg-zinc-800 px-2.5 py-0.5 text-[10px] text-zinc-400">{fmt}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
          <Button onClick={analyze} disabled={!file || loading} className="gap-2">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            {loading ? "Analyzing…" : "Analyze Rules"}
          </Button>
        </CardContent>
      </Card>

      {result && <RuleAnalysisResultView result={result} sortedAnomalies={sortedAnomalies} />}

      {!result && !loading && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
          <FileText className="h-12 w-12" />
          <p className="text-sm">Upload a firewall config to analyze its rules</p>
        </div>
      )}
    </div>
  );
}

function RuleAnalysisResultView({ result, sortedAnomalies }: { result: RuleAnalysisResult; sortedAnomalies: RuleAnomaly[] }) {
  const complianceSummary = buildComplianceSummary(sortedAnomalies);
  const hasCompliance = Object.keys(complianceSummary).length > 0;

  return (
    <div className="space-y-4">
      {/* Compliance summary */}
      {hasCompliance && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-orange-400" /> Compliance Violations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              {Object.entries(complianceSummary).map(([framework, count]) => (
                <div key={framework} className="flex items-center gap-2 rounded-md border border-orange-500/30 bg-orange-500/10 px-3 py-2">
                  <span className="text-xs font-semibold text-orange-300">{framework}</span>
                  <span className="text-xs font-bold text-orange-400 font-mono">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="flex items-center gap-3 flex-wrap">
        <Badge className="bg-purple-500/20 text-purple-300 border-purple-500/40 px-3 py-1">{result.format || "Unknown Format"}</Badge>
        <span className="text-sm text-zinc-400"><span className="font-semibold text-zinc-200">{result.total_rules}</span> rules parsed</span>
        <span className="text-sm text-zinc-400">
          <span className={cn("font-semibold", sortedAnomalies.length > 0 ? "text-red-400" : "text-emerald-400")}>{sortedAnomalies.length}</span>{" "}
          {sortedAnomalies.length === 1 ? "anomaly" : "anomalies"} found
        </span>
      </div>

      {sortedAnomalies.length === 0 && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-6 py-8 flex items-center gap-4">
          <CheckCircle2 className="h-8 w-8 text-emerald-400 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-emerald-300">No anomalies detected</p>
            <p className="text-xs text-emerald-500/70 mt-0.5">All {result.total_rules} rules look clean.</p>
          </div>
        </div>
      )}

      {sortedAnomalies.length > 0 && (
        <div className="space-y-3">
          {sortedAnomalies.map((anomaly, i) => (
            <div key={i} className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Badge className={cn("text-[10px] px-2 py-0.5 border capitalize", SEVERITY_BADGE[anomaly.severity])}>{anomaly.severity}</Badge>
                    <span className="text-sm font-semibold text-zinc-200 capitalize">{anomaly.type.replace(/_/g, " ")}</span>
                  </div>
                  <p className="text-sm text-zinc-400">{anomaly.description}</p>
                  {/* Compliance tags */}
                  {anomaly.compliance && anomaly.compliance.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-1.5">
                      {anomaly.compliance.map((tag) => (
                        <span key={tag} className="text-[10px] px-2 py-0.5 rounded-full border border-zinc-700 bg-zinc-800 text-zinc-400">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                {anomaly.line_number != null && <span className="text-xs text-zinc-600 font-mono shrink-0">line {anomaly.line_number}</span>}
              </div>
              {anomaly.rule_text && (
                <div className="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2">
                  <code className="text-xs font-mono text-zinc-300 whitespace-pre-wrap break-all">{anomaly.rule_text}</code>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Tab 5: Rate Limit Probe ──────────────────────────────────────────────────

function RateLimitTab({ onSave }: { onSave: (entry: FirewallHistoryEntry) => void }) {
  const [target, setTarget] = useState("");
  const [path, setPath] = useState("/");
  const [maxRps, setMaxRps] = useState(50);
  const [running, setRunning] = useState(false);
  const [bursts, setBursts] = useState<BurstResult[]>([]);
  const [profile, setProfile] = useState<RateLimitProfile | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const start = useCallback(async () => {
    if (!target.trim()) { toast.error("Please enter a target URL"); return; }
    setRunning(true);
    setBursts([]);
    setProfile(null);
    abortRef.current = new AbortController();
    const startedAt = new Date().toISOString();

    try {
      await sseStream(
        `${API_BASE}/firewall/ratelimit/probe`,
        { target: target.trim(), path: path.trim() || "/", max_rps: maxRps },
        (eventType, data) => {
          if (eventType === "burst") {
            setBursts((prev) => [...prev, data as BurstResult]);
          } else if (eventType === "complete") {
            const p = data as RateLimitProfile;
            setProfile(p);
            setRunning(false);
            toast.success("Rate limit probe complete");
            onSave({
              id: crypto.randomUUID(),
              type: "rate_limit",
              target: target.trim(),
              started_at: startedAt,
              summary: p.threshold_rps != null ? `Threshold: ${p.threshold_rps} req/s` : "No threshold detected",
              rate_limit_profile: p,
            });
          } else if (eventType === "error") {
            const e = data as { message: string };
            setRunning(false);
            toast.error(`Rate limit error: ${e.message}`);
          }
        },
        abortRef.current.signal
      );
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") toast.error(`Rate limit probe failed: ${err.message}`);
      setRunning(false);
    }
  }, [target, path, maxRps, onSave]);

  const stop = () => { abortRef.current?.abort(); setRunning(false); toast.info("Probe stopped"); };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <Gauge className="h-4 w-4 text-orange-400" /> Rate Limit Probe Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Target URL</Label>
              <Input placeholder="https://example.com" value={target} onChange={(e) => setTarget(e.target.value)}
                disabled={running} className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Path</Label>
              <Input placeholder="/" value={path} onChange={(e) => setPath(e.target.value)}
                disabled={running} className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm" />
            </div>
          </div>
          <div className="space-y-2">
            <Label className="text-xs text-zinc-400">Max RPS: <span className="text-zinc-200 font-mono">{maxRps}</span></Label>
            <input
              type="range" min={1} max={200} value={maxRps}
              onChange={(e) => setMaxRps(Number(e.target.value))}
              disabled={running}
              className="w-full accent-orange-500"
            />
            <div className="flex justify-between text-xs text-zinc-600">
              <span>1</span><span>200</span>
            </div>
          </div>
          <div className="flex gap-3">
            {running
              ? <Button onClick={stop} variant="destructive" className="gap-2"><XCircle className="h-4 w-4" /> Stop Probe</Button>
              : <Button onClick={start} className="gap-2 bg-orange-600 hover:bg-orange-700 text-white"><Gauge className="h-4 w-4" /> Start Rate Limit Probe</Button>}
          </div>
        </CardContent>
      </Card>

      {bursts.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-zinc-400" /> Burst Results
              {running && <Loader2 className="h-3.5 w-3.5 animate-spin text-orange-400 ml-auto" />}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-zinc-800/60 max-h-72 overflow-y-auto">
              {bursts.map((b, i) => {
                const statusEntries = Object.entries(b.statuses);
                const has429 = b.statuses["429"] && b.statuses["429"] > 0;
                return (
                  <div key={i} className="flex items-center gap-4 px-4 py-2.5 text-xs hover:bg-zinc-800/30">
                    <span className="text-zinc-400 font-mono w-24 shrink-0">Burst: <span className="text-zinc-200 font-semibold">{b.burst_size}</span> req/s</span>
                    <div className="flex gap-2 flex-1 flex-wrap">
                      {statusEntries.map(([code, count]) => (
                        <span key={code} className={cn("font-mono",
                          code === "200" ? "text-emerald-400" :
                          code === "429" ? "text-red-400" :
                          code.startsWith("4") || code.startsWith("5") ? "text-orange-400" : "text-zinc-400"
                        )}>
                          {code}: {count}
                        </span>
                      ))}
                    </div>
                    <span className="text-zinc-500 font-mono shrink-0">Avg {b.avg_ms}ms</span>
                    {b.throttled && (
                      <span className="flex items-center gap-1 text-red-400 shrink-0 font-semibold">
                        {has429 ? "🔴" : "🟡"} Throttled
                      </span>
                    )}
                    {!b.throttled && <span className="text-emerald-400 shrink-0">🟢 OK</span>}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {profile && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <Gauge className="h-4 w-4 text-orange-400" /> Rate Limit Profile
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Threshold</p>
                <p className="text-xl font-bold font-mono text-zinc-100">
                  {profile.threshold_rps != null ? `${profile.threshold_rps} r/s` : "N/A"}
                </p>
              </div>
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Reset Window</p>
                <p className="text-xl font-bold font-mono text-zinc-100">
                  {profile.reset_window_seconds != null ? `${profile.reset_window_seconds}s` : "N/A"}
                </p>
              </div>
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Enforcement</p>
                <p className="text-sm font-bold text-zinc-100 capitalize">{profile.enforcement_type}</p>
              </div>
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Bot Detection</p>
                <p className="text-sm font-bold text-zinc-100 capitalize">{profile.bot_detection_type.replace(/_/g, " ")}</p>
              </div>
            </div>
            {profile.headers_exposed.length > 0 && (
              <div className="space-y-1.5">
                <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Exposed Rate-Limit Headers</p>
                <div className="flex flex-wrap gap-2">
                  {profile.headers_exposed.map((h) => (
                    <span key={h} className="font-mono text-[11px] px-2.5 py-1 rounded border border-zinc-700 bg-zinc-800 text-zinc-300">{h}</span>
                  ))}
                </div>
              </div>
            )}
            {profile.bypass_vectors.length > 0 ? (
              <div className="space-y-1.5">
                <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Bypass Vectors Found</p>
                <ul className="space-y-1">
                  {profile.bypass_vectors.map((v, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-red-300">
                      <AlertTriangle className="h-3.5 w-3.5 text-red-400 mt-0.5 shrink-0" />
                      {v}
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-sm text-emerald-400">
                <CheckCircle2 className="h-4 w-4" />
                No bypass vectors found
              </div>
            )}
            <p className="text-xs text-zinc-600">Total requests sent: {profile.total_requests_sent}</p>
          </CardContent>
        </Card>
      )}

      {bursts.length === 0 && !running && !profile && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
          <Gauge className="h-12 w-12" />
          <p className="text-sm">Enter a target URL and start the rate limit probe</p>
        </div>
      )}
    </div>
  );
}

// ─── Tab 6: Smuggling Probe ───────────────────────────────────────────────────

function SmugglingTab({ onSave }: { onSave: (entry: FirewallHistoryEntry) => void }) {
  const [target, setTarget] = useState("");
  const [running, setRunning] = useState(false);
  const [probes, setProbes] = useState<SmugglingProbeResult[]>([]);
  const [complete, setComplete] = useState<SmugglingComplete | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const start = useCallback(async () => {
    if (!target.trim()) { toast.error("Please enter a target URL"); return; }
    setRunning(true);
    setProbes([]);
    setComplete(null);
    abortRef.current = new AbortController();
    const startedAt = new Date().toISOString();

    try {
      await sseStream(
        `${API_BASE}/firewall/smuggling/probe`,
        { target: target.trim() },
        (eventType, data) => {
          if (eventType === "probe") {
            setProbes((prev) => [...prev, data as SmugglingProbeResult]);
          } else if (eventType === "complete") {
            const c = data as SmugglingComplete;
            setComplete(c);
            setRunning(false);
            toast.success(`Smuggling probe complete — ${c.desync_risk} risk`);
            onSave({
              id: crypto.randomUUID(),
              type: "smuggling",
              target: target.trim(),
              started_at: startedAt,
              summary: `${c.desync_risk} desync risk — ${c.anomalies_detected} anomalies`,
              smuggling_complete: c,
            });
          } else if (eventType === "error") {
            const e = data as { message: string };
            setRunning(false);
            toast.error(`Smuggling error: ${e.message}`);
          }
        },
        abortRef.current.signal
      );
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") toast.error(`Smuggling probe failed: ${err.message}`);
      setRunning(false);
    }
  }, [target, onSave]);

  const stop = () => { abortRef.current?.abort(); setRunning(false); toast.info("Probe stopped"); };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
            <ArrowLeftRight className="h-4 w-4 text-pink-400" /> HTTP Request Smuggling Probe
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label className="text-xs text-zinc-400">Target URL</Label>
            <Input placeholder="https://example.com" value={target} onChange={(e) => setTarget(e.target.value)}
              disabled={running}
              onKeyDown={(e) => e.key === "Enter" && !running && start()}
              className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder-zinc-500 font-mono text-sm" />
          </div>
          <p className="text-xs text-zinc-600">
            Sends CL.TE, TE.CL, and timing-based desync probes to detect HTTP request smuggling vulnerabilities.
          </p>
          <div className="flex gap-3">
            {running
              ? <Button onClick={stop} variant="destructive" className="gap-2"><XCircle className="h-4 w-4" /> Stop Probe</Button>
              : <Button onClick={start} className="gap-2 bg-pink-700 hover:bg-pink-800 text-white"><ArrowLeftRight className="h-4 w-4" /> Run Smuggling Probe</Button>}
          </div>
        </CardContent>
      </Card>

      {probes.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <ArrowLeftRight className="h-4 w-4 text-zinc-400" /> Probe Results
              {running && <Loader2 className="h-3.5 w-3.5 animate-spin text-pink-400 ml-auto" />}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-zinc-900 border-b border-zinc-800">
                    {["Probe Type", "Result", "Response Time", "Baseline", "Detail"].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left font-semibold text-zinc-400 uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {probes.map((p, i) => {
                    const badge = SMUGGLING_RESULT_BADGE[p.result] ?? SMUGGLING_RESULT_BADGE.ERROR;
                    return (
                      <tr key={i} className="hover:bg-zinc-800/30">
                        <td className="px-4 py-2.5 font-mono text-zinc-200 font-semibold">{p.probe_type}</td>
                        <td className="px-4 py-2.5">
                          <Badge className={cn("text-[10px] px-2 py-0.5 border", badge.className)}>{badge.label}</Badge>
                        </td>
                        <td className={cn("px-4 py-2.5 font-mono",
                          p.response_time_ms > p.baseline_ms * 2 ? "text-red-400" : "text-zinc-300"
                        )}>{p.response_time_ms}ms</td>
                        <td className="px-4 py-2.5 font-mono text-zinc-500">{p.baseline_ms}ms</td>
                        <td className="px-4 py-2.5 text-zinc-400 max-w-xs truncate" title={p.detail}>{p.detail || "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {complete && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-zinc-400" /> Smuggling Summary
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3 flex-wrap">
              <Badge className={cn("text-sm px-3 py-1 border", RISK_BADGE[complete.desync_risk] ?? RISK_BADGE.Low)}>
                {complete.desync_risk} Desync Risk
              </Badge>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3 text-center">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Probes Run</p>
                <p className="text-2xl font-bold font-mono text-zinc-100">{complete.probes_run}</p>
              </div>
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3 text-center">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Anomalies</p>
                <p className={cn("text-2xl font-bold font-mono", complete.anomalies_detected > 0 ? "text-red-400" : "text-emerald-400")}>
                  {complete.anomalies_detected}
                </p>
              </div>
              <div className="rounded-md bg-zinc-800/60 border border-zinc-700 px-4 py-3">
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Recommendation</p>
                <p className="text-xs text-zinc-300">{complete.recommendation}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {probes.length === 0 && !running && !complete && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
          <ArrowLeftRight className="h-12 w-12" />
          <p className="text-sm">Enter a target URL and run the smuggling probe</p>
        </div>
      )}
    </div>
  );
}

// ─── History Panel ────────────────────────────────────────────────────────────

function HistoryEntryExpanded({ entry }: { entry: FirewallHistoryEntry }) {
  if (entry.type === "waf_detect" && entry.waf_result) {
    return <WAFDetectResultCard result={entry.waf_result} />;
  }
  if (entry.type === "waf_bypass") {
    return (
      <div className="space-y-4 pt-2">
        {entry.bypass_summary && <BypassSummaryGrid summary={entry.bypass_summary} />}
        {entry.bypass_probes && entry.bypass_probes.length > 0 && <BypassProbeTable probes={entry.bypass_probes} />}
      </div>
    );
  }
  if (entry.type === "port_map" && entry.port_rows) {
    return entry.port_rows.length > 0
      ? <div className="pt-2"><PortMapTable rows={entry.port_rows} /></div>
      : <p className="text-sm text-zinc-500 pt-2">No port data captured.</p>;
  }
  if (entry.type === "rule_analyze" && entry.rule_result) {
    const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const sorted = [...entry.rule_result.anomalies].sort(
      (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
    );
    return <div className="pt-2"><RuleAnalysisResultView result={entry.rule_result} sortedAnomalies={sorted} /></div>;
  }
  if (entry.type === "rate_limit" && entry.rate_limit_profile) {
    const p = entry.rate_limit_profile;
    return (
      <div className="pt-2 space-y-2">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {[
            { label: "Threshold", value: p.threshold_rps != null ? `${p.threshold_rps} r/s` : "N/A" },
            { label: "Reset Window", value: p.reset_window_seconds != null ? `${p.reset_window_seconds}s` : "N/A" },
            { label: "Enforcement", value: p.enforcement_type },
            { label: "Bot Detection", value: p.bot_detection_type.replace(/_/g, " ") },
          ].map((s) => (
            <div key={s.label} className="rounded-md bg-zinc-800/60 border border-zinc-700 px-3 py-2">
              <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-0.5">{s.label}</p>
              <p className="text-sm font-semibold text-zinc-200 capitalize font-mono">{s.value}</p>
            </div>
          ))}
        </div>
      </div>
    );
  }
  if (entry.type === "smuggling" && entry.smuggling_complete) {
    const c = entry.smuggling_complete;
    return (
      <div className="pt-2 space-y-2">
        <div className="flex items-center gap-3">
          <Badge className={cn("text-sm px-3 py-1 border", RISK_BADGE[c.desync_risk] ?? RISK_BADGE.Low)}>
            {c.desync_risk} Desync Risk
          </Badge>
          <span className="text-xs text-zinc-400">{c.anomalies_detected} anomalies — {c.probes_run} probes</span>
        </div>
        <p className="text-xs text-zinc-400">{c.recommendation}</p>
      </div>
    );
  }
  return null;
}

function HistoryPanel({
  history,
  onClear,
}: {
  history: FirewallHistoryEntry[];
  onClear: () => void;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/60">
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <div className="flex items-center gap-2">
          <History className="h-4 w-4 text-zinc-400" />
          <span className="text-sm font-semibold text-zinc-300">Scan History</span>
          <span className="rounded-full bg-zinc-700 px-2 py-0.5 text-xs text-zinc-400">{history.length}</span>
        </div>
        {history.length > 0 && (
          <Button variant="ghost" size="sm" onClick={onClear} className="gap-1.5 text-xs text-zinc-500 hover:text-red-400">
            <Trash2 className="h-3.5 w-3.5" /> Clear All
          </Button>
        )}
      </div>

      {history.length === 0 ? (
        <div className="px-4 py-10 text-center text-zinc-600 text-sm">No scans yet — run a scan to see history here.</div>
      ) : (
        <div className="divide-y divide-zinc-800/60">
          {history.map((entry) => {
            const meta = TYPE_META[entry.type];
            const isOpen = expandedId === entry.id;
            return (
              <div key={entry.id} className="px-4 py-3">
                <button
                  className="w-full flex items-center gap-3 text-left"
                  onClick={() => setExpandedId(isOpen ? null : entry.id)}
                >
                  <span className={cn("inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded border shrink-0", meta.color)}>
                    {meta.icon} {meta.label}
                  </span>
                  <span className="flex-1 text-sm text-zinc-300 font-mono truncate">{entry.target}</span>
                  <span className="text-xs text-zinc-500 shrink-0 hidden sm:block">{entry.summary}</span>
                  <span className="flex items-center gap-1 text-xs text-zinc-600 shrink-0">
                    <Clock className="h-3 w-3" />
                    {formatRelativeTime(entry.started_at)}
                  </span>
                  {isOpen
                    ? <ChevronUp className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
                    : <ChevronDown className="h-3.5 w-3.5 text-zinc-500 shrink-0" />}
                </button>

                {isOpen && (
                  <div className="mt-3">
                    <HistoryEntryExpanded entry={entry} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function FirewallPage() {
  const [history, setHistory] = useState<FirewallHistoryEntry[]>(() => {
    try {
      const saved = typeof window !== "undefined" ? localStorage.getItem(HISTORY_KEY) : null;
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY))); } catch {}
  }, [history]);

  const addHistory = useCallback((entry: FirewallHistoryEntry) => {
    setHistory((prev) => [entry, ...prev].slice(0, MAX_HISTORY));
  }, []);

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem(HISTORY_KEY);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Firewall & WAF Scanner"
        description="Detect WAF vendors, test bypass techniques, map firewall rules, probe rate limits, and detect HTTP smuggling"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowHistory((s) => !s)}
          className={cn("gap-1.5", showHistory && "border-zinc-600 bg-zinc-800")}
        >
          <History className="h-3.5 w-3.5" />
          History {history.length > 0 && `(${history.length})`}
        </Button>
      </PageHeader>

      <Tabs defaultValue="waf-detect" className="space-y-6">
        <TabsList className="bg-zinc-900 border border-zinc-800 p-1 gap-1 flex-wrap h-auto">
          {[
            { value: "waf-detect",    icon: ShieldX,       label: "WAF Detection" },
            { value: "waf-bypass",    icon: Zap,           label: "WAF Bypass" },
            { value: "port-map",      icon: Network,       label: "Port Mapper" },
            { value: "rule-analyzer", icon: FileText,      label: "Rule Analyzer" },
            { value: "rate-limit",    icon: Gauge,         label: "Rate Limit" },
            { value: "smuggling",     icon: ArrowLeftRight, label: "Smuggling" },
          ].map(({ value, icon: Icon, label }) => (
            <TabsTrigger key={value} value={value}
              className="flex items-center gap-2 text-xs data-[state=active]:bg-zinc-800 data-[state=active]:text-zinc-100 text-zinc-400 px-3 py-1.5 rounded-md transition-colors">
              <Icon className="h-3.5 w-3.5" /> {label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="waf-detect"><WAFDetectionTab onSave={addHistory} /></TabsContent>
        <TabsContent value="waf-bypass"><WAFBypassTab onSave={addHistory} /></TabsContent>
        <TabsContent value="port-map"><PortFirewallMapperTab onSave={addHistory} /></TabsContent>
        <TabsContent value="rule-analyzer"><RuleAnalyzerTab onSave={addHistory} /></TabsContent>
        <TabsContent value="rate-limit"><RateLimitTab onSave={addHistory} /></TabsContent>
        <TabsContent value="smuggling"><SmugglingTab onSave={addHistory} /></TabsContent>
      </Tabs>

      {showHistory && <HistoryPanel history={history} onClear={clearHistory} />}
    </div>
  );
}
