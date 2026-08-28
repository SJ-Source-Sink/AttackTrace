"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Upload, FileText, X, Play, Loader2, ChevronDown, ChevronRight,
  Copy, Check, AlertTriangle, Shield, Zap, Brain, Globe,
  Lock, Search, Code2, Server, Bug, RefreshCw, History,
  Network, Trash2, GitBranch, Activity, Plus, Eye, EyeOff,
  CheckCircle2, XCircle, Clock, FlaskConical,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { fetchWithAuth, getAccessToken } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ─── Types ────────────────────────────────────────────────────────────────────

interface TestCase {
  id: string;
  endpoint: string;
  method: string;
  vuln_type: string;
  title: string;
  description: string;
  parameters: string[];
  payloads: string[];
  severity: string;
  priority: number;
  cwe: string;
  owasp: string;
  rationale: string;
  steps: string[];
}

interface ResponseFinding {
  type: string;
  title: string;
  vuln: string;
  severity: string;
  endpoint: string;
  evidence: string;
  description: string;
}

interface AnalysisStats {
  total_requests: number;
  unique_hosts: string[];
  unique_endpoints: number;
  tech_stack: string[];
  auth_mechanisms: string[];
  test_cases: number;
  response_findings: number;
  severity_counts: Record<string, number>;
  interesting_endpoints: Array<{
    endpoint: string;
    full_url: string;
    class: string;
    auth_types: string[];
    params: string[];
    priority: number;
  }>;
  analysis_id?: string;
}

interface ParamCorrelation {
  param: string;
  endpoint_count: number;
  endpoints: Array<{ endpoint: string; full_url: string; method: string; auth: string[] }>;
  is_high_risk: boolean;
  risk_score: number;
}

interface TokenFlow {
  token_preview: string;
  issuer_path: string;
  issuer_method: string;
  alg: string;
  claims: Record<string, unknown>;
  usage_count: number;
  used_by: string[];
}

interface AuthFlows {
  token_flows: TokenFlow[];
  protected_count: number;
  unprotected_count: number;
  suspicious_unprotected: Array<{ endpoint: string; full_url: string; params: string[] }>;
  anomalies: Array<{ type: string; severity: string; detail: string; issuer: string }>;
}

interface BurpHistoryEntry {
  id: string;
  filename: string;
  saved_at: number;
  total_requests: number;
  test_cases: number;
  response_findings: number;
  severity_counts: Record<string, number>;
  tech_stack: string[];
  unique_hosts: string[];
}

interface BurpHistoryDetail {
  id: string;
  filename: string;
  saved_at: number;
  summary: AnalysisStats;
  test_cases: TestCase[];
  response_findings: ResponseFinding[];
  ai_text: string;
  param_graph: ParamCorrelation[];
  auth_flows: AuthFlows;
}

interface VerifyResult {
  verified: boolean;
  confidence: string;
  status_code: number;
  response_snippet: string;
  evidence: string;
  url_used?: string;
  error?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-950/40 border-red-800/40",
  high:     "text-orange-400 bg-orange-950/40 border-orange-800/40",
  medium:   "text-yellow-400 bg-yellow-950/40 border-yellow-800/40",
  low:      "text-blue-400 bg-blue-950/40 border-blue-800/40",
  info:     "text-zinc-400 bg-zinc-800/40 border-zinc-700/40",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-500",
  medium: "bg-yellow-500", low: "bg-blue-500", info: "bg-zinc-500",
};

const VULN_ICONS: Record<string, React.ReactNode> = {
  idor:            <Lock className="h-3.5 w-3.5" />,
  sqli:            <Code2 className="h-3.5 w-3.5" />,
  xss:             <Bug className="h-3.5 w-3.5" />,
  ssrf:            <Server className="h-3.5 w-3.5" />,
  open_redirect:   <Globe className="h-3.5 w-3.5" />,
  path_traversal:  <Search className="h-3.5 w-3.5" />,
  csrf:            <Shield className="h-3.5 w-3.5" />,
  ssti:            <Code2 className="h-3.5 w-3.5" />,
  jwt_attack:      <Lock className="h-3.5 w-3.5" />,
  brute_force:     <Zap className="h-3.5 w-3.5" />,
  auth_bypass:     <Shield className="h-3.5 w-3.5" />,
  file_upload:     <Upload className="h-3.5 w-3.5" />,
  mass_assignment: <AlertTriangle className="h-3.5 w-3.5" />,
  business_logic:  <AlertTriangle className="h-3.5 w-3.5" />,
  info_disclosure: <Globe className="h-3.5 w-3.5" />,
  account_takeover:<Lock className="h-3.5 w-3.5" />,
};

const VULN_LABELS: Record<string, string> = {
  idor: "IDOR", sqli: "SQL Injection", xss: "XSS", ssrf: "SSRF",
  open_redirect: "Open Redirect", path_traversal: "Path Traversal",
  csrf: "CSRF", ssti: "SSTI", jwt_attack: "JWT Attack",
  brute_force: "Brute Force", auth_bypass: "Auth Bypass",
  file_upload: "File Upload", mass_assignment: "Mass Assignment",
  business_logic: "Business Logic", info_disclosure: "Info Disclosure",
  account_takeover: "Account Takeover", sqli_exposure: "SQL Error",
  secret_exposure: "Secret Exposure", jwt_exposure: "JWT Exposure",
  nosql_injection: "NoSQL Injection",
};

const EP_CLASS_COLORS: Record<string, string> = {
  admin:       "text-red-400 bg-red-950/30",
  auth:        "text-orange-400 bg-orange-950/30",
  payment:     "text-yellow-400 bg-yellow-950/30",
  file_upload: "text-purple-400 bg-purple-950/30",
  debug:       "text-red-400 bg-red-950/30",
  export:      "text-blue-400 bg-blue-950/30",
  user_data:   "text-cyan-400 bg-cyan-950/30",
  webhook:     "text-zinc-300 bg-zinc-800/30",
  password:    "text-orange-400 bg-orange-950/30",
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

// ─── Small helpers ────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }); }}
      className="ml-1 p-0.5 rounded text-zinc-500 hover:text-zinc-300 transition-colors"
    >
      {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

function SevBadge({ severity }: { severity: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border", SEV_COLORS[severity] ?? SEV_COLORS.info)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", SEV_DOT[severity] ?? "bg-zinc-500")} />
      {severity}
    </span>
  );
}

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 text-center">
      <div className="text-xl font-bold text-zinc-100">{value}</div>
      <div className="text-xs text-zinc-400 mt-0.5">{label}</div>
      {sub && <div className="text-[10px] text-zinc-600 mt-0.5 truncate">{sub}</div>}
    </div>
  );
}

// ─── Verify button ────────────────────────────────────────────────────────────

function VerifyButton({
  tc,
  authHeaders,
  verifySsl,
}: {
  tc: TestCase;
  authHeaders: Record<string, string>;
  verifySsl: boolean;
}) {
  const [state, setState] = useState<"idle" | "loading" | "done">("idle");
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [expanded, setExpanded] = useState(false);

  const run = async () => {
    if (!tc.parameters.length || !tc.payloads.length) {
      toast.error("No parameters or payloads to verify with");
      return;
    }
    setState("loading");

    // Determine inject_in from endpoint method
    const method = tc.method.toUpperCase();
    const inject_in = method === "GET" || method === "DELETE" ? "query"
      : tc.endpoint.includes("application/json") ? "body_json"
      : "query";

    const body = {
      endpoint:        tc.endpoint,
      method:          method,
      vuln_type:       tc.vuln_type,
      param:           tc.parameters[0],
      payload:         tc.payloads[0],
      inject_in,
      body_params:     {},
      auth_headers:    authHeaders,
      original_status: 200,
      timeout:         10,
      verify_ssl:      verifySsl,
    };

    try {
      const r = await fetchWithAuth(`${API_BASE}/attack-suite/burp/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data: VerifyResult = await r.json();
      setResult(data);
      setState("done");
      setExpanded(true);
    } catch {
      setState("idle");
      toast.error("Verification request failed");
    }
  };

  if (state === "idle") {
    return (
      <button
        onClick={(e) => { e.stopPropagation(); run(); }}
        className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-blue-400 transition-colors border border-zinc-700 hover:border-blue-600/50 rounded px-1.5 py-0.5"
      >
        <FlaskConical className="h-2.5 w-2.5" /> Verify
      </button>
    );
  }
  if (state === "loading") {
    return (
      <span className="flex items-center gap-1 text-[10px] text-zinc-500">
        <Loader2 className="h-2.5 w-2.5 animate-spin" /> Verifying…
      </span>
    );
  }

  const verified = result?.verified;
  return (
    <div className="mt-2 space-y-1">
      <button
        onClick={(e) => { e.stopPropagation(); setExpanded(v => !v); }}
        className={cn(
          "flex items-center gap-1.5 text-[10px] rounded px-1.5 py-0.5 border transition-colors",
          verified
            ? "text-red-400 border-red-600/40 bg-red-950/20 hover:bg-red-950/30"
            : "text-emerald-400 border-emerald-600/40 bg-emerald-950/20 hover:bg-emerald-950/30"
        )}
      >
        {verified
          ? <><XCircle className="h-2.5 w-2.5" /> CONFIRMED VULNERABLE</>
          : <><CheckCircle2 className="h-2.5 w-2.5" /> Not confirmed ({result?.confidence} confidence)</>}
        {expanded ? <ChevronDown className="h-2.5 w-2.5 ml-1" /> : <ChevronRight className="h-2.5 w-2.5 ml-1" />}
      </button>
      {expanded && result && (
        <div className="rounded bg-zinc-950 border border-zinc-800 p-2 text-[10px] space-y-1">
          <div className="flex items-center gap-2 text-zinc-500">
            <span>HTTP {result.status_code}</span>
            {result.url_used && <span className="font-mono truncate max-w-[260px]">{result.url_used}</span>}
          </div>
          {result.evidence && (
            <pre className="text-zinc-400 font-mono whitespace-pre-wrap break-all max-h-24 overflow-y-auto">
              {result.evidence}
            </pre>
          )}
          {result.error && <p className="text-red-400">{result.error}</p>}
          <button
            onClick={(e) => { e.stopPropagation(); setState("idle"); setResult(null); }}
            className="text-zinc-600 hover:text-zinc-400 transition-colors"
          >
            Reset
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Test case card ───────────────────────────────────────────────────────────

function TestCaseCard({
  tc,
  authHeaders,
  verifySsl,
}: {
  tc: TestCase;
  authHeaders: Record<string, string>;
  verifySsl: boolean;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div className={cn("rounded border transition-colors", open ? "border-zinc-700 bg-zinc-900/80" : "border-zinc-800 bg-zinc-900/30 hover:border-zinc-700")}>
      <button className="w-full text-left flex items-start gap-2 p-3" onClick={() => setOpen(o => !o)}>
        <span className="mt-0.5 text-zinc-500">
          {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-semibold text-zinc-200">{tc.title}</span>
            <SevBadge severity={tc.severity} />
          </div>
          <div className="text-[11px] text-zinc-500 mt-0.5 truncate">{tc.endpoint}</div>
          {tc.parameters.length > 0 && (
            <div className="flex items-center gap-1 mt-1 flex-wrap">
              {tc.parameters.map(p => (
                <span key={p} className="px-1 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px] font-mono">{p}</span>
              ))}
            </div>
          )}
        </div>
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-3 border-t border-zinc-800 pt-3">
          <p className="text-xs text-zinc-400 leading-relaxed">{tc.description}</p>
          <div className="rounded bg-zinc-800/50 p-2">
            <p className="text-[11px] text-zinc-500"><span className="text-zinc-400 font-medium">Why:</span> {tc.rationale}</p>
          </div>
          <div className="flex items-center gap-3 text-[10px] text-zinc-500">
            <span className="text-zinc-400">{tc.cwe}</span>
            <span className="text-zinc-700">•</span>
            <span>{tc.owasp}</span>
          </div>
          <div>
            <p className="text-[11px] font-medium text-zinc-400 mb-1.5">Steps</p>
            <ol className="space-y-1">
              {tc.steps.map((step, i) => (
                <li key={i} className="flex gap-2 text-[11px] text-zinc-400">
                  <span className="text-zinc-600 font-mono shrink-0">{i + 1}.</span>
                  <span className="leading-relaxed">{step}</span>
                </li>
              ))}
            </ol>
          </div>
          {tc.payloads.length > 0 && (
            <div>
              <p className="text-[11px] font-medium text-zinc-400 mb-1.5">Payloads ({tc.payloads.length})</p>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {tc.payloads.slice(0, 8).map((pl, i) => (
                  <div key={i} className="flex items-center gap-1 rounded bg-zinc-950 border border-zinc-800 px-2 py-1">
                    <code className="text-[11px] text-green-400 font-mono flex-1 break-all">{pl}</code>
                    <CopyButton text={pl} />
                  </div>
                ))}
                {tc.payloads.length > 8 && (
                  <p className="text-[10px] text-zinc-600 pl-1">+{tc.payloads.length - 8} more payloads</p>
                )}
              </div>
            </div>
          )}
          {/* Active verify */}
          <div className="pt-1 border-t border-zinc-800/60">
            <VerifyButton tc={tc} authHeaders={authHeaders} verifySsl={verifySsl} />
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Vuln group accordion ─────────────────────────────────────────────────────

function VulnGroup({
  vulnType, cases, authHeaders, verifySsl,
}: {
  vulnType: string; cases: TestCase[];
  authHeaders: Record<string, string>; verifySsl: boolean;
}) {
  const [open, setOpen] = useState(true);
  const worst = cases.reduce<string>(
    (acc, tc) => SEV_ORDER.indexOf(tc.severity as typeof SEV_ORDER[number]) < SEV_ORDER.indexOf(acc as typeof SEV_ORDER[number]) ? tc.severity : acc,
    "info"
  );
  return (
    <div className="rounded-lg border border-zinc-800 overflow-hidden">
      <button
        className="w-full flex items-center gap-2.5 px-3 py-2.5 bg-zinc-900/80 hover:bg-zinc-800/60 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <span className="text-zinc-400">{VULN_ICONS[vulnType] ?? <Bug className="h-3.5 w-3.5" />}</span>
        <span className="text-xs font-semibold text-zinc-200 flex-1 text-left">{VULN_LABELS[vulnType] ?? vulnType}</span>
        <SevBadge severity={worst} />
        <span className="text-[11px] text-zinc-500 ml-1">{cases.length}</span>
        {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
      </button>
      {open && (
        <div className="divide-y divide-zinc-800/50">
          {cases.map(tc => (
            <TestCaseCard key={tc.id} tc={tc} authHeaders={authHeaders} verifySsl={verifySsl} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Param correlation section ────────────────────────────────────────────────

function ParamGraph({ correlations }: { correlations: ParamCorrelation[] }) {
  const [open, setOpen] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  if (!correlations.length) return null;

  return (
    <div className="rounded-lg border border-zinc-800 overflow-hidden">
      <button
        className="w-full flex items-center gap-2 px-3 py-2.5 bg-zinc-900/80 hover:bg-zinc-800/60 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <Network className="h-3.5 w-3.5 text-blue-400" />
        <span className="text-xs font-semibold text-zinc-200 flex-1 text-left">Parameter Correlation Graph</span>
        <Badge variant="secondary" className="text-[10px] py-0 h-4">{correlations.length}</Badge>
        {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
      </button>
      {open && (
        <div className="p-3 space-y-2">
          <p className="text-[11px] text-zinc-500 leading-relaxed">
            Parameters appearing in multiple endpoints — an IDOR or injection in these params affects all endpoints listed.
          </p>
          <div className="space-y-1.5 max-h-72 overflow-y-auto">
            {correlations.map(c => (
              <div key={c.param} className="rounded border border-zinc-800">
                <button
                  className="w-full flex items-center gap-2 px-2.5 py-2 text-left hover:bg-zinc-800/40 transition-colors"
                  onClick={() => setExpanded(expanded === c.param ? null : c.param)}
                >
                  <span className={cn(
                    "text-[11px] font-mono font-semibold",
                    c.is_high_risk ? "text-orange-400" : "text-zinc-300"
                  )}>{c.param}</span>
                  {c.is_high_risk && (
                    <span className="text-[9px] bg-orange-950/40 border border-orange-800/40 text-orange-400 rounded px-1">HIGH RISK</span>
                  )}
                  <span className="ml-auto text-[10px] text-zinc-500">{c.endpoint_count} endpoints</span>
                  {expanded === c.param
                    ? <ChevronDown className="h-3 w-3 text-zinc-600" />
                    : <ChevronRight className="h-3 w-3 text-zinc-600" />}
                </button>
                {expanded === c.param && (
                  <div className="px-2.5 pb-2 space-y-1 border-t border-zinc-800/60">
                    {c.endpoints.map((ep, i) => (
                      <div key={i} className="flex items-center gap-2 text-[10px]">
                        <span className={cn(
                          "font-mono shrink-0 px-1 rounded text-[9px]",
                          ep.method === "GET" ? "bg-blue-950/40 text-blue-400" :
                          ep.method === "POST" ? "bg-green-950/40 text-green-400" :
                          ep.method === "DELETE" ? "bg-red-950/40 text-red-400" :
                          "bg-zinc-800 text-zinc-400"
                        )}>{ep.method}</span>
                        <span className="font-mono text-zinc-400 truncate">{ep.endpoint.split(" ").slice(1).join(" ")}</span>
                        {ep.auth.length === 0 && (
                          <span className="shrink-0 text-[9px] text-red-400 border border-red-800/30 rounded px-1">no auth</span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Auth flow section ────────────────────────────────────────────────────────

function AuthFlowPanel({ flows }: { flows: AuthFlows }) {
  const [open, setOpen] = useState(true);
  const hasContent = flows.token_flows.length > 0 || flows.anomalies.length > 0 || flows.suspicious_unprotected.length > 0;
  if (!hasContent) return null;

  const coveragePct = flows.protected_count + flows.unprotected_count > 0
    ? Math.round((flows.protected_count / (flows.protected_count + flows.unprotected_count)) * 100)
    : 0;

  return (
    <div className="rounded-lg border border-zinc-800 overflow-hidden">
      <button
        className="w-full flex items-center gap-2 px-3 py-2.5 bg-zinc-900/80 hover:bg-zinc-800/60 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <GitBranch className="h-3.5 w-3.5 text-purple-400" />
        <span className="text-xs font-semibold text-zinc-200 flex-1 text-left">Auth Flow Analysis</span>
        {flows.anomalies.length > 0 && (
          <span className="text-[10px] text-red-400 border border-red-800/30 rounded px-1.5 py-0.5">
            {flows.anomalies.length} anomaly{flows.anomalies.length > 1 ? "ies" : ""}
          </span>
        )}
        {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
      </button>
      {open && (
        <div className="p-3 space-y-3">
          {/* Coverage bar */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-500">Auth coverage</span>
              <span className={cn("font-semibold", coveragePct >= 80 ? "text-emerald-400" : coveragePct >= 50 ? "text-yellow-400" : "text-red-400")}>
                {coveragePct}% ({flows.protected_count}/{flows.protected_count + flows.unprotected_count})
              </span>
            </div>
            <div className="h-1.5 rounded-full bg-zinc-800 overflow-hidden">
              <div
                className={cn("h-full rounded-full transition-all", coveragePct >= 80 ? "bg-emerald-500" : coveragePct >= 50 ? "bg-yellow-500" : "bg-red-500")}
                style={{ width: `${coveragePct}%` }}
              />
            </div>
          </div>

          {/* JWT anomalies */}
          {flows.anomalies.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[11px] font-medium text-zinc-400 flex items-center gap-1.5">
                <AlertTriangle className="h-3 w-3 text-orange-400" /> JWT Anomalies
              </p>
              {flows.anomalies.map((a, i) => (
                <div key={i} className={cn("rounded p-2 text-[11px] border", SEV_COLORS[a.severity] ?? SEV_COLORS.info)}>
                  <div className="flex items-start gap-1.5">
                    <SevBadge severity={a.severity} />
                    <p className="leading-relaxed">{a.detail}</p>
                  </div>
                  <p className="text-zinc-600 mt-0.5 font-mono">{a.issuer}</p>
                </div>
              ))}
            </div>
          )}

          {/* Token flows */}
          {flows.token_flows.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[11px] font-medium text-zinc-400 flex items-center gap-1.5">
                <Activity className="h-3 w-3 text-blue-400" /> Token Flows
              </p>
              {flows.token_flows.map((tf, i) => (
                <div key={i} className="rounded border border-zinc-800 bg-zinc-900/40 p-2 text-[11px] space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-zinc-600 shrink-0">{tf.issuer_method}</span>
                    <span className="font-mono text-zinc-400">{tf.issuer_path}</span>
                    <span className="ml-auto text-[10px] text-zinc-600 border border-zinc-700 rounded px-1">{tf.alg || "unknown alg"}</span>
                  </div>
                  <div className="flex items-center gap-3 text-zinc-600">
                    <span>Used {tf.usage_count}× across {tf.used_by.length} endpoint(s)</span>
                    {Object.keys(tf.claims).length > 0 && (
                      <span className="font-mono text-zinc-500">
                        claims: {Object.keys(tf.claims).join(", ")}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Suspicious unprotected */}
          {flows.suspicious_unprotected.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[11px] font-medium text-zinc-400 flex items-center gap-1.5">
                <Shield className="h-3 w-3 text-red-400" /> Suspicious Unprotected Endpoints
              </p>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {flows.suspicious_unprotected.map((ep, i) => (
                  <div key={i} className="rounded border border-red-900/20 bg-red-950/10 px-2 py-1.5 text-[11px]">
                    <p className="font-mono text-red-300">{ep.endpoint}</p>
                    {ep.params.length > 0 && (
                      <p className="text-zinc-600 mt-0.5">params: {ep.params.join(", ")}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Response findings ────────────────────────────────────────────────────────

function ResponseFindingRow({ finding }: { finding: ResponseFinding }) {
  return (
    <div className={cn("rounded border p-3", SEV_COLORS[finding.severity] ?? SEV_COLORS.info)}>
      <div className="flex items-start gap-2">
        <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-semibold">{finding.title}</span>
            <SevBadge severity={finding.severity} />
          </div>
          <p className="text-[11px] mt-0.5 opacity-80">{finding.description}</p>
          {finding.evidence && (
            <code className="mt-1.5 block rounded bg-black/30 px-2 py-1 text-[10px] font-mono break-all opacity-70">
              {finding.evidence}
            </code>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── History panel ────────────────────────────────────────────────────────────

function HistoryPanel({
  onRestore,
}: {
  onRestore: (detail: BurpHistoryDetail) => void;
}) {
  const [entries, setEntries] = useState<BurpHistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<BurpHistoryDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetchWithAuth(`${API_BASE}/attack-suite/burp/history`);
      if (r.ok) setEntries(await r.json());
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const loadDetail = async (id: string) => {
    setDetailLoading(true);
    try {
      const r = await fetchWithAuth(`${API_BASE}/attack-suite/burp/history/${id}`);
      if (r.ok) setSelected(await r.json());
    } catch { toast.error("Failed to load analysis"); }
    finally { setDetailLoading(false); }
  };

  const del = async (id: string) => {
    if (!confirm("Delete this analysis?")) return;
    const r = await fetchWithAuth(`${API_BASE}/attack-suite/burp/history/${id}`, { method: "DELETE" });
    if (r.ok) { setEntries(e => e.filter(x => x.id !== id)); if (selected?.id === id) setSelected(null); }
  };

  if (selected) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <button onClick={() => setSelected(null)} className="text-zinc-500 hover:text-zinc-300 transition-colors">
            <ChevronRight className="h-4 w-4 rotate-180" />
          </button>
          <h3 className="text-sm font-semibold text-zinc-200 truncate">{selected.filename}</h3>
          <span className="text-xs text-zinc-500 ml-auto shrink-0">
            {new Date(selected.saved_at * 1000).toLocaleString()}
          </span>
          <Button size="sm" variant="outline" className="gap-1.5 text-xs shrink-0" onClick={() => onRestore(selected)}>
            <RefreshCw className="h-3 w-3" /> Restore
          </Button>
        </div>

        {/* Summary stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Requests" value={(selected.summary.total_requests ?? 0).toLocaleString()} />
          <StatCard label="Endpoints" value={(selected.summary.unique_endpoints ?? 0).toLocaleString()} />
          <StatCard label="Test Cases" value={selected.test_cases.length.toLocaleString()} />
          <StatCard label="Response Findings" value={selected.response_findings.length.toLocaleString()} />
        </div>

        {/* Severity bars */}
        {selected.summary.severity_counts && (
          <div className="flex items-center gap-2 flex-wrap">
            {SEV_ORDER.map(sev => {
              const c = selected.summary.severity_counts[sev] ?? 0;
              if (!c) return null;
              return (
                <span key={sev} className={cn("flex items-center gap-1 px-2 py-0.5 rounded text-[11px] border", SEV_COLORS[sev])}>
                  <span className={cn("h-1.5 w-1.5 rounded-full", SEV_DOT[sev])} />
                  {sev} {c}
                </span>
              );
            })}
          </div>
        )}

        {/* AI text if present */}
        {selected.ai_text && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold text-zinc-300 flex items-center gap-1.5">
                <Brain className="h-3.5 w-3.5 text-orange-400" /> Claude AI Analysis
                <CopyButton text={selected.ai_text} />
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="max-h-64 overflow-y-auto text-xs text-zinc-300 whitespace-pre-wrap leading-relaxed">
                {selected.ai_text}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Auth flows */}
        {selected.auth_flows && <AuthFlowPanel flows={selected.auth_flows} />}

        {/* Param graph */}
        {selected.param_graph?.length > 0 && <ParamGraph correlations={selected.param_graph} />}

        {/* Test cases (abbreviated) */}
        {selected.test_cases.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-semibold text-zinc-400">{selected.test_cases.length} test cases (read-only)</p>
            {Object.entries(
              selected.test_cases.reduce<Record<string, TestCase[]>>((acc, tc) => {
                (acc[tc.vuln_type] ??= []).push(tc);
                return acc;
              }, {})
            ).sort(([, a], [, b]) => {
              const wa = SEV_ORDER.indexOf(a.reduce<typeof SEV_ORDER[number]>((w, t) => SEV_ORDER.indexOf(t.severity as typeof SEV_ORDER[number]) < SEV_ORDER.indexOf(w) ? t.severity as typeof SEV_ORDER[number] : w, "info"));
              const wb = SEV_ORDER.indexOf(b.reduce<typeof SEV_ORDER[number]>((w, t) => SEV_ORDER.indexOf(t.severity as typeof SEV_ORDER[number]) < SEV_ORDER.indexOf(w) ? t.severity as typeof SEV_ORDER[number] : w, "info"));
              return wa - wb;
            }).map(([vtype, cases]) => (
              <VulnGroup key={vtype} vulnType={vtype} cases={cases} authHeaders={{}} verifySsl={true} />
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-zinc-200">Analysis History</h3>
        <Button variant="ghost" size="sm" onClick={load} className="gap-1 text-xs text-zinc-500">
          <RefreshCw className="h-3 w-3" /> Refresh
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12 text-zinc-600">
          <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading…
        </div>
      ) : entries.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-zinc-600 space-y-2">
          <History className="h-10 w-10" />
          <p className="text-sm">No past analyses yet</p>
          <p className="text-xs text-zinc-700">Run an analysis to save it here</p>
        </div>
      ) : (
        <div className="space-y-2">
          {entries.map(e => (
            <div key={e.id} className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 hover:border-zinc-700 transition-colors">
              <div className="flex items-start gap-3">
                <FileText className="h-4 w-4 text-orange-400 shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-zinc-200 truncate">{e.filename}</p>
                  <p className="text-[11px] text-zinc-500">
                    {new Date(e.saved_at * 1000).toLocaleString()}
                    {e.unique_hosts.length > 0 && ` · ${e.unique_hosts[0]}`}
                  </p>
                  <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                    <span className="text-[10px] text-zinc-500">{e.total_requests.toLocaleString()} reqs</span>
                    <span className="text-zinc-700 text-[10px]">·</span>
                    <span className="text-[10px] text-zinc-500">{e.test_cases} test cases</span>
                    {SEV_ORDER.map(sev => {
                      const c = e.severity_counts[sev] ?? 0;
                      if (!c) return null;
                      return (
                        <span key={sev} className={cn("text-[10px] px-1 rounded", SEV_COLORS[sev])}>
                          {sev[0].toUpperCase()}: {c}
                        </span>
                      );
                    })}
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <Button variant="ghost" size="sm" className="h-7 px-2 text-xs"
                    onClick={() => loadDetail(e.id)} disabled={detailLoading}>
                    {detailLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Eye className="h-3 w-3" />}
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 px-2 text-xs text-red-500 hover:text-red-400"
                    onClick={() => del(e.id)}>
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function BurpImport() {
  const [activeTab, setActiveTab] = useState<"analyze" | "history">("analyze");
  const [file, setFile]           = useState<File | null>(null);
  const [aiAnalysis, setAi]       = useState(true);
  const [status, setStatus]       = useState<"idle" | "analyzing" | "complete" | "error">("idle");
  const [progress, setProgress]   = useState("");
  const [stats, setStats]         = useState<AnalysisStats | null>(null);
  const [testCases, setTestCases] = useState<TestCase[]>([]);
  const [responseFindings, setResponseFindings] = useState<ResponseFinding[]>([]);
  const [aiText, setAiText]       = useState("");
  const [paramGraph, setParamGraph] = useState<ParamCorrelation[]>([]);
  const [authFlows, setAuthFlows]   = useState<AuthFlows | null>(null);
  const [isDragging, setDragging] = useState(false);
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [analysisId, setAnalysisId] = useState<string | null>(null);

  // Verification auth
  const [verifyHeaders, setVerifyHeaders] = useState<{ key: string; value: string }[]>([]);
  const [showVerifyAuth, setShowVerifyAuth] = useState(false);
  const [verifySsl, setVerifySsl] = useState(true);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const aiScrollRef  = useRef<HTMLDivElement>(null);
  const abortRef     = useRef<AbortController | null>(null);

  const verifyAuthHeaders = Object.fromEntries(
    verifyHeaders.filter(h => h.key.trim()).map(h => [h.key.trim(), h.value])
  );

  const handleFile = (f: File) => {
    if (!f.name.endsWith(".xml") && !f.name.endsWith(".burp")) {
      toast.error("Please upload a Burp Suite XML export (.xml)");
      return;
    }
    setFile(f);
    resetResults();
  };

  const resetResults = () => {
    setStats(null); setTestCases([]); setResponseFindings([]);
    setAiText(""); setProgress(""); setStatus("idle");
    setParamGraph([]); setAuthFlows(null); setAnalysisId(null);
  };

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }, []);

  // ── Analysis ────────────────────────────────────────────────────────────────

  const startAnalysis = async () => {
    if (!file) return;
    setStatus("analyzing"); setProgress("Uploading file…");
    setTestCases([]); setResponseFindings([]); setAiText("");
    setStats(null); setParamGraph([]); setAuthFlows(null); setAnalysisId(null);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("ai_analysis", String(aiAnalysis));
    abortRef.current = new AbortController();

    try {
      const resp = await fetchWithAuth(`${API_BASE}/attack-suite/burp/analyze`, {
        method: "POST", body: formData, signal: abortRef.current.signal,
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Request failed" }));
        throw new Error(err.detail ?? "Analysis failed");
      }

      const reader  = resp.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = ""; let currentEvent = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (line.startsWith("event: ")) { currentEvent = line.slice(7).trim(); }
          else if (line.startsWith("data: ")) {
            try { handleEvent(currentEvent, JSON.parse(line.slice(6))); } catch { /* ignore */ }
          }
        }
      }
      setStatus("complete");
    } catch (err: unknown) {
      if ((err as Error).name === "AbortError") return;
      setStatus("error"); setProgress(`Error: ${(err as Error).message}`);
      toast.error((err as Error).message);
    }
  };

  const handleEvent = (event: string, data: Record<string, unknown>) => {
    switch (event) {
      case "parsed":    setProgress(data.message as string); break;
      case "profiled":  setProgress(data.message as string); break;
      case "progress":  setProgress(data.message as string); break;
      case "response_finding":
        setResponseFindings(prev => [...prev, data as unknown as ResponseFinding]); break;
      case "test_cases": {
        const cases = (data.cases as TestCase[]) ?? [];
        setTestCases(prev => [...prev, ...cases]);
        setProgress(`Generating test cases… (${data.endpoint})`);
        break;
      }
      case "generation_complete":
        setProgress(data.message as string);
        if (data.interesting_endpoints) {
          setStats(prev => prev ? { ...prev, interesting_endpoints: data.interesting_endpoints as AnalysisStats["interesting_endpoints"] } : null);
        }
        break;
      case "param_graph":
        setParamGraph((data.correlations as ParamCorrelation[]) ?? []);
        setProgress(data.message as string);
        break;
      case "auth_flows":
        setAuthFlows(data as unknown as AuthFlows);
        setProgress(data.message as string);
        break;
      case "ai_start":  setProgress(data.message as string); break;
      case "ai_chunk":
        setAiText(prev => {
          const next = prev + (data.text as string);
          setTimeout(() => { if (aiScrollRef.current) aiScrollRef.current.scrollTop = aiScrollRef.current.scrollHeight; }, 0);
          return next;
        });
        break;
      case "ai_error":  setProgress(data.message as string); break;
      case "complete":
        setStats({
          total_requests:    data.total_requests as number,
          unique_hosts:      (data.unique_hosts as string[]) ?? [],
          unique_endpoints:  data.unique_endpoints as number,
          tech_stack:        (data.tech_stack as string[]) ?? [],
          auth_mechanisms:   (data.auth_mechanisms as string[]) ?? [],
          test_cases:        data.test_cases as number,
          response_findings: data.response_findings as number,
          severity_counts:   (data.severity_counts as Record<string, number>) ?? {},
          interesting_endpoints: (data.interesting_endpoints as AnalysisStats["interesting_endpoints"]) ?? [],
          analysis_id:       (data.analysis_id as string | undefined),
        });
        setAnalysisId((data.analysis_id as string) ?? null);
        setStatus("complete"); setProgress("Analysis complete");
        break;
      case "error":
        setStatus("error"); setProgress(data.message as string); break;
    }
  };

  const stop = () => { abortRef.current?.abort(); setStatus("idle"); };

  // ── Restore from history ─────────────────────────────────────────────────────

  const restoreFromHistory = (detail: BurpHistoryDetail) => {
    setTestCases(detail.test_cases);
    setResponseFindings(detail.response_findings);
    setAiText(detail.ai_text || "");
    setParamGraph(detail.param_graph || []);
    setAuthFlows(detail.auth_flows || null);
    setStats({ ...detail.summary, analysis_id: detail.id });
    setAnalysisId(detail.id);
    setStatus("complete");
    setActiveTab("analyze");
    toast.success(`Restored: ${detail.filename}`);
  };

  // ── Derived state ────────────────────────────────────────────────────────────

  const grouped = testCases.reduce<Record<string, TestCase[]>>((acc, tc) => {
    (acc[tc.vuln_type] ??= []).push(tc);
    return acc;
  }, {});

  const filteredGrouped = sevFilter
    ? Object.fromEntries(
        Object.entries(grouped)
          .map(([k, v]) => [k, v.filter(tc => tc.severity === sevFilter)])
          .filter(([, v]) => v.length > 0)
      )
    : grouped;

  const worstSev = (tcs: TestCase[]) =>
    SEV_ORDER.indexOf(tcs.reduce<typeof SEV_ORDER[number]>(
      (w, tc) => SEV_ORDER.indexOf(tc.severity as typeof SEV_ORDER[number]) < SEV_ORDER.indexOf(w) ? tc.severity as typeof SEV_ORDER[number] : w,
      "info"
    ));

  const sortedVulnTypes = Object.keys(filteredGrouped).sort(
    (a, b) => worstSev(filteredGrouped[a]) - worstSev(filteredGrouped[b])
  );

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">
      {/* Tab switcher */}
      <div className="flex items-center gap-1 rounded-lg bg-zinc-900 border border-zinc-800 p-1 w-fit">
        {(["analyze", "history"] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors capitalize",
              activeTab === tab ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            {tab === "analyze" ? <Upload className="h-3.5 w-3.5" /> : <History className="h-3.5 w-3.5" />}
            {tab}
          </button>
        ))}
      </div>

      {/* ── History tab ── */}
      {activeTab === "history" && <HistoryPanel onRestore={restoreFromHistory} />}

      {/* ── Analyze tab ── */}
      {activeTab === "analyze" && (
        <>
          {/* Upload zone */}
          {status === "idle" && !stats && (
            <div className="space-y-5">
              <div
                className={cn(
                  "relative rounded-xl border-2 border-dashed transition-all cursor-pointer",
                  isDragging ? "border-orange-500 bg-orange-950/20"
                    : file ? "border-zinc-600 bg-zinc-900/60"
                    : "border-zinc-700 bg-zinc-900/30 hover:border-zinc-600 hover:bg-zinc-900/50"
                )}
                onDragOver={e => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                onClick={() => !file && fileInputRef.current?.click()}
              >
                <input ref={fileInputRef} type="file" accept=".xml,.burp" className="hidden"
                  onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
                <div className="p-10 text-center">
                  {file ? (
                    <div className="flex items-center justify-center gap-3">
                      <div className="p-3 rounded-lg bg-orange-950/40 border border-orange-800/40">
                        <FileText className="h-6 w-6 text-orange-400" />
                      </div>
                      <div className="text-left">
                        <p className="text-sm font-semibold text-zinc-200">{file.name}</p>
                        <p className="text-xs text-zinc-500">{(file.size / 1024).toFixed(1)} KB</p>
                      </div>
                      <button className="ml-4 p-1.5 rounded hover:bg-zinc-800 text-zinc-500 hover:text-zinc-300 transition-colors"
                        onClick={e => { e.stopPropagation(); setFile(null); }}>
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <div className="flex justify-center">
                        <div className="p-4 rounded-full bg-zinc-800/60 border border-zinc-700">
                          <Upload className="h-8 w-8 text-zinc-400" />
                        </div>
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-zinc-300">Drop your Burp Suite export here</p>
                        <p className="text-xs text-zinc-500 mt-1">or click to browse — XML format only</p>
                      </div>
                      <div className="rounded-lg bg-zinc-800/40 border border-zinc-700/50 p-3 text-left inline-block mx-auto">
                        <p className="text-[11px] text-zinc-400 font-medium mb-1">How to export from Burp Suite:</p>
                        <ol className="text-[11px] text-zinc-500 space-y-0.5 list-decimal list-inside">
                          <li>Open <span className="text-zinc-300">Proxy → HTTP history</span></li>
                          <li>Select all requests <span className="text-zinc-300">(Ctrl+A)</span></li>
                          <li>Right-click → <span className="text-zinc-300">Save items</span></li>
                          <li>Save as <span className="text-zinc-300">.xml</span></li>
                        </ol>
                      </div>
                    </div>
                  )}
                </div>
              </div>
              {file && (
                <div className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
                  <div className="flex items-center gap-2.5">
                    <Switch id="ai-toggle" checked={aiAnalysis} onCheckedChange={setAi}
                      className="data-[state=checked]:bg-orange-600" />
                    <Label htmlFor="ai-toggle" className="text-sm text-zinc-300 flex items-center gap-1.5 cursor-pointer">
                      <Brain className="h-3.5 w-3.5 text-orange-400" />
                      Claude AI deep analysis
                      <span className="text-xs text-zinc-600">(recommended)</span>
                    </Label>
                  </div>
                  <Button onClick={startAnalysis} className="bg-orange-600 hover:bg-orange-700 text-white gap-1.5">
                    <Play className="h-3.5 w-3.5" /> Analyse
                  </Button>
                </div>
              )}
              {!file && (
                <p className="text-center text-xs text-zinc-600">
                  Supports Burp Suite HTTP history exports up to 500 MB · up to 20,000 requests
                </p>
              )}
            </div>
          )}

          {/* Analysing state */}
          {status === "analyzing" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
                <div className="flex items-center gap-3">
                  <Loader2 className="h-4 w-4 text-orange-400 animate-spin" />
                  <span className="text-sm text-zinc-300">{progress || "Analysing…"}</span>
                </div>
                <Button variant="outline" size="sm" onClick={stop} className="gap-1.5 text-xs">
                  <X className="h-3 w-3" /> Stop
                </Button>
              </div>
              {(testCases.length > 0 || responseFindings.length > 0) && (
                <div className="grid grid-cols-3 gap-3">
                  <StatCard label="Test Cases" value={testCases.length} />
                  <StatCard label="Response Findings" value={responseFindings.length} />
                  <StatCard label="Vuln Types" value={Object.keys(grouped).length} />
                </div>
              )}
              {testCases.length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-semibold text-zinc-400">Generating test cases…</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2 max-h-64 overflow-y-auto">
                    {testCases.slice(-5).map(tc => (
                      <div key={tc.id} className="flex items-center gap-2 text-xs text-zinc-400 animate-in fade-in">
                        <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", SEV_DOT[tc.severity] ?? "bg-zinc-500")} />
                        <span className="font-medium text-zinc-300 truncate">{tc.title}</span>
                        <span className="text-zinc-600 shrink-0 truncate">{tc.endpoint.split(" ")[1]}</span>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}
              {aiText && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-semibold text-zinc-400 flex items-center gap-1.5">
                      <Brain className="h-3.5 w-3.5 text-orange-400" /> Claude AI Analysis
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div ref={aiScrollRef} className="max-h-48 overflow-y-auto text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap font-mono">
                      {aiText}<span className="animate-pulse text-orange-400">▍</span>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {/* Results */}
          {(status === "complete" || (stats && testCases.length > 0)) && (
            <div className="space-y-5">
              {/* Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-zinc-200">Analysis Results</h3>
                  {file && <span className="text-xs text-zinc-500">{file.name}</span>}
                  {analysisId && (
                    <span className="text-[10px] text-emerald-500 border border-emerald-800/40 rounded px-1.5 py-0.5 flex items-center gap-1">
                      <Clock className="h-2.5 w-2.5" /> Saved to history
                    </span>
                  )}
                </div>
                <Button variant="outline" size="sm" onClick={() => { setFile(null); resetResults(); }} className="gap-1.5 text-xs">
                  <RefreshCw className="h-3 w-3" /> New Analysis
                </Button>
              </div>

              {/* Stats */}
              {stats && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <StatCard label="Requests Parsed" value={stats.total_requests.toLocaleString()} sub={stats.unique_hosts.slice(0, 2).join(", ")} />
                  <StatCard label="Unique Endpoints" value={stats.unique_endpoints.toLocaleString()} />
                  <StatCard label="Test Cases" value={testCases.length.toLocaleString()} />
                  <StatCard label="Response Findings" value={responseFindings.length.toLocaleString()} />
                </div>
              )}

              {/* Tech + auth pills */}
              {stats && (stats.tech_stack.length > 0 || stats.auth_mechanisms.length > 0) && (
                <div className="flex flex-wrap gap-2">
                  {stats.tech_stack.map(t => (
                    <span key={t} className="px-2 py-0.5 rounded-full bg-blue-950/40 border border-blue-800/30 text-[11px] text-blue-300">{t}</span>
                  ))}
                  {stats.auth_mechanisms.map(a => (
                    <span key={a} className="px-2 py-0.5 rounded-full bg-green-950/40 border border-green-800/30 text-[11px] text-green-300">
                      <Lock className="inline h-2.5 w-2.5 mr-1" />{a}
                    </span>
                  ))}
                </div>
              )}

              {/* Severity filter */}
              {stats && (
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] text-zinc-500">Filter:</span>
                  <button onClick={() => setSevFilter(null)}
                    className={cn("px-2 py-0.5 rounded text-[11px] transition-colors", !sevFilter ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300")}>
                    All ({testCases.length})
                  </button>
                  {SEV_ORDER.map(sev => {
                    const count = testCases.filter(tc => tc.severity === sev).length;
                    if (!count) return null;
                    return (
                      <button key={sev} onClick={() => setSevFilter(sevFilter === sev ? null : sev)}
                        className={cn("px-2 py-0.5 rounded text-[11px] flex items-center gap-1 transition-colors border",
                          sevFilter === sev ? SEV_COLORS[sev] : "text-zinc-500 border-zinc-700 hover:text-zinc-300 hover:border-zinc-600")}>
                        <span className={cn("h-1.5 w-1.5 rounded-full", SEV_DOT[sev])} />
                        {sev} ({count})
                      </button>
                    );
                  })}
                </div>
              )}

              {/* Verification auth config */}
              <div className="rounded-lg border border-zinc-800 bg-zinc-900/40">
                <button
                  className="w-full flex items-center gap-2 px-3 py-2.5 hover:bg-zinc-800/30 transition-colors"
                  onClick={() => setShowVerifyAuth(v => !v)}
                >
                  <FlaskConical className="h-3.5 w-3.5 text-blue-400" />
                  <span className="text-xs font-medium text-zinc-300 flex-1 text-left">Active Verification Auth</span>
                  <span className="text-[10px] text-zinc-500">
                    {verifyHeaders.filter(h => h.key).length > 0 ? `${verifyHeaders.filter(h => h.key).length} header(s) configured` : "No auth — public endpoints only"}
                  </span>
                  {showVerifyAuth ? <ChevronDown className="h-3 w-3 text-zinc-500" /> : <ChevronRight className="h-3 w-3 text-zinc-500" />}
                </button>
                {showVerifyAuth && (
                  <div className="px-3 pb-3 pt-1 border-t border-zinc-800 space-y-2">
                    <p className="text-[11px] text-zinc-500">Headers sent with every Verify request. Add your Bearer token or session cookie here.</p>
                    {verifyHeaders.map((h, i) => (
                      <div key={i} className="flex items-center gap-1.5">
                        <Input placeholder="Header-Name" value={h.key}
                          onChange={e => setVerifyHeaders(p => p.map((x, j) => j === i ? { ...x, key: e.target.value } : x))}
                          className="font-mono text-xs h-7" />
                        <span className="text-zinc-600">:</span>
                        <Input placeholder="value" value={h.value}
                          onChange={e => setVerifyHeaders(p => p.map((x, j) => j === i ? { ...x, value: e.target.value } : x))}
                          className="font-mono text-xs h-7" />
                        <button onClick={() => setVerifyHeaders(p => p.filter((_, j) => j !== i))}
                          className="text-zinc-600 hover:text-zinc-300 transition-colors shrink-0">
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                    <div className="flex items-center justify-between">
                      <button onClick={() => setVerifyHeaders(p => [...p, { key: "", value: "" }])}
                        className="flex items-center gap-1 text-[11px] text-zinc-500 hover:text-zinc-300 transition-colors">
                        <Plus className="h-3 w-3" /> Add header
                      </button>
                      <label className="flex items-center gap-1.5 text-[11px] text-zinc-500 cursor-pointer">
                        <input type="checkbox" checked={verifySsl} onChange={e => setVerifySsl(e.target.checked)}
                          className="accent-blue-500" />
                        Verify SSL
                      </label>
                    </div>
                  </div>
                )}
              </div>

              {/* Main 2-col layout */}
              <div className={cn("grid gap-5", aiText ? "grid-cols-1 lg:grid-cols-5" : "grid-cols-1")}>
                {/* Test cases */}
                <div className={cn("space-y-3", aiText ? "lg:col-span-3" : "")}>
                  {sortedVulnTypes.length === 0 ? (
                    <div className="rounded-lg border border-zinc-800 p-8 text-center text-zinc-500 text-sm">
                      No test cases for the selected filter.
                    </div>
                  ) : (
                    sortedVulnTypes.map(vtype => (
                      <VulnGroup
                        key={vtype}
                        vulnType={vtype}
                        cases={filteredGrouped[vtype]}
                        authHeaders={verifyAuthHeaders}
                        verifySsl={verifySsl}
                      />
                    ))
                  )}
                </div>

                {/* AI */}
                {aiText && (
                  <Card className="lg:col-span-2 h-fit sticky top-4">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-xs font-semibold text-zinc-300 flex items-center gap-1.5">
                        <Brain className="h-3.5 w-3.5 text-orange-400" /> Claude AI Analysis
                        <CopyButton text={aiText} />
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div ref={aiScrollRef} className="max-h-[600px] overflow-y-auto text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap">
                        {aiText}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>

              {/* Auth flows */}
              {authFlows && <AuthFlowPanel flows={authFlows} />}

              {/* Param graph */}
              {paramGraph.length > 0 && <ParamGraph correlations={paramGraph} />}

              {/* Response findings */}
              {responseFindings.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-zinc-400 flex items-center gap-1.5">
                    <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
                    Direct Findings in Responses ({responseFindings.length})
                  </h4>
                  <div className="space-y-2">
                    {responseFindings.map((f, i) => <ResponseFindingRow key={i} finding={f} />)}
                  </div>
                </div>
              )}

              {/* Interesting endpoints */}
              {stats != null && (stats.interesting_endpoints?.length ?? 0) > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-zinc-400 flex items-center gap-1.5">
                    <Zap className="h-3.5 w-3.5 text-yellow-400" />
                    High-Priority Endpoints ({stats.interesting_endpoints.length})
                  </h4>
                  <div className="rounded-lg border border-zinc-800 overflow-hidden">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-zinc-800 bg-zinc-900/80">
                          <th className="text-left px-3 py-2 text-zinc-500 font-medium">Endpoint</th>
                          <th className="text-left px-3 py-2 text-zinc-500 font-medium">Type</th>
                          <th className="text-left px-3 py-2 text-zinc-500 font-medium">Auth</th>
                          <th className="text-left px-3 py-2 text-zinc-500 font-medium">Key Params</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-800/50">
                        {stats.interesting_endpoints.slice(0, 20).map((ep, i) => (
                          <tr key={i} className="hover:bg-zinc-800/30 transition-colors">
                            <td className="px-3 py-2 font-mono text-zinc-300 max-w-[200px] truncate">{ep.endpoint}</td>
                            <td className="px-3 py-2">
                              <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-medium", EP_CLASS_COLORS[ep.class] ?? "text-zinc-400 bg-zinc-800/30")}>
                                {ep.class}
                              </span>
                            </td>
                            <td className="px-3 py-2 text-zinc-500">{ep.auth_types.join(", ") || "—"}</td>
                            <td className="px-3 py-2 text-zinc-500 max-w-[160px] truncate">{ep.params.slice(0, 4).join(", ") || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
