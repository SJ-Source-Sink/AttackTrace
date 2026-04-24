"use client";

import React, { useState, useRef, useCallback } from "react";
import {
  Upload, FileText, X, Play, Loader2, ChevronDown, ChevronRight,
  Copy, Check, AlertTriangle, Shield, Zap, Brain, Globe,
  Lock, Search, Code2, Server, Bug, RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
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
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
  info:     "bg-zinc-500",
};

const VULN_ICONS: Record<string, React.ReactNode> = {
  idor:           <Lock className="h-3.5 w-3.5" />,
  sqli:           <Code2 className="h-3.5 w-3.5" />,
  xss:            <Bug className="h-3.5 w-3.5" />,
  ssrf:           <Server className="h-3.5 w-3.5" />,
  open_redirect:  <Globe className="h-3.5 w-3.5" />,
  path_traversal: <Search className="h-3.5 w-3.5" />,
  csrf:           <Shield className="h-3.5 w-3.5" />,
  ssti:           <Code2 className="h-3.5 w-3.5" />,
  jwt_attack:     <Lock className="h-3.5 w-3.5" />,
  brute_force:    <Zap className="h-3.5 w-3.5" />,
  auth_bypass:    <Shield className="h-3.5 w-3.5" />,
  file_upload:    <Upload className="h-3.5 w-3.5" />,
  mass_assignment:<AlertTriangle className="h-3.5 w-3.5" />,
  business_logic: <AlertTriangle className="h-3.5 w-3.5" />,
  info_disclosure:<Globe className="h-3.5 w-3.5" />,
  account_takeover:<Lock className="h-3.5 w-3.5" />,
};

const VULN_LABELS: Record<string, string> = {
  idor: "IDOR", sqli: "SQL Injection", xss: "XSS",
  ssrf: "SSRF", open_redirect: "Open Redirect", path_traversal: "Path Traversal",
  csrf: "CSRF", ssti: "SSTI", jwt_attack: "JWT Attack",
  brute_force: "Brute Force", auth_bypass: "Auth Bypass", file_upload: "File Upload",
  mass_assignment: "Mass Assignment", business_logic: "Business Logic",
  info_disclosure: "Info Disclosure", account_takeover: "Account Takeover",
  sqli_exposure: "SQL Error", secret_exposure: "Secret Exposure",
  jwt_exposure: "JWT Exposure",
};

const EP_CLASS_COLORS: Record<string, string> = {
  admin:       "text-red-400 bg-red-950/30",
  auth:        "text-orange-400 bg-orange-950/30",
  payment:     "text-yellow-400 bg-yellow-950/30",
  file_upload: "text-purple-400 bg-purple-950/30",
  debug:       "text-red-400 bg-red-950/30",
  export:      "text-blue-400 bg-blue-950/30",
  user_data:   "text-cyan-400 bg-cyan-950/30",
  api:         "text-zinc-300 bg-zinc-800/30",
  webhook:     "text-zinc-400 bg-zinc-800/30",
  password:    "text-orange-400 bg-orange-950/30",
};

// ─── Small helpers ────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button
      onClick={copy}
      className="ml-1 p-0.5 rounded text-zinc-500 hover:text-zinc-300 transition-colors"
      title="Copy"
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
      {sub && <div className="text-[10px] text-zinc-600 mt-0.5">{sub}</div>}
    </div>
  );
}

// ─── Test case card ───────────────────────────────────────────────────────────

function TestCaseCard({ tc }: { tc: TestCase }) {
  const [open, setOpen] = useState(false);

  return (
    <div className={cn("rounded border transition-colors", open ? "border-zinc-700 bg-zinc-900/80" : "border-zinc-800 bg-zinc-900/30 hover:border-zinc-700")}>
      <button
        className="w-full text-left flex items-start gap-2 p-3"
        onClick={() => setOpen(o => !o)}
      >
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
          {/* Description */}
          <p className="text-xs text-zinc-400 leading-relaxed">{tc.description}</p>

          {/* Rationale */}
          <div className="rounded bg-zinc-800/50 p-2">
            <p className="text-[11px] text-zinc-500"><span className="text-zinc-400 font-medium">Why:</span> {tc.rationale}</p>
          </div>

          {/* CWE / OWASP */}
          <div className="flex items-center gap-3 text-[10px] text-zinc-500">
            <span><span className="text-zinc-400">{tc.cwe}</span></span>
            <span className="text-zinc-700">•</span>
            <span>{tc.owasp}</span>
          </div>

          {/* Steps */}
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

          {/* Payloads */}
          {tc.payloads.length > 0 && (
            <div>
              <p className="text-[11px] font-medium text-zinc-400 mb-1.5">Payloads</p>
              <div className="space-y-1">
                {tc.payloads.map((pl, i) => (
                  <div key={i} className="flex items-center gap-1 rounded bg-zinc-950 border border-zinc-800 px-2 py-1">
                    <code className="text-[11px] text-green-400 font-mono flex-1 break-all">{pl}</code>
                    <CopyButton text={pl} />
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

// ─── Vuln group accordion ─────────────────────────────────────────────────────

function VulnGroup({ vulnType, cases }: { vulnType: string; cases: TestCase[] }) {
  const [open, setOpen] = useState(true);

  const worst = cases.reduce<string>((acc, tc) => {
    const order = ["critical", "high", "medium", "low", "info"];
    return order.indexOf(tc.severity) < order.indexOf(acc) ? tc.severity : acc;
  }, "info");

  return (
    <div className="rounded-lg border border-zinc-800 overflow-hidden">
      <button
        className="w-full flex items-center gap-2.5 px-3 py-2.5 bg-zinc-900/80 hover:bg-zinc-800/60 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <span className="text-zinc-400">{VULN_ICONS[vulnType] ?? <Bug className="h-3.5 w-3.5" />}</span>
        <span className="text-xs font-semibold text-zinc-200 flex-1 text-left">
          {VULN_LABELS[vulnType] ?? vulnType}
        </span>
        <SevBadge severity={worst} />
        <span className="text-[11px] text-zinc-500 ml-1">{cases.length}</span>
        {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
      </button>
      {open && (
        <div className="divide-y divide-zinc-800/50">
          {cases.map(tc => <TestCaseCard key={tc.id} tc={tc} />)}
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

// ─── Main component ───────────────────────────────────────────────────────────

export function BurpImport() {
  const [file, setFile]           = useState<File | null>(null);
  const [aiAnalysis, setAi]       = useState(true);
  const [status, setStatus]       = useState<"idle" | "analyzing" | "complete" | "error">("idle");
  const [progress, setProgress]   = useState("");
  const [stats, setStats]         = useState<AnalysisStats | null>(null);
  const [testCases, setTestCases] = useState<TestCase[]>([]);
  const [responseFindings, setResponseFindings] = useState<ResponseFinding[]>([]);
  const [aiText, setAiText]       = useState("");
  const [isDragging, setDragging] = useState(false);
  const [sevFilter, setSevFilter] = useState<string | null>(null);

  const fileInputRef  = useRef<HTMLInputElement>(null);
  const aiScrollRef   = useRef<HTMLDivElement>(null);
  const abortRef      = useRef<AbortController | null>(null);

  // ── File drop / select ──────────────────────────────────────────────────────

  const handleFile = (f: File) => {
    if (!f.name.endsWith(".xml") && !f.name.endsWith(".burp")) {
      toast.error("Please upload a Burp Suite XML export (.xml)");
      return;
    }
    setFile(f);
    resetResults();
  };

  const resetResults = () => {
    setStats(null);
    setTestCases([]);
    setResponseFindings([]);
    setAiText("");
    setProgress("");
    setStatus("idle");
  };

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }, []);

  // ── Analysis ────────────────────────────────────────────────────────────────

  const startAnalysis = async () => {
    if (!file) return;

    setStatus("analyzing");
    setProgress("Uploading file…");
    setTestCases([]);
    setResponseFindings([]);
    setAiText("");
    setStats(null);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("ai_analysis", String(aiAnalysis));

    abortRef.current = new AbortController();

    try {
      const resp = await fetchWithAuth(`${API_BASE}/attack-suite/burp/analyze`, {
        method: "POST",
        body: formData,
        signal: abortRef.current.signal,
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Request failed" }));
        throw new Error(err.detail ?? "Analysis failed");
      }

      const reader  = resp.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let currentEvent = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (line.startsWith("event: ")) {
            currentEvent = line.slice(7).trim();
          } else if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              handleEvent(currentEvent, data);
            } catch {
              // ignore malformed
            }
          }
        }
      }

      setStatus("complete");
    } catch (err: unknown) {
      if ((err as Error).name === "AbortError") return;
      setStatus("error");
      setProgress(`Error: ${(err as Error).message}`);
      toast.error((err as Error).message);
    }
  };

  const handleEvent = (event: string, data: Record<string, unknown>) => {
    switch (event) {
      case "parsed":
        setProgress(data.message as string);
        break;
      case "profiled":
        setProgress(data.message as string);
        break;
      case "progress":
        setProgress(data.message as string);
        break;
      case "response_finding":
        setResponseFindings(prev => [...prev, data as unknown as ResponseFinding]);
        break;
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
      case "ai_start":
        setProgress(data.message as string);
        break;
      case "ai_chunk":
        setAiText(prev => {
          const next = prev + (data.text as string);
          setTimeout(() => {
            if (aiScrollRef.current) {
              aiScrollRef.current.scrollTop = aiScrollRef.current.scrollHeight;
            }
          }, 0);
          return next;
        });
        break;
      case "ai_error":
        setProgress(data.message as string);
        break;
      case "complete":
        setStats(prev => ({
          total_requests:   data.total_requests as number,
          unique_hosts:     data.unique_hosts as string[] ?? [],
          unique_endpoints: data.unique_endpoints as number,
          tech_stack:       data.tech_stack as string[] ?? [],
          auth_mechanisms:  data.auth_mechanisms as string[] ?? [],
          test_cases:       data.test_cases as number,
          response_findings:data.response_findings as number,
          severity_counts:  data.severity_counts as Record<string, number> ?? {},
          interesting_endpoints: prev?.interesting_endpoints ?? [],
        }));
        setStatus("complete");
        setProgress("Analysis complete");
        break;
      case "error":
        setStatus("error");
        setProgress(data.message as string);
        break;
    }
  };

  const stop = () => {
    abortRef.current?.abort();
    setStatus("idle");
  };

  // ── Derived state ───────────────────────────────────────────────────────────

  const grouped = testCases.reduce<Record<string, TestCase[]>>((acc, tc) => {
    (acc[tc.vuln_type] ??= []).push(tc);
    return acc;
  }, {});

  const filteredGrouped = sevFilter
    ? Object.fromEntries(
        Object.entries(grouped).map(([k, v]) => [k, v.filter(tc => tc.severity === sevFilter)])
          .filter(([, v]) => v.length > 0)
      )
    : grouped;

  type SevLevel = "critical" | "high" | "medium" | "low" | "info";
  const SEV_ORDER: SevLevel[] = ["critical", "high", "medium", "low", "info"];
  const worstSev = (tcs: TestCase[]): number => {
    const best = tcs.reduce<SevLevel>((w, tc) => {
      const s = tc.severity as SevLevel;
      return SEV_ORDER.indexOf(s) < SEV_ORDER.indexOf(w) ? s : w;
    }, "info");
    return SEV_ORDER.indexOf(best);
  };
  const sortedVulnTypes = Object.keys(filteredGrouped).sort(
    (a, b) => worstSev(filteredGrouped[a]) - worstSev(filteredGrouped[b])
  );

  // ── Render: Upload zone ─────────────────────────────────────────────────────

  if (status === "idle" && !stats) {
    return (
      <div className="space-y-5">
        {/* Upload zone */}
        <div
          className={cn(
            "relative rounded-xl border-2 border-dashed transition-all cursor-pointer",
            isDragging
              ? "border-orange-500 bg-orange-950/20"
              : file
              ? "border-zinc-600 bg-zinc-900/60"
              : "border-zinc-700 bg-zinc-900/30 hover:border-zinc-600 hover:bg-zinc-900/50"
          )}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => !file && fileInputRef.current?.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".xml,.burp"
            className="hidden"
            onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
          />

          <div className="p-10 text-center">
            {file ? (
              <div className="space-y-3">
                <div className="flex items-center justify-center gap-3">
                  <div className="p-3 rounded-lg bg-orange-950/40 border border-orange-800/40">
                    <FileText className="h-6 w-6 text-orange-400" />
                  </div>
                  <div className="text-left">
                    <p className="text-sm font-semibold text-zinc-200">{file.name}</p>
                    <p className="text-xs text-zinc-500">{(file.size / 1024).toFixed(1)} KB</p>
                  </div>
                  <button
                    className="ml-4 p-1.5 rounded hover:bg-zinc-800 text-zinc-500 hover:text-zinc-300 transition-colors"
                    onClick={e => { e.stopPropagation(); setFile(null); }}
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
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

        {/* Options + Analyse */}
        {file && (
          <div className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="flex items-center gap-2.5">
              <Switch
                id="ai-toggle"
                checked={aiAnalysis}
                onCheckedChange={setAi}
                className="data-[state=checked]:bg-orange-600"
              />
              <Label htmlFor="ai-toggle" className="text-sm text-zinc-300 flex items-center gap-1.5 cursor-pointer">
                <Brain className="h-3.5 w-3.5 text-orange-400" />
                Claude AI deep analysis
                <span className="text-xs text-zinc-600">(recommended)</span>
              </Label>
            </div>
            <Button
              onClick={startAnalysis}
              className="bg-orange-600 hover:bg-orange-700 text-white gap-1.5"
            >
              <Play className="h-3.5 w-3.5" />
              Analyse
            </Button>
          </div>
        )}

        {/* Hint when no file */}
        {!file && (
          <p className="text-center text-xs text-zinc-600">
            Supports Burp Suite HTTP history exports up to 500 MB · up to 20,000 requests
          </p>
        )}
      </div>
    );
  }

  // ── Render: Analysing ───────────────────────────────────────────────────────

  if (status === "analyzing") {
    return (
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

        {/* Live counters */}
        {(testCases.length > 0 || responseFindings.length > 0) && (
          <div className="grid grid-cols-3 gap-3">
            <StatCard label="Test Cases" value={testCases.length} />
            <StatCard label="Response Findings" value={responseFindings.length} />
            <StatCard label="Vuln Types" value={Object.keys(grouped).length} />
          </div>
        )}

        {/* Live test case stream */}
        {testCases.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold text-zinc-400">
                Generating test cases…
              </CardTitle>
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

        {/* AI streaming */}
        {aiText && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold text-zinc-400 flex items-center gap-1.5">
                <Brain className="h-3.5 w-3.5 text-orange-400" />
                Claude AI Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div
                ref={aiScrollRef}
                className="max-h-48 overflow-y-auto text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap font-mono"
              >
                {aiText}
                <span className="animate-pulse text-orange-400">▍</span>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    );
  }

  // ── Render: Results ─────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-zinc-200">Analysis Results</h3>
          {file && <span className="text-xs text-zinc-500">{file.name}</span>}
        </div>
        <Button
          variant="outline" size="sm"
          onClick={() => { setFile(null); resetResults(); }}
          className="gap-1.5 text-xs"
        >
          <RefreshCw className="h-3 w-3" /> New Analysis
        </Button>
      </div>

      {/* Stats grid */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Requests Parsed" value={stats.total_requests.toLocaleString()} sub={stats.unique_hosts.slice(0, 2).join(", ")} />
          <StatCard label="Unique Endpoints" value={stats.unique_endpoints.toLocaleString()} />
          <StatCard label="Test Cases" value={testCases.length.toLocaleString()} />
          <StatCard label="Response Findings" value={responseFindings.length.toLocaleString()} />
        </div>
      )}

      {/* Tech + Auth pills */}
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

      {/* Severity breakdown */}
      {stats && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] text-zinc-500">Filter:</span>
          <button
            onClick={() => setSevFilter(null)}
            className={cn("px-2 py-0.5 rounded text-[11px] transition-colors", !sevFilter ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300")}
          >
            All ({testCases.length})
          </button>
          {SEV_ORDER.map(sev => {
            const count = testCases.filter(tc => tc.severity === sev).length;
            if (!count) return null;
            return (
              <button
                key={sev}
                onClick={() => setSevFilter(sevFilter === sev ? null : sev)}
                className={cn(
                  "px-2 py-0.5 rounded text-[11px] flex items-center gap-1 transition-colors border",
                  sevFilter === sev
                    ? SEV_COLORS[sev]
                    : "text-zinc-500 border-zinc-700 hover:text-zinc-300 hover:border-zinc-600"
                )}
              >
                <span className={cn("h-1.5 w-1.5 rounded-full", SEV_DOT[sev])} />
                {sev} ({count})
              </button>
            );
          })}
        </div>
      )}

      {/* Main content: test cases + AI */}
      <div className={cn("grid gap-5", aiText ? "grid-cols-1 lg:grid-cols-5" : "grid-cols-1")}>
        {/* Test cases */}
        <div className={cn("space-y-3", aiText ? "lg:col-span-3" : "")}>
          {sortedVulnTypes.length === 0 ? (
            <div className="rounded-lg border border-zinc-800 p-8 text-center text-zinc-500 text-sm">
              No test cases found for the selected filter.
            </div>
          ) : (
            sortedVulnTypes.map(vtype => (
              <VulnGroup key={vtype} vulnType={vtype} cases={filteredGrouped[vtype]} />
            ))
          )}
        </div>

        {/* AI Analysis */}
        {aiText && (
          <Card className="lg:col-span-2 h-fit sticky top-4">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold text-zinc-300 flex items-center gap-1.5">
                <Brain className="h-3.5 w-3.5 text-orange-400" />
                Claude AI Analysis
                <CopyButton text={aiText} />
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div
                ref={aiScrollRef}
                className="max-h-[600px] overflow-y-auto text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap"
              >
                {aiText}
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Response Findings */}
      {responseFindings.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-zinc-400 flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
            Direct Findings in Responses ({responseFindings.length})
          </h4>
          <div className="space-y-2">
            {responseFindings.map((f, i) => (
              <ResponseFindingRow key={i} finding={f} />
            ))}
          </div>
        </div>
      )}

      {/* Interesting endpoints */}
      {stats?.interesting_endpoints && stats.interesting_endpoints.length > 0 && (
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
                    <td className="px-3 py-2 font-mono text-zinc-300 max-w-[200px] truncate">
                      {ep.endpoint}
                    </td>
                    <td className="px-3 py-2">
                      <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-medium", EP_CLASS_COLORS[ep.class] ?? "text-zinc-400 bg-zinc-800/30")}>
                        {ep.class}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-zinc-500">
                      {ep.auth_types.join(", ") || "—"}
                    </td>
                    <td className="px-3 py-2 text-zinc-500 max-w-[160px] truncate">
                      {ep.params.slice(0, 4).join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
