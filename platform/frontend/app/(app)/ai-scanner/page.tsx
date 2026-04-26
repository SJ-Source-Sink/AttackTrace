"use client";

import React, { useState, useRef, useCallback } from "react";
import {
  Bot,
  Play,
  Square,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
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

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface AIEndpoint {
  url: string;
  type: string;
  authenticated: boolean;
  details?: string;
}

interface OWASPFinding {
  test: string;
  severity: Severity;
  description: string;
  endpoint: string;
  evidence?: string;
}

interface ScanResult {
  endpoints: AIEndpoint[];
  findings: OWASPFinding[];
  summary: {
    total_discovered: number;
    unauthenticated: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-zinc-700/50 text-zinc-400 border-zinc-600/30",
};

const OWASP_LLM_TESTS = [
  { id: "llm01", label: "LLM01 - Prompt Injection", desc: "Test for prompt injection vulnerabilities" },
  { id: "llm02", label: "LLM02 - Insecure Output Handling", desc: "Check for unsafe output rendering" },
  { id: "llm03", label: "LLM03 - Training Data Poisoning", desc: "Probe for training data leakage" },
  { id: "llm06", label: "LLM06 - Sensitive Information Disclosure", desc: "Test for PII/credential leakage" },
  { id: "llm09", label: "LLM09 - Overreliance", desc: "Check for hallucination-based vulnerabilities" },
  { id: "llm10", label: "LLM10 - Model Theft", desc: "Test for model extraction risks" },
];

export default function AIScannerPage() {
  const [target, setTarget] = useState("");
  const [enableOWASP, setEnableOWASP] = useState(true);
  const [selectedTests, setSelectedTests] = useState<string[]>(OWASP_LLM_TESTS.map((t) => t.id));
  const [isScanning, setIsScanning] = useState(false);
  const [rawLines, setRawLines] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [showRaw, setShowRaw] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const rawEndRef = useRef<HTMLDivElement>(null);

  const toggleTest = (id: string) => {
    setSelectedTests((prev) =>
      prev.includes(id) ? prev.filter((t) => t !== id) : [...prev, id]
    );
  };

  const startScan = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target URL");
      return;
    }

    setIsScanning(true);
    setScanStatus("running");
    setRawLines([]);
    setResult(null);
    abortRef.current = new AbortController();

    try {
      const res = await fetchWithAuth(`${API_BASE}/ai-scanner/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          owasp_tests: enableOWASP ? selectedTests : [],
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
          const eventMatch = part.match(/^event: (\w+)/m);
          const dataMatch = part.match(/^data: ([\s\S]+)/m);
          if (!eventMatch || !dataMatch) continue;

          const event = eventMatch[1];
          const data = JSON.parse(dataMatch[1]);

          if (event === "progress") {
            setRawLines((prev) => {
              const next = [...prev, data.message ?? data.line ?? JSON.stringify(data)];
              setTimeout(() => rawEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
              return next;
            });
          } else if (event === "output") {
            setRawLines((prev) => {
              const next = [...prev, data.line ?? JSON.stringify(data)];
              setTimeout(() => rawEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
              return next;
            });
          } else if (event === "complete") {
            setResult(data);
            setScanStatus("completed");
            setIsScanning(false);
            const total = data.summary?.total_discovered ?? 0;
            const unauth = data.summary?.unauthenticated ?? 0;
            toast.success(`Scan completed — ${total} endpoint(s) found, ${unauth} unauthenticated`);
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
  }, [target, enableOWASP, selectedTests]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI/LLM Scanner"
        description="Discover exposed AI endpoints and test for OWASP LLM Top 10 vulnerabilities"
      >
        {scanStatus === "running" && (
          <Button variant="destructive" size="sm" onClick={stopScan} className="gap-1.5">
            <Square className="h-3.5 w-3.5" /> Stop
          </Button>
        )}
      </PageHeader>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Config panel */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Bot className="h-4 w-4 text-blue-400" />
                Scan Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
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
                <p className="text-[10px] text-zinc-600">Base URL to scan for AI/LLM endpoints</p>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-zinc-400">OWASP LLM Tests</Label>
                  <button
                    type="button"
                    onClick={() => setEnableOWASP((v) => !v)}
                    className={cn(
                      "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                      enableOWASP ? "bg-blue-600" : "bg-zinc-700"
                    )}
                  >
                    <span
                      className={cn(
                        "inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform",
                        enableOWASP ? "translate-x-4.5" : "translate-x-0.5"
                      )}
                    />
                  </button>
                </div>

                {enableOWASP && (
                  <div className="space-y-2">
                    {OWASP_LLM_TESTS.map((test) => (
                      <label
                        key={test.id}
                        className="flex items-start gap-2 cursor-pointer group"
                      >
                        <input
                          type="checkbox"
                          checked={selectedTests.includes(test.id)}
                          onChange={() => toggleTest(test.id)}
                          disabled={isScanning}
                          className="mt-0.5 accent-blue-500"
                        />
                        <div>
                          <p className="text-xs font-medium text-zinc-300 group-hover:text-zinc-100 transition-colors">
                            {test.label}
                          </p>
                          <p className="text-[10px] text-zinc-600">{test.desc}</p>
                        </div>
                      </label>
                    ))}
                  </div>
                )}
              </div>

              <Button
                onClick={isScanning ? stopScan : startScan}
                className={cn("w-full gap-2", isScanning ? "bg-red-600 hover:bg-red-700" : "")}
                disabled={!target.trim() && !isScanning}
              >
                {isScanning ? (
                  <>
                    <Square className="h-4 w-4" /> Stop Scan
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" /> Start Scan
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Status */}
          {scanStatus !== "idle" && (
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-2">
                  {scanStatus === "running" && (
                    <>
                      <div className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
                      <span className="text-xs text-blue-400">Scanning in progress...</span>
                    </>
                  )}
                  {scanStatus === "completed" && (
                    <>
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                      <span className="text-xs text-emerald-400">Scan completed</span>
                    </>
                  )}
                  {scanStatus === "failed" && (
                    <>
                      <XCircle className="h-4 w-4 text-red-400" />
                      <span className="text-xs text-red-400">Scan failed</span>
                    </>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Results panel */}
        <div className="lg:col-span-2 space-y-4">
          {/* Summary cards */}
          {result && (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Card>
                <CardContent className="pt-4 pb-3">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Discovered</p>
                  <p className="text-2xl font-bold text-zinc-100">{result.summary.total_discovered}</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4 pb-3">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Unauthenticated</p>
                  <p className="text-2xl font-bold text-orange-400">{result.summary.unauthenticated}</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4 pb-3">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Critical</p>
                  <p className="text-2xl font-bold text-red-400">{result.summary.critical}</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4 pb-3">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">High</p>
                  <p className="text-2xl font-bold text-orange-400">{result.summary.high}</p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Discovered endpoints */}
          {result && result.endpoints.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300">
                  Discovered AI Endpoints ({result.endpoints.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-zinc-800">
                        <th className="pb-2 text-left font-semibold text-zinc-500">URL</th>
                        <th className="pb-2 text-left font-semibold text-zinc-500">Type</th>
                        <th className="pb-2 text-left font-semibold text-zinc-500">Auth</th>
                        <th className="pb-2 text-left font-semibold text-zinc-500">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/50">
                      {result.endpoints.map((ep, i) => (
                        <tr key={i} className="hover:bg-zinc-800/30 transition-colors">
                          <td className="py-2 pr-3 font-mono text-blue-400 break-all max-w-xs">{ep.url}</td>
                          <td className="py-2 pr-3">
                            <Badge variant="outline" className="text-xs font-normal">{ep.type}</Badge>
                          </td>
                          <td className="py-2 pr-3">
                            {ep.authenticated ? (
                              <span className="flex items-center gap-1 text-emerald-400">
                                <CheckCircle2 className="h-3 w-3" /> Auth
                              </span>
                            ) : (
                              <span className="flex items-center gap-1 text-red-400">
                                <XCircle className="h-3 w-3" /> Open
                              </span>
                            )}
                          </td>
                          <td className="py-2 text-zinc-500 truncate max-w-xs">{ep.details ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          {/* OWASP findings */}
          {result && result.findings.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-400" />
                  OWASP LLM Findings ({result.findings.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {result.findings.map((f, i) => (
                    <div
                      key={i}
                      className="rounded-md border border-zinc-800 bg-zinc-900/50 p-3 space-y-1"
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge className={cn("text-xs border", SEVERITY_STYLES[f.severity])}>
                          {f.severity.toUpperCase()}
                        </Badge>
                        <span className="text-xs font-semibold text-zinc-300">{f.test}</span>
                        <span className="text-xs font-mono text-blue-400 ml-auto">{f.endpoint}</span>
                      </div>
                      <p className="text-xs text-zinc-400">{f.description}</p>
                      {f.evidence && (
                        <pre className="text-[10px] font-mono text-zinc-500 bg-zinc-950 rounded p-2 overflow-x-auto">
                          {f.evidence}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Live output */}
          {rawLines.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <button
                  className="flex w-full items-center justify-between"
                  onClick={() => setShowRaw((v) => !v)}
                >
                  <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                    <Bot className="h-4 w-4 text-zinc-400" />
                    Live Output ({rawLines.length} lines)
                  </CardTitle>
                  {showRaw ? <ChevronUp className="h-4 w-4 text-zinc-500" /> : <ChevronDown className="h-4 w-4 text-zinc-500" />}
                </button>
              </CardHeader>
              {showRaw && (
                <CardContent>
                  <div className="bg-zinc-950 rounded-md p-3 max-h-64 overflow-y-auto font-mono text-xs text-zinc-400">
                    {rawLines.map((line, i) => (
                      <div key={i} className="leading-5">{line}</div>
                    ))}
                    <div ref={rawEndRef} />
                  </div>
                </CardContent>
              )}
            </Card>
          )}

          {scanStatus === "idle" && rawLines.length === 0 && (
            <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-16 text-center">
              <Bot className="h-10 w-10 text-zinc-700 mb-3" />
              <p className="text-sm font-medium text-zinc-500">No scan running</p>
              <p className="text-xs text-zinc-600 mt-1">Enter a target and click Start Scan to discover AI/LLM endpoints</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
