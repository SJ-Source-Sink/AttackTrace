"use client";

import React, { useState, useCallback, useEffect } from "react";
import {
  GitBranch, Play, CheckCircle2, XCircle, AlertTriangle,
  History, Clock, Loader2, Copy, Download, RefreshCw, ArrowLeft,
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

// ── Types ─────────────────────────────────────────────────────────────────────

type Intensity = "passive" | "normal" | "aggressive" | "passive_due_diligence";
type Severity = "critical" | "high" | "medium" | "low";

interface GateResult {
  id: string;
  scan_id: string;
  status: string;
  target_domains: string[];
  findings_count: number;
  ci_failed: boolean;
  fail_reason: string | null;
  created_at: number;
  sarif?: Record<string, unknown>;
  github_action_snippet?: string;
}

const INTENSITY_OPTIONS: { value: Intensity; label: string }[] = [
  { value: "passive", label: "Passive (safest, read-only recon)" },
  { value: "normal", label: "Normal" },
  { value: "aggressive", label: "Aggressive" },
  { value: "passive_due_diligence", label: "Passive Due Diligence" },
];

const SEVERITY_OPTIONS: Severity[] = ["critical", "high", "medium", "low"];

// ── Page ──────────────────────────────────────────────────────────────────────

export default function CicdGatewayPage() {
  const [tab, setTab] = useState<"gate" | "history">("gate");

  // Config
  const [targetDomains, setTargetDomains] = useState("");
  const [intensity, setIntensity] = useState<Intensity>("passive");
  const [timeoutSeconds, setTimeoutSeconds] = useState(120);
  const [failOnSeverity, setFailOnSeverity] = useState<Severity>("high");
  const [companyName, setCompanyName] = useState("");

  // Run state
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<GateResult | null>(null);

  // History
  const [history, setHistory] = useState<GateResult[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyDetail, setHistoryDetail] = useState<GateResult | null>(null);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await fetchWithAuth(`${API_BASE}/cicd/history`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.items ?? []);
      }
    } catch {
      toast.error("Failed to load gate history");
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => { if (tab === "history") loadHistory(); }, [tab, loadHistory]);

  const openHistoryDetail = async (id: string) => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/cicd/history/${id}`);
      if (res.ok) setHistoryDetail(await res.json());
    } catch {
      toast.error("Failed to load scan detail");
    }
  };

  const restoreFromHistory = (h: GateResult) => {
    setTargetDomains((h.target_domains ?? []).join("\n"));
    setTab("gate");
    setHistoryDetail(null);
    toast.success("Restored target domains to the gate config");
  };

  const runGate = async () => {
    const domains = targetDomains
      .split(/[\n,]/)
      .map((d) => d.trim())
      .filter(Boolean);
    if (domains.length === 0) {
      toast.error("Enter at least one target domain");
      return;
    }

    setRunning(true);
    setResult(null);

    try {
      const res = await fetchWithAuth(`${API_BASE}/cicd/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_domains: domains,
          intensity,
          timeout_seconds: timeoutSeconds,
          fail_on_severity: failOnSeverity,
          company_name: companyName.trim() || null,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Gate check failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }

      const data: GateResult = await res.json();
      setResult(data);
      toast[data.ci_failed ? "error" : "success"](
        data.ci_failed ? "Gate FAILED — blocking findings found" : "Gate PASSED"
      );
    } catch (e: unknown) {
      toast.error("Gate check failed: " + ((e as Error)?.message ?? "Unknown error"));
    } finally {
      setRunning(false);
    }
  };

  const downloadSarif = (sarif: Record<string, unknown> | undefined, id: string) => {
    if (!sarif) {
      toast.error("No SARIF output available for this run");
      return;
    }
    const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `attacktrace-cicd-${id}.sarif.json`;
    a.click();
  };

  const copySnippet = (snippet: string | undefined) => {
    if (!snippet) return;
    navigator.clipboard.writeText(snippet).then(() => toast.success("Copied workflow snippet"));
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="CI/CD Gateway"
        description="Run a security gate check against target domains and get SARIF output for GitHub Actions / GitLab CI / Jenkins"
      />

      {/* Tab switcher */}
      <div className="flex gap-1 rounded-lg bg-zinc-900 border border-zinc-800 p-1 w-fit">
        <button
          onClick={() => setTab("gate")}
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors",
            tab === "gate" ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"
          )}
        >
          <GitBranch className="h-3.5 w-3.5" /> Gate Check
        </button>
        <button
          onClick={() => setTab("history")}
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors",
            tab === "history" ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"
          )}
        >
          <History className="h-3.5 w-3.5" /> History
        </button>
      </div>

      {tab === "gate" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Config */}
          <Card className="lg:col-span-1">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300">Gate Configuration</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Target Domains (one per line)</Label>
                <textarea
                  value={targetDomains}
                  onChange={(e) => setTargetDomains(e.target.value)}
                  placeholder={"example.com\napi.example.com"}
                  rows={4}
                  disabled={running}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-xs font-mono text-zinc-100 placeholder:text-zinc-600"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Intensity</Label>
                <select
                  value={intensity}
                  onChange={(e) => setIntensity(e.target.value as Intensity)}
                  disabled={running}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-md px-3 py-2 text-xs text-zinc-100"
                >
                  {INTENSITY_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Fail Build On Severity</Label>
                <select
                  value={failOnSeverity}
                  onChange={(e) => setFailOnSeverity(e.target.value as Severity)}
                  disabled={running}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-md px-3 py-2 text-xs text-zinc-100 capitalize"
                >
                  {SEVERITY_OPTIONS.map((s) => (
                    <option key={s} value={s} className="capitalize">{s} and above</option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Timeout (seconds, 30–600)</Label>
                <Input
                  type="number"
                  min={30}
                  max={600}
                  value={timeoutSeconds}
                  disabled={running}
                  onChange={(e) => setTimeoutSeconds(Number(e.target.value) || 120)}
                  className="text-xs"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Company Name (optional)</Label>
                <Input
                  value={companyName}
                  disabled={running}
                  onChange={(e) => setCompanyName(e.target.value)}
                  className="text-xs"
                />
              </div>

              <Button onClick={runGate} disabled={running} className="w-full gap-1.5">
                {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                {running ? "Running gate check..." : "Run Gate Check"}
              </Button>
              {running && (
                <p className="text-[10px] text-zinc-500">
                  This blocks until the scan finishes or the timeout is hit — up to {timeoutSeconds}s.
                </p>
              )}
            </CardContent>
          </Card>

          {/* Result */}
          <div className="lg:col-span-2 space-y-4">
            {!result && !running && (
              <div className="flex flex-col items-center justify-center h-64 text-zinc-600 border border-dashed border-zinc-800 rounded-lg">
                <GitBranch className="h-10 w-10 mb-3 opacity-40" />
                <p className="text-sm">Configure targets and run a gate check</p>
              </div>
            )}

            {result && (
              <>
                <Card className={cn("border", result.ci_failed ? "border-red-800/60 bg-red-950/10" : "border-emerald-800/60 bg-emerald-950/10")}>
                  <CardContent className="pt-4 space-y-3">
                    <div className="flex items-center gap-2">
                      {result.ci_failed ? (
                        <XCircle className="h-5 w-5 text-red-400" />
                      ) : (
                        <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                      )}
                      <span className={cn("text-sm font-semibold", result.ci_failed ? "text-red-400" : "text-emerald-400")}>
                        Gate {result.ci_failed ? "FAILED" : "PASSED"}
                      </span>
                      <Badge variant="outline" className="text-[10px] ml-auto">{result.status}</Badge>
                    </div>
                    {result.fail_reason && (
                      <p className="text-xs text-zinc-400 flex items-center gap-1.5">
                        <AlertTriangle className="h-3.5 w-3.5 text-orange-400 shrink-0" /> {result.fail_reason}
                      </p>
                    )}
                    <div className="flex items-center gap-4 text-xs text-zinc-400">
                      <span>{result.findings_count} findings</span>
                      <span className="font-mono text-zinc-600">{result.target_domains.join(", ")}</span>
                    </div>
                    <div className="flex gap-2 pt-1">
                      <Button size="sm" variant="outline" className="gap-1.5" onClick={() => downloadSarif(result.sarif, result.id)}>
                        <Download className="h-3.5 w-3.5" /> Download SARIF
                      </Button>
                      <Button size="sm" variant="outline" className="gap-1.5" onClick={() => copySnippet(result.github_action_snippet)}>
                        <Copy className="h-3.5 w-3.5" /> Copy CI Snippet
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                {result.github_action_snippet && (
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-xs font-semibold text-zinc-400">GitHub Actions Snippet</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <pre className="text-[10px] font-mono text-zinc-400 bg-zinc-950 rounded p-3 overflow-x-auto whitespace-pre-wrap border border-zinc-800">
                        {result.github_action_snippet}
                      </pre>
                    </CardContent>
                  </Card>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {tab === "history" && (
        <div className="space-y-4">
          {historyDetail ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <Button variant="ghost" size="sm" onClick={() => setHistoryDetail(null)} className="gap-1.5 text-zinc-400">
                  <ArrowLeft className="h-4 w-4" /> Back to history
                </Button>
                <Button size="sm" variant="outline" className="gap-1.5 ml-auto" onClick={() => restoreFromHistory(historyDetail)}>
                  <RefreshCw className="h-3.5 w-3.5" /> Restore to Gate
                </Button>
              </div>
              <Card className={cn("border", historyDetail.ci_failed ? "border-red-800/60" : "border-emerald-800/60")}>
                <CardContent className="pt-4 space-y-2">
                  <div className="flex items-center gap-2">
                    {historyDetail.ci_failed ? (
                      <XCircle className="h-4 w-4 text-red-400" />
                    ) : (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    )}
                    <span className="text-sm font-semibold text-zinc-200">
                      {historyDetail.ci_failed ? "Failed" : "Passed"}
                    </span>
                    <span className="text-xs text-zinc-500 ml-auto">
                      {new Date(historyDetail.created_at * 1000).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-zinc-400">{(historyDetail.target_domains ?? []).join(", ")}</p>
                  <p className="text-xs text-zinc-500">{historyDetail.findings_count} findings · status: {historyDetail.status}</p>
                  {historyDetail.fail_reason && (
                    <p className="text-xs text-orange-400">{historyDetail.fail_reason}</p>
                  )}
                </CardContent>
              </Card>
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <p className="text-xs text-zinc-500">{history.length} gate check{history.length !== 1 ? "s" : ""} on record</p>
                <button onClick={loadHistory} className="text-[10px] text-zinc-500 hover:text-zinc-300 flex items-center gap-1">
                  <RefreshCw className="h-3 w-3" /> Refresh
                </button>
              </div>

              {historyLoading && (
                <div className="flex items-center justify-center py-16">
                  <Loader2 className="h-6 w-6 animate-spin text-zinc-600" />
                </div>
              )}

              {!historyLoading && history.length === 0 && (
                <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-16 text-center">
                  <History className="h-10 w-10 text-zinc-700 mb-3" />
                  <p className="text-sm font-medium text-zinc-500">No gate checks yet</p>
                  <p className="text-xs text-zinc-600 mt-1">Runs from the CI/CD API or this page will appear here.</p>
                </div>
              )}

              {!historyLoading && history.length > 0 && (
                <div className="space-y-2">
                  {history.map((h) => (
                    <div
                      key={h.id}
                      onClick={() => openHistoryDetail(h.id)}
                      className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-4 cursor-pointer transition-colors hover:border-zinc-600"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            {h.ci_failed ? (
                              <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                            ) : (
                              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                            )}
                            <span className="text-xs font-mono text-zinc-300 truncate">
                              {(h.target_domains ?? []).join(", ")}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-[10px] text-zinc-500 mt-1">
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {new Date(h.created_at * 1000).toLocaleString()}
                            </span>
                            <span>{h.findings_count} findings</span>
                          </div>
                        </div>
                        <Badge className={cn("text-[10px] border shrink-0", h.ci_failed ? "bg-red-500/20 text-red-400 border-red-500/30" : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30")}>
                          {h.ci_failed ? "FAILED" : "PASSED"}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
