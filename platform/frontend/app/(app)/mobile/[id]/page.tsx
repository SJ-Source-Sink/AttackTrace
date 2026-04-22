"use client";

import React, { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft, Download, RefreshCw, ChevronDown, ChevronRight,
  CheckCircle2, Clock, XCircle, Shield, Smartphone,
  Code2, Zap, Activity, Play, Loader2, Terminal,
  AlertTriangle, Info,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const SEV_COLORS: Record<string, string> = {
  Critical: "bg-red-500/10 text-red-400 border-red-500/30",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  Low:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
  Info:     "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

const SEV_ROW_ACCENT: Record<string, string> = {
  Critical: "border-l-red-500",
  High:     "border-l-orange-500",
  Medium:   "border-l-yellow-500",
  Low:      "border-l-blue-400",
  Info:     "border-l-zinc-600",
};

const TRIAGE_COLORS: Record<string, string> = {
  true_positive:  "bg-red-500/10 text-red-400 border-red-500/30",
  false_positive: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
  needs_review:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
};

const JOB_STATUS_COLOR: Record<string, string> = {
  queued:    "text-zinc-400",
  running:   "text-blue-400",
  completed: "text-emerald-400",
  failed:    "text-red-400",
};

interface Finding {
  id: number;
  title: string;
  severity: string;
  category: string;
  description: string;
  cwe?: string[];
  triage_status?: string;
  poc?: string;
  evidence?: string;
  remediation?: string;
}

interface FindingsResponse {
  apk: string;
  package: string;
  scan_time: string;
  total_findings: number;
  severity_counts: Record<string, number>;
  findings: Finding[];
}

interface DynJob {
  job_id: string;
  finding_title: string;
  status: string;
  progress: number;
  message: string;
  logcat?: string;
  evidence?: string;
}

// ── Status badge ─────────────────────────────────────────────────────────────

function StatusPill({ status }: { status: string }) {
  if (status === "completed" || status === "done")
    return <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400"><CheckCircle2 className="h-3 w-3" /> Completed</span>;
  if (status === "scanning" || status === "processing" || status === "pending" || status === "queued")
    return <span className="inline-flex items-center gap-1.5 text-xs text-blue-400"><Clock className="h-3 w-3 animate-pulse" /> Scanning</span>;
  if (status === "failed" || status === "error")
    return <span className="inline-flex items-center gap-1.5 text-xs text-red-400"><XCircle className="h-3 w-3" /> Failed</span>;
  return <span className="inline-flex items-center gap-1.5 text-xs text-zinc-400"><Clock className="h-3 w-3" /> {status}</span>;
}

// ── Finding row ───────────────────────────────────────────────────────────────

function FindingRow({
  finding,
  idx,
  scanId,
  onRunDynamic,
}: {
  finding: Finding;
  idx: number;
  scanId: string;
  onRunDynamic: (finding: Finding, idx: number) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [loadingPoc, setLoadingPoc] = useState(false);
  const [poc, setPoc] = useState<string | null>(finding.poc ?? null);
  const queryClient = useQueryClient();

  const triageMutation = useMutation({
    mutationFn: async (status: string) => {
      const res = await fetchWithAuth(
        `${API_BASE}/mobile/scans/${scanId}/findings/${finding.id}/triage`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ triage_status: status }),
        },
      );
      if (!res.ok) throw new Error("Triage failed");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mobile", "scan", scanId] });
      toast.success("Triage updated");
    },
    onError: () => toast.error("Failed to update triage"),
  });

  const generatePoc = async () => {
    setLoadingPoc(true);
    try {
      const res = await fetchWithAuth(`${API_BASE}/mobile/ai/poc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_id: scanId, finding_id: finding.id }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error?.message ?? "PoC generation failed");
      setPoc(data.poc_code ?? data.code ?? data.poc ?? "");
      toast.success("PoC generated");
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "PoC generation failed");
    } finally {
      setLoadingPoc(false);
    }
  };

  const sev = finding.severity ?? "Info";
  const cweList = Array.isArray(finding.cwe) ? finding.cwe.join(", ") : (finding.cwe ?? "");

  return (
    <div className={cn("border-l-2 hover:bg-zinc-800/30 transition-colors", SEV_ROW_ACCENT[sev] ?? "border-l-zinc-600")}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
        )}
        <Badge variant="outline" className={cn("text-xs font-medium w-20 justify-center shrink-0", SEV_COLORS[sev] ?? SEV_COLORS.Info)}>
          {sev}
        </Badge>
        <span className="flex-1 text-sm text-zinc-200 font-medium truncate">{finding.title}</span>
        <span className="text-xs text-zinc-500 shrink-0 hidden md:block">{finding.category}</span>
        {finding.triage_status && finding.triage_status !== "New" && (
          <Badge variant="outline" className={cn("text-xs ml-2 shrink-0", TRIAGE_COLORS[finding.triage_status] ?? "")}>
            {finding.triage_status.replace(/_/g, " ")}
          </Badge>
        )}
        {cweList && (
          <span className="text-xs text-zinc-600 ml-2 shrink-0 hidden lg:block">{cweList}</span>
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 ml-6 space-y-3 border-t border-zinc-800/50">
          <p className="text-sm text-zinc-400 pt-3">{finding.description}</p>

          {finding.evidence && (
            <div>
              <p className="text-xs font-medium text-zinc-500 mb-1 flex items-center gap-1.5">
                <Code2 className="h-3.5 w-3.5" /> Evidence
              </p>
              <pre className="bg-zinc-950 rounded-md p-3 text-xs text-zinc-300 font-mono overflow-x-auto border border-zinc-800 whitespace-pre-wrap">
                {finding.evidence}
              </pre>
            </div>
          )}

          {poc && (
            <div>
              <p className="text-xs font-medium text-zinc-400 mb-1 flex items-center gap-1.5">
                <Zap className="h-3.5 w-3.5 text-yellow-400" /> Proof of Concept
              </p>
              <pre className="bg-zinc-950 rounded-md p-3 text-xs text-yellow-200 font-mono overflow-x-auto border border-yellow-900/30 whitespace-pre-wrap">
                {poc}
              </pre>
            </div>
          )}

          {finding.remediation && (
            <div className="bg-emerald-900/10 border border-emerald-900/30 rounded-md p-3">
              <p className="text-xs font-medium text-emerald-400 mb-1">Remediation</p>
              <p className="text-xs text-zinc-400">{finding.remediation}</p>
            </div>
          )}

          <div className="flex items-center gap-2 pt-1 flex-wrap">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="h-7 text-xs border-zinc-700 hover:border-zinc-600">
                  Triage <ChevronDown className="h-3 w-3 ml-1" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="bg-zinc-900 border-zinc-800">
                {["true_positive", "false_positive", "needs_review"].map((s) => (
                  <DropdownMenuItem
                    key={s}
                    className="text-xs text-zinc-300 hover:text-zinc-100 cursor-pointer"
                    onClick={() => triageMutation.mutate(s)}
                  >
                    {s.replace(/_/g, " ")}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>

            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs border-zinc-700 hover:border-zinc-600"
              onClick={generatePoc}
              disabled={loadingPoc}
            >
              {loadingPoc ? <RefreshCw className="h-3 w-3 mr-1 animate-spin" /> : <Zap className="h-3 w-3 mr-1 text-yellow-400" />}
              AI PoC
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs border-zinc-700 hover:border-violet-500/50 text-violet-400"
              onClick={() => onRunDynamic(finding, idx)}
            >
              <Activity className="h-3 w-3 mr-1" />
              Dynamic Analysis
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Dynamic Analysis job card ─────────────────────────────────────────────────

function DynJobCard({ job }: { job: DynJob }) {
  const [expanded, setExpanded] = useState(false);
  const color = JOB_STATUS_COLOR[job.status] ?? "text-zinc-400";
  const isRunning = job.status === "running" || job.status === "queued";

  return (
    <div className="border border-zinc-800 rounded-lg bg-zinc-900/50">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        {isRunning ? (
          <Loader2 className="h-3.5 w-3.5 text-blue-400 animate-spin shrink-0" />
        ) : job.status === "completed" ? (
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
        ) : (
          <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
        )}
        <span className="flex-1 text-sm text-zinc-200 font-medium truncate">{job.finding_title}</span>
        <span className={cn("text-xs shrink-0", color)}>{job.message}</span>
        {job.progress > 0 && job.progress < 100 && (
          <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden shrink-0">
            <div className="h-full bg-blue-500 transition-all" style={{ width: `${job.progress}%` }} />
          </div>
        )}
        {expanded ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500 shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500 shrink-0" />}
      </button>
      {expanded && (
        <div className="px-4 pb-4 border-t border-zinc-800/50 space-y-3">
          {job.evidence && (
            <div className="pt-3">
              <p className="text-xs font-medium text-zinc-400 mb-1 flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5 text-orange-400" /> Evidence
              </p>
              <pre className="bg-zinc-950 rounded-md p-3 text-xs text-orange-200 font-mono overflow-x-auto border border-orange-900/30 whitespace-pre-wrap">
                {job.evidence}
              </pre>
            </div>
          )}
          {job.logcat && (
            <div>
              <p className="text-xs font-medium text-zinc-400 mb-1 flex items-center gap-1.5">
                <Terminal className="h-3.5 w-3.5" /> Logcat
              </p>
              <pre className="bg-zinc-950 rounded-md p-3 text-xs text-zinc-400 font-mono overflow-x-auto border border-zinc-800 whitespace-pre-wrap max-h-64">
                {job.logcat}
              </pre>
            </div>
          )}
          {!job.evidence && !job.logcat && (
            <p className="text-xs text-zinc-500 pt-2">
              {isRunning ? "Analysis in progress…" : "No output captured."}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

type Tab = "findings" | "dynamic";

export default function MobileScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("findings");

  // Findings
  const { data: scanData, isLoading, refetch } = useQuery<FindingsResponse>({
    queryKey: ["mobile", "scan", id],
    queryFn: async () => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/scans/${id}/findings`);
      if (!res.ok) throw new Error("Failed to load scan");
      return res.json();
    },
  });

  // Dynamic jobs — poll while any job is running
  const { data: dynJobs = [] } = useQuery<DynJob[]>({
    queryKey: ["mobile", "dyn-jobs", id],
    queryFn: async () => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/dynamic/jobs`);
      if (!res.ok) return [];
      const all: DynJob[] = await res.json();
      // Filter to jobs for this scan — MSRA doesn't filter by scan, so we keep all
      return all;
    },
    refetchInterval: (query) => {
      const jobs: DynJob[] = query.state.data ?? [];
      const hasRunning = jobs.some((j) => j.status === "running" || j.status === "queued");
      return hasRunning ? 2000 : 10000;
    },
  });

  // Start dynamic analysis for a finding
  const startDynamic = async (finding: Finding, findingIdx: number) => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/mobile/scans/${id}/dynamic`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scan_id: id,
          finding_index: findingIdx,
          finding: { title: finding.title, severity: finding.severity, description: finding.description },
          use_ai: true,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error?.message ?? "Failed to start analysis");
      toast.success("Dynamic analysis started");
      setActiveTab("dynamic");
      queryClient.invalidateQueries({ queryKey: ["mobile", "dyn-jobs", id] });
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to start dynamic analysis");
    }
  };

  const handleExport = async (fmt: string) => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/mobile/scans/${id}/export/${fmt}`);
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan_${id}.${fmt}`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported as ${fmt.toUpperCase()}`);
    } catch {
      toast.error("Export failed");
    }
  };

  const findings = scanData?.findings ?? [];
  const SEVS = ["Critical", "High", "Medium", "Low", "Info"];
  const filtered = sevFilter ? findings.filter((f) => f.severity === sevFilter) : findings;
  const counts = scanData?.severity_counts ?? {};

  const displayName = scanData?.apk
    ? scanData.apk.replace(/^[a-f0-9]{12}_/, "")  // strip scan_id prefix
    : id;

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" className="h-8 w-8 text-zinc-400" onClick={() => router.push("/mobile")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-2">
              <Smartphone className="h-5 w-5 text-blue-400" />
              <h1 className="text-lg font-semibold text-zinc-100 truncate max-w-lg" title={scanData?.apk}>
                {displayName}
              </h1>
            </div>
            {scanData?.package && (
              <p className="text-xs text-zinc-500 mt-0.5 ml-7">
                {scanData.package}
                {scanData.scan_time && ` · ${scanData.scan_time}`}
              </p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={() => refetch()} className="text-zinc-400 hover:text-zinc-100 h-8">
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="h-8 border-zinc-700 text-zinc-300 hover:border-zinc-600">
                <Download className="h-3.5 w-3.5 mr-1.5" />
                Export <ChevronDown className="h-3 w-3 ml-1" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="bg-zinc-900 border-zinc-800">
              {["pdf", "csv", "sarif", "json"].map((fmt) => (
                <DropdownMenuItem
                  key={fmt}
                  className="text-xs text-zinc-300 hover:text-zinc-100 cursor-pointer"
                  onClick={() => handleExport(fmt)}
                >
                  {fmt.toUpperCase()}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Severity summary cards */}
      {scanData && (
        <div className="grid grid-cols-5 gap-3">
          {SEVS.map((sev) => {
            const count = counts[sev] ?? 0;
            const active = sevFilter === sev;
            return (
              <button
                key={sev}
                onClick={() => { setSevFilter(active ? null : sev); setActiveTab("findings"); }}
                className={cn(
                  "rounded-lg border p-3 text-left transition-all",
                  active ? SEV_COLORS[sev] : "bg-zinc-900 border-zinc-800 hover:border-zinc-700",
                )}
              >
                <p className="text-xs text-zinc-500 mb-1">{sev}</p>
                <p className="text-xl font-bold text-zinc-100">{count}</p>
              </button>
            );
          })}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-zinc-800">
        <button
          onClick={() => setActiveTab("findings")}
          className={cn(
            "px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors flex items-center gap-2",
            activeTab === "findings"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-zinc-500 hover:text-zinc-300",
          )}
        >
          <Shield className="h-3.5 w-3.5" />
          Findings
          {findings.length > 0 && (
            <span className="ml-1 bg-zinc-800 text-zinc-400 text-xs px-1.5 py-0.5 rounded-full">
              {findings.length}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab("dynamic")}
          className={cn(
            "px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors flex items-center gap-2",
            activeTab === "dynamic"
              ? "border-violet-500 text-violet-400"
              : "border-transparent text-zinc-500 hover:text-zinc-300",
          )}
        >
          <Activity className="h-3.5 w-3.5" />
          Dynamic Analysis
          {dynJobs.length > 0 && (
            <span className="ml-1 bg-zinc-800 text-zinc-400 text-xs px-1.5 py-0.5 rounded-full">
              {dynJobs.length}
            </span>
          )}
        </button>
      </div>

      {/* Findings tab */}
      {activeTab === "findings" && (
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
              <Shield className="h-4 w-4 text-zinc-400" />
              Findings
              {sevFilter && (
                <Badge variant="outline" className={cn("text-xs ml-1", SEV_COLORS[sevFilter] ?? "")}>
                  {sevFilter}
                </Badge>
              )}
              <span className="ml-auto text-xs text-zinc-500 font-normal">{filtered.length} shown</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {isLoading ? (
              <div className="p-6 text-center text-sm text-zinc-500">Loading findings…</div>
            ) : filtered.length === 0 ? (
              <div className="p-12 text-center">
                <CheckCircle2 className="h-10 w-10 text-emerald-500/50 mx-auto mb-3" />
                <p className="text-sm text-zinc-500">
                  {sevFilter ? `No ${sevFilter} findings` : "No findings — scan may still be running"}
                </p>
              </div>
            ) : (
              <div className="divide-y divide-zinc-800">
                {filtered.map((f, i) => (
                  <FindingRow
                    key={f.id}
                    finding={f}
                    idx={i}
                    scanId={id}
                    onRunDynamic={startDynamic}
                  />
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Dynamic analysis tab */}
      {activeTab === "dynamic" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                <Activity className="h-4 w-4 text-violet-400" />
                Dynamic Analysis Jobs
              </h2>
              <p className="text-xs text-zinc-500 mt-0.5">
                Expand a finding on the Findings tab and click "Dynamic Analysis" to start a live verification job.
              </p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => queryClient.invalidateQueries({ queryKey: ["mobile", "dyn-jobs", id] })}
              className="text-zinc-400 hover:text-zinc-100 h-8"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>

          {dynJobs.length === 0 ? (
            <div className="border border-zinc-800 rounded-lg p-12 text-center bg-zinc-900/50">
              <Activity className="h-10 w-10 text-zinc-700 mx-auto mb-3" />
              <p className="text-sm text-zinc-500 mb-1">No dynamic analysis jobs yet</p>
              <p className="text-xs text-zinc-600">
                Go to the Findings tab, expand a finding, and click <span className="text-violet-400 font-medium">Dynamic Analysis</span>
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {dynJobs.map((job) => (
                <DynJobCard key={job.job_id} job={job} />
              ))}
            </div>
          )}

          {/* ADB devices status */}
          <AdbDevicesCard />
        </div>
      )}
    </div>
  );
}

function AdbDevicesCard() {
  const { data } = useQuery({
    queryKey: ["mobile", "adb-devices"],
    queryFn: async () => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/adb-devices`);
      return res.json();
    },
    refetchInterval: 15000,
  });

  const devices: Array<{ serial: string; model: string }> = data?.devices ?? [];
  const error: string | null = data?.error ?? null;

  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
          <Smartphone className="h-4 w-4 text-zinc-400" />
          Connected ADB Devices
          <span className={cn("ml-auto h-2 w-2 rounded-full", devices.length > 0 ? "bg-emerald-400" : "bg-zinc-600")} />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {error ? (
          <p className="text-xs text-red-400 flex items-center gap-1.5">
            <Info className="h-3.5 w-3.5" /> {error}
          </p>
        ) : devices.length === 0 ? (
          <p className="text-xs text-zinc-500">No ADB devices connected. Plug in a device or start an emulator to enable runtime analysis.</p>
        ) : (
          <div className="space-y-1.5">
            {devices.map((d) => (
              <div key={d.serial} className="flex items-center gap-2 text-xs">
                <span className="h-2 w-2 rounded-full bg-emerald-400 shrink-0" />
                <span className="text-zinc-300 font-mono">{d.serial}</span>
                {d.model && <span className="text-zinc-500">{d.model}</span>}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
