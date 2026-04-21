"use client";

import React, { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft, Download, RefreshCw, ChevronDown, ChevronRight,
  CheckCircle2, Clock, XCircle, Shield, Smartphone,
  Code2, Zap,
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
  CRITICAL: "bg-red-500/10 text-red-400 border-red-500/30",
  HIGH:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  MEDIUM:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  LOW:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
  INFO:     "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

const SEV_ROW_ACCENT: Record<string, string> = {
  CRITICAL: "border-l-red-500",
  HIGH:     "border-l-orange-500",
  MEDIUM:   "border-l-yellow-500",
  LOW:      "border-l-blue-400",
  INFO:     "border-l-zinc-600",
};

const TRIAGE_COLORS: Record<string, string> = {
  true_positive:  "bg-red-500/10 text-red-400 border-red-500/30",
  false_positive: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
  needs_review:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
};

interface Finding {
  id: number;
  title: string;
  severity: string;
  category: string;
  platform: string;
  description: string;
  file_path?: string;
  line_number?: number;
  code_snippet?: string;
  cwe?: string;
  owasp?: string;
  triage_status?: string;
  poc_code?: string;
}

interface ScanDetail {
  id: string;
  file_name: string;
  platform: string;
  status: string;
  risk_score: number;
  created_at: string;
  app_name?: string;
  package_name?: string;
  version?: string;
  findings: Finding[];
  finding_counts?: Record<string, number>;
}

function StatusBadge({ status }: { status: string }) {
  if (status === "completed")
    return <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400"><CheckCircle2 className="h-3 w-3" /> Completed</span>;
  if (status === "scanning" || status === "processing")
    return <span className="inline-flex items-center gap-1.5 text-xs text-blue-400"><Clock className="h-3 w-3 animate-pulse" /> Scanning</span>;
  if (status === "failed")
    return <span className="inline-flex items-center gap-1.5 text-xs text-red-400"><XCircle className="h-3 w-3" /> Failed</span>;
  return <span className="inline-flex items-center gap-1.5 text-xs text-zinc-400"><Clock className="h-3 w-3" /> {status}</span>;
}

function FindingRow({ finding, scanId }: { finding: Finding; scanId: string }) {
  const [expanded, setExpanded] = useState(false);
  const [loadingPoc, setLoadingPoc] = useState(false);
  const [poc, setPoc] = useState<string | null>(finding.poc_code ?? null);
  const queryClient = useQueryClient();

  const triageMutation = useMutation({
    mutationFn: async (status: string) => {
      const res = await fetchWithAuth(
        `${API_BASE}/mobile/scans/${scanId}/findings/${finding.id}/triage`,
        { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ triage_status: status }) },
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
      setPoc(data.poc_code ?? data.code ?? "");
      toast.success("PoC generated");
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "PoC generation failed");
    } finally {
      setLoadingPoc(false);
    }
  };

  const sev = finding.severity?.toUpperCase() ?? "INFO";

  return (
    <div className={cn("border-l-2 border-zinc-800 hover:bg-zinc-800/30 transition-colors", SEV_ROW_ACCENT[sev])}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
        )}
        <Badge variant="outline" className={cn("text-xs font-medium w-20 justify-center", SEV_COLORS[sev])}>
          {sev}
        </Badge>
        <span className="flex-1 text-sm text-zinc-200 font-medium truncate">{finding.title}</span>
        <span className="text-xs text-zinc-500">{finding.category}</span>
        {finding.triage_status && (
          <Badge variant="outline" className={cn("text-xs ml-2", TRIAGE_COLORS[finding.triage_status])}>
            {finding.triage_status.replace("_", " ")}
          </Badge>
        )}
        {finding.cwe && (
          <span className="text-xs text-zinc-600 ml-2">{finding.cwe}</span>
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 ml-6 space-y-3">
          <p className="text-sm text-zinc-400">{finding.description}</p>

          {finding.file_path && (
            <div className="flex items-center gap-2 text-xs text-zinc-500">
              <Code2 className="h-3.5 w-3.5" />
              <span className="font-mono">{finding.file_path}</span>
              {finding.line_number && <span>:{finding.line_number}</span>}
            </div>
          )}

          {finding.code_snippet && (
            <pre className="bg-zinc-950 rounded-md p-3 text-xs text-zinc-300 font-mono overflow-x-auto border border-zinc-800">
              {finding.code_snippet}
            </pre>
          )}

          {poc && (
            <div>
              <p className="text-xs font-medium text-zinc-400 mb-1 flex items-center gap-1.5">
                <Zap className="h-3.5 w-3.5 text-yellow-400" /> AI-Generated PoC
              </p>
              <pre className="bg-zinc-950 rounded-md p-3 text-xs text-yellow-200 font-mono overflow-x-auto border border-yellow-900/30">
                {poc}
              </pre>
            </div>
          )}

          <div className="flex items-center gap-2 pt-1">
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
                    {s.replace("_", " ")}
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
              {loadingPoc ? (
                <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
              ) : (
                <Zap className="h-3 w-3 mr-1 text-yellow-400" />
              )}
              Generate PoC
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function MobileScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [sevFilter, setSevFilter] = useState<string | null>(null);

  const { data: scan, isLoading, refetch } = useQuery<ScanDetail>({
    queryKey: ["mobile", "scan", id],
    queryFn: async () => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/scans/${id}/findings`);
      if (!res.ok) throw new Error("Failed to load scan");
      return res.json();
    },
    refetchInterval: (data) => {
      const status = (data as ScanDetail | undefined)?.status;
      return status === "scanning" || status === "processing" ? 3000 : false;
    },
  });

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
    } catch {
      toast.error("Export failed");
    }
  };

  const findings = scan?.findings ?? [];
  const filtered = sevFilter ? findings.filter((f) => f.severity?.toUpperCase() === sevFilter) : findings;
  const counts = scan?.finding_counts ?? {};

  const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-zinc-400"
            onClick={() => router.push("/mobile")}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-2">
              <Smartphone className="h-5 w-5 text-blue-400" />
              <h1 className="text-lg font-semibold text-zinc-100 truncate max-w-lg">
                {scan?.file_name ?? "Loading…"}
              </h1>
              {scan && <StatusBadge status={scan.status} />}
            </div>
            {scan?.app_name && (
              <p className="text-xs text-zinc-500 mt-0.5 ml-7">{scan.app_name} · {scan.package_name}</p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => refetch()}
            className="text-zinc-400 hover:text-zinc-100 h-8"
          >
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
                  className="text-xs text-zinc-300 hover:text-zinc-100 cursor-pointer uppercase"
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
      {scan && (
        <div className="grid grid-cols-5 gap-3">
          {SEVS.map((sev) => {
            const count = counts[sev] ?? 0;
            const active = sevFilter === sev;
            return (
              <button
                key={sev}
                onClick={() => setSevFilter(active ? null : sev)}
                className={cn(
                  "rounded-lg border p-3 text-left transition-all",
                  active
                    ? cn("border-opacity-60", SEV_COLORS[sev])
                    : "bg-zinc-900 border-zinc-800 hover:border-zinc-700",
                )}
              >
                <p className="text-xs text-zinc-500 mb-1">{sev}</p>
                <p className="text-xl font-bold text-zinc-100">{count}</p>
              </button>
            );
          })}
        </div>
      )}

      {/* Findings */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
            <Shield className="h-4 w-4 text-zinc-400" />
            Findings
            {sevFilter && (
              <Badge variant="outline" className={cn("text-xs ml-1", SEV_COLORS[sevFilter])}>
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
                {sevFilter ? `No ${sevFilter} findings` : "No findings"}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-zinc-800">
              {filtered.map((f) => (
                <FindingRow key={f.id} finding={f} scanId={id} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
