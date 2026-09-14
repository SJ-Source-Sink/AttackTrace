"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Shield, Upload, Play, Square, CheckCircle2, XCircle,
  ChevronDown, ChevronUp, AlertTriangle, FileCode, History,
  Trash2, ArrowLeft, Clock, RotateCcw, Loader2, Info,
  FileText, Package, FolderOpen,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ── Types ─────────────────────────────────────────────────────────────────────

type Severity = "critical" | "high" | "medium" | "low" | "info";
type IacType = "auto" | "terraform" | "kubernetes" | "dockerfile" | "cloudformation";

interface IacFinding {
  check_id: string;
  name: string;
  severity: Severity;
  filename: string;
  line: number;
  description: string;
  remediation: string;
  code_snippet: string;
  source?: string;
}

interface FileResult {
  filename: string;
  iac_type: string;
  findings: IacFinding[];
}

interface ScanComplete {
  id: string;
  files_scanned: number;
  total_findings: number;
  by_severity: Record<Severity, number>;
}

interface HistoryScan {
  id: string;
  started_at: string;
  completed_at: string;
  iac_type: string;
  files_scanned: number;
  total_findings: number;
  by_severity: Record<Severity, number>;
}

interface FullHistoryScan extends HistoryScan {
  findings: IacFinding[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SEV_STYLES: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info:     "bg-zinc-700/50 text-zinc-400 border-zinc-600/30",
};

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const IAC_TYPE_LABELS: Record<string, string> = {
  auto: "Auto-detect",
  terraform: "Terraform",
  kubernetes: "Kubernetes",
  dockerfile: "Dockerfile",
  cloudformation: "CloudFormation",
};

const SEV_THRESHOLD_OPTIONS: { value: Severity; label: string }[] = [
  { value: "critical", label: "Critical only" },
  { value: "high", label: "High and above" },
  { value: "medium", label: "Medium and above" },
  { value: "low", label: "All findings" },
];

const ACCEPTED_EXTENSIONS = ".tf,.tfvars,.yaml,.yml,.json,Dockerfile,dockerfile,.dockerfile";

// ── Sub-components ─────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const sev = (severity || "info") as Severity;
  return (
    <Badge className={cn("text-[10px] font-semibold border", SEV_STYLES[sev] ?? SEV_STYLES.info)}>
      {sev.toUpperCase()}
    </Badge>
  );
}

function FindingCard({ finding }: { finding: IacFinding }) {
  const [expanded, setExpanded] = useState(false);
  const sev = finding.severity as Severity;
  return (
    <div className={cn(
      "rounded-lg border transition-colors",
      sev === "critical" ? "border-red-500/30 bg-red-950/10" :
      sev === "high"     ? "border-orange-500/30 bg-orange-950/10" :
      sev === "medium"   ? "border-yellow-500/30 bg-yellow-950/10" :
                           "border-zinc-700/50 bg-zinc-900/30"
    )}>
      <button
        className="w-full flex items-start gap-3 p-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <Badge variant="outline" className="text-[10px] font-mono py-0 text-zinc-400">
              {finding.check_id}
            </Badge>
            <span className="text-xs font-semibold text-zinc-200">{finding.name}</span>
          </div>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <span className="text-[10px] font-mono text-zinc-500">{finding.filename}</span>
            {finding.line > 0 && (
              <span className="text-[10px] text-zinc-600">line {finding.line}</span>
            )}
            {finding.source === "checkov" && (
              <Badge variant="outline" className="text-[9px] py-0 text-purple-400 border-purple-500/30">
                checkov
              </Badge>
            )}
          </div>
        </div>
        <div className="shrink-0 text-zinc-600">
          {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-3 border-t border-zinc-800/50 pt-3">
          <p className="text-xs text-zinc-300">{finding.description}</p>

          {finding.code_snippet && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Code</p>
              <pre className="text-[10px] font-mono text-zinc-300 bg-zinc-950 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all border border-zinc-800">
                {finding.code_snippet}
              </pre>
            </div>
          )}

          <div className="rounded bg-emerald-950/20 border border-emerald-800/30 p-2">
            <p className="text-[10px] uppercase tracking-wider text-emerald-600 mb-1">Remediation</p>
            <p className="text-xs text-emerald-300">{finding.remediation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function FileResultCard({ result }: { result: FileResult }) {
  const [open, setOpen] = useState(true);
  const sorted = [...result.findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );
  return (
    <Card className="border-zinc-800">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={() => setOpen(!open)}
      >
        <FileCode className="h-4 w-4 text-blue-400 shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-xs font-mono text-zinc-200 truncate">{result.filename}</p>
          <p className="text-[10px] text-zinc-500 mt-0.5 capitalize">{result.iac_type}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {sorted.length > 0 ? (
            <Badge className={cn("text-[10px] border",
              sorted[0].severity === "critical" ? SEV_STYLES.critical :
              sorted[0].severity === "high" ? SEV_STYLES.high :
              sorted[0].severity === "medium" ? SEV_STYLES.medium :
              SEV_STYLES.low
            )}>
              {sorted.length} finding{sorted.length !== 1 ? "s" : ""}
            </Badge>
          ) : (
            <Badge className="text-[10px] border border-emerald-800/50 text-emerald-400 bg-emerald-950/20">
              Clean
            </Badge>
          )}
          {open ? <ChevronUp className="h-4 w-4 text-zinc-600" /> : <ChevronDown className="h-4 w-4 text-zinc-600" />}
        </div>
      </button>

      {open && sorted.length > 0 && (
        <CardContent className="pt-0 pb-3 space-y-2">
          {sorted.map((f, i) => <FindingCard key={i} finding={f} />)}
        </CardContent>
      )}
      {open && sorted.length === 0 && (
        <CardContent className="pt-0 pb-3">
          <div className="flex items-center gap-2 text-emerald-400 text-xs py-2">
            <CheckCircle2 className="h-4 w-4" />
            No issues found in this file
          </div>
        </CardContent>
      )}
    </Card>
  );
}

// ── History Tab ────────────────────────────────────────────────────────────────

function HistoryTab({ onRestore }: { onRestore: (iacType: string) => void }) {
  const [scans, setScans] = useState<HistoryScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<FullHistoryScan | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  useEffect(() => {
    fetchWithAuth(`${API_BASE}/iac/history`)
      .then((r) => r.ok ? r.json() : [])
      .then((d) => setScans(Array.isArray(d) ? d : []))
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  }, []);

  const deleteScan = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await fetchWithAuth(`${API_BASE}/iac/history/${id}`, { method: "DELETE" });
    setScans((prev) => prev.filter((s) => s.id !== id));
    if (selected?.id === id) setSelected(null);
    toast.success("Scan deleted");
  };

  const openDetail = async (scan: HistoryScan) => {
    setLoadingDetail(true);
    try {
      const r = await fetchWithAuth(`${API_BASE}/iac/history/${scan.id}`);
      if (r.ok) setSelected(await r.json());
    } finally {
      setLoadingDetail(false);
    }
  };

  if (selected) {
    const sorted = [...(selected.findings ?? [])].sort(
      (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
    );
    // Group findings by file
    const byFile = sorted.reduce<Record<string, IacFinding[]>>((acc, f) => {
      (acc[f.filename] ??= []).push(f);
      return acc;
    }, {});

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => setSelected(null)} className="gap-1.5 text-zinc-400">
            <ArrowLeft className="h-4 w-4" /> Back to history
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="gap-1.5 ml-auto"
            onClick={() => {
              onRestore(selected.iac_type);
              toast.info("IaC type restored — re-upload the files to rescan");
            }}
          >
            <RotateCcw className="h-3.5 w-3.5" /> Restore to Scanner
          </Button>
        </div>

        <Card>
          <CardContent className="pt-4 space-y-3">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div>
                <p className="text-xs text-zinc-400">
                  {new Date(selected.started_at).toLocaleString()}
                </p>
                <p className="text-[10px] text-zinc-500 mt-0.5 capitalize">
                  Type: {selected.iac_type} · {selected.files_scanned} file(s) scanned
                </p>
              </div>
              <div className="flex gap-2 flex-wrap">
                {(["critical", "high", "medium", "low"] as Severity[]).map((s) =>
                  (selected.by_severity?.[s] ?? 0) > 0 ? (
                    <Badge key={s} className={cn("text-[10px] border", SEV_STYLES[s])}>
                      {selected.by_severity[s]} {s}
                    </Badge>
                  ) : null
                )}
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="rounded bg-zinc-800/50 p-2 text-center">
                <p className="text-lg font-bold text-zinc-100">{selected.files_scanned}</p>
                <p className="text-[10px] text-zinc-500">Files</p>
              </div>
              <div className="rounded bg-zinc-800/50 p-2 text-center">
                <p className="text-lg font-bold text-zinc-100">{selected.total_findings}</p>
                <p className="text-[10px] text-zinc-500">Findings</p>
              </div>
              <div className="rounded bg-zinc-800/50 p-2 text-center">
                <p className="text-lg font-bold text-red-400">{selected.by_severity?.critical ?? 0}</p>
                <p className="text-[10px] text-zinc-500">Critical</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {Object.keys(byFile).length > 0 ? (
          <div className="space-y-3">
            {Object.entries(byFile).map(([filename, findings]) => (
              <FileResultCard
                key={filename}
                result={{ filename, iac_type: selected.iac_type, findings }}
              />
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center py-12 text-center">
            <CheckCircle2 className="h-8 w-8 text-emerald-500 mb-2" />
            <p className="text-sm text-emerald-400">No findings recorded for this scan</p>
          </div>
        )}
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-5 w-5 text-blue-400 animate-spin mr-2" />
        <span className="text-xs text-zinc-500">Loading history...</span>
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-16 text-center">
        <History className="h-10 w-10 text-zinc-700 mb-3" />
        <p className="text-sm font-medium text-zinc-500">No scan history yet</p>
        <p className="text-xs text-zinc-600 mt-1">Run your first IaC scan to see results here</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {scans.map((scan) => {
        const crit = scan.by_severity?.critical ?? 0;
        const high = scan.by_severity?.high ?? 0;
        return (
          <Card
            key={scan.id}
            className="cursor-pointer hover:border-zinc-600 transition-colors"
            onClick={() => openDetail(scan)}
          >
            <CardContent className="pt-3 pb-3">
              <div className="flex items-start gap-3">
                <Shield className="h-4 w-4 text-blue-400 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-zinc-300">
                    {scan.files_scanned} file(s) · <span className="capitalize">{scan.iac_type}</span>
                  </p>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <span className="flex items-center gap-1 text-[10px] text-zinc-500">
                      <Clock className="h-3 w-3" />
                      {new Date(scan.started_at).toLocaleString()}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {crit > 0 && (
                    <Badge className={cn("text-[10px] border", SEV_STYLES.critical)}>{crit} critical</Badge>
                  )}
                  {high > 0 && (
                    <Badge className={cn("text-[10px] border", SEV_STYLES.high)}>{high} high</Badge>
                  )}
                  {crit === 0 && high === 0 && (
                    <Badge className="text-[10px] border border-zinc-700 text-zinc-500">
                      {scan.total_findings} finding(s)
                    </Badge>
                  )}
                  <button
                    onClick={(e) => deleteScan(scan.id, e)}
                    className="p-1 rounded hover:bg-red-900/30 text-zinc-600 hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function IacScannerPage() {
  const [activeTab, setActiveTab] = useState<"scan" | "history">("scan");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [iacType, setIacType] = useState<IacType>("auto");
  const [severityThreshold, setSeverityThreshold] = useState<Severity>("low");
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [fileResults, setFileResults] = useState<Record<string, FileResult>>({});
  const [allFindings, setAllFindings] = useState<IacFinding[]>([]);
  const [complete, setComplete] = useState<ScanComplete | null>(null);
  const [currentFile, setCurrentFile] = useState<string>("");
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const handleFiles = useCallback((files: FileList | File[]) => {
    const arr = Array.from(files);
    setSelectedFiles((prev) => {
      const names = new Set(prev.map((f) => f.name));
      return [...prev, ...arr.filter((f) => !names.has(f.name))];
    });
  }, []);

  const removeFile = (name: string) => {
    setSelectedFiles((prev) => prev.filter((f) => f.name !== name));
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    handleFiles(e.dataTransfer.files);
  };

  const startScan = async () => {
    if (!selectedFiles.length) {
      toast.error("Please select at least one file");
      return;
    }

    setIsScanning(true);
    setScanStatus("running");
    setFileResults({});
    setAllFindings([]);
    setComplete(null);
    setCurrentFile("");

    const controller = new AbortController();
    abortRef.current = controller;

    const formData = new FormData();
    selectedFiles.forEach((f) => formData.append("files", f));
    formData.append("iac_type", iacType);
    formData.append("severity_threshold", severityThreshold);

    try {
      const resp = await fetchWithAuth(`${API_BASE}/iac/scan`, {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });

      if (!resp.ok || !resp.body) {
        throw new Error(`HTTP ${resp.status}`);
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });

        const blocks = buf.split("\n\n");
        buf = blocks.pop() ?? "";

        for (const block of blocks) {
          const lines = block.split("\n");
          let event = "";
          let dataStr = "";
          for (const line of lines) {
            if (line.startsWith("event: ")) event = line.slice(7).trim();
            if (line.startsWith("data: ")) dataStr = line.slice(6);
          }
          if (!dataStr) continue;
          try {
            const data = JSON.parse(dataStr);

            if (event === "file_start") {
              setCurrentFile(data.filename);
              setFileResults((prev) => ({
                ...prev,
                [data.filename]: { filename: data.filename, iac_type: data.iac_type, findings: [] },
              }));
            } else if (event === "finding") {
              const finding = data as IacFinding;
              setAllFindings((prev) => [...prev, finding]);
              setFileResults((prev) => {
                const existing = prev[finding.filename] ?? { filename: finding.filename, iac_type: "unknown", findings: [] };
                return {
                  ...prev,
                  [finding.filename]: { ...existing, findings: [...existing.findings, finding] },
                };
              });
            } else if (event === "complete") {
              setComplete(data);
              setScanStatus("completed");
            } else if (event === "error") {
              toast.error(data.message ?? "Scan error");
              setScanStatus("failed");
            }
          } catch {}
        }
      }
    } catch (e: any) {
      if (e?.name !== "AbortError") {
        toast.error("Scan failed: " + (e?.message ?? "Unknown error"));
        setScanStatus("failed");
      }
    } finally {
      setIsScanning(false);
      abortRef.current = null;
    }
  };

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("failed");
  };

  const reset = () => {
    setScanStatus("idle");
    setFileResults({});
    setAllFindings([]);
    setComplete(null);
    setCurrentFile("");
  };

  const fileResultList = Object.values(fileResults);
  const totalFindings = allFindings.length;

  return (
    <div className="space-y-6 p-6 max-w-5xl mx-auto">
      <PageHeader
        title="IaC Security Scanner"
        description="Static analysis of Terraform, Kubernetes, Dockerfile, and CloudFormation files"
      />

      {/* Tab switcher */}
      <div className="flex gap-1 border-b border-zinc-800">
        {(["scan", "history"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              "px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px capitalize",
              activeTab === tab
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-zinc-500 hover:text-zinc-300"
            )}
          >
            {tab === "history" && <History className="inline h-3.5 w-3.5 mr-1.5" />}
            {tab === "scan" && <Shield className="inline h-3.5 w-3.5 mr-1.5" />}
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {activeTab === "history" ? (
        <HistoryTab
          onRestore={(type) => {
            const validTypes: IacType[] = ["auto", "terraform", "kubernetes", "dockerfile", "cloudformation"];
            if (validTypes.includes(type as IacType)) setIacType(type as IacType);
            setActiveTab("scan");
          }}
        />
      ) : (
        <div className="space-y-6">
          {/* Config panel */}
          {scanStatus === "idle" && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <FolderOpen className="h-4 w-4 text-blue-400" />
                  Upload IaC Files
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-5">
                {/* Dropzone */}
                <div
                  onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
                  onDragLeave={() => setIsDragOver(false)}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className={cn(
                    "border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors",
                    isDragOver
                      ? "border-blue-500 bg-blue-950/20"
                      : "border-zinc-700 hover:border-zinc-600 bg-zinc-900/30"
                  )}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    accept={ACCEPTED_EXTENSIONS}
                    className="hidden"
                    onChange={(e) => e.target.files && handleFiles(e.target.files)}
                  />
                  <Upload className="h-8 w-8 text-zinc-600 mx-auto mb-2" />
                  <p className="text-sm text-zinc-400 font-medium">
                    Drop files here or click to browse
                  </p>
                  <p className="text-[11px] text-zinc-600 mt-1">
                    Supports: .tf, .tfvars, .yaml, .yml, Dockerfile, .json
                  </p>
                </div>

                {/* Selected files list */}
                {selectedFiles.length > 0 && (
                  <div className="space-y-1.5">
                    {selectedFiles.map((f) => (
                      <div
                        key={f.name}
                        className="flex items-center gap-2 px-3 py-2 rounded-md bg-zinc-800/50 border border-zinc-700/50"
                      >
                        <FileText className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
                        <span className="text-xs font-mono text-zinc-300 flex-1 truncate">{f.name}</span>
                        <span className="text-[10px] text-zinc-600">
                          {(f.size / 1024).toFixed(1)} KB
                        </span>
                        <button
                          onClick={(e) => { e.stopPropagation(); removeFile(f.name); }}
                          className="text-zinc-600 hover:text-red-400 transition-colors"
                        >
                          <XCircle className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {/* Options row */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label className="text-xs text-zinc-400">IaC Type</Label>
                    <select
                      value={iacType}
                      onChange={(e) => setIacType(e.target.value as IacType)}
                      className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-blue-500"
                    >
                      {Object.entries(IAC_TYPE_LABELS).map(([val, label]) => (
                        <option key={val} value={val}>{label}</option>
                      ))}
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs text-zinc-400">Severity Threshold</Label>
                    <select
                      value={severityThreshold}
                      onChange={(e) => setSeverityThreshold(e.target.value as Severity)}
                      className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-blue-500"
                    >
                      {SEV_THRESHOLD_OPTIONS.map((o) => (
                        <option key={o.value} value={o.value}>{o.label}</option>
                      ))}
                    </select>
                  </div>
                </div>

                <Button
                  onClick={startScan}
                  disabled={!selectedFiles.length}
                  className="w-full gap-2 bg-blue-600 hover:bg-blue-700 text-white"
                >
                  <Play className="h-4 w-4" />
                  Scan {selectedFiles.length > 0 ? `${selectedFiles.length} file(s)` : "Files"}
                </Button>
              </CardContent>
            </Card>
          )}

          {/* Running state banner */}
          {scanStatus === "running" && (
            <Card className="border-blue-500/30 bg-blue-950/10">
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
                    <div>
                      <p className="text-sm text-blue-300 font-medium">Scanning...</p>
                      {currentFile && (
                        <p className="text-[11px] text-zinc-500 font-mono mt-0.5">{currentFile}</p>
                      )}
                    </div>
                  </div>
                  <Button variant="outline" size="sm" onClick={stopScan} className="gap-1.5 text-red-400 border-red-500/30 hover:bg-red-950/20">
                    <Square className="h-3.5 w-3.5" /> Stop
                  </Button>
                </div>
                {totalFindings > 0 && (
                  <p className="text-[11px] text-zinc-500 mt-2">{totalFindings} finding(s) so far</p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Completion summary */}
          {complete && (
            <Card className="border-emerald-800/30 bg-emerald-950/10">
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center justify-between flex-wrap gap-3">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                    <div>
                      <p className="text-sm font-semibold text-emerald-300">Scan Complete</p>
                      <p className="text-[11px] text-zinc-500">
                        {complete.files_scanned} file(s) · {complete.total_findings} total findings
                      </p>
                    </div>
                  </div>
                  <div className="flex gap-2 flex-wrap">
                    {(["critical", "high", "medium", "low"] as Severity[]).map((s) =>
                      (complete.by_severity?.[s] ?? 0) > 0 ? (
                        <Badge key={s} className={cn("text-[10px] border", SEV_STYLES[s])}>
                          {complete.by_severity[s]} {s}
                        </Badge>
                      ) : null
                    )}
                    <Button variant="ghost" size="sm" onClick={reset} className="gap-1 text-zinc-400 h-6 px-2">
                      <RotateCcw className="h-3 w-3" /> New scan
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Results by file */}
          {fileResultList.length > 0 && (
            <div className="space-y-3">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                Results — {fileResultList.length} file(s)
              </p>
              {fileResultList.map((result) => (
                <FileResultCard key={result.filename} result={result} />
              ))}
            </div>
          )}

          {/* Idle empty state */}
          {scanStatus === "idle" && selectedFiles.length === 0 && (
            <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-16 text-center">
              <Shield className="h-10 w-10 text-zinc-700 mb-3" />
              <p className="text-sm font-medium text-zinc-500">Upload IaC files to begin scanning</p>
              <p className="text-xs text-zinc-600 mt-1">
                Supports Terraform, Kubernetes manifests, Dockerfiles, and CloudFormation templates
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
