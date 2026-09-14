"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Cloud, Play, Square, Shield, ShieldAlert, ShieldCheck, ShieldX,
  CheckCircle2, XCircle, AlertTriangle, Info, ChevronDown, ChevronRight,
  History, Trash2, Clock, Download, Eye, EyeOff, RefreshCw, RotateCcw,
  Server, Database, Lock, Key, Globe, Layers,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ── Types ─────────────────────────────────────────────────────────────────────

type Provider = "aws" | "gcp" | "azure" | "kubernetes";
type Severity  = "critical" | "high" | "medium" | "low" | "info";
type Tab       = "scanner" | "history";

interface Finding {
  check_id: string;
  severity: Severity;
  resource: string;
  resource_arn: string;
  description: string;
  remediation: string;
}

interface CheckState {
  check_id: string;
  check_name: string;
  status: "running" | "complete";
  findings_count?: number;
}

interface ScanSummary {
  scan_id: string;
  total_findings: number;
  by_severity: Record<Severity, number>;
  checks_run: number;
  duration_seconds: number;
  prowler_used: boolean;
}

interface HistoryRecord {
  id: string;
  provider: string;
  region: string | null;
  started_at: string;
  duration_seconds: number;
  checks_run: number;
  total_findings: number;
  by_severity: Record<Severity, number>;
  severity_filter: string;
  prowler_used: boolean;
}

interface HistoryDetail extends HistoryRecord {
  findings: Finding[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const PROVIDERS: { value: Provider; label: string; icon: React.ReactNode; available: boolean }[] = [
  { value: "aws",        label: "Amazon AWS",    icon: <Cloud className="h-4 w-4" />,    available: true },
  { value: "gcp",        label: "Google GCP",    icon: <Globe className="h-4 w-4" />,    available: true },
  { value: "azure",      label: "Microsoft Azure", icon: <Layers className="h-4 w-4" />, available: true },
  { value: "kubernetes", label: "Kubernetes",    icon: <Server className="h-4 w-4" />,   available: true },
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info:     "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

const SEVERITY_DOT: Record<Severity, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
  info:     "bg-zinc-500",
};

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  S3:         <Database className="h-3.5 w-3.5" />,
  IAM:        <Lock className="h-3.5 w-3.5" />,
  EC2:        <Server className="h-3.5 w-3.5" />,
  RDS:        <Database className="h-3.5 w-3.5" />,
  CloudTrail: <Eye className="h-3.5 w-3.5" />,
  KMS:        <Key className="h-3.5 w-3.5" />,
  Lambda:     <Layers className="h-3.5 w-3.5" />,
  Storage:    <Database className="h-3.5 w-3.5" />,
  Network:    <Globe className="h-3.5 w-3.5" />,
  Compute:    <Server className="h-3.5 w-3.5" />,
  Database:   <Database className="h-3.5 w-3.5" />,
  KeyVault:   <Key className="h-3.5 w-3.5" />,
  Cluster:    <Server className="h-3.5 w-3.5" />,
  Workloads:  <Layers className="h-3.5 w-3.5" />,
  RBAC:       <Lock className="h-3.5 w-3.5" />,
};

const AWS_REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
  "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-south-1",
  "ca-central-1", "sa-east-1",
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={cn(
      "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
      SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info,
    )}>
      <span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_DOT[severity] ?? "bg-zinc-500")} />
      {severity}
    </span>
  );
}

function SeveritySummaryBar({ by_severity }: { by_severity: Record<string, number> }) {
  return (
    <div className="flex flex-wrap gap-3">
      {(["critical", "high", "medium", "low"] as Severity[]).map((sev) => (
        <div key={sev} className="flex items-center gap-1.5">
          <span className={cn("h-2 w-2 rounded-full", SEVERITY_DOT[sev])} />
          <span className="text-xs font-semibold capitalize text-zinc-300">
            {by_severity[sev] ?? 0}
          </span>
          <span className="text-xs text-zinc-600 capitalize">{sev}</span>
        </div>
      ))}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CSPMPage() {
  const [activeTab, setActiveTab] = useState<Tab>("scanner");

  // Form state
  const [provider, setProvider] = useState<Provider>("aws");
  const [awsKey, setAwsKey] = useState("");
  const [awsSecret, setAwsSecret] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [awsSessionToken, setAwsSessionToken] = useState("");
  const [gcpProjectId, setGcpProjectId] = useState("");
  const [gcpServiceAccountKey, setGcpServiceAccountKey] = useState("");
  const [azureSubscriptionId, setAzureSubscriptionId] = useState("");
  const [azureTenantId, setAzureTenantId] = useState("");
  const [azureClientId, setAzureClientId] = useState("");
  const [azureClientSecret, setAzureClientSecret] = useState("");
  const [k8sApiServer, setK8sApiServer] = useState("");
  const [k8sToken, setK8sToken] = useState("");
  const [k8sCaCert, setK8sCaCert] = useState("");
  const [k8sInsecureSkipTlsVerify, setK8sInsecureSkipTlsVerify] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("medium");
  const [showSecret, setShowSecret] = useState(false);

  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [activeChecks, setActiveChecks] = useState<Record<string, CheckState>>({});
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [totalChecks, setTotalChecks] = useState(0);
  const [checksCompleted, setChecksCompleted] = useState(0);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set(["IAM", "EC2", "S3"]));
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());

  // History state
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selectedHistory, setSelectedHistory] = useState<HistoryDetail | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  // Fetch available checks count whenever the selected provider changes
  useEffect(() => {
    fetchWithAuth(`${API_BASE}/cspm/checks?provider=${provider}`)
      .then((r) => r.json())
      .then((d) => setTotalChecks(d.total ?? 0))
      .catch(() => setTotalChecks(0));
  }, [provider]);

  // ── History helpers ────────────────────────────────────────────────────────

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await fetchWithAuth(`${API_BASE}/cspm/history`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.items ?? []);
      }
    } catch {
      toast.error("Failed to load history");
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "history") loadHistory();
  }, [activeTab, loadHistory]);

  const loadHistoryDetail = async (id: string) => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/cspm/history/${id}`);
      if (res.ok) {
        setSelectedHistory(await res.json());
      }
    } catch {
      toast.error("Failed to load scan detail");
    }
  };

  const deleteHistory = async (id: string) => {
    try {
      await fetchWithAuth(`${API_BASE}/cspm/history/${id}`, { method: "DELETE" });
      setHistory((prev) => prev.filter((h) => h.id !== id));
      if (selectedHistory?.id === id) setSelectedHistory(null);
      toast.success("Scan deleted");
    } catch {
      toast.error("Failed to delete scan");
    }
  };

  const restoreFromHistory = (h: HistoryDetail) => {
    const p = h.provider as Provider;
    setProvider(p);
    if (p === "aws" && h.region) setAwsRegion(h.region);
    if (h.severity_filter) setSeverityFilter(h.severity_filter);
    setActiveTab("scanner");
    toast.success(`Restored ${h.provider.toUpperCase()} scan configuration`);
  };

  // ── Scan ──────────────────────────────────────────────────────────────────

  const startScan = useCallback(async () => {
    if (provider === "aws" && (!awsKey.trim() || !awsSecret.trim())) {
      toast.error("AWS Access Key ID and Secret Access Key are required");
      return;
    }
    if (provider === "gcp" && (!gcpProjectId.trim() || !gcpServiceAccountKey.trim())) {
      toast.error("GCP Project ID and Service Account Key are required");
      return;
    }
    if (provider === "azure" && (!azureSubscriptionId.trim() || !azureTenantId.trim() || !azureClientId.trim() || !azureClientSecret.trim())) {
      toast.error("All Azure fields are required");
      return;
    }
    if (provider === "kubernetes" && (!k8sApiServer.trim() || !k8sToken.trim())) {
      toast.error("Kubernetes API server URL and token are required");
      return;
    }

    setIsScanning(true);
    setScanStatus("running");
    setFindings([]);
    setActiveChecks({});
    setSummary(null);
    setChecksCompleted(0);

    abortRef.current = new AbortController();

    try {
      const body: Record<string, unknown> = {
        provider,
        severity_filter: severityFilter,
      };
      if (provider === "aws") {
        body.aws_access_key = awsKey.trim();
        body.aws_secret_key = awsSecret.trim();
        body.aws_region = awsRegion;
        if (awsSessionToken.trim()) body.aws_session_token = awsSessionToken.trim();
      } else if (provider === "gcp") {
        body.gcp_project_id = gcpProjectId.trim();
        body.gcp_service_account_key = gcpServiceAccountKey.trim();
      } else if (provider === "azure") {
        body.azure_subscription_id = azureSubscriptionId.trim();
        body.azure_tenant_id = azureTenantId.trim();
        body.azure_client_id = azureClientId.trim();
        body.azure_client_secret = azureClientSecret.trim();
      } else if (provider === "kubernetes") {
        body.k8s_api_server = k8sApiServer.trim();
        body.k8s_token = k8sToken.trim();
        if (k8sCaCert.trim()) body.k8s_ca_cert = k8sCaCert.trim();
        body.k8s_insecure_skip_tls_verify = k8sInsecureSkipTlsVerify;
      }

      const res = await fetchWithAuth(`${API_BASE}/cspm/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
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
          let data: Record<string, unknown>;
          try { data = JSON.parse(dataMatch[1]); } catch { continue; }

          if (event === "check_start") {
            setActiveChecks((prev) => ({
              ...prev,
              [data.check_id as string]: {
                check_id: data.check_id as string,
                check_name: data.check_name as string,
                status: "running",
              },
            }));
          } else if (event === "check_complete") {
            setActiveChecks((prev) => ({
              ...prev,
              [data.check_id as string]: {
                ...prev[data.check_id as string],
                status: "complete",
                findings_count: data.findings_count as number,
              },
            }));
            setChecksCompleted((n) => n + 1);
          } else if (event === "finding") {
            setFindings((prev) => [...prev, data as unknown as Finding]);
          } else if (event === "status") {
            toast.info(data.message as string);
          } else if (event === "complete") {
            setSummary(data as unknown as ScanSummary);
            setScanStatus("completed");
            setIsScanning(false);
            const total = (data.total_findings as number) ?? 0;
            toast.success(`CSPM scan complete — ${total} finding${total !== 1 ? "s" : ""} detected`);
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
        setIsScanning(false);
        toast.error(`Scan failed: ${err.message}`);
      } else {
        setIsScanning(false);
      }
    }
  }, [provider, awsKey, awsSecret, awsRegion, awsSessionToken, severityFilter]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  // ── Group findings by category ────────────────────────────────────────────

  const findingsByCategory = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    // Derive category from check_id prefix
    const cat =
      f.check_id.startsWith("s3_")           ? "S3"
      : f.check_id.startsWith("iam_")        ? "IAM"
      : f.check_id.startsWith("ec2_")        ? "EC2"
      : f.check_id.startsWith("rds_")        ? "RDS"
      : f.check_id.startsWith("cloudtrail_") ? "CloudTrail"
      : f.check_id.startsWith("kms_")        ? "KMS"
      : f.check_id.startsWith("lambda_")     ? "Lambda"
      : "Other";
    (acc[cat] ??= []).push(f);
    return acc;
  }, {});

  const toggleCategory = (cat: string) =>
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      next.has(cat) ? next.delete(cat) : next.add(cat);
      return next;
    });

  const toggleFinding = (idx: number) =>
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });

  const exportJSON = () => {
    if (!findings.length) return;
    const blob = new Blob([JSON.stringify({ summary, findings }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cspm-${provider}-${Date.now()}.json`;
    a.click();
  };

  const progressPct = totalChecks > 0 ? Math.round((checksCompleted / totalChecks) * 100) : 0;

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <PageHeader
        title="CSPM Scanner"
        description="Cloud Security Posture Management — scan your cloud environment for misconfigurations"
      >
        <div className="flex items-center gap-2">
          {findings.length > 0 && (
            <Button variant="outline" size="sm" onClick={exportJSON} className="gap-1.5">
              <Download className="h-3.5 w-3.5" /> Export JSON
            </Button>
          )}
        </div>
      </PageHeader>

      {/* Tab switcher */}
      <div className="flex gap-1 rounded-lg border border-zinc-800 bg-zinc-900 p-1 w-fit">
        {(["scanner", "history"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setActiveTab(t)}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-4 py-1.5 text-sm font-medium transition-colors capitalize",
              activeTab === t
                ? "bg-zinc-700 text-zinc-100"
                : "text-zinc-500 hover:text-zinc-300",
            )}
          >
            {t === "scanner" ? <ShieldAlert className="h-3.5 w-3.5" /> : <History className="h-3.5 w-3.5" />}
            {t}
          </button>
        ))}
      </div>

      {/* ── Scanner tab ──────────────────────────────────────────────────────── */}
      {activeTab === "scanner" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Left: config panel */}
          <div className="space-y-4">
            {/* Credential warning */}
            <div className="flex items-start gap-2 rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-2.5">
              <Shield className="h-4 w-4 text-blue-400 mt-0.5 shrink-0" />
              <p className="text-xs text-blue-300 leading-relaxed">
                Credentials are used only for this scan and are <strong>never stored</strong> or logged.
              </p>
            </div>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <Cloud className="h-4 w-4 text-blue-400" />
                  Cloud Provider
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Provider selector */}
                <div className="grid grid-cols-2 gap-2">
                  {PROVIDERS.map((p) => (
                    <button
                      key={p.value}
                      disabled={!p.available || isScanning}
                      onClick={() => setProvider(p.value)}
                      className={cn(
                        "flex items-center gap-2 rounded-lg border px-3 py-2.5 text-xs font-medium transition-colors text-left",
                        provider === p.value
                          ? "border-blue-500/60 bg-blue-500/10 text-blue-300"
                          : p.available
                          ? "border-zinc-700 bg-zinc-800/50 text-zinc-400 hover:border-zinc-600"
                          : "border-zinc-800 bg-zinc-900/50 text-zinc-600 cursor-not-allowed",
                      )}
                    >
                      {p.icon}
                      <span className="leading-tight">
                        {p.label}
                        {!p.available && <span className="block text-[9px] text-zinc-600">Coming soon</span>}
                      </span>
                    </button>
                  ))}
                </div>

                {/* AWS credentials */}
                {provider === "aws" && (
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Access Key ID</Label>
                      <Input
                        placeholder="AKIAIOSFODNN7EXAMPLE"
                        value={awsKey}
                        onChange={(e) => setAwsKey(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs"
                        autoComplete="off"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Secret Access Key</Label>
                      <div className="relative">
                        <Input
                          type={showSecret ? "text" : "password"}
                          placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                          value={awsSecret}
                          onChange={(e) => setAwsSecret(e.target.value)}
                          disabled={isScanning}
                          className="font-mono text-xs pr-8"
                          autoComplete="off"
                        />
                        <button
                          type="button"
                          onClick={() => setShowSecret((v) => !v)}
                          className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                        >
                          {showSecret
                            ? <EyeOff className="h-3.5 w-3.5" />
                            : <Eye className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Region</Label>
                      <Select value={awsRegion} onValueChange={setAwsRegion} disabled={isScanning}>
                        <SelectTrigger className="text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {AWS_REGIONS.map((r) => (
                            <SelectItem key={r} value={r}>{r}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Session Token <span className="text-zinc-600">(optional)</span></Label>
                      <Input
                        type="password"
                        placeholder="For temporary credentials / assumed roles"
                        value={awsSessionToken}
                        onChange={(e) => setAwsSessionToken(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs"
                        autoComplete="off"
                      />
                    </div>
                  </div>
                )}

                {/* GCP credentials */}
                {provider === "gcp" && (
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Project ID</Label>
                      <Input
                        placeholder="my-gcp-project"
                        value={gcpProjectId}
                        onChange={(e) => setGcpProjectId(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs"
                        autoComplete="off"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Service Account Key (JSON)</Label>
                      <textarea
                        placeholder='{"type": "service_account", ...}'
                        value={gcpServiceAccountKey}
                        onChange={(e) => setGcpServiceAccountKey(e.target.value)}
                        disabled={isScanning}
                        rows={4}
                        className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-2 font-mono text-[10px] text-zinc-300 placeholder:text-zinc-600"
                      />
                    </div>
                  </div>
                )}

                {/* Azure credentials */}
                {provider === "azure" && (
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Subscription ID</Label>
                      <Input
                        value={azureSubscriptionId}
                        onChange={(e) => setAzureSubscriptionId(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs"
                        autoComplete="off"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Tenant ID</Label>
                      <Input
                        value={azureTenantId}
                        onChange={(e) => setAzureTenantId(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs"
                        autoComplete="off"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Client (App) ID</Label>
                      <Input
                        value={azureClientId}
                        onChange={(e) => setAzureClientId(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs"
                        autoComplete="off"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Client Secret</Label>
                      <Input
                        type={showSecret ? "text" : "password"}
                        value={azureClientSecret}
                        onChange={(e) => setAzureClientSecret(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs"
                        autoComplete="off"
                      />
                    </div>
                    <p className="text-[10px] text-zinc-600">
                      Requires a service principal with Reader access on the subscription.
                    </p>
                  </div>
                )}

                {/* Kubernetes credentials */}
                {provider === "kubernetes" && (
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">API Server URL</Label>
                      <Input
                        placeholder="https://kubernetes.example.com:6443"
                        value={k8sApiServer}
                        onChange={(e) => setK8sApiServer(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs"
                        autoComplete="off"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Bearer Token</Label>
                      <Input
                        type={showSecret ? "text" : "password"}
                        value={k8sToken}
                        onChange={(e) => setK8sToken(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs"
                        autoComplete="off"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">CA Certificate <span className="text-zinc-600">(optional, PEM)</span></Label>
                      <textarea
                        placeholder="-----BEGIN CERTIFICATE-----"
                        value={k8sCaCert}
                        onChange={(e) => setK8sCaCert(e.target.value)}
                        disabled={isScanning}
                        rows={3}
                        className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-2 font-mono text-[10px] text-zinc-300 placeholder:text-zinc-600"
                      />
                    </div>
                    {!k8sCaCert.trim() && (
                      <label className="flex items-start gap-2 text-[10px] text-zinc-500">
                        <input
                          type="checkbox"
                          checked={k8sInsecureSkipTlsVerify}
                          onChange={(e) => setK8sInsecureSkipTlsVerify(e.target.checked)}
                          disabled={isScanning}
                          className="mt-0.5"
                        />
                        <span>
                          Skip TLS verification (self-signed cluster with no CA cert available). Only use for
                          clusters you control — this allows a network attacker to intercept your token.
                        </span>
                      </label>
                    )}
                  </div>
                )}

                {/* Severity filter */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Minimum Severity</Label>
                  <Select value={severityFilter} onValueChange={setSeverityFilter} disabled={isScanning}>
                    <SelectTrigger className="text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical only</SelectItem>
                      <SelectItem value="high">High and above</SelectItem>
                      <SelectItem value="medium">Medium and above</SelectItem>
                      <SelectItem value="low">Low and above</SelectItem>
                      <SelectItem value="info">All</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {isScanning ? (
                  <Button onClick={stopScan} variant="destructive" className="w-full gap-2">
                    <Square className="h-4 w-4" /> Stop Scan
                  </Button>
                ) : (
                  <Button
                    onClick={startScan}
                    disabled={
                      (provider === "aws" && (!awsKey.trim() || !awsSecret.trim())) ||
                      (provider === "gcp" && (!gcpProjectId.trim() || !gcpServiceAccountKey.trim())) ||
                      (provider === "azure" && (!azureSubscriptionId.trim() || !azureTenantId.trim() || !azureClientId.trim() || !azureClientSecret.trim())) ||
                      (provider === "kubernetes" && (!k8sApiServer.trim() || !k8sToken.trim()))
                    }
                    className="w-full gap-2"
                  >
                    <Play className="h-4 w-4" /> Run CSPM Scan
                  </Button>
                )}
              </CardContent>
            </Card>

            {/* Progress / stats card */}
            {(isScanning || scanStatus !== "idle") && (
              <Card>
                <CardContent className="pt-4 space-y-3">
                  {/* Progress bar */}
                  {isScanning && (
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-zinc-500">Checks progress</span>
                        <span className="text-zinc-400">{checksCompleted} / {totalChecks}</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded-full transition-all duration-300"
                          style={{ width: `${progressPct}%` }}
                        />
                      </div>
                    </div>
                  )}
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-zinc-500">Status</span>
                    <span className={cn("text-xs font-medium capitalize",
                      scanStatus === "running"   && "text-blue-400",
                      scanStatus === "completed" && "text-emerald-400",
                      scanStatus === "failed"    && "text-red-400",
                      scanStatus === "idle"      && "text-zinc-500",
                    )}>
                      {scanStatus === "running" && <RefreshCw className="inline h-3 w-3 mr-1 animate-spin" />}
                      {scanStatus}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-zinc-500">Findings</span>
                    <span className="text-xs font-semibold text-red-400">{findings.length}</span>
                  </div>
                  {summary && (
                    <>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-zinc-500">Duration</span>
                        <span className="text-xs text-zinc-300">{summary.duration_seconds}s</span>
                      </div>
                      {summary.prowler_used && (
                        <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1.5">
                          <p className="text-[10px] text-emerald-400 flex items-center gap-1">
                            <ShieldCheck className="h-3 w-3" /> Powered by Prowler CLI
                          </p>
                        </div>
                      )}
                    </>
                  )}
                </CardContent>
              </Card>
            )}
          </div>

          {/* Right: results panel */}
          <div className="lg:col-span-2 space-y-4">
            {/* Summary bar */}
            {summary && (
              <Card className="border-zinc-800">
                <CardContent className="pt-4">
                  <div className="flex flex-wrap items-center gap-4 justify-between">
                    <div>
                      <p className="text-sm font-semibold text-zinc-200 mb-1">Scan Complete</p>
                      <p className="text-xs text-zinc-500">
                        {summary.checks_run} checks run · {summary.duration_seconds}s · {awsRegion}
                      </p>
                    </div>
                    <SeveritySummaryBar by_severity={summary.by_severity} />
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Active checks ticker */}
            {isScanning && Object.values(activeChecks).filter((c) => c.status === "running").length > 0 && (
              <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-4 py-2">
                <div className="flex items-center gap-2 text-xs text-zinc-400">
                  <RefreshCw className="h-3 w-3 animate-spin text-blue-400 shrink-0" />
                  <span>
                    Running:{" "}
                    {Object.values(activeChecks)
                      .filter((c) => c.status === "running")
                      .map((c) => c.check_name)
                      .slice(0, 3)
                      .join(", ")}
                    {Object.values(activeChecks).filter((c) => c.status === "running").length > 3 && " …"}
                  </span>
                </div>
              </div>
            )}

            {/* Findings grouped by category */}
            {Object.keys(findingsByCategory).length > 0 && (
              <div className="space-y-3">
                {Object.entries(findingsByCategory).map(([category, catFindings]) => {
                  const isOpen = expandedCategories.has(category);
                  const critCount = catFindings.filter((f) => f.severity === "critical").length;
                  const highCount = catFindings.filter((f) => f.severity === "high").length;
                  return (
                    <Card key={category} className="border-zinc-800">
                      <button
                        className="w-full px-4 py-3 flex items-center gap-3 hover:bg-zinc-800/40 transition-colors rounded-t-lg"
                        onClick={() => toggleCategory(category)}
                      >
                        <span className="text-zinc-500">
                          {CATEGORY_ICONS[category] ?? <Shield className="h-3.5 w-3.5" />}
                        </span>
                        <span className="text-sm font-semibold text-zinc-200 flex-1 text-left">
                          {category}
                        </span>
                        <div className="flex items-center gap-2">
                          {critCount > 0 && (
                            <span className={cn("text-[10px] font-bold rounded-full px-1.5 py-0.5", SEVERITY_COLORS.critical)}>
                              {critCount} CRIT
                            </span>
                          )}
                          {highCount > 0 && (
                            <span className={cn("text-[10px] font-bold rounded-full px-1.5 py-0.5", SEVERITY_COLORS.high)}>
                              {highCount} HIGH
                            </span>
                          )}
                          <span className="text-xs text-zinc-500">{catFindings.length} total</span>
                          {isOpen
                            ? <ChevronDown className="h-4 w-4 text-zinc-500" />
                            : <ChevronRight className="h-4 w-4 text-zinc-500" />}
                        </div>
                      </button>

                      {isOpen && (
                        <CardContent className="pt-0 pb-3 space-y-2">
                          {catFindings.map((f, localIdx) => {
                            // Use a global index for expansion tracking
                            const globalIdx = findings.indexOf(f);
                            const isExpanded = expandedFindings.has(globalIdx);
                            return (
                              <div
                                key={globalIdx}
                                className="rounded-lg border border-zinc-800 bg-zinc-900/60 overflow-hidden"
                              >
                                <button
                                  className="w-full flex items-start gap-3 px-3 py-2.5 hover:bg-zinc-800/40 transition-colors text-left"
                                  onClick={() => toggleFinding(globalIdx)}
                                >
                                  <div className="mt-0.5">
                                    <SeverityBadge severity={f.severity} />
                                  </div>
                                  <div className="flex-1 min-w-0">
                                    <p className="text-xs font-medium text-zinc-200 leading-snug">
                                      {f.description}
                                    </p>
                                    <p className="text-[10px] text-zinc-500 font-mono mt-0.5 truncate">
                                      {f.resource_arn || f.resource}
                                    </p>
                                  </div>
                                  {isExpanded
                                    ? <ChevronDown className="h-3.5 w-3.5 text-zinc-600 shrink-0 mt-0.5" />
                                    : <ChevronRight className="h-3.5 w-3.5 text-zinc-600 shrink-0 mt-0.5" />}
                                </button>

                                {isExpanded && (
                                  <div className="px-3 pb-3 space-y-2 border-t border-zinc-800">
                                    <div className="pt-2">
                                      <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1">
                                        Resource
                                      </p>
                                      <p className="text-xs text-zinc-300 font-mono break-all">
                                        {f.resource_arn || f.resource}
                                      </p>
                                    </div>
                                    <div>
                                      <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1">
                                        Remediation
                                      </p>
                                      <p className="text-xs text-zinc-400 leading-relaxed">
                                        {f.remediation}
                                      </p>
                                    </div>
                                    <div>
                                      <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1">
                                        Check ID
                                      </p>
                                      <code className="text-[10px] text-zinc-500 font-mono">{f.check_id}</code>
                                    </div>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </CardContent>
                      )}
                    </Card>
                  );
                })}
              </div>
            )}

            {/* Empty/idle state */}
            {!isScanning && findings.length === 0 && scanStatus === "idle" && (
              <div className="flex flex-col items-center justify-center py-24 text-zinc-600 space-y-4">
                <ShieldAlert className="h-14 w-14 text-zinc-700" />
                <div className="text-center">
                  <p className="text-sm font-medium text-zinc-500">No scan running</p>
                  <p className="text-xs mt-1">Enter your cloud credentials and run a CSPM scan</p>
                </div>
              </div>
            )}

            {/* Clean bill of health */}
            {!isScanning && scanStatus === "completed" && findings.length === 0 && (
              <div className="flex flex-col items-center justify-center py-20 text-zinc-500 space-y-3">
                <ShieldCheck className="h-12 w-12 text-emerald-500" />
                <p className="text-sm font-semibold text-emerald-400">No findings detected</p>
                <p className="text-xs text-zinc-600">
                  All checks passed at or above the &quot;{severityFilter}&quot; severity threshold.
                </p>
              </div>
            )}

            {/* Scanning + no findings yet */}
            {isScanning && findings.length === 0 && (
              <div className="flex flex-col items-center justify-center py-20 text-zinc-500 space-y-3">
                <Cloud className="h-10 w-10 animate-pulse text-blue-400" />
                <p className="text-sm">Scanning {provider.toUpperCase()} environment…</p>
                <p className="text-xs text-zinc-600">{checksCompleted} of {totalChecks} checks complete</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── History tab ──────────────────────────────────────────────────────── */}
      {activeTab === "history" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
          {/* History list */}
          <div className="lg:col-span-2 space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-zinc-300">Past Scans</p>
              <Button variant="ghost" size="sm" onClick={loadHistory} className="h-7 gap-1.5 text-xs">
                <RefreshCw className="h-3 w-3" /> Refresh
              </Button>
            </div>

            {historyLoading && (
              <div className="flex items-center justify-center py-12 text-zinc-500">
                <RefreshCw className="h-5 w-5 animate-spin" />
              </div>
            )}

            {!historyLoading && history.length === 0 && (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-600 space-y-2">
                <Clock className="h-8 w-8" />
                <p className="text-sm">No past scans</p>
              </div>
            )}

            {history.map((entry) => (
              <button
                key={entry.id}
                onClick={() => loadHistoryDetail(entry.id)}
                className={cn(
                  "w-full rounded-lg border p-3 text-left transition-colors hover:border-zinc-700",
                  selectedHistory?.id === entry.id
                    ? "border-blue-500/50 bg-blue-500/5"
                    : "border-zinc-800 bg-zinc-900/60",
                )}
              >
                <div className="flex items-center gap-2 mb-2">
                  <Cloud className="h-3.5 w-3.5 text-blue-400" />
                  <span className="text-xs font-semibold text-zinc-200 uppercase">{entry.provider}</span>
                  {entry.region && (
                    <span className="text-[10px] text-zinc-600 font-mono">{entry.region}</span>
                  )}
                  {entry.prowler_used && (
                    <span className="text-[10px] text-emerald-500 ml-auto">Prowler</span>
                  )}
                </div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] text-zinc-500">
                    {new Date(entry.started_at).toLocaleString()}
                  </span>
                  <span className="text-[10px] text-zinc-600">{entry.duration_seconds}s</span>
                </div>
                <SeveritySummaryBar by_severity={entry.by_severity} />
              </button>
            ))}
          </div>

          {/* History detail */}
          <div className="lg:col-span-3">
            {!selectedHistory ? (
              <div className="flex flex-col items-center justify-center h-64 text-zinc-600 space-y-2">
                <History className="h-10 w-10" />
                <p className="text-sm">Select a scan to view details</p>
              </div>
            ) : (
              <Card className="border-zinc-800">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-blue-400" />
                      Scan Detail — {selectedHistory.provider.toUpperCase()}
                      {selectedHistory.region && (
                        <span className="text-xs text-zinc-500 font-normal">{selectedHistory.region}</span>
                      )}
                    </CardTitle>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => restoreFromHistory(selectedHistory)}
                        className="gap-1.5 h-7"
                      >
                        <RotateCcw className="h-3.5 w-3.5" /> Restore to Scanner
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => deleteHistory(selectedHistory.id)}
                        className="h-7 w-7 p-0 text-zinc-500 hover:text-red-400"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                  <p className="text-xs text-zinc-500">
                    {new Date(selectedHistory.started_at).toLocaleString()} ·{" "}
                    {selectedHistory.duration_seconds}s ·{" "}
                    {selectedHistory.checks_run} checks · min severity: {selectedHistory.severity_filter}
                  </p>
                  <SeveritySummaryBar by_severity={selectedHistory.by_severity} />
                </CardHeader>
                <CardContent className="space-y-2 max-h-[600px] overflow-y-auto">
                  {selectedHistory.findings.length === 0 ? (
                    <div className="flex items-center gap-2 py-4 text-emerald-400">
                      <ShieldCheck className="h-4 w-4" />
                      <p className="text-sm">No findings — clean posture</p>
                    </div>
                  ) : (
                    selectedHistory.findings.map((f, idx) => (
                      <div
                        key={idx}
                        className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2.5 space-y-1"
                      >
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={f.severity} />
                          <code className="text-[10px] text-zinc-500 font-mono">{f.check_id}</code>
                        </div>
                        <p className="text-xs text-zinc-300">{f.description}</p>
                        <p className="text-[10px] text-zinc-500 font-mono truncate">{f.resource_arn || f.resource}</p>
                        <p className="text-[10px] text-zinc-600 leading-snug">{f.remediation}</p>
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
