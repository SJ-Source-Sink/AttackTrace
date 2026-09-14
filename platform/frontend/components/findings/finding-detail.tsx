"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  X,
  ExternalLink,
  Brain,
  AlertTriangle,
  CheckCircle2,
  FileText,
  BookOpen,
  ChevronRight,
  UserCircle,
  ChevronDown,
  RefreshCw,
  Trash2,
  Search,
  MapPin,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { ConfidenceBadge } from "@/components/findings/confidence-badge";
import { StatusWorkflow } from "@/components/findings/status-workflow";
import { EvidenceBlock } from "@/components/findings/evidence-block";
import { FindingComments } from "@/components/findings/finding-comments";
import { FindingHistory } from "@/components/findings/finding-history";
import { severityBgColor, formatDate, capitalize } from "@/lib/utils";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { findingsApi } from "@/lib/api";
import { useDeleteFinding } from "@/hooks/use-findings";
import { toast } from "sonner";
import type { Finding, FindingSeverity } from "@/types";

interface FindingDetailProps {
  finding: Finding;
  onClose: () => void;
}

// Mirrors app/services/report_service.py's _SOURCE_LABELS — keep in sync
// when a new scanner source is added on the backend.
const SOURCE_LABELS: Record<string, string> = {
  attacktrace: "Core Scan Pipeline",
  cspm: "Cloud Security Posture Management",
  secrets: "Secret Scanner",
  supply_chain: "Supply Chain Scanner",
  container_scanner: "Container/Kubernetes Scanner",
  firewall_physical: "Physical Firewall Scanner",
  exposure_scanner: "Exposure Scanner",
  mcp_scanner: "MCP Scanner",
  takeover: "Subdomain Takeover Scanner",
  email_security: "Email Security Scanner",
  msra: "Mobile Scanner",
  attack_suite_agent: "Attack Suite AI Agent",
  attack_suite: "Attack Suite Scanner",
  js_scanner: "JavaScript Analysis Scanner",
  api_scanner: "API Security Scanner",
  ai_scanner: "AI/LLM Red-Team Scanner",
  cloud: "Cloud Discovery Scanner",
  firewall_waf_bypass: "Firewall — WAF Bypass Scanner",
  firewall_port_map: "Firewall — Port/Service Mapper",
  firewall_rules_analyze: "Firewall — Rule Analyzer",
  firewall_rate_limit: "Firewall — Rate-Limit Probe",
  firewall_smuggling: "Firewall — Request Smuggling Probe",
  correlation_engine: "Cross-Scanner Correlation Engine",
  manual: "Manually Added",
};

function AssigneeSelector({ finding }: { finding: Finding }) {
  const qc = useQueryClient();

  const { data: assigneesData } = useQuery({
    queryKey: ["findings", "assignees"],
    queryFn: () => findingsApi.assignees(),
    staleTime: 5 * 60_000,
  });

  const assignMutation = useMutation({
    mutationFn: (userId: string | null) =>
      findingsApi.update(finding.id, { assigned_to: userId ?? "" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      toast.success(userId ? "Finding assigned" : "Assignee removed");
    },
    onError: () => toast.error("Failed to update assignee"),
  });

  // We need userId in scope for the success toast — capture from closure
  let userId: string | null = null;

  const assignees = assigneesData?.items ?? [];
  const currentAssignee = assignees.find((a) => a.id === finding.assigned_to);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="h-7 px-2 text-xs gap-1.5 text-zinc-400 hover:text-zinc-200">
          <UserCircle className="h-3.5 w-3.5" />
          {currentAssignee ? currentAssignee.name : "Unassigned"}
          <ChevronDown className="h-3 w-3" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-52">
        {assignees.map((a) => (
          <DropdownMenuItem
            key={a.id}
            onClick={() => { userId = a.id; assignMutation.mutate(a.id); }}
            className={finding.assigned_to === a.id ? "bg-zinc-800" : ""}
          >
            <div className="flex flex-col gap-0.5">
              <span className="text-sm">{a.name}</span>
              <span className="text-xs text-zinc-500">{a.email}</span>
            </div>
          </DropdownMenuItem>
        ))}
        {finding.assigned_to && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => { userId = null; assignMutation.mutate(null); }}
              className="text-zinc-500"
            >
              Remove assignee
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function RevalidateButton({ finding }: { finding: Finding }) {
  const qc = useQueryClient();

  const revalidateMutation = useMutation({
    mutationFn: () => findingsApi.revalidate(finding.id),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      if (result.checked === "none") {
        toast.info("Nothing to re-check — this finding has no port/URL in its affected asset.");
      } else if (result.stale) {
        toast.warning("No longer reproduces — this may be stale.");
      } else {
        toast.success(`Still live — confidence updated to "${result.confidence}".`);
      }
    },
    onError: () => toast.error("Failed to re-verify finding"),
  });

  return (
    <Button
      variant="ghost"
      size="sm"
      className="h-7 px-2 text-xs gap-1.5 text-zinc-400 hover:text-zinc-200"
      disabled={revalidateMutation.isPending}
      onClick={() => revalidateMutation.mutate()}
    >
      <RefreshCw className={`h-3.5 w-3.5 ${revalidateMutation.isPending ? "animate-spin" : ""}`} />
      Re-verify
    </Button>
  );
}

export function FindingDetail({ finding, onClose }: FindingDetailProps) {
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const deleteFinding = useDeleteFinding();
  const confidenceColor =
    finding.ai_triage?.confidence !== undefined
      ? finding.ai_triage.confidence >= 80
        ? "text-emerald-400"
        : finding.ai_triage.confidence >= 50
          ? "text-yellow-400"
          : "text-red-400"
      : "text-zinc-500";

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="flex items-start gap-3 p-6 pb-4 border-b border-zinc-800">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <SeverityBadge severity={finding.severity} />
            {finding.cve_id && (
              <a
                href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 border border-blue-400/30 bg-blue-400/10 rounded px-1.5 py-0.5"
              >
                {finding.cve_id}
                <ExternalLink className="h-2.5 w-2.5" />
              </a>
            )}
            {finding.cvss_score && (
              <span className="text-xs text-zinc-500">CVSS: {finding.cvss_score.toFixed(1)}</span>
            )}
          </div>
          <h2 className="text-base font-semibold text-zinc-100 leading-tight">
            {finding.title}
          </h2>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-xs text-zinc-500 font-mono truncate">{finding.asset_value}</span>
            <Badge variant="secondary" className="text-[10px] capitalize">
              {finding.category.replace("_", " ")}
            </Badge>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <RevalidateButton finding={finding} />
          <AssigneeSelector finding={finding} />
          <StatusWorkflow finding={finding} />
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setShowDeleteConfirm(true)}
            className="h-8 w-8 text-red-400/70 hover:text-red-400 hover:bg-red-500/10"
            title="Delete finding"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" onClick={onClose} className="h-8 w-8">
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <Dialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete this finding?</DialogTitle>
            <DialogDescription>
              &ldquo;{finding.title}&rdquo; will be permanently deleted, along with any comments and history
              attached to it. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteConfirm(false)} disabled={deleteFinding.isPending}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteFinding.mutate(finding.id, { onSuccess: () => { setShowDeleteConfirm(false); onClose(); } })}
              disabled={deleteFinding.isPending}
            >
              {deleteFinding.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Scrollable content */}
      <ScrollArea className="flex-1">
        <div className="p-6 space-y-6">
          {/* Description */}
          <div>
            <p className="text-sm text-zinc-300 leading-relaxed">{finding.description}</p>
          </div>

          {/* Detection Details — what found this, where, and how confident to be.
              Answers "what does this mean / where did it find it / how did it
              find it" directly on the finding, rather than leaving the reader
              to infer it from a raw evidence blob. */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4 space-y-3">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-zinc-300">
              <Search className="h-4 w-4 text-zinc-400" />
              Detection Details
            </h3>
            <div className="grid grid-cols-2 gap-x-4 gap-y-2.5 text-xs">
              <div>
                <p className="text-zinc-500 mb-1">Found By</p>
                <p className="text-zinc-300">
                  {SOURCE_LABELS[finding.source ?? ""] ?? finding.source ?? "Unknown"}
                </p>
              </div>
              <div>
                <p className="text-zinc-500 mb-1">Confidence</p>
                {finding.confidence ? (
                  <ConfidenceBadge confidence={finding.confidence} />
                ) : (
                  <span className="text-zinc-500">Not graded</span>
                )}
              </div>
              <div className="col-span-2">
                <p className="text-zinc-500 mb-1 flex items-center gap-1">
                  <MapPin className="h-3 w-3" /> Location / Affected Asset
                </p>
                <p className="text-zinc-300 font-mono break-all">
                  {finding.asset_value || "Not specified"}
                </p>
              </div>
            </div>
            {finding.confidence_explanation && (
              <div className="pt-1 border-t border-zinc-800">
                <p className="text-zinc-500 mb-1 text-xs">
                  How this was verified
                  {finding.oracle && (
                    <span className="text-zinc-600 font-mono"> ({finding.oracle})</span>
                  )}
                </p>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  {finding.confidence_explanation}
                </p>
              </div>
            )}
          </div>

          {/* AI Triage */}
          {finding.ai_triage && (
            <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4 space-y-3">
              <div className="flex items-center gap-2">
                <Brain className="h-4 w-4 text-blue-400" />
                <h3 className="text-sm font-semibold text-blue-400">AI Triage Analysis</h3>
                <span className={`text-xs ml-auto ${confidenceColor}`}>
                  {finding.ai_triage.confidence}% confidence
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <p className="text-zinc-500 mb-1">AI Severity</p>
                  <SeverityBadge severity={finding.ai_triage.severity} />
                </div>
                <div>
                  <p className="text-zinc-500 mb-1">False Positive Likelihood</p>
                  <span className={finding.ai_triage.false_positive_likelihood > 50 ? "text-yellow-400" : "text-zinc-300"}>
                    {finding.ai_triage.false_positive_likelihood}%
                  </span>
                </div>
              </div>

              <div>
                <p className="text-xs text-zinc-500 mb-1">Reasoning</p>
                <p className="text-xs text-zinc-300 leading-relaxed">{finding.ai_triage.reasoning}</p>
              </div>

              {finding.ai_triage.business_impact && (
                <div>
                  <p className="text-xs text-zinc-500 mb-1">Business Impact</p>
                  <p className="text-xs text-zinc-300">{finding.ai_triage.business_impact}</p>
                </div>
              )}
            </div>
          )}

          {/* Remediation steps */}
          {finding.remediation_steps.length > 0 && (
            <div>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-zinc-300 mb-3">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                Remediation Steps
              </h3>
              <ol className="space-y-2">
                {finding.remediation_steps.map((step, idx) => (
                  <li key={idx} className="flex gap-2 text-sm text-zinc-400">
                    <span className="shrink-0 flex h-5 w-5 items-center justify-center rounded-full bg-zinc-800 text-xs font-medium text-zinc-300">
                      {idx + 1}
                    </span>
                    <span className="leading-relaxed">{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Evidence — finding.evidence is a dict at the API level (see
              backend FindingResponse.evidence: Optional[dict]), not an
              array; EvidenceBlock handles every shape actually produced. */}
          {finding.evidence && (
            <div>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-zinc-300 mb-3">
                <FileText className="h-4 w-4 text-zinc-400" />
                Evidence
              </h3>
              <EvidenceBlock evidence={finding.evidence} />
            </div>
          )}
          {/* References */}
          {finding.references.length > 0 && (
            <div>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-zinc-300 mb-3">
                <BookOpen className="h-4 w-4 text-zinc-400" />
                References
              </h3>
              <ul className="space-y-1">
                {finding.references.map((ref, idx) => (
                  <li key={idx}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 hover:underline break-all"
                    >
                      {ref}
                      <ExternalLink className="h-2.5 w-2.5 shrink-0" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Accept Risk info */}
          {finding.accept_risk_info && (
            <div className="rounded-md border border-yellow-500/20 bg-yellow-500/5 p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="h-4 w-4 text-yellow-400" />
                <h3 className="text-sm font-semibold text-yellow-400">Risk Accepted</h3>
              </div>
              <dl className="space-y-1 text-xs">
                <div className="flex gap-2">
                  <dt className="text-zinc-500 w-20">Reason:</dt>
                  <dd className="text-zinc-300">{finding.accept_risk_info.reason}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-zinc-500 w-20">Approver:</dt>
                  <dd className="text-zinc-300">{finding.accept_risk_info.approver}</dd>
                </div>
                {finding.accept_risk_info.expires_at && (
                  <div className="flex gap-2">
                    <dt className="text-zinc-500 w-20">Expires:</dt>
                    <dd className="text-zinc-300">
                      {formatDate(finding.accept_risk_info.expires_at)}
                    </dd>
                  </div>
                )}
              </dl>
            </div>
          )}

          <Separator />

          {/* History */}
          <FindingHistory findingId={finding.id} />

          <Separator />

          {/* Comments */}
          <FindingComments findingId={finding.id} />
        </div>
      </ScrollArea>
    </div>
  );
}
