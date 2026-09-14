"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  ChevronRight, ChevronDown, Code2, Zap, Activity,
  Shield, ExternalLink, Smartphone, Globe, Loader2, Lock, Trash2,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { StatusWorkflow } from "@/components/findings/status-workflow";
import { EvidenceBlock } from "@/components/findings/evidence-block";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { ConfidenceBadge } from "@/components/findings/confidence-badge";
import { KevBadge } from "@/components/findings/kev-badge";
import { SlaBadge } from "@/components/findings/sla-badge";
import { ComplianceTags } from "@/components/findings/compliance-tags";
import { RiskScoreGauge } from "@/components/findings/risk-score-gauge";
import { fetchWithAuth } from "@/lib/auth";
import { cn, formatRelativeTime } from "@/lib/utils";
import { toast } from "sonner";
import { useUpdateFinding, useDeleteFinding } from "@/hooks/use-findings";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import type { Finding } from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const SEV_ACCENT: Record<string, string> = {
  critical: "border-l-red-500",
  high:     "border-l-orange-500",
  medium:   "border-l-yellow-500",
  low:      "border-l-blue-400",
  info:     "border-l-zinc-600",
};

// Evidence can be a string, a dict {file,line,snippet}, or an array of evidence objects

interface FindingRowProps {
  finding: Finding;
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

const SEV_MENU_COLORS: Record<string, string> = {
  critical: "text-red-400 hover:bg-red-500/10",
  high: "text-orange-400 hover:bg-orange-500/10",
  medium: "text-yellow-400 hover:bg-yellow-500/10",
  low: "text-blue-400 hover:bg-blue-500/10",
  info: "text-zinc-400 hover:bg-zinc-500/10",
};

export function FindingRow({ finding }: FindingRowProps) {
  const router = useRouter();
  const [expanded, setExpanded] = useState(false);
  const [loadingPoc, setLoadingPoc] = useState(false);
  const [poc, setPoc] = useState<string | null>(null);
  const [severityMenuOpen, setSeverityMenuOpen] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const severityMenuRef = useRef<HTMLDivElement>(null);
  const updateFinding = useUpdateFinding();
  const deleteFinding = useDeleteFinding();

  useEffect(() => {
    if (!severityMenuOpen) return;
    const handler = (e: MouseEvent) => {
      if (severityMenuRef.current && !severityMenuRef.current.contains(e.target as Node)) {
        setSeverityMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [severityMenuOpen]);

  const isMobile = finding.source === "msra";
  const isManual = finding.source === "manual";

  const generatePoc = async () => {
    setLoadingPoc(true);
    try {
      const res = await fetchWithAuth(`${API_BASE}/mobile/ai/poc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scan_id: finding.source_scan_id,
          finding_id: finding.id,
        }),
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

  const [startingDynamic, setStartingDynamic] = useState(false);

  const startDynamicAnalysis = async () => {
    if (!finding.source_scan_id) return;
    setStartingDynamic(true);
    try {
      const res = await fetchWithAuth(
        `${API_BASE}/mobile/scans/${finding.source_scan_id}/dynamic`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scan_id: finding.source_scan_id,
            finding_index: 0,
            finding: {
              title: finding.title,
              severity: finding.severity,
              description: finding.description,
            },
            use_ai: true,
          }),
        }
      );
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error?.message ?? "Failed to start analysis");
      toast.success("Dynamic analysis started — redirecting…");
      router.push(`/mobile/${finding.source_scan_id}?tab=dynamic`);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to start dynamic analysis");
    } finally {
      setStartingDynamic(false);
    }
  };

  const hasEvidence = finding.evidence &&
    (Array.isArray(finding.evidence) ? finding.evidence.length > 0 : true);

  const remediationSteps = finding.remediation_steps?.filter(Boolean) ?? [];

  return (
    <div className={cn("border-l-2 transition-colors", SEV_ACCENT[finding.severity] ?? "border-l-zinc-600",
      expanded ? "bg-zinc-900/60" : "hover:bg-zinc-800/30")}>

      {/* Collapsed row — div instead of button to avoid nested-button violation
          (StatusWorkflow contains buttons; <button> cannot nest <button>) */}
      <div
        role="button"
        tabIndex={0}
        className="w-full flex items-center gap-3 px-4 py-3 text-left cursor-pointer"
        onClick={() => setExpanded(!expanded)}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setExpanded(!expanded); } }}
      >
        {expanded
          ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
          : <ChevronRight className="h-3.5 w-3.5 text-zinc-500 shrink-0" />}

        {/* Severity + confidence stacked */}
        <div className="flex flex-col gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
          <div className="relative" ref={severityMenuRef}>
            <button
              title="Click to adjust severity"
              onClick={() => setSeverityMenuOpen((o) => !o)}
              className="focus:outline-none"
            >
              <SeverityBadge severity={finding.severity} />
            </button>
            {severityMenuOpen && (
              <div className="absolute left-0 top-full mt-1 z-50 w-28 rounded-md border border-zinc-700 bg-zinc-900 shadow-lg py-1">
                {SEVERITIES.map((sev) => (
                  <button
                    key={sev}
                    className={cn(
                      "w-full text-left px-3 py-1.5 text-xs font-medium capitalize transition-colors",
                      SEV_MENU_COLORS[sev],
                      sev === finding.severity && "bg-zinc-800"
                    )}
                    onClick={() => {
                      setSeverityMenuOpen(false);
                      if (sev !== finding.severity) {
                        updateFinding.mutate({ id: finding.id, data: { severity: sev } });
                      }
                    }}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            )}
          </div>
          <ConfidenceBadge confidence={finding.confidence ?? null} />
        </div>

        {/* Risk score gauge */}
        <RiskScoreGauge score={finding.risk_score} explanation={finding.risk_explanation} />

        {/* Title + meta */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-zinc-200 truncate max-w-md">{finding.title}</span>
            <KevBadge kev_status={finding.kev_status} epss_score={finding.epss_score} />
            <SlaBadge sla_deadline={finding.sla_deadline} />
          </div>
          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
            {/* Source badge */}
            {isMobile ? (
              <span className="inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded border border-violet-500/30 bg-violet-500/10 text-violet-400">
                <Smartphone className="h-2.5 w-2.5" /> Mobile
              </span>
            ) : isManual ? (
              <span className="inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
                <Shield className="h-2.5 w-2.5" /> Manual
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded border border-blue-500/30 bg-blue-500/10 text-blue-400">
                <Globe className="h-2.5 w-2.5" /> Recon
              </span>
            )}
            <span className="text-xs text-zinc-500 truncate max-w-xs font-mono">{finding.asset_value}</span>
            <span className="inline-flex items-center gap-1 text-xs text-zinc-600">
              {finding.category === "exposed_secret" && (
                <Lock className="h-3 w-3 text-amber-400" />
              )}
              {finding.category}
            </span>
            {finding.cve_id && (
              <a href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                target="_blank" rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="text-[10px] text-blue-400 hover:underline flex items-center gap-0.5">
                {finding.cve_id} <ExternalLink className="h-2.5 w-2.5" />
              </a>
            )}
          </div>
        </div>

        {/* Right side: status + age */}
        <div className="flex items-center gap-3 shrink-0" onClick={(e) => e.stopPropagation()}>
          <StatusWorkflow finding={finding} />
          <span className={cn("text-xs w-8 text-right",
            (finding.age_days ?? 0) > 30 ? "text-red-400" :
            (finding.age_days ?? 0) > 7  ? "text-yellow-400" : "text-zinc-500")}>
            {finding.age_days ?? 0}d
          </span>
        </div>
      </div>

      {/* Expanded panel */}
      {expanded && (
        <div className="px-4 pb-5 ml-6 space-y-4 border-t border-zinc-800/50">
          {/* Description */}
          <p className="text-sm text-zinc-400 pt-3 leading-relaxed">{finding.description}</p>

          {/* Evidence */}
          {hasEvidence && (
            <div>
              <p className="text-xs font-medium text-zinc-500 mb-2 flex items-center gap-1.5">
                <Code2 className="h-3.5 w-3.5" /> Evidence
              </p>
              <EvidenceBlock evidence={finding.evidence} />
            </div>
          )}

          {/* PoC (mobile AI-generated or loaded) */}
          {poc && (
            <div>
              <p className="text-xs font-medium text-zinc-400 mb-2 flex items-center gap-1.5">
                <Zap className="h-3.5 w-3.5 text-yellow-400" /> Proof of Concept
              </p>
              <pre className="bg-zinc-950 rounded-md p-3 text-xs text-yellow-200 font-mono overflow-x-auto border border-yellow-900/30 whitespace-pre-wrap">
                {poc}
              </pre>
            </div>
          )}

          {/* Remediation */}
          {remediationSteps.length > 0 && (
            <div className="bg-emerald-900/10 border border-emerald-900/30 rounded-md p-3">
              <p className="text-xs font-medium text-emerald-400 mb-2 flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5" /> Remediation
              </p>
              <ol className="space-y-1.5">
                {remediationSteps.map((step, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-zinc-400">
                    <span className="shrink-0 h-4 w-4 rounded-full bg-emerald-900/50 border border-emerald-800/50 text-emerald-400 flex items-center justify-center text-[10px] font-bold mt-0.5">
                      {i + 1}
                    </span>
                    {step}
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* References */}
          {finding.references?.length > 0 && (
            <div>
              <p className="text-xs font-medium text-zinc-500 mb-1.5">References</p>
              <ul className="space-y-1">
                {finding.references.slice(0, 4).map((ref, i) => (
                  <li key={i}>
                    <a href={ref} target="_blank" rel="noopener noreferrer"
                      className="text-xs text-blue-400 hover:underline flex items-center gap-1 truncate max-w-lg">
                      {ref} <ExternalLink className="h-2.5 w-2.5 shrink-0" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* AI Triage summary (if available) */}
          {finding.ai_triage && (
            <div className="bg-blue-500/5 border border-blue-500/20 rounded-md p-3">
              <p className="text-xs font-medium text-blue-400 mb-1.5">AI Triage</p>
              <p className="text-xs text-zinc-400">{finding.ai_triage.reasoning}</p>
              {finding.ai_triage.false_positive_likelihood > 40 && (
                <p className="text-xs text-yellow-400 mt-1">
                  {finding.ai_triage.false_positive_likelihood}% false positive likelihood
                </p>
              )}
            </div>
          )}

          {/* Risk explanation */}
          {finding.risk_explanation && (
            <div className="text-xs text-zinc-500 flex items-center gap-2">
              <RiskScoreGauge score={finding.risk_score} size="md" />
              <span>{finding.risk_explanation}</span>
            </div>
          )}

          {/* Compliance tags */}
          {finding.compliance_tags && finding.compliance_tags.length > 0 && (
            <div>
              <p className="text-xs font-medium text-zinc-500 mb-1.5">Compliance Frameworks</p>
              <ComplianceTags tags={finding.compliance_tags} />
            </div>
          )}

          {/* Actions row */}
          <div className="flex items-center gap-2 pt-1 flex-wrap">
            {/* AI PoC — only for mobile findings */}
            {isMobile && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs border-zinc-700 hover:border-zinc-600"
                onClick={generatePoc}
                disabled={loadingPoc}
              >
                {loadingPoc
                  ? <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                  : <Zap className="h-3 w-3 mr-1 text-yellow-400" />}
                AI PoC
              </Button>
            )}

            {/* Dynamic Analysis — only for mobile findings with a source scan */}
            {isMobile && finding.source_scan_id && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs border-zinc-700 hover:border-violet-500/50 text-violet-400"
                onClick={startDynamicAnalysis}
                disabled={startingDynamic}
              >
                {startingDynamic
                  ? <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                  : <Activity className="h-3 w-3 mr-1" />}
                Dynamic Analysis
              </Button>
            )}

            {/* View in Mobile Scanner — for mobile findings */}
            {isMobile && finding.source_scan_id && (
              <Button
                variant="ghost"
                size="sm"
                className="h-7 text-xs text-zinc-500 hover:text-zinc-300"
                onClick={() => router.push(`/mobile/${finding.source_scan_id}`)}
              >
                <Smartphone className="h-3 w-3 mr-1" />
                View in Mobile Scanner
              </Button>
            )}

            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs text-red-400/70 hover:text-red-400 hover:bg-red-500/10 ml-auto"
              onClick={() => setShowDeleteConfirm(true)}
            >
              <Trash2 className="h-3 w-3 mr-1" />
              Delete
            </Button>
          </div>
        </div>
      )}

      <Dialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
        <DialogContent onClick={(e) => e.stopPropagation()}>
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
              onClick={() => deleteFinding.mutate(finding.id, { onSuccess: () => setShowDeleteConfirm(false) })}
              disabled={deleteFinding.isPending}
            >
              {deleteFinding.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
