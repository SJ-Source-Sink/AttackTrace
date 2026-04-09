"use client";

import React from "react";
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
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { StatusWorkflow } from "@/components/findings/status-workflow";
import { FindingComments } from "@/components/findings/finding-comments";
import { severityBgColor, formatDate, capitalize } from "@/lib/utils";
import type { Finding, FindingSeverity } from "@/types";

interface FindingDetailProps {
  finding: Finding;
  onClose: () => void;
}

export function FindingDetail({ finding, onClose }: FindingDetailProps) {
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
          <StatusWorkflow finding={finding} />
          <Button variant="ghost" size="icon" onClick={onClose} className="h-8 w-8">
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Scrollable content */}
      <ScrollArea className="flex-1">
        <div className="p-6 space-y-6">
          {/* Description */}
          <div>
            <p className="text-sm text-zinc-300 leading-relaxed">{finding.description}</p>
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

              <div>
                <p className="text-xs text-zinc-500 mb-1">Business Impact</p>
                <p className="text-xs text-zinc-300">{finding.ai_triage.business_impact}</p>
              </div>
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

          {/* Evidence */}
          {finding.evidence.length > 0 && (
            <div>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-zinc-300 mb-3">
                <FileText className="h-4 w-4 text-zinc-400" />
                Evidence
              </h3>
              <Accordion type="multiple" className="space-y-1">
                {finding.evidence.map((ev, idx) => (
                  <AccordionItem
                    key={idx}
                    value={`evidence-${idx}`}
                    className="border border-zinc-800 rounded-lg overflow-hidden"
                  >
                    <AccordionTrigger className="px-4 py-3 hover:no-underline hover:bg-zinc-800/40">
                      <span className="text-sm font-medium text-zinc-300">{ev.title}</span>
                    </AccordionTrigger>
                    <AccordionContent className="px-4 pb-4">
                      {ev.url && (
                        <a
                          href={ev.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-xs text-blue-400 hover:underline mb-2"
                        >
                          {ev.url}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                      <pre className="text-xs text-zinc-400 font-mono bg-zinc-950 p-3 rounded-md overflow-x-auto whitespace-pre-wrap">
                        {ev.content}
                      </pre>
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
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

          {/* Comments */}
          <FindingComments findingId={finding.id} comments={finding.comments} />
        </div>
      </ScrollArea>
    </div>
  );
}
