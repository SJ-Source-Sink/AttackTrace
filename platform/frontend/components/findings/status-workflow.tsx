"use client";

import React, { useState } from "react";
import { ChevronDown, AlertTriangle } from "lucide-react";
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
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useUpdateFinding } from "@/hooks/use-findings";
import type { Finding, FindingStatus } from "@/types";

const STATUS_CONFIG: Record<FindingStatus, { label: string; className: string }> = {
  open: { label: "Open", className: "border-red-500/30 bg-red-500/10 text-red-400" },
  in_progress: { label: "In Progress", className: "border-blue-500/30 bg-blue-500/10 text-blue-400" },
  remediated: { label: "Remediated", className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400" },
  accepted_risk: { label: "Accepted Risk", className: "border-yellow-500/30 bg-yellow-500/10 text-yellow-400" },
  false_positive: { label: "False Positive", className: "border-zinc-500/30 bg-zinc-500/10 text-zinc-400" },
};

const STATUS_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  open: ["in_progress", "remediated", "accepted_risk", "false_positive"],
  in_progress: ["open", "remediated", "accepted_risk", "false_positive"],
  remediated: ["open"],
  accepted_risk: ["open"],
  false_positive: ["open"],
};

interface StatusWorkflowProps {
  finding: Finding;
}

interface AcceptRiskFormData {
  reason: string;
  expires_at: string;
  approver: string;
}

export function StatusWorkflow({ finding }: StatusWorkflowProps) {
  const { mutate: updateFinding, isPending } = useUpdateFinding();
  const [showAcceptRiskModal, setShowAcceptRiskModal] = useState(false);
  const [acceptRiskData, setAcceptRiskData] = useState<AcceptRiskFormData>({
    reason: "",
    expires_at: "",
    approver: "",
  });

  const transitions = STATUS_TRANSITIONS[finding.status] ?? [];
  const currentConfig = STATUS_CONFIG[finding.status];

  const handleStatusChange = (newStatus: FindingStatus) => {
    if (newStatus === "accepted_risk") {
      setShowAcceptRiskModal(true);
      return;
    }
    updateFinding({ id: finding.id, data: { status: newStatus } });
  };

  const handleAcceptRisk = () => {
    updateFinding({
      id: finding.id,
      data: {
        status: "accepted_risk",
        accept_risk_info: {
          reason: acceptRiskData.reason,
          expires_at: acceptRiskData.expires_at || undefined,
          approver: acceptRiskData.approver,
        },
      },
    });
    setShowAcceptRiskModal(false);
  };

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            disabled={isPending || transitions.length === 0}
            className={`gap-1.5 border font-medium text-xs h-7 ${currentConfig.className}`}
          >
            {currentConfig.label}
            {transitions.length > 0 && <ChevronDown className="h-3 w-3" />}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-48">
          {transitions.map((status, idx) => {
            const config = STATUS_CONFIG[status];
            if (!config) return null;

            const isDestructive = status === "accepted_risk";
            if (isDestructive && idx > 0) {
              return (
                <React.Fragment key={status}>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onClick={() => handleStatusChange(status)}
                    className="text-yellow-400 focus:text-yellow-400 gap-2"
                  >
                    <AlertTriangle className="h-3.5 w-3.5" />
                    {config.label}
                  </DropdownMenuItem>
                </React.Fragment>
              );
            }
            return (
              <DropdownMenuItem
                key={status}
                onClick={() => handleStatusChange(status)}
                className="gap-2"
              >
                <div className={`h-2 w-2 rounded-full ${config.className.includes("red") ? "bg-red-500" : config.className.includes("blue") ? "bg-blue-500" : config.className.includes("emerald") ? "bg-emerald-500" : "bg-zinc-500"}`} />
                {config.label}
              </DropdownMenuItem>
            );
          })}
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Accept Risk Modal */}
      <Dialog open={showAcceptRiskModal} onOpenChange={setShowAcceptRiskModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Accept Risk</DialogTitle>
            <DialogDescription>
              Document the business reason for accepting this risk. This will be audited.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="p-3 rounded-md border border-yellow-500/20 bg-yellow-500/5 flex gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0 mt-0.5" />
              <p className="text-xs text-yellow-400">
                Accepting risk means acknowledging this vulnerability and choosing not to remediate it.
              </p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="reason">Business Reason *</Label>
              <Textarea
                id="reason"
                placeholder="Explain why this risk is acceptable..."
                value={acceptRiskData.reason}
                onChange={(e) => setAcceptRiskData((d) => ({ ...d, reason: e.target.value }))}
                rows={3}
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="approver">Approver *</Label>
              <Input
                id="approver"
                placeholder="John Smith (CISO)"
                value={acceptRiskData.approver}
                onChange={(e) => setAcceptRiskData((d) => ({ ...d, approver: e.target.value }))}
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="expires_at">Expiry Date (optional)</Label>
              <Input
                id="expires_at"
                type="date"
                value={acceptRiskData.expires_at}
                onChange={(e) => setAcceptRiskData((d) => ({ ...d, expires_at: e.target.value }))}
                className="[color-scheme:dark]"
              />
              <p className="text-xs text-zinc-500">Risk acceptance will expire on this date for re-review.</p>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAcceptRiskModal(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleAcceptRisk}
              disabled={!acceptRiskData.reason || !acceptRiskData.approver}
              className="bg-yellow-600 hover:bg-yellow-700"
            >
              Accept Risk
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
