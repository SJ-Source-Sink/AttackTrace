"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ClipboardCheck, CheckCircle2, XCircle, MinusCircle, Download,
  ChevronDown, ChevronRight, Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { API_BASE, complianceApi } from "@/lib/api";
import { toast } from "sonner";

type Framework = "soc2" | "pci_dss" | "iso27001";
type ControlState = "pass" | "fail" | "not_assessed";

const FRAMEWORKS: { value: Framework; label: string }[] = [
  { value: "soc2", label: "SOC 2" },
  { value: "pci_dss", label: "PCI-DSS" },
  { value: "iso27001", label: "ISO/IEC 27001" },
];

interface FailingFinding {
  finding_id: string;
  title: string;
  severity: string;
  affected_asset: string | null;
  cwe: string;
}

interface ControlRow {
  control_id: string;
  name: string;
  description: string;
  state: ControlState;
  failing_findings: FailingFinding[];
}

interface Coverage {
  framework: string;
  generated_at: string;
  total_controls: number;
  passing: number;
  failing: number;
  not_assessed: number;
  controls: ControlRow[];
}

const STATE_CONFIG: Record<ControlState, { label: string; color: string; icon: React.ComponentType<{ className?: string }> }> = {
  pass: { label: "Pass", color: "text-green-400 border-green-800 bg-green-950/30", icon: CheckCircle2 },
  fail: { label: "Fail", color: "text-red-400 border-red-800 bg-red-950/30", icon: XCircle },
  not_assessed: { label: "Not Assessed", color: "text-zinc-500 border-zinc-700 bg-zinc-900/50", icon: MinusCircle },
};

function ControlCard({ control }: { control: ControlRow }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = STATE_CONFIG[control.state];
  const Icon = cfg.icon;
  const hasDetail = control.failing_findings.length > 0;

  return (
    <div className={cn("rounded-lg border p-3 space-y-2", cfg.color)}>
      <div
        className={cn("flex items-start gap-3", hasDetail && "cursor-pointer")}
        onClick={() => hasDetail && setExpanded((v) => !v)}
      >
        <Icon className={cn("h-4 w-4 mt-0.5 shrink-0", cfg.color.split(" ")[0])} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <code className="text-xs font-mono text-zinc-400">{control.control_id}</code>
            <span className="text-sm font-medium text-zinc-200">{control.name}</span>
            <Badge variant="outline" className={cn("text-[10px]", cfg.color)}>{cfg.label}</Badge>
            {hasDetail && (
              <span className="text-[10px] text-zinc-500">
                {control.failing_findings.length} finding{control.failing_findings.length === 1 ? "" : "s"}
              </span>
            )}
          </div>
          <p className="text-xs text-zinc-500 mt-0.5">{control.description}</p>
        </div>
        {hasDetail && (
          expanded ? <ChevronDown className="h-4 w-4 text-zinc-500 shrink-0" /> : <ChevronRight className="h-4 w-4 text-zinc-500 shrink-0" />
        )}
      </div>
      {expanded && hasDetail && (
        <div className="ml-7 space-y-1 border-t border-zinc-800 pt-2">
          {control.failing_findings.slice(0, 20).map((f) => (
            <div key={f.finding_id} className="flex items-center gap-2 text-xs">
              <Badge variant="outline" className="text-[9px] uppercase">{f.severity}</Badge>
              <span className="text-zinc-300">{f.title}</span>
              {f.affected_asset && <span className="text-zinc-600 truncate">— {f.affected_asset}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function CompliancePage() {
  const [framework, setFramework] = useState<Framework>("soc2");
  const [exporting, setExporting] = useState<"pdf" | "csv" | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["compliance", "coverage", framework],
    queryFn: () => complianceApi.coverage(framework) as Promise<Coverage>,
  });

  const handleExport = async (fmt: "pdf" | "csv") => {
    setExporting(fmt);
    try {
      const res = await fetchWithAuth(`${API_BASE}/compliance/${framework}/export?fmt=${fmt}`);
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${framework}-evidence.${fmt}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch {
      toast.error(`Failed to export ${fmt.toUpperCase()}`);
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Compliance"
        description="Map live findings to SOC 2 / PCI-DSS / ISO 27001 controls and export auditor-ready evidence"
      >
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            disabled={exporting !== null}
            onClick={() => handleExport("csv")}
          >
            {exporting === "csv" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
            CSV
          </Button>
          <Button
            size="sm"
            className="gap-1.5"
            disabled={exporting !== null}
            onClick={() => handleExport("pdf")}
          >
            {exporting === "pdf" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
            Export Evidence PDF
          </Button>
        </div>
      </PageHeader>

      {/* Framework tabs */}
      <div className="flex gap-1 border-b border-zinc-800">
        {FRAMEWORKS.map((f) => (
          <button
            key={f.value}
            onClick={() => setFramework(f.value)}
            className={cn(
              "px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors",
              framework === f.value
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200",
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      {isLoading || !data ? (
        <div className="flex items-center justify-center h-40 text-zinc-500">
          <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading coverage...
        </div>
      ) : (
        <>
          {/* Summary */}
          <div className="grid grid-cols-3 gap-3 max-w-lg">
            <Card className="border-green-900/50 bg-green-950/10">
              <CardContent className="p-3 text-center">
                <p className="text-xl font-bold text-green-400">{data.passing}</p>
                <p className="text-[10px] text-zinc-500 uppercase">Passing</p>
              </CardContent>
            </Card>
            <Card className="border-red-900/50 bg-red-950/10">
              <CardContent className="p-3 text-center">
                <p className="text-xl font-bold text-red-400">{data.failing}</p>
                <p className="text-[10px] text-zinc-500 uppercase">Failing</p>
              </CardContent>
            </Card>
            <Card className="border-zinc-800 bg-zinc-900/50">
              <CardContent className="p-3 text-center">
                <p className="text-xl font-bold text-zinc-400">{data.not_assessed}</p>
                <p className="text-[10px] text-zinc-500 uppercase">Not Assessed</p>
              </CardContent>
            </Card>
          </div>

          {/* Control grid */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <ClipboardCheck className="h-4 w-4 text-blue-400" />
                Control Coverage
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {data.controls.map((c) => (
                <ControlCard key={c.control_id} control={c} />
              ))}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
