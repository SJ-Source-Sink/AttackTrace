"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Clock, Shield, TrendingUp, TrendingDown, Minus,
  Activity, Target, RefreshCw, Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { dashboardApi } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ExecutiveMetrics {
  mttr_by_severity: Record<string, number | null>;
  risk_trend: { "30d": number; "60d": number; "90d": number };
  new_vs_recurring: { new: number; recurring: number; total: number };
  coverage_percent: number;
  total_assets: number;
  open_critical: number;
  sla_compliance_percent: number;
  generated_at: string;
}

const NEUTRAL_COLOR = "bg-zinc-500/10 text-zinc-400";

function MetricCard({
  label,
  value,
  subtext,
  icon: Icon,
  color,
  trend,
}: {
  label: string;
  value: string;
  subtext?: string;
  icon: React.ElementType;
  color: string;
  trend?: "up" | "down" | "neutral";
}) {
  const TrendIcon = trend === "up" ? TrendingUp : trend === "down" ? TrendingDown : Minus;
  return (
    <div className="flex items-start gap-3 p-4 rounded-lg border border-zinc-800 bg-zinc-900/60">
      <div className={cn("rounded-lg p-2 shrink-0", color)}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-zinc-500 font-medium">{label}</p>
        <p className="text-xl font-bold text-zinc-100 mt-0.5">{value}</p>
        {subtext && <p className="text-xs text-zinc-500 mt-0.5">{subtext}</p>}
      </div>
      {trend && (
        <TrendIcon className={cn(
          "h-4 w-4 shrink-0 mt-1",
          trend === "up" ? "text-red-400" : trend === "down" ? "text-emerald-400" : "text-zinc-600"
        )} />
      )}
    </div>
  );
}

function MttrBar({ severity, days }: { severity: string; days: number | null }) {
  const SEVERITY_COLORS: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-500",
  };
  const maxDays = 90;
  const width = days !== null ? Math.min(100, (days / maxDays) * 100) : 0;

  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-zinc-500 capitalize w-14 shrink-0">{severity}</span>
      <div className="flex-1 h-1.5 rounded-full bg-zinc-800">
        {days !== null && (
          <div
            className={cn("h-full rounded-full", SEVERITY_COLORS[severity] ?? "bg-zinc-600")}
            style={{ width: `${width}%` }}
          />
        )}
      </div>
      <span className="text-xs font-mono text-zinc-300 w-16 text-right shrink-0">
        {days !== null ? `${days.toFixed(0)}d` : "—"}
      </span>
    </div>
  );
}

export function ExecutiveKPIs() {
  const { data, isLoading } = useQuery({
    queryKey: ["dashboard", "executive"],
    queryFn: () => dashboardApi.executive() as Promise<ExecutiveMetrics>,
    staleTime: 15 * 60_000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8 text-zinc-500 gap-2">
        <Loader2 className="h-4 w-4 animate-spin" />
        <span className="text-sm">Loading security KPIs…</span>
      </div>
    );
  }

  if (!data) return null;

  // Risk trend: compare 30d vs 90d avg risk
  const riskTrend = data.risk_trend["30d"] > data.risk_trend["90d"]
    ? "up"
    : data.risk_trend["30d"] < data.risk_trend["90d"]
    ? "down"
    : "neutral";

  const totalFP = data.new_vs_recurring.total;
  const recurringPct = totalFP > 0
    ? Math.round((data.new_vs_recurring.recurring / totalFP) * 100)
    : 0;

  // A brand-new org (no assets onboarded yet) or one with no findings at all
  // shouldn't show alarming red/orange KPI tiles — those thresholds are only
  // meaningful once there's actually something to measure.
  const hasNoAssets = data.total_assets === 0;
  const hasNoFindings = totalFP === 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
          <Shield className="h-4 w-4 text-orange-400" />
          Security KPIs
        </h2>
        <span className="text-[10px] text-zinc-600">
          Updated {new Date(data.generated_at).toLocaleTimeString()}
        </span>
      </div>

      {/* Top KPI row */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          label="SLA Compliance"
          value={hasNoFindings ? "—" : `${data.sla_compliance_percent.toFixed(0)}%`}
          subtext={hasNoFindings ? "no findings yet" : "findings resolved on time"}
          icon={Target}
          color={hasNoFindings ? NEUTRAL_COLOR : data.sla_compliance_percent >= 80 ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}
          trend={hasNoFindings ? "neutral" : data.sla_compliance_percent >= 80 ? "down" : "up"}
        />
        <MetricCard
          label="Open Critical"
          value={String(data.open_critical)}
          subtext={hasNoAssets ? "no assets onboarded yet" : "require immediate action"}
          icon={Shield}
          color={data.open_critical === 0 ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}
          trend={data.open_critical === 0 ? "neutral" : "up"}
        />
        <MetricCard
          label="Asset Coverage"
          value={hasNoAssets ? "No assets" : `${data.coverage_percent.toFixed(0)}%`}
          subtext={hasNoAssets ? "add assets to track coverage" : "assets scanned recently"}
          icon={Activity}
          color={hasNoAssets ? NEUTRAL_COLOR : "bg-blue-500/10 text-blue-400"}
          trend={hasNoAssets ? "neutral" : data.coverage_percent >= 80 ? "down" : "up"}
        />
        <MetricCard
          label="Avg Risk Score"
          value={hasNoFindings ? "—" : data.risk_trend["30d"].toFixed(0)}
          subtext={hasNoFindings ? "no findings yet" : "30-day average (0–100)"}
          icon={TrendingUp}
          color={hasNoFindings ? NEUTRAL_COLOR : riskTrend === "down" ? "bg-emerald-500/10 text-emerald-400" : "bg-orange-500/10 text-orange-400"}
          trend={hasNoFindings ? "neutral" : riskTrend}
        />
      </div>

      {/* Two-column: MTTR + Findings mix */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* MTTR by severity */}
        <Card className="border-zinc-800 bg-zinc-900/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Clock className="h-4 w-4 text-zinc-400" />
              Mean Time to Remediate (MTTR)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(["critical", "high", "medium", "low"] as const).map((sev) => (
              <MttrBar key={sev} severity={sev} days={data.mttr_by_severity[sev]} />
            ))}
            <p className="text-[10px] text-zinc-600 pt-1">
              Based on time from finding creation to remediation status
            </p>
          </CardContent>
        </Card>

        {/* New vs Recurring + Risk Trend */}
        <div className="space-y-4">
          <Card className="border-zinc-800 bg-zinc-900/60">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <RefreshCw className="h-4 w-4 text-zinc-400" />
                New vs Recurring Findings
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-4">
                <div className="flex-1">
                  <div className="h-2 rounded-full bg-zinc-800 overflow-hidden">
                    {totalFP > 0 && (
                      <>
                        <div
                          className="h-full bg-blue-500 float-left"
                          style={{ width: `${100 - recurringPct}%` }}
                        />
                        <div
                          className="h-full bg-orange-500 float-left"
                          style={{ width: `${recurringPct}%` }}
                        />
                      </>
                    )}
                  </div>
                  <div className="flex items-center justify-between mt-2 text-xs text-zinc-500">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-blue-500 inline-block" />
                      {data.new_vs_recurring.new} new
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-orange-500 inline-block" />
                      {data.new_vs_recurring.recurring} recurring
                    </span>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-2xl font-bold text-zinc-100">{totalFP}</p>
                  <p className="text-xs text-zinc-500">total findings</p>
                </div>
              </div>
              {recurringPct > 30 && (
                <p className="text-xs text-orange-400 mt-3 flex items-center gap-1">
                  <TrendingUp className="h-3 w-3" />
                  {recurringPct}% recurring — remediation not sticking
                </p>
              )}
            </CardContent>
          </Card>

          {/* Risk trend over time */}
          <Card className="border-zinc-800 bg-zinc-900/60">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Activity className="h-4 w-4 text-zinc-400" />
                Avg Risk Score Trend
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-end gap-3 h-12">
                {([
                  { label: "90d", value: data.risk_trend["90d"] },
                  { label: "60d", value: data.risk_trend["60d"] },
                  { label: "30d", value: data.risk_trend["30d"] },
                ] as const).map(({ label, value }) => {
                  const maxVal = Math.max(data.risk_trend["90d"], data.risk_trend["60d"], data.risk_trend["30d"], 1);
                  const heightPct = Math.max(8, (value / maxVal) * 100);
                  const isLatest = label === "30d";
                  return (
                    <div key={label} className="flex-1 flex flex-col items-center gap-1">
                      <span className="text-xs font-mono text-zinc-300">{value.toFixed(0)}</span>
                      <div className="w-full rounded-t-sm" style={{ height: `${heightPct}%`, background: isLatest ? (riskTrend === "down" ? "#10b981" : "#f97316") : "#3f3f46" }} />
                      <span className="text-[10px] text-zinc-600">{label}</span>
                    </div>
                  );
                })}
              </div>
              <p className={cn("text-xs mt-2 flex items-center gap-1", riskTrend === "down" ? "text-emerald-400" : riskTrend === "up" ? "text-red-400" : "text-zinc-500")}>
                {riskTrend === "down" ? <TrendingDown className="h-3 w-3" /> : riskTrend === "up" ? <TrendingUp className="h-3 w-3" /> : <Minus className="h-3 w-3" />}
                {riskTrend === "down" ? "Risk improving over 90 days" : riskTrend === "up" ? "Risk increasing over 90 days" : "Risk stable over 90 days"}
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
