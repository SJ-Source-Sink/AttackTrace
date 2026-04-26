"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  RefreshCw,
  Shield,
  TrendingUp,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { dashboardApi } from "@/lib/api";
import type { ExecutiveDashboardData } from "@/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
};

const PIE_COLORS = ["#2563eb", "#ea580c"];

function KpiCard({
  title,
  value,
  subtitle,
  icon: Icon,
  accent,
}: {
  title: string;
  value: React.ReactNode;
  subtitle?: string;
  icon: React.ElementType;
  accent?: string;
}) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs text-zinc-500 font-medium uppercase tracking-wide">{title}</p>
            <p
              className="text-3xl font-bold mt-1"
              style={accent ? { color: accent } : undefined}
            >
              {value}
            </p>
            {subtitle && <p className="text-xs text-zinc-500 mt-1">{subtitle}</p>}
          </div>
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-800">
            <Icon className="h-5 w-5 text-zinc-400" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function ExecutiveDashboardPage() {
  const { data, isLoading, refetch, dataUpdatedAt } = useQuery({
    queryKey: ["dashboard", "executive"],
    queryFn: () => dashboardApi.executive() as Promise<ExecutiveDashboardData>,
    staleTime: 15 * 60_000, // 15 minutes — matches backend cache TTL
  });

  const mttrData = data
    ? (["critical", "high", "medium", "low"] as const).map((sev) => ({
        severity: sev.charAt(0).toUpperCase() + sev.slice(1),
        days: data.mttr_by_severity[sev] ?? 0,
        fill: SEVERITY_COLORS[sev],
      }))
    : [];

  const riskTrendData = data
    ? [
        { period: "90d", score: data.risk_trend["90d"] },
        { period: "60d", score: data.risk_trend["60d"] },
        { period: "30d", score: data.risk_trend["30d"] },
      ]
    : [];

  const newVsRecurring = data
    ? [
        { name: "New", value: data.new_vs_recurring.new },
        { name: "Recurring", value: data.new_vs_recurring.recurring },
      ]
    : [];

  const generatedAt = data
    ? new Date(data.generated_at).toLocaleString()
    : null;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Executive Dashboard"
        description="High-level security KPIs for leadership review"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => refetch()}
          className="gap-1.5"
          disabled={isLoading}
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </PageHeader>

      {generatedAt && (
        <p className="text-xs text-zinc-500">
          Data as of: {generatedAt} (cached 15 min)
        </p>
      )}

      {/* KPI Cards row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        {isLoading ? (
          Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-28 rounded-xl" />
          ))
        ) : (
          <>
            <KpiCard
              title="Open Critical Findings"
              value={data?.open_critical ?? "—"}
              subtitle="Requires immediate attention"
              icon={AlertTriangle}
              accent={data && data.open_critical > 0 ? "#dc2626" : undefined}
            />
            <KpiCard
              title="SLA Compliance"
              value={data ? `${data.sla_compliance_percent.toFixed(1)}%` : "—"}
              subtitle="Findings resolved before deadline"
              icon={CheckCircle2}
              accent={
                data && data.sla_compliance_percent >= 80
                  ? "#22c55e"
                  : "#d97706"
              }
            />
            <KpiCard
              title="Asset Coverage"
              value={data ? `${data.coverage_percent.toFixed(1)}%` : "—"}
              subtitle="Assets scanned in last 30 days"
              icon={Shield}
            />
            <KpiCard
              title="Avg Risk Score (30d)"
              value={data ? data.risk_trend["30d"].toFixed(1) : "—"}
              subtitle="Based on finding risk scores"
              icon={BarChart3}
            />
            <KpiCard
              title="New Findings"
              value={data?.new_vs_recurring.new ?? "—"}
              subtitle="First-time occurrences"
              icon={TrendingUp}
            />
            <KpiCard
              title="Recurring Findings"
              value={data?.new_vs_recurring.recurring ?? "—"}
              subtitle="Previously seen, not remediated"
              icon={AlertTriangle}
              accent={
                data && data.new_vs_recurring.recurring > 10 ? "#d97706" : undefined
              }
            />
          </>
        )}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* MTTR by severity */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300">
              Mean Time to Remediate (days)
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-48 w-full" />
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={mttrData} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
                  <XAxis dataKey="severity" tick={{ fontSize: 12, fill: "#a1a1aa" }} />
                  <YAxis tick={{ fontSize: 12, fill: "#a1a1aa" }} unit="d" />
                  <Tooltip
                    contentStyle={{
                      background: "#18181b",
                      border: "1px solid #3f3f46",
                      borderRadius: "6px",
                      fontSize: "12px",
                    }}
                    formatter={(v: number) => [`${v.toFixed(1)} days`, "MTTR"]}
                  />
                  <Bar dataKey="days" radius={[4, 4, 0, 0]}>
                    {mttrData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Risk trend */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300">
              Average Risk Score Trend
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-48 w-full" />
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={riskTrendData} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                  <XAxis dataKey="period" tick={{ fontSize: 12, fill: "#a1a1aa" }} />
                  <YAxis tick={{ fontSize: 12, fill: "#a1a1aa" }} domain={[0, 100]} />
                  <Tooltip
                    contentStyle={{
                      background: "#18181b",
                      border: "1px solid #3f3f46",
                      borderRadius: "6px",
                      fontSize: "12px",
                    }}
                    formatter={(v: number) => [v.toFixed(1), "Risk Score"]}
                  />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="#2563eb"
                    strokeWidth={2}
                    dot={{ r: 4, fill: "#2563eb" }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* New vs Recurring donut */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300">
              New vs Recurring Findings
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center justify-center">
            {isLoading ? (
              <Skeleton className="h-48 w-48 rounded-full" />
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={newVsRecurring}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                    labelLine={false}
                  >
                    {newVsRecurring.map((_, i) => (
                      <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Legend wrapperStyle={{ fontSize: "12px", color: "#a1a1aa" }} />
                  <Tooltip
                    contentStyle={{
                      background: "#18181b",
                      border: "1px solid #3f3f46",
                      borderRadius: "6px",
                      fontSize: "12px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* SLA compliance progress */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-300">
              SLA Compliance
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 pt-4">
            {isLoading ? (
              <Skeleton className="h-8 w-full" />
            ) : (
              <>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-zinc-400">Resolved before SLA deadline</span>
                  <span className="font-bold text-zinc-100">
                    {data?.sla_compliance_percent.toFixed(1)}%
                  </span>
                </div>
                <div className="relative h-4 w-full overflow-hidden rounded-full bg-zinc-800">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${Math.min(100, data?.sla_compliance_percent ?? 0)}%`,
                      background:
                        (data?.sla_compliance_percent ?? 0) >= 80
                          ? "#22c55e"
                          : (data?.sla_compliance_percent ?? 0) >= 60
                          ? "#d97706"
                          : "#dc2626",
                    }}
                  />
                </div>
                <p className="text-xs text-zinc-500">
                  {(data?.sla_compliance_percent ?? 0) >= 80
                    ? "On track — compliance is healthy."
                    : (data?.sla_compliance_percent ?? 0) >= 60
                    ? "Moderate — some SLAs are being missed."
                    : "Critical — many SLAs are being missed. Immediate action required."}
                </p>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
