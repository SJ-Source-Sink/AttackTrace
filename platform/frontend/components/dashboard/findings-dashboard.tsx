"use client";

import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { findingsApi } from "@/lib/api";
import { CalendarDays } from "lucide-react";
import { cn } from "@/lib/utils";

const PRESETS = [
  { label: "7d", days: 7 },
  { label: "14d", days: 14 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
];

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#60a5fa",
  info: "#71717a",
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

interface TimelinePoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

interface TimelineResponse {
  data: TimelinePoint[];
  totals: Record<string, number>;
  from_date: string;
  to_date: string;
}

function CustomTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name: string; value: number; fill: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((s, p) => s + (p.value || 0), 0);
  const shown = payload.filter((p) => p.value > 0);
  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900 p-3 shadow-xl text-sm min-w-[160px]">
      <p className="font-medium text-zinc-300 mb-2 text-xs">
        {label
          ? new Date(label + "T00:00:00").toLocaleDateString(undefined, {
              month: "short",
              day: "numeric",
              year: "numeric",
            })
          : ""}
      </p>
      {shown.length === 0 ? (
        <p className="text-xs text-zinc-600">No findings</p>
      ) : (
        <>
          {shown.map((entry) => (
            <div key={entry.name} className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-1.5">
                <div className="h-2 w-2 rounded-full" style={{ backgroundColor: entry.fill }} />
                <span className="text-zinc-400 capitalize text-xs">{entry.name}</span>
              </div>
              <span className="font-semibold text-zinc-100 text-xs">{entry.value}</span>
            </div>
          ))}
          {total > 0 && (
            <div className="flex items-center justify-between gap-3 mt-2 pt-2 border-t border-zinc-700/50">
              <span className="text-zinc-500 text-xs">Total</span>
              <span className="font-bold text-zinc-100 text-xs">{total}</span>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export function FindingsDashboard() {
  const [preset, setPreset] = useState<number | null>(30);
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [customActive, setCustomActive] = useState(false);

  const queryParams = useMemo(() => {
    if (customActive && fromDate && toDate) {
      return { from_date: fromDate, to_date: toDate };
    }
    return { days: preset ?? 30 };
  }, [customActive, fromDate, toDate, preset]);

  const { data, isLoading } = useQuery({
    queryKey: ["findings", "timeline", queryParams],
    queryFn: () => findingsApi.timeline(queryParams) as Promise<TimelineResponse>,
    staleTime: 60_000,
  });

  const chartData = data?.data ?? [];
  const totals = data?.totals ?? {};

  // Condense x-axis labels when range is large
  const tickInterval = useMemo(() => {
    const n = chartData.length;
    if (n <= 14) return 0;
    if (n <= 30) return 2;
    if (n <= 60) return 6;
    return 13;
  }, [chartData.length]);

  const applyPreset = (days: number) => {
    setPreset(days);
    setCustomActive(false);
    setFromDate("");
    setToDate("");
  };

  const applyCustom = () => {
    if (fromDate && toDate) {
      setCustomActive(true);
      setPreset(null);
    }
  };

  const totalFindings = Object.values(totals).reduce((a, b) => a + b, 0);

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold text-zinc-300">Findings Dashboard</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64 animate-pulse rounded bg-zinc-800" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          {/* Title + totals */}
          <div>
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-1.5">
              <CalendarDays className="h-4 w-4 text-zinc-500" />
              Findings Dashboard
            </CardTitle>
            {totalFindings > 0 && (
              <div className="flex items-center gap-3 mt-2 flex-wrap">
                {SEV_ORDER.map((sev) =>
                  (totals[sev] ?? 0) > 0 ? (
                    <div key={sev} className="flex items-center gap-1">
                      <div className="h-2 w-2 rounded-full" style={{ backgroundColor: SEV_COLORS[sev] }} />
                      <span className="text-xs text-zinc-500 capitalize">{sev}</span>
                      <span className="text-xs font-semibold text-zinc-300">{totals[sev]}</span>
                    </div>
                  ) : null
                )}
                <span className="text-xs text-zinc-600 ml-1">({totalFindings} total)</span>
              </div>
            )}
          </div>

          {/* Controls */}
          <div className="flex flex-col gap-2 items-end">
            {/* Preset buttons */}
            <div className="flex items-center gap-1 rounded-md bg-zinc-800/60 p-0.5">
              {PRESETS.map((p) => (
                <button
                  key={p.days}
                  onClick={() => applyPreset(p.days)}
                  className={cn(
                    "px-2.5 py-1 rounded text-xs font-medium transition-colors",
                    preset === p.days && !customActive
                      ? "bg-zinc-700 text-zinc-100"
                      : "text-zinc-500 hover:text-zinc-300"
                  )}
                >
                  {p.label}
                </button>
              ))}
            </div>

            {/* Custom date range */}
            <div className="flex items-center gap-1.5">
              <input
                type="date"
                value={fromDate}
                onChange={(e) => { setFromDate(e.target.value); setCustomActive(false); }}
                className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-zinc-500"
              />
              <span className="text-xs text-zinc-600">to</span>
              <input
                type="date"
                value={toDate}
                onChange={(e) => { setToDate(e.target.value); setCustomActive(false); }}
                className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-zinc-500"
              />
              <button
                onClick={applyCustom}
                disabled={!fromDate || !toDate}
                className={cn(
                  "px-2.5 py-1 rounded text-xs font-medium transition-colors border",
                  customActive
                    ? "bg-blue-600/20 border-blue-500/50 text-blue-300"
                    : "border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 disabled:opacity-40 disabled:cursor-not-allowed"
                )}
              >
                Apply
              </button>
            </div>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pb-4">
        {chartData.length === 0 || totalFindings === 0 ? (
          <div className="h-56 flex items-center justify-center text-zinc-600 text-sm">
            No findings in this date range
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={chartData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }} barSize={chartData.length > 45 ? 4 : chartData.length > 20 ? 7 : 12}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fill: "#71717a", fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                interval={tickInterval}
                tickFormatter={(val: string) => {
                  try {
                    const d = new Date(val + "T00:00:00");
                    return isNaN(d.getTime())
                      ? val
                      : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
                  } catch {
                    return val;
                  }
                }}
              />
              <YAxis
                tick={{ fill: "#71717a", fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
              <Legend
                iconType="circle"
                iconSize={7}
                wrapperStyle={{ fontSize: "11px", paddingTop: "8px", color: "#71717a" }}
                formatter={(value) => <span className="capitalize">{value}</span>}
              />
              {SEV_ORDER.map((sev) => (
                <Bar
                  key={sev}
                  dataKey={sev}
                  stackId="a"
                  fill={SEV_COLORS[sev]}
                  name={sev}
                  radius={sev === "critical" ? [2, 2, 0, 0] : undefined}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
