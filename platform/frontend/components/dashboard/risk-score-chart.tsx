"use client";

import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { RiskScoreDataPoint } from "@/types";

interface RiskScoreChartProps {
  data: RiskScoreDataPoint[];
  isLoading?: boolean;
}

function CustomTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900 p-3 shadow-lg text-sm">
      <p className="font-medium text-zinc-300 mb-2">{label}</p>
      {payload.map((entry) => (
        <div key={entry.name} className="flex items-center gap-2">
          <div
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-zinc-400 capitalize">{entry.name}:</span>
          <span className="font-medium text-zinc-100">{entry.value}</span>
        </div>
      ))}
    </div>
  );
}

export function RiskScoreChart({ data, isLoading }: RiskScoreChartProps) {
  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold text-zinc-300">Risk Score Trend</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64 animate-pulse rounded bg-zinc-800" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold text-zinc-300">
            Risk Score — Last 30 Days
          </CardTitle>
          <div className="flex items-center gap-4 text-xs text-zinc-500">
            <div className="flex items-center gap-1.5">
              <div className="h-2 w-2 rounded-full bg-blue-500" />
              Risk Score
            </div>
            <div className="flex items-center gap-1.5">
              <div className="h-2 w-2 rounded-full bg-red-500" />
              Critical
            </div>
            <div className="flex items-center gap-1.5">
              <div className="h-2 w-2 rounded-full bg-orange-500" />
              High
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pb-4">
        <ResponsiveContainer width="100%" height={240}>
          <AreaChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.15} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f97316" stopOpacity={0.15} />
                <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
            <XAxis
              dataKey="date"
              tick={{ fill: "#71717a", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              interval="preserveStartEnd"
              tickFormatter={(val: string) => {
                try {
                  const d = new Date(val);
                  return isNaN(d.getTime()) ? val : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
                } catch {
                  return val;
                }
              }}
            />
            <YAxis
              tick={{ fill: "#71717a", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              domain={[0, 100]}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey="score"
              name="score"
              stroke="#3b82f6"
              strokeWidth={2}
              fill="url(#colorScore)"
              dot={false}
              activeDot={{ r: 4, fill: "#3b82f6" }}
            />
            <Area
              type="monotone"
              dataKey="critical"
              name="critical"
              stroke="#ef4444"
              strokeWidth={1.5}
              fill="url(#colorCritical)"
              dot={false}
              activeDot={{ r: 3, fill: "#ef4444" }}
            />
            <Area
              type="monotone"
              dataKey="high"
              name="high"
              stroke="#f97316"
              strokeWidth={1.5}
              fill="url(#colorHigh)"
              dot={false}
              activeDot={{ r: 3, fill: "#f97316" }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
