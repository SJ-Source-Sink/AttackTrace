"use client";

import React from "react";
import { Globe, ShieldAlert, Radar, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { DashboardStats } from "@/types";

interface StatsCardProps {
  title: string;
  value: string | number;
  subtext?: string;
  icon: React.ElementType;
  iconClassName?: string;
  trend?: "up" | "down" | "stable";
  trendValue?: string;
  isLoading?: boolean;
}

function StatsCard({
  title,
  value,
  subtext,
  icon: Icon,
  iconClassName,
  trend,
  trendValue,
  isLoading,
}: StatsCardProps) {
  const TrendIcon = trend === "up" ? TrendingUp : trend === "down" ? TrendingDown : Minus;
  const trendColor =
    trend === "up" ? "text-red-400" : trend === "down" ? "text-emerald-400" : "text-zinc-500";

  return (
    <Card className="relative overflow-hidden">
      <CardContent className="p-6">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">{title}</p>
            <div className="flex items-baseline gap-2">
              {isLoading ? (
                <div className="h-8 w-20 animate-pulse rounded bg-zinc-800" />
              ) : (
                <span className="text-3xl font-bold text-zinc-100">{value}</span>
              )}
            </div>
            {subtext && !isLoading && (
              <p className="text-xs text-zinc-500">{subtext}</p>
            )}
          </div>
          <div className={cn("rounded-lg p-2.5", iconClassName ?? "bg-zinc-800")}>
            <Icon className="h-5 w-5" />
          </div>
        </div>
        {trend && trendValue && (
          <div className={cn("mt-3 flex items-center gap-1 text-xs", trendColor)}>
            <TrendIcon className="h-3.5 w-3.5" />
            <span>{trendValue}</span>
          </div>
        )}
      </CardContent>
      {/* Subtle gradient overlay */}
      <div className="absolute inset-0 pointer-events-none rounded-lg ring-1 ring-inset ring-white/5" />
    </Card>
  );
}

interface StatsCardsProps {
  stats?: DashboardStats;
  isLoading?: boolean;
}

export function StatsCards({ stats, isLoading }: StatsCardsProps) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatsCard
        title="Total Assets"
        value={stats?.total_assets?.toLocaleString() ?? "0"}
        subtext={`${stats?.active_assets ?? 0} active`}
        icon={Globe}
        iconClassName="bg-blue-500/10 text-blue-400"
        trend="stable"
        trendValue="vs last scan"
        isLoading={isLoading}
      />
      <StatsCard
        title="Critical Findings"
        value={stats?.critical_findings ?? 0}
        subtext={`${stats?.high_findings ?? 0} high severity`}
        icon={ShieldAlert}
        iconClassName="bg-red-500/10 text-red-500"
        trend={stats?.critical_findings && stats.critical_findings > 0 ? "up" : "stable"}
        trendValue="requires attention"
        isLoading={isLoading}
      />
      <StatsCard
        title="Active Scans"
        value={stats?.active_scans ?? 0}
        subtext="running now"
        icon={Radar}
        iconClassName="bg-emerald-500/10 text-emerald-400"
        isLoading={isLoading}
      />
      <StatsCard
        title="Risk Score"
        value={stats?.risk_score ?? 0}
        subtext={
          (stats?.risk_score ?? 0) >= 75 ? "Critical risk level" :
          (stats?.risk_score ?? 0) >= 50 ? "High risk level" :
          (stats?.risk_score ?? 0) >= 25 ? "Medium risk level" : "Low risk level"
        }
        icon={
          (stats?.risk_score ?? 0) >= 75 ? TrendingUp :
          (stats?.risk_score ?? 0) >= 25 ? TrendingDown : Minus
        }
        iconClassName={
          (stats?.risk_score ?? 0) >= 75 ? "bg-red-500/10 text-red-500" :
          (stats?.risk_score ?? 0) >= 50 ? "bg-orange-500/10 text-orange-500" :
          (stats?.risk_score ?? 0) >= 25 ? "bg-yellow-500/10 text-yellow-500" :
                                           "bg-emerald-500/10 text-emerald-400"
        }
        trend={stats?.risk_trend}
        trendValue={
          stats?.risk_trend === "up" ? "Rising since last scan" :
          stats?.risk_trend === "down" ? "Improving since last scan" : "Stable"
        }
        isLoading={isLoading}
      />
    </div>
  );
}
