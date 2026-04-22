"use client";

import React from "react";
import Link from "next/link";
import { Plus, RefreshCw } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { RiskScoreChart } from "@/components/dashboard/risk-score-chart";
import { RecentFindings } from "@/components/dashboard/recent-findings";
import { ScanActivity } from "@/components/dashboard/scan-activity";
import { dashboardApi } from "@/lib/api";
import { scansApi, findingsApi } from "@/lib/api";
import type { DashboardStats, ScanListResponse, FindingListResponse } from "@/types";

export default function DashboardPage() {
  const { data: stats, isLoading: statsLoading, refetch } = useQuery({
    queryKey: ["dashboard", "stats"],
    queryFn: () => dashboardApi.stats() as Promise<DashboardStats>,
    staleTime: 0,
  });

  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ["scans", "list", { per_page: 8 }],
    queryFn: () => scansApi.list({ per_page: "8" }) as Promise<ScanListResponse>,
    staleTime: 30_000,
  });

  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ["findings", "list", { per_page: 10 }],
    queryFn: () =>
      findingsApi.list({ per_page: 10 }) as Promise<FindingListResponse>,
    staleTime: 60_000,
  });

  const riskHistory = stats?.risk_score_history ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="Attack surface overview for your organization"
      >
        <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
        <Button size="sm" className="gap-1.5" asChild>
          <Link href="/scans/new">
            <Plus className="h-3.5 w-3.5" />
            New Scan
          </Link>
        </Button>
      </PageHeader>

      {/* Stats Cards */}
      <StatsCards stats={stats} isLoading={statsLoading} />

      {/* Risk Score Chart */}
      <RiskScoreChart data={riskHistory} isLoading={statsLoading} />

      {/* Two column grid: findings + scans */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <RecentFindings
          findings={findingsData?.items}
          isLoading={findingsLoading}
        />
        <ScanActivity
          scans={scansData?.items}
          isLoading={scansLoading}
        />
      </div>
    </div>
  );
}
