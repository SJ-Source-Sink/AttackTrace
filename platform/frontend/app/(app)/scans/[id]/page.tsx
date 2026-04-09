"use client";

import React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ChevronLeft, Calendar, Zap, Globe } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/page-header";
import { ScanProgress } from "@/components/scans/scan-progress";
import { ScanResultsTabs } from "@/components/scans/scan-results-tabs";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { useScan } from "@/hooks/use-scans";
import { scanStatusColor, formatDateTime, capitalize } from "@/lib/utils";

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: scan, isLoading, error } = useScan(id);

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <p className="text-zinc-400 mb-4">Scan not found or failed to load.</p>
        <Button asChild variant="outline">
          <Link href="/scans">Back to scans</Link>
        </Button>
      </div>
    );
  }

  const isRunning = scan.status === "running" || scan.status === "pending";

  return (
    <div className="space-y-6">
      <PageHeader
        title={scan.company_name || scan.target_domains?.[0] || "Unnamed Scan"}
        description={`Scan ID: ${scan.id.slice(0, 8)}...`}
      >
        <Button variant="outline" size="sm" asChild>
          <Link href="/scans" className="gap-1.5">
            <ChevronLeft className="h-4 w-4" />
            Back
          </Link>
        </Button>
      </PageHeader>

      {/* Scan meta */}
      <div className="flex flex-wrap items-center gap-3 p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
        <Badge
          className={`capitalize border ${scanStatusColor(scan.status)}`}
        >
          {scan.status}
        </Badge>
        <Badge variant="secondary" className="capitalize">
          {scan.intensity}
        </Badge>

        <div className="flex items-center gap-1.5 text-xs text-zinc-500">
          <Globe className="h-3.5 w-3.5" />
          {(scan.target_domains ?? []).slice(0, 3).join(", ")}
          {(scan.target_domains ?? []).length > 3 && ` +${(scan.target_domains ?? []).length - 3}`}
        </div>

        <div className="flex items-center gap-1.5 text-xs text-zinc-500">
          <Calendar className="h-3.5 w-3.5" />
          {formatDateTime(scan.created_at)}
        </div>

        {(scan.modules_to_skip ?? []).length > 0 && (
          <div className="flex items-center gap-1.5 text-xs text-zinc-500">
            <Zap className="h-3.5 w-3.5" />
            Skipped: {(scan.modules_to_skip ?? []).map(capitalize).join(", ")}
          </div>
        )}
      </div>

      {/* Content: live progress OR completed results */}
      {isRunning ? (
        <ScanProgress scanId={scan.id} />
      ) : (
        <ScanResultsTabs scan={scan} />
      )}
    </div>
  );
}
