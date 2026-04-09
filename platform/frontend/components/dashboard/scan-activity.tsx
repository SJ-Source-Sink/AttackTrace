"use client";

import React from "react";
import Link from "next/link";
import { Radar, Clock, CheckCircle2, XCircle, Loader2, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { formatRelativeTime, scanStatusColor, formatDuration } from "@/lib/utils";
import type { Scan, ScanStatus } from "@/types";

interface ScanActivityProps {
  scans?: Scan[];
  isLoading?: boolean;
}

function StatusIcon({ status }: { status: ScanStatus }) {
  switch (status) {
    case "running":
      return <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-400" />;
    case "completed":
      return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />;
    case "failed":
      return <XCircle className="h-3.5 w-3.5 text-red-400" />;
    case "cancelled":
      return <AlertCircle className="h-3.5 w-3.5 text-orange-400" />;
    default:
      return <Clock className="h-3.5 w-3.5 text-zinc-500" />;
  }
}

export function ScanActivity({ scans = [], isLoading }: ScanActivityProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold text-zinc-300">
            Recent Scans
          </CardTitle>
          <Button variant="ghost" size="sm" className="text-xs h-7" asChild>
            <Link href="/scans">View all</Link>
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {isLoading ? (
          <div className="space-y-2 px-6 pb-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3">
                <Skeleton className="h-8 w-8 rounded-full" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-3 w-24" />
                </div>
                <Skeleton className="h-5 w-20" />
              </div>
            ))}
          </div>
        ) : scans.length === 0 ? (
          <div className="px-6 pb-6 pt-4 text-center">
            <Radar className="h-8 w-8 text-zinc-600 mx-auto mb-2" />
            <p className="text-sm text-zinc-500">No scans yet.</p>
            <Button size="sm" className="mt-3" asChild>
              <Link href="/scans/new">Start your first scan</Link>
            </Button>
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/60">
            {scans.slice(0, 8).map((scan) => (
              <Link
                key={scan.id}
                href={`/scans/${scan.id}`}
                className="flex items-center gap-3 px-6 py-3 hover:bg-zinc-800/40 transition-colors group"
              >
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-zinc-800 group-hover:bg-zinc-700 transition-colors">
                  <StatusIcon status={scan.status} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-zinc-300 group-hover:text-zinc-100 truncate">
                    {scan.company_name || scan.target_domains?.[0] || "Unnamed Scan"}
                  </p>
                  <p className="text-xs text-zinc-500 truncate">
                    {(scan.target_domains ?? []).slice(0, 2).join(", ")}
                    {(scan.target_domains ?? []).length > 2 && ` +${(scan.target_domains ?? []).length - 2}`}
                  </p>
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <Badge
                    className={`text-[10px] py-0 h-5 capitalize border ${scanStatusColor(scan.status)}`}
                  >
                    {scan.status}
                  </Badge>
                  <span className="text-[10px] text-zinc-600">
                    {formatRelativeTime(scan.created_at)}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
