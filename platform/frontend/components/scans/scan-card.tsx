"use client";

import React from "react";
import Link from "next/link";
import {
  Radar,
  Globe,
  ShieldAlert,
  Clock,
  ChevronRight,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Trash2,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { formatRelativeTime, formatDuration, scanStatusColor } from "@/lib/utils";
import { useDeleteScan } from "@/hooks/use-scans";
import type { Scan } from "@/types";

interface ScanCardProps {
  scan: Scan;
}

function StatusIcon({ status }: { status: Scan["status"] }) {
  switch (status) {
    case "running":
      return <Loader2 className="h-4 w-4 animate-spin text-blue-400" />;
    case "completed":
      return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    case "failed":
      return <XCircle className="h-4 w-4 text-red-400" />;
    case "cancelled":
      return <AlertCircle className="h-4 w-4 text-orange-400" />;
    default:
      return <Clock className="h-4 w-4 text-zinc-500" />;
  }
}

export function ScanCard({ scan }: ScanCardProps) {
  const { mutate: deleteScan } = useDeleteScan();

  return (
    <Card className="hover:border-zinc-700 transition-colors group">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-800 group-hover:bg-zinc-700 transition-colors">
              <StatusIcon status={scan.status} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <Link
                  href={`/scans/${scan.id}`}
                  className="font-semibold text-zinc-100 hover:text-blue-400 transition-colors truncate"
                >
                  {scan.company_name || scan.target_domains?.[0] || "Unnamed Scan"}
                </Link>
                <Badge
                  className={`text-[10px] h-5 capitalize border ${scanStatusColor(scan.status)}`}
                >
                  {scan.status}
                </Badge>
                <Badge variant="secondary" className="text-[10px] h-5 capitalize">
                  {scan.intensity}
                </Badge>
              </div>
              <p className="text-xs text-zinc-500 mt-1 truncate">
                {(scan.target_domains ?? []).slice(0, 3).join(", ")}
                {(scan.target_domains ?? []).length > 3 && ` +${(scan.target_domains ?? []).length - 3} more`}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1 shrink-0">
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
              asChild
            >
              <Link href={`/scans/${scan.id}`}>
                <ChevronRight className="h-4 w-4" />
              </Link>
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  <span className="sr-only">Actions</span>
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24">
                    <circle cx="12" cy="5" r="1.5" />
                    <circle cx="12" cy="12" r="1.5" />
                    <circle cx="12" cy="19" r="1.5" />
                  </svg>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem asChild>
                  <Link href={`/scans/${scan.id}`} className="cursor-pointer">
                    <Radar className="h-4 w-4 mr-2" />
                    View details
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuItem
                  className="text-red-400 focus:text-red-400 focus:bg-red-400/10 cursor-pointer"
                  onClick={() => deleteScan(scan.id)}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete scan
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {/* Stats row */}
        {scan.findings_count && (
          <div className="flex items-center gap-4 mt-4 pt-4 border-t border-zinc-800/60">
            <div className="flex items-center gap-1.5 text-xs">
              <ShieldAlert className="h-3.5 w-3.5 text-red-500" />
              <span className="text-zinc-300">
                {scan.findings_count.critical ?? 0} critical
              </span>
              <span className="text-zinc-600">/</span>
              <span className="text-orange-400">{scan.findings_count.high ?? 0} high</span>
            </div>
            {scan.started_at && scan.completed_at && (
              <div className="flex items-center gap-1.5 text-xs text-zinc-500 ml-auto">
                <Clock className="h-3.5 w-3.5" />
                <span>{formatDuration(
                  Math.floor((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
                )}</span>
              </div>
            )}
          </div>
        )}

        <div className="flex items-center justify-between mt-2">
          <span className="text-[11px] text-zinc-600">
            {formatRelativeTime(scan.created_at)}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
