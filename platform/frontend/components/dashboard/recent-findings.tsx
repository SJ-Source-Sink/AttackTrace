"use client";

import React from "react";
import Link from "next/link";
import { ExternalLink } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { formatRelativeTime, severityBgColor, truncate } from "@/lib/utils";
import type { Finding, FindingSeverity } from "@/types";

interface RecentFindingsProps {
  findings?: Finding[];
  isLoading?: boolean;
}

function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  const variant = severity as "critical" | "high" | "medium" | "low" | "info";
  return (
    <Badge variant={variant} className="text-[10px] py-0 h-5 capitalize">
      {severity}
    </Badge>
  );
}

export function RecentFindings({ findings = [], isLoading }: RecentFindingsProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold text-zinc-300">
            Recent Critical &amp; High Findings
          </CardTitle>
          <Button variant="ghost" size="sm" className="text-xs h-7" asChild>
            <Link href="/findings">View all</Link>
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {isLoading ? (
          <div className="space-y-2 px-6 pb-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3">
                <Skeleton className="h-5 w-16" />
                <Skeleton className="h-4 flex-1" />
                <Skeleton className="h-4 w-20" />
              </div>
            ))}
          </div>
        ) : findings.length === 0 ? (
          <div className="px-6 pb-6 text-center text-sm text-zinc-500 pt-4">
            No critical or high findings.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/60">
            {findings.slice(0, 10).map((finding) => (
              <Link
                key={finding.id}
                href={`/findings/${finding.id}`}
                className="flex items-center gap-3 px-6 py-3 hover:bg-zinc-800/40 transition-colors group"
              >
                <SeverityBadge severity={finding.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-zinc-300 group-hover:text-zinc-100 truncate">
                    {truncate(finding.title, 60)}
                  </p>
                  <p className="text-xs text-zinc-500 truncate mt-0.5">
                    {finding.asset_value}
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs text-zinc-500">
                    {formatRelativeTime(finding.created_at)}
                  </span>
                  <ExternalLink className="h-3 w-3 text-zinc-600 group-hover:text-zinc-400 transition-colors" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
