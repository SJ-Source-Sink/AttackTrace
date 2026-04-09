"use client";

import React, { useState } from "react";
import Link from "next/link";
import { Plus, Search, Filter } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/empty-state";
import { ScanCard } from "@/components/scans/scan-card";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { useScans } from "@/hooks/use-scans";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { ScanStatus } from "@/types";

export default function ScansPage() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const { data, isLoading } = useScans({
    status: statusFilter === "all" ? undefined : statusFilter,
    per_page: 20,
  });

  const scans = data?.items ?? [];
  const filteredScans = search
    ? scans.filter(
        (s) =>
          (s.company_name ?? "").toLowerCase().includes(search.toLowerCase()) ||
          (s.target_domains ?? []).some((d) => d.includes(search.toLowerCase())),
      )
    : scans;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scans"
        description="Manage and monitor your attack surface scans"
      >
        <Button asChild className="gap-1.5">
          <Link href="/scans/new">
            <Plus className="h-4 w-4" />
            New Scan
          </Link>
        </Button>
      </PageHeader>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
          <Input
            placeholder="Search scans..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-36">
            <Filter className="h-3.5 w-3.5 mr-1.5 text-zinc-500" />
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
            <SelectItem value="cancelled">Cancelled</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Scans list */}
      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-28 w-full rounded-lg" />
          ))}
        </div>
      ) : filteredScans.length === 0 ? (
        <EmptyState
          icon={<Search className="h-8 w-8" />}
          title="No scans found"
          description={
            search
              ? `No scans match "${search}"`
              : "Start your first scan to discover your attack surface"
          }
          action={
            !search ? (
              <Button asChild>
                <Link href="/scans/new">Start your first scan</Link>
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-3">
          {filteredScans.map((scan) => (
            <ScanCard key={scan.id} scan={scan} />
          ))}
        </div>
      )}

      {/* Pagination info */}
      {data && data.total > data.per_page && (
        <div className="text-center text-sm text-zinc-500">
          Showing {data.items.length} of {data.total} scans
        </div>
      )}
    </div>
  );
}
