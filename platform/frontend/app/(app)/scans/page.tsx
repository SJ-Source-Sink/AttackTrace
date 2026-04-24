"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { Plus, Search, Filter, Trash2, CheckSquare, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/empty-state";
import { ScanCard } from "@/components/scans/scan-card";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { useScans, useDeleteScan } from "@/hooks/use-scans";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export default function ScansPage() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [searchInput, setSearchInput] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Debounce search input 300 ms before sending to the API
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchInput), 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const { data, isLoading } = useScans({
    status: statusFilter === "all" ? undefined : statusFilter,
    per_page: 20,
    search: debouncedSearch || undefined,
  });

  const { mutateAsync: deleteScan } = useDeleteScan();

  const scans = data?.items ?? [];
  const filteredScans = scans;

  const selectableIds = filteredScans
    .filter((s) => s.status === "completed" || s.status === "failed" || s.status === "cancelled")
    .map((s) => s.id);

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (selected.size === selectableIds.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(selectableIds));
    }
  }

  async function bulkDelete() {
    const ids = [...selected];
    if (ids.length === 0) return;
    try {
      await Promise.all(ids.map((id) => deleteScan(id)));
      setSelected(new Set());
      toast.success(`Deleted ${ids.length} scan${ids.length > 1 ? "s" : ""}`);
    } catch {
      toast.error("Some scans could not be deleted");
    }
  }

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
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
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

        {/* Select all toggle (only shown when there are selectable scans) */}
        {selectableIds.length > 0 && (
          <button
            type="button"
            onClick={toggleSelectAll}
            className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors ml-auto"
          >
            {selected.size === selectableIds.length && selectableIds.length > 0
              ? <CheckSquare className="h-4 w-4" />
              : <Square className="h-4 w-4" />}
            Select all
          </button>
        )}
      </div>

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg border border-zinc-700 bg-zinc-900">
          <span className="text-sm text-zinc-300 font-medium">
            {selected.size} scan{selected.size > 1 ? "s" : ""} selected
          </span>
          <div className="flex gap-2 ml-auto">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setSelected(new Set())}
              className="text-zinc-400 hover:text-zinc-200"
            >
              Clear
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={bulkDelete}
              className="gap-1.5"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Delete {selected.size} scan{selected.size > 1 ? "s" : ""}
            </Button>
          </div>
        </div>
      )}

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
            debouncedSearch
              ? `No scans match "${debouncedSearch}"`
              : "Start your first scan to discover your attack surface"
          }
          action={
            !debouncedSearch ? (
              <Button asChild>
                <Link href="/scans/new">Start your first scan</Link>
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-3">
          {filteredScans.map((scan) => {
            const selectable = selectableIds.includes(scan.id);
            return (
              <div
                key={scan.id}
                className={cn(
                  "relative",
                  selectable && selected.size > 0 && "cursor-pointer"
                )}
              >
                {selectable && (
                  <button
                    type="button"
                    onClick={() => toggleSelect(scan.id)}
                    className="absolute left-3 top-1/2 -translate-y-1/2 z-10 text-zinc-500 hover:text-zinc-200 transition-colors"
                    aria-label={selected.has(scan.id) ? "Deselect scan" : "Select scan"}
                  >
                    {selected.has(scan.id)
                      ? <CheckSquare className="h-4 w-4 text-blue-400" />
                      : <Square className="h-4 w-4" />}
                  </button>
                )}
                <div className={cn(selectable && "pl-8")}>
                  <ScanCard scan={scan} />
                </div>
              </div>
            );
          })}
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
