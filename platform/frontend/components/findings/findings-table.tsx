"use client";

import React, { useState } from "react";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  type ColumnDef,
  type SortingState,
  flexRender,
} from "@tanstack/react-table";
import {
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  ExternalLink,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { StatusWorkflow } from "@/components/findings/status-workflow";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { formatRelativeTime, capitalize } from "@/lib/utils";
import type { Finding, FindingSeverity } from "@/types";

interface FindingsTableProps {
  findings: Finding[];
  isLoading?: boolean;
  onRowClick?: (finding: Finding) => void;
}

const STATUS_COLORS: Record<string, string> = {
  open: "border-red-500/30 bg-red-500/10 text-red-400",
  in_progress: "border-blue-500/30 bg-blue-500/10 text-blue-400",
  remediated: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  accepted_risk: "border-yellow-500/30 bg-yellow-500/10 text-yellow-400",
  false_positive: "border-zinc-500/30 bg-zinc-500/10 text-zinc-400",
};

export function FindingsTable({ findings, isLoading, onRowClick }: FindingsTableProps) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: "severity", desc: true },
  ]);

  const SEVERITY_ORDER: Record<FindingSeverity, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };

  const columns: ColumnDef<Finding>[] = [
    {
      accessorKey: "severity",
      header: "Severity",
      cell: ({ getValue }) => (
        <SeverityBadge severity={getValue<FindingSeverity>()} />
      ),
      sortingFn: (a, b) => {
        const aVal = SEVERITY_ORDER[a.original.severity] ?? 0;
        const bVal = SEVERITY_ORDER[b.original.severity] ?? 0;
        return aVal - bVal;
      },
    },
    {
      accessorKey: "title",
      header: "Title",
      cell: ({ row }) => (
        <div className="flex flex-col gap-0.5 max-w-xs">
          <span className="text-sm font-medium text-zinc-200 leading-tight line-clamp-2">
            {row.original.title}
          </span>
          {row.original.cve_id && (
            <a
              href={`https://nvd.nist.gov/vuln/detail/${row.original.cve_id}`}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="inline-flex items-center gap-0.5 text-[10px] text-blue-400 hover:underline w-fit"
            >
              {row.original.cve_id}
              <ExternalLink className="h-2.5 w-2.5" />
            </a>
          )}
        </div>
      ),
    },
    {
      accessorKey: "asset_value",
      header: "Asset",
      cell: ({ row }) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-mono text-xs text-zinc-400 truncate max-w-[160px]">
            {row.original.asset_value}
          </span>
          <Badge variant="secondary" className="text-[10px] py-0 h-4 w-fit capitalize">
            {row.original.asset_type?.replace("_", " ") ?? "—"}
          </Badge>
        </div>
      ),
    },
    {
      accessorKey: "category",
      header: "Category",
      cell: ({ getValue }) => (
        <span className="text-xs text-zinc-500 capitalize">
          {String(getValue()).replace("_", " ")}
        </span>
      ),
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => (
        <div onClick={(e) => e.stopPropagation()}>
          <StatusWorkflow finding={row.original} />
        </div>
      ),
      enableSorting: false,
    },
    {
      accessorKey: "age_days",
      header: "Age",
      cell: ({ getValue }) => {
        const days = getValue<number>();
        return (
          <span className={`text-xs ${days > 30 ? "text-red-400" : days > 7 ? "text-yellow-400" : "text-zinc-500"}`}>
            {days}d
          </span>
        );
      },
    },
    {
      accessorKey: "created_at",
      header: "Found",
      cell: ({ getValue }) => (
        <span className="text-xs text-zinc-600">
          {formatRelativeTime(getValue<string>())}
        </span>
      ),
    },
  ];

  const table = useReactTable({
    data: findings,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <div className="rounded-lg border border-zinc-800 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-zinc-800 bg-zinc-900">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-4 py-3 text-left text-xs font-semibold text-zinc-400 uppercase tracking-wider whitespace-nowrap"
                  >
                    {header.isPlaceholder ? null : (
                      <div
                        className={`flex items-center gap-1 ${
                          header.column.getCanSort()
                            ? "cursor-pointer select-none hover:text-zinc-200"
                            : ""
                        }`}
                        onClick={header.column.getToggleSortingHandler()}
                      >
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        {header.column.getCanSort() && (
                          <>
                            {header.column.getIsSorted() === "asc" ? (
                              <ChevronUp className="h-3 w-3" />
                            ) : header.column.getIsSorted() === "desc" ? (
                              <ChevronDown className="h-3 w-3" />
                            ) : (
                              <ChevronsUpDown className="h-3 w-3 opacity-40" />
                            )}
                          </>
                        )}
                      </div>
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {isLoading
              ? Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i}>
                    {columns.map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <Skeleton className="h-5 w-full" />
                      </td>
                    ))}
                  </tr>
                ))
              : table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    className="hover:bg-zinc-800/40 transition-colors cursor-pointer"
                    onClick={() => onRowClick?.(row.original)}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-4 py-3">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))}
          </tbody>
        </table>
      </div>

      {!isLoading && findings.length === 0 && (
        <div className="py-12 text-center text-zinc-600 text-sm">
          No findings match your current filters.
        </div>
      )}
    </div>
  );
}
