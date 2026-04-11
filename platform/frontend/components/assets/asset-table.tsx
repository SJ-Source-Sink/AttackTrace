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
  Globe,
  Network,
  Link as LinkIcon,
  Mail,
  Shield,
  Cloud,
  Code2,
  Cpu,
  Server,
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  Tag,
  UserCircle,
  Download,
  CheckSquare,
  Camera,
  X,
  GitFork,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/shared/loading-skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { formatDate, riskScoreBarColor } from "@/lib/utils";
import type { Asset, AssetType } from "@/types";

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL?.replace("/api/v1", "") ?? "http://localhost:8000";

function ScreenshotModal({ url, value, onClose }: { url: string; value: string; onClose: () => void }) {
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative max-w-5xl w-full mx-6 rounded-xl border border-zinc-700/60 bg-zinc-950 overflow-hidden shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-zinc-800">
          <a
            href={value.startsWith("http") ? value : `https://${value}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs font-mono text-zinc-400 hover:text-blue-400 transition-colors truncate max-w-[90%]"
            onClick={(e) => e.stopPropagation()}
          >
            {value}
          </a>
          <button
            onClick={onClose}
            className="ml-3 shrink-0 text-zinc-600 hover:text-zinc-300 transition-colors p-0.5 rounded"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="w-full bg-zinc-950" style={{ aspectRatio: "16/9" }}>
          <img
            src={`${BACKEND_URL}${url}`}
            alt={`Screenshot of ${value}`}
            className="w-full h-full object-contain"
            onError={(e) => {
              e.currentTarget.style.display = "none";
              const fallback = e.currentTarget.nextElementSibling as HTMLElement | null;
              if (fallback) fallback.style.display = "flex";
            }}
          />
          <div className="hidden w-full h-full items-center justify-center text-zinc-600 text-sm flex-col gap-2">
            <Camera className="h-8 w-8 opacity-30" />
            <span>Screenshot unavailable</span>
          </div>
        </div>
      </div>
    </div>
  );
}

const TYPE_ICONS: Record<string, React.ElementType> = {
  subdomain: Globe,
  domain: Globe,
  ip: Network,
  webapp: LinkIcon,
  cloud: Cloud,
};

interface AssetTableProps {
  assets: Asset[];
  isLoading?: boolean;
  onBulkTag?: (ids: string[]) => void;
  onBulkAssign?: (ids: string[]) => void;
  onExport?: () => void;
  onCheckTakeover?: (values: string[]) => void;
}

export function AssetTable({
  assets,
  isLoading,
  onBulkTag,
  onBulkAssign,
  onExport,
  onCheckTakeover,
}: AssetTableProps) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [rowSelection, setRowSelection] = useState<Record<string, boolean>>({});
  const [screenshotModal, setScreenshotModal] = useState<{ url: string; value: string } | null>(null);

  const columns: ColumnDef<Asset>[] = [
    {
      id: "select",
      header: ({ table }) => (
        <Checkbox
          checked={table.getIsAllPageRowsSelected()}
          onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
          aria-label="Select all"
        />
      ),
      cell: ({ row }) => (
        <Checkbox
          checked={row.getIsSelected()}
          onCheckedChange={(value) => row.toggleSelected(!!value)}
          aria-label="Select row"
          onClick={(e) => e.stopPropagation()}
        />
      ),
      size: 40,
      enableSorting: false,
    },
    {
      accessorKey: "asset_type",
      header: "Type",
      cell: ({ getValue }) => {
        const type = getValue<AssetType>();
        const Icon = TYPE_ICONS[type] ?? Globe;
        return (
          <div className="flex items-center gap-2">
            <Icon className="h-3.5 w-3.5 text-zinc-500" />
            <Badge variant="secondary" className="text-xs capitalize">
              {type?.replace("_", " ") ?? "unknown"}
            </Badge>
          </div>
        );
      },
    },
    {
      accessorKey: "value",
      header: "Value",
      cell: ({ row }) => {
        const asset = row.original;
        return (
          <div className="flex items-center gap-2 min-w-0">
            <span className="font-mono text-xs text-zinc-300 truncate">{asset.value}</span>
            {asset.screenshot_url && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setScreenshotModal({ url: asset.screenshot_url!, value: asset.value });
                }}
                className="shrink-0 group relative h-7 w-11 overflow-hidden rounded border border-zinc-700 hover:border-blue-500/50 transition-colors"
                title="View screenshot"
              >
                <img
                  src={`${BACKEND_URL}${asset.screenshot_url}`}
                  alt=""
                  className="h-full w-full object-cover"
                  onError={(e) => { (e.currentTarget.parentElement as HTMLElement).style.display = "none"; }}
                />
                <div className="absolute inset-0 flex items-center justify-center bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Camera className="h-3 w-3 text-white" />
                </div>
              </button>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: "risk_score",
      header: "Risk Score",
      cell: ({ getValue }) => {
        const score = getValue<number>();
        return (
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-20 rounded-full bg-zinc-800 overflow-hidden">
              <div
                className={`h-full rounded-full ${riskScoreBarColor(score)}`}
                style={{ width: `${score}%` }}
              />
            </div>
            <span className="text-xs font-medium text-zinc-300 w-6 text-right">
              {score}
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: "first_seen",
      header: "First Seen",
      cell: ({ getValue }) => (
        <span className="text-xs text-zinc-500">{formatDate(getValue<string>())}</span>
      ),
    },
    {
      accessorKey: "last_seen",
      header: "Last Seen",
      cell: ({ getValue }) => (
        <span className="text-xs text-zinc-500">{formatDate(getValue<string>())}</span>
      ),
    },
    {
      accessorKey: "tags",
      header: "Tags",
      cell: ({ getValue }) => {
        const tags = getValue<string[]>();
        if (!tags?.length) return <span className="text-zinc-700 text-xs">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {tags.slice(0, 2).map((tag) => (
              <Badge key={tag} variant="outline" className="text-[10px] py-0 h-4">
                {tag}
              </Badge>
            ))}
            {tags.length > 2 && (
              <span className="text-xs text-zinc-600">+{tags.length - 2}</span>
            )}
          </div>
        );
      },
      enableSorting: false,
    },
    {
      accessorKey: "is_active",
      header: "Status",
      cell: ({ getValue }) => {
        const active = getValue<boolean>();
        return active ? (
          <Badge variant="secondary" className="text-xs text-emerald-400 border-emerald-400/30">Active</Badge>
        ) : (
          <Badge variant="secondary" className="text-xs text-zinc-500">Inactive</Badge>
        );
      },
    },
  ];

  const table = useReactTable({
    data: assets,
    columns,
    state: { sorting, rowSelection },
    onSortingChange: setSorting,
    onRowSelectionChange: setRowSelection,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const selectedIds = Object.keys(rowSelection).filter((k) => rowSelection[k]);
  // Map row indices to asset values for takeover check
  const selectedAssets = selectedIds
    .map((k) => {
      const idx = parseInt(k, 10);
      return isNaN(idx) ? null : assets[idx];
    })
    .filter((a): a is Asset => a != null && (a.asset_type === "subdomain" || a.asset_type === "domain"));

  return (
    <div className="space-y-3">
      {/* Bulk actions */}
      {selectedIds.length > 0 && (
        <div className="flex items-center gap-2 rounded-md border border-blue-500/30 bg-blue-500/5 px-3 py-2">
          <CheckSquare className="h-4 w-4 text-blue-400" />
          <span className="text-sm text-blue-400 font-medium">
            {selectedIds.length} selected
          </span>
          <div className="flex items-center gap-2 ml-2">
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs gap-1"
              onClick={() => onBulkTag?.(selectedIds)}
            >
              <Tag className="h-3 w-3" />
              Add Tags
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs gap-1"
              onClick={() => onBulkAssign?.(selectedIds)}
            >
              <UserCircle className="h-3 w-3" />
              Assign Owner
            </Button>
            {selectedAssets.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs gap-1 border-purple-500/40 text-purple-400 hover:bg-purple-500/10 hover:text-purple-300"
                onClick={() => onCheckTakeover?.(selectedAssets.map((a) => a.value))}
              >
                <GitFork className="h-3 w-3" />
                Check Takeover ({selectedAssets.length})
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs gap-1"
              onClick={onExport}
            >
              <Download className="h-3 w-3" />
              Export CSV
            </Button>
          </div>
        </div>
      )}

      {/* Table */}
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
                      style={{ width: header.getSize() }}
                    >
                      {header.isPlaceholder ? null : (
                        <div
                          className={`flex items-center gap-1 ${
                            header.column.getCanSort() ? "cursor-pointer select-none hover:text-zinc-200" : ""
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
                ? Array.from({ length: 10 }).map((_, i) => (
                    <tr key={i}>
                      {columns.map((_, j) => (
                        <td key={j} className="px-4 py-3">
                          <Skeleton className="h-4 w-full" />
                        </td>
                      ))}
                    </tr>
                  ))
                : table.getRowModel().rows.map((row) => (
                    <tr
                      key={row.id}
                      className={`hover:bg-zinc-800/40 transition-colors ${
                        row.getIsSelected() ? "bg-blue-500/5" : ""
                      }`}
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

        {!isLoading && assets.length === 0 && (
          <div className="py-12 text-center text-zinc-500 text-sm">
            No assets found matching your filters.
          </div>
        )}
      </div>

      {screenshotModal && (
        <ScreenshotModal
          url={screenshotModal.url}
          value={screenshotModal.value}
          onClose={() => setScreenshotModal(null)}
        />
      )}
    </div>
  );
}
