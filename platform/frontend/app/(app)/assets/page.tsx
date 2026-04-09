"use client";

import React, { useCallback } from "react";
import { Globe, ChevronLeft, ChevronRight } from "lucide-react";
import { useRouter, useSearchParams, usePathname } from "next/navigation";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/empty-state";
import { AssetTable } from "@/components/assets/asset-table";
import { AssetFilterPanel } from "@/components/assets/asset-filters";
import { NLSearchBar } from "@/components/assets/nl-search-bar";
import { useAssets } from "@/hooks/use-assets";
import type { AssetFilters, AssetType } from "@/types";

const PER_PAGE = 25;

function parseFiltersFromParams(params: URLSearchParams): AssetFilters & { page: number } {
  const types = params.getAll("type") as AssetType[];
  const risk_min = params.get("risk_min") ? Number(params.get("risk_min")) : undefined;
  const risk_max = params.get("risk_max") ? Number(params.get("risk_max")) : undefined;
  const is_active = params.has("is_active") ? params.get("is_active") === "true" : undefined;
  const has_screenshot = params.get("has_screenshot") === "true" ? true : undefined;
  const search = params.get("search") ?? undefined;
  const page = params.get("page") ? Math.max(1, Number(params.get("page"))) : 1;

  return {
    types: types.length > 0 ? types : undefined,
    risk_min,
    risk_max,
    is_active,
    has_screenshot,
    search,
    page,
  };
}

function filtersToSearchParams(filters: AssetFilters, page: number): URLSearchParams {
  const params = new URLSearchParams();
  filters.types?.forEach((t) => params.append("type", t));
  if (filters.risk_min !== undefined) params.set("risk_min", String(filters.risk_min));
  if (filters.risk_max !== undefined) params.set("risk_max", String(filters.risk_max));
  if (filters.is_active !== undefined) params.set("is_active", String(filters.is_active));
  if (filters.has_screenshot) params.set("has_screenshot", "true");
  if (filters.search) params.set("search", filters.search);
  if (page > 1) params.set("page", String(page));
  return params;
}

export default function AssetsPage() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const { filters, page } = React.useMemo(() => {
    const parsed = parseFiltersFromParams(searchParams);
    const { page, ...rest } = parsed;
    return { filters: rest as AssetFilters, page };
  }, [searchParams]);

  const pushParams = useCallback(
    (newFilters: AssetFilters, newPage: number) => {
      const params = filtersToSearchParams(newFilters, newPage);
      const qs = params.toString();
      router.push(`${pathname}${qs ? `?${qs}` : ""}`, { scroll: false });
    },
    [router, pathname],
  );

  const { data, isLoading } = useAssets({ ...filters, page, per_page: PER_PAGE });
  const assets = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PER_PAGE);

  const handleNLFilters = (nlFilters: Record<string, unknown>) => {
    pushParams({ ...filters, ...(nlFilters as Partial<AssetFilters>) }, 1);
  };

  const handleFilterChange = (newFilters: AssetFilters) => {
    pushParams(newFilters, 1);
  };

  const handleClearFilters = () => {
    pushParams({}, 1);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Asset Inventory"
        description={`${total.toLocaleString()} assets discovered`}
      />

      {/* NL Search */}
      <NLSearchBar
        context="assets"
        onFiltersChange={handleNLFilters}
        placeholder='Try: "show all cloud resources with high risk" or "staging subdomains"'
      />

      <div className="flex gap-6">
        {/* Filter panel */}
        <div className="w-56 shrink-0 rounded-lg border border-zinc-800 bg-zinc-900 self-start">
          <AssetFilterPanel
            filters={filters}
            onChange={handleFilterChange}
            onClear={handleClearFilters}
          />
        </div>

        {/* Table */}
        <div className="flex-1 min-w-0 space-y-4">
          {assets.length === 0 && !isLoading ? (
            <EmptyState
              icon={<Globe className="h-8 w-8" />}
              title="No assets found"
              description="Start a scan to discover assets, or adjust your filters"
            />
          ) : (
            <AssetTable
              assets={assets}
              isLoading={isLoading}
              onBulkTag={(ids) => console.log("bulk tag", ids)}
              onBulkAssign={(ids) => console.log("bulk assign", ids)}
              onExport={() => console.log("export")}
            />
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between text-sm text-zinc-500">
              <span>
                Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of{" "}
                {total.toLocaleString()} assets
              </span>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => pushParams(filters, Math.max(1, page - 1))}
                  disabled={page === 1}
                  className="h-8"
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <span className="text-zinc-400">
                  Page {page} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => pushParams(filters, Math.min(totalPages, page + 1))}
                  disabled={page === totalPages}
                  className="h-8"
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
