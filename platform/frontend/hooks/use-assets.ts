"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { assetsApi } from "@/lib/api";
import type { Asset, AssetListResponse, AssetFilters } from "@/types";
import { toast } from "sonner";

export const assetKeys = {
  all: ["assets"] as const,
  lists: () => [...assetKeys.all, "list"] as const,
  list: (params: Record<string, unknown>) => [...assetKeys.lists(), params] as const,
  details: () => [...assetKeys.all, "detail"] as const,
  detail: (id: string) => [...assetKeys.details(), id] as const,
};

function filtersToParams(filters?: AssetFilters & { page?: number; per_page?: number }): Record<string, string | number | string[] | undefined> {
  if (!filters) return {};
  const params: Record<string, string | number | string[] | undefined> = {};

  if (filters.page !== undefined) params.page = filters.page;
  if (filters.per_page !== undefined) params.per_page = filters.per_page;
  if (filters.types?.length) params.asset_type = filters.types[0];
  if (filters.scan_id) params.scan_job_id = filters.scan_id;
  if (filters.risk_min !== undefined) params.min_risk_score = filters.risk_min;
  if (filters.risk_max !== undefined) params.max_risk_score = filters.risk_max;
  if (filters.tags?.length) params.tags = filters.tags;
  if (filters.first_seen_after) params.first_seen_after = filters.first_seen_after;
  if (filters.first_seen_before) params.first_seen_before = filters.first_seen_before;
  if (filters.search) params.search = filters.search;
  if (filters.owner) params.owner = filters.owner;
  if (filters.is_active !== undefined) params.is_active = String(filters.is_active);
  if (filters.has_screenshot) params.has_screenshot = "true";

  return params;
}

export function useAssets(filters?: AssetFilters & { page?: number; per_page?: number }) {
  return useQuery({
    queryKey: assetKeys.list((filters ?? {}) as Record<string, unknown>),
    queryFn: () =>
      assetsApi.list(filtersToParams(filters)) as Promise<AssetListResponse>,
    staleTime: 60_000,
    placeholderData: (prev) => prev,
  });
}

export function useAsset(id: string | null) {
  return useQuery({
    queryKey: assetKeys.detail(id ?? ""),
    queryFn: () => assetsApi.get(id!) as Promise<Asset>,
    enabled: !!id,
  });
}

export function useBulkTagAssets() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ ids, tags }: { ids: string[]; tags: unknown[] }) =>
      assetsApi.bulkTag(ids, tags),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: assetKeys.lists() });
      toast.success("Tags updated successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update tags: ${error.message}`);
    },
  });
}

export function useBulkAssignAssets() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ ids, owner }: { ids: string[]; owner: string }) =>
      assetsApi.bulkAssign(ids, owner),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: assetKeys.lists() });
      toast.success("Owner assigned successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to assign owner: ${error.message}`);
    },
  });
}
