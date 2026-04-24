"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { scansApi } from "@/lib/api";
import type { Scan, ScanListResponse, CreateScanRequest } from "@/types";
import { toast } from "sonner";

export const scanKeys = {
  all: ["scans"] as const,
  lists: () => [...scanKeys.all, "list"] as const,
  list: (params: Record<string, unknown>) => [...scanKeys.lists(), params] as const,
  details: () => [...scanKeys.all, "detail"] as const,
  detail: (id: string) => [...scanKeys.details(), id] as const,
};

export function useScans(params?: { page?: number; per_page?: number; status?: string; search?: string }) {
  return useQuery({
    queryKey: scanKeys.list(params ?? {}),
    queryFn: () =>
      scansApi.list(
        params
          ? Object.fromEntries(
              Object.entries(params).filter(([, v]) => v !== undefined && v !== ""),
            ) as Record<string, string | number>
          : undefined,
      ) as Promise<ScanListResponse>,
    staleTime: 30_000,
  });
}

export function useScan(id: string | null) {
  return useQuery({
    queryKey: scanKeys.detail(id ?? ""),
    queryFn: () => scansApi.get(id!) as Promise<Scan>,
    enabled: !!id,
    refetchInterval: (query) => {
      const data = query.state.data as Scan | undefined;
      if (data?.status === "pending") return 3_000;
      if (data?.status === "running") return 5_000;
      return false;
    },
    refetchIntervalInBackground: false,
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateScanRequest) => scansApi.create(data) as Promise<Scan>,
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
      toast.success(`Scan started for ${scan.company_name ?? scan.target_domains?.[0] ?? "target"}`);
    },
    onError: (error: Error) => {
      toast.error(`Failed to create scan: ${error.message}`);
    },
  });
}

export function useCancelScan() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: scanKeys.detail(id) });
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
      toast.success("Scan cancelled");
    },
    onError: (error: Error) => {
      toast.error(`Failed to cancel scan: ${error.message}`);
    },
  });
}

export function useDeleteScan() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => scansApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
      queryClient.invalidateQueries({ queryKey: ["dashboard", "stats"] });
      toast.success("Scan deleted");
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete scan: ${error.message}`);
    },
  });
}
