"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { findingsApi } from "@/lib/api";
import type { Finding, FindingListResponse, FindingFilters, UpdateFindingRequest } from "@/types";
import { toast } from "sonner";

export const findingKeys = {
  all: ["findings"] as const,
  lists: () => [...findingKeys.all, "list"] as const,
  list: (params: Record<string, unknown>) => [...findingKeys.lists(), params] as const,
  details: () => [...findingKeys.all, "detail"] as const,
  detail: (id: string) => [...findingKeys.details(), id] as const,
};

function filtersToParams(
  filters?: FindingFilters & { page?: number; per_page?: number },
): Record<string, string | number | string[] | undefined> {
  if (!filters) return {};
  const params: Record<string, string | number | string[] | undefined> = {};

  if (filters.page !== undefined) params.page = filters.page;
  if (filters.per_page !== undefined) params.per_page = filters.per_page;
  if (filters.severities?.length) params.severity = filters.severities;
  if (filters.statuses?.length) params.finding_status = filters.statuses;
  if (filters.categories?.length) params.category = filters.categories[0];
  if (filters.scan_id) params.scan_job_id = filters.scan_id;
  if (filters.search) params.search = filters.search;
  if (filters.has_cve !== undefined) params.has_cve = String(filters.has_cve);
  if (filters.age_min !== undefined) params.age_min = filters.age_min;
  if (filters.age_max !== undefined) params.age_max = filters.age_max;
  if (filters.assigned_to) params.assigned_to = filters.assigned_to;
  if (filters.kev_only !== undefined) params.kev_only = String(filters.kev_only);
  if (filters.confidence) params.confidence = filters.confidence;
  if (filters.suppressed !== undefined) params.suppressed = String(filters.suppressed);

  return params;
}

export function useFindings(
  filters?: FindingFilters & { page?: number; per_page?: number },
) {
  return useQuery({
    queryKey: findingKeys.list((filters ?? {}) as Record<string, unknown>),
    queryFn: () =>
      findingsApi.list(filtersToParams(filters)) as Promise<FindingListResponse>,
    staleTime: 60_000,
    placeholderData: (prev) => prev,
  });
}

export function useFinding(id: string | null) {
  return useQuery({
    queryKey: findingKeys.detail(id ?? ""),
    queryFn: () => findingsApi.get(id!) as Promise<Finding>,
    enabled: !!id,
  });
}

export function useCreateFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: unknown) => findingsApi.create(data) as Promise<Finding>,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
      toast.success("Finding created");
    },
    onError: (error: Error) => {
      toast.error(`Failed to create finding: ${error.message}`);
    },
  });
}

export function useUpdateFinding() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateFindingRequest }) =>
      findingsApi.update(id, data) as Promise<Finding>,
    onSuccess: (finding) => {
      queryClient.invalidateQueries({ queryKey: findingKeys.detail(finding.id) });
      queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
      toast.success("Finding updated");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update finding: ${error.message}`);
    },
  });
}

export function useDeleteFinding() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => findingsApi.delete(id),
    onSuccess: (_data, id) => {
      queryClient.removeQueries({ queryKey: findingKeys.detail(id) });
      queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
      toast.success("Finding deleted");
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete finding: ${error.message}`);
    },
  });
}

export function useAddFindingComment() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, content }: { id: string; content: string }) =>
      findingsApi.addComment(id, content) as Promise<Finding>,
    onSuccess: (finding) => {
      queryClient.invalidateQueries({ queryKey: findingKeys.detail(finding.id) });
      toast.success("Comment added");
    },
    onError: (error: Error) => {
      toast.error(`Failed to add comment: ${error.message}`);
    },
  });
}
