"use client";

import React, { useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ChevronLeft,
  ChevronRight,
  FileCode2,
  Search,
  Upload,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { EmptyState } from "@/components/shared/empty-state";
import { nucleiApi } from "@/lib/api";
import { toast } from "sonner";
import type { NucleiTemplate, NucleiTemplateListResponse } from "@/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 border-red-500/30 bg-red-500/10",
  high: "text-orange-400 border-orange-500/30 bg-orange-500/10",
  medium: "text-yellow-400 border-yellow-500/30 bg-yellow-500/10",
  low: "text-blue-400 border-blue-500/30 bg-blue-500/10",
  unknown: "text-zinc-400 border-zinc-600/30 bg-zinc-700/10",
  info: "text-zinc-400 border-zinc-600/30 bg-zinc-700/10",
};

const CATEGORIES = [
  "", "cves", "exposures", "misconfiguration", "takeovers",
  "technologies", "default-logins", "fuzzing", "workflows",
  "network", "dns", "ssl", "headless", "file", "code",
];

export default function TemplatesPage() {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [page, setPage] = useState(1);

  const PER_PAGE = 50;

  const { data, isLoading } = useQuery({
    queryKey: ["nuclei", "templates", "browse", search, category, page],
    queryFn: () =>
      nucleiApi.browseTemplates({ search, category, page, per_page: PER_PAGE }) as Promise<NucleiTemplateListResponse>,
    staleTime: 60_000,
  });

  const templates = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PER_PAGE);

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      nucleiApi.toggleTemplate(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["nuclei", "templates", "browse"] });
      toast.success("Template updated");
    },
    onError: (err: unknown) => {
      toast.error("Update failed", {
        description: (err as { message?: string })?.message ?? "Unknown error",
      });
    },
  });

  const uploadMutation = useMutation({
    mutationFn: (file: File) => nucleiApi.uploadTemplate(file),
    onSuccess: (data) => {
      toast.success("Template uploaded", { description: data.filename });
      queryClient.invalidateQueries({ queryKey: ["nuclei", "templates", "browse"] });
    },
    onError: (err: unknown) => {
      toast.error("Upload failed", {
        description: (err as { message?: string })?.message ?? "Unknown error",
      });
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    uploadMutation.mutate(file);
    e.target.value = "";
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value);
    setPage(1);
  };

  const handleCategoryChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setCategory(e.target.value);
    setPage(1);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Nuclei Templates"
        description="Browse, enable/disable, and upload custom nuclei templates"
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".yaml"
          className="hidden"
          onChange={handleFileChange}
        />
        <Button
          variant="outline"
          size="sm"
          className="gap-1.5"
          disabled={uploadMutation.isPending}
          onClick={() => fileInputRef.current?.click()}
        >
          <Upload className="h-4 w-4" />
          Upload Template
        </Button>
      </PageHeader>

      {/* Filters */}
      <Card>
        <CardContent className="pt-4 pb-4">
          <div className="flex gap-3 flex-wrap">
            <div className="relative flex-1 min-w-48">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-zinc-500" />
              <Input
                placeholder="Search by name or ID..."
                className="pl-8"
                value={search}
                onChange={handleSearchChange}
              />
            </div>
            <select
              className="h-9 rounded-md border border-zinc-700 bg-zinc-900 px-3 text-sm text-zinc-300 focus:outline-none focus:ring-2 focus:ring-blue-600"
              value={category}
              onChange={handleCategoryChange}
            >
              <option value="">All categories</option>
              {CATEGORIES.filter(Boolean).map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
        </CardContent>
      </Card>

      {/* Template table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center justify-between">
            <span>Templates {total > 0 && <span className="text-zinc-500 font-normal">({total})</span>}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-2">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : templates.length === 0 ? (
            <div className="p-6">
              <EmptyState
                icon={<FileCode2 className="h-8 w-8" />}
                title="No templates found"
                description={
                  search || category
                    ? "Try adjusting your search or category filter."
                    : "Nuclei templates directory not found. Install nuclei-templates."
                }
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900/50">
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                      Name
                    </th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                      Category
                    </th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                      Severity
                    </th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                      Tags
                    </th>
                    <th className="px-4 py-2.5 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                      Enabled
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {templates.map((t: NucleiTemplate) => (
                    <tr
                      key={t.id}
                      className="border-b border-zinc-800/60 hover:bg-zinc-800/30 transition-colors"
                    >
                      <td className="px-4 py-3 max-w-xs">
                        <p className="font-medium text-zinc-200 truncate">{t.name}</p>
                        <p className="text-xs text-zinc-500 truncate">{t.id}</p>
                      </td>
                      <td className="px-4 py-3 text-zinc-400 text-xs">{t.category}</td>
                      <td className="px-4 py-3">
                        <Badge
                          variant="outline"
                          className={`text-[10px] uppercase ${SEVERITY_COLORS[t.severity] ?? SEVERITY_COLORS.unknown}`}
                        >
                          {t.severity}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {t.tags.slice(0, 3).map((tag) => (
                            <span
                              key={tag}
                              className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-zinc-800 text-zinc-400"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          role="switch"
                          aria-checked={t.enabled}
                          onClick={() =>
                            toggleMutation.mutate({ id: t.id, enabled: !t.enabled })
                          }
                          disabled={toggleMutation.isPending}
                          className={`relative inline-flex h-5 w-9 cursor-pointer items-center rounded-full transition-colors focus:outline-none ${
                            t.enabled ? "bg-blue-600" : "bg-zinc-700"
                          }`}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                              t.enabled ? "translate-x-4" : "translate-x-0.5"
                            }`}
                          />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-zinc-500">
          <span>
            Page {page} of {totalPages} ({total} templates)
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              <ChevronLeft className="h-4 w-4" />
              Prev
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
