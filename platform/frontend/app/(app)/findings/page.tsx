"use client";

import React, { useState, useEffect } from "react";
import { ShieldAlert, ChevronLeft, ChevronRight, X, Plus, AlertTriangle, Lock, Clock, Search, Download, CheckSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/shared/empty-state";
import { FindingRow } from "@/components/findings/finding-row";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useFindings } from "@/hooks/use-findings";
import { useCreateFinding } from "@/hooks/use-findings";
import { toast } from "sonner";
import type { FindingFilters, FindingSeverity, FindingStatus } from "@/types";
import { API_BASE } from "@/lib/api";

const SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: FindingStatus[] = ["open", "in_progress", "remediated", "accepted_risk", "false_positive"];
const PER_PAGE = 25;

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-zinc-400",
};

interface CreateFindingForm {
  title: string;
  severity: string;
  category: string;
  affected_asset: string;
  description: string;
  evidence_text: string;
  remediation: string;
  cve_text: string;
  cvss_score: string;
  references_text: string;
  status: string;
  ticket_ref: string;
}

const EMPTY_FORM: CreateFindingForm = {
  title: "",
  severity: "high",
  category: "",
  affected_asset: "",
  description: "",
  evidence_text: "",
  remediation: "",
  cve_text: "",
  cvss_score: "",
  references_text: "",
  status: "open",
  ticket_ref: "",
};

function CreateFindingDrawer({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [form, setForm] = useState<CreateFindingForm>(EMPTY_FORM);
  const createFinding = useCreateFinding();

  const set = (field: keyof CreateFindingForm) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => setForm((f) => ({ ...f, [field]: e.target.value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.title.trim()) {
      toast.error("Title is required");
      return;
    }

    const cvssNum = form.cvss_score ? parseFloat(form.cvss_score) : undefined;
    if (cvssNum !== undefined && (isNaN(cvssNum) || cvssNum < 0 || cvssNum > 10)) {
      toast.error("CVSS score must be between 0 and 10");
      return;
    }

    const payload = {
      title: form.title.trim(),
      severity: form.severity,
      category: form.category.trim(),
      affected_asset: form.affected_asset.trim(),
      description: form.description.trim(),
      evidence: form.evidence_text.trim() ? { content: form.evidence_text.trim() } : undefined,
      remediation: form.remediation.trim(),
      cve: form.cve_text
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
      cvss_score: cvssNum,
      references: form.references_text
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      status: form.status,
      ticket_ref: form.ticket_ref.trim() || undefined,
    };

    createFinding.mutate(payload, {
      onSuccess: () => {
        setForm(EMPTY_FORM);
        onClose();
      },
    });
  };

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xl flex flex-col bg-zinc-950 border-l border-zinc-800 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800 shrink-0">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-orange-400" />
            <h2 className="text-base font-semibold text-zinc-100">Create Manual Finding</h2>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          {/* Title */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
              Title <span className="text-red-400">*</span>
            </label>
            <input
              value={form.title}
              onChange={set("title")}
              placeholder="e.g. SQL Injection in /api/users endpoint"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
              required
            />
          </div>

          {/* Severity + Status row */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
                Severity <span className="text-red-400">*</span>
              </label>
              <select
                value={form.severity}
                onChange={set("severity")}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-zinc-500"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s} className={SEV_COLORS[s]}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Status</label>
              <select
                value={form.status}
                onChange={set("status")}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-zinc-500"
              >
                {STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Category + Affected Asset */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Category</label>
              <input
                value={form.category}
                onChange={set("category")}
                placeholder="e.g. injection, auth"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Affected Asset</label>
              <input
                value={form.affected_asset}
                onChange={set("affected_asset")}
                placeholder="e.g. https://api.example.com"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>
          </div>

          {/* Description */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Description</label>
            <textarea
              value={form.description}
              onChange={set("description")}
              rows={3}
              placeholder="Describe the vulnerability, its impact, and how it was found..."
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 resize-none"
            />
          </div>

          {/* Evidence */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Evidence</label>
            <textarea
              value={form.evidence_text}
              onChange={set("evidence_text")}
              rows={4}
              placeholder="Paste request/response, payload, or PoC output here..."
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 font-mono resize-none"
            />
          </div>

          {/* Remediation */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Remediation</label>
            <textarea
              value={form.remediation}
              onChange={set("remediation")}
              rows={3}
              placeholder="Steps to fix this vulnerability (one per line)..."
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 resize-none"
            />
          </div>

          {/* CVE + CVSS */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">CVE IDs</label>
              <textarea
                value={form.cve_text}
                onChange={set("cve_text")}
                rows={2}
                placeholder="CVE-2024-1234&#10;CVE-2024-5678"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 font-mono resize-none"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">CVSS Score (0–10)</label>
              <input
                value={form.cvss_score}
                onChange={set("cvss_score")}
                type="number"
                min={0}
                max={10}
                step={0.1}
                placeholder="e.g. 8.1"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>
          </div>

          {/* References */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">References (one URL per line)</label>
            <textarea
              value={form.references_text}
              onChange={set("references_text")}
              rows={2}
              placeholder="https://owasp.org/...&#10;https://cve.mitre.org/..."
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 resize-none"
            />
          </div>

          {/* Ticket Ref */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Ticket Reference</label>
            <input
              value={form.ticket_ref}
              onChange={set("ticket_ref")}
              placeholder="e.g. JIRA-1234 or GitHub #42"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
            />
          </div>
        </form>

        {/* Footer */}
        <div className="shrink-0 flex items-center justify-end gap-3 px-6 py-4 border-t border-zinc-800 bg-zinc-950">
          <Button variant="ghost" onClick={onClose} className="text-zinc-400">
            Cancel
          </Button>
          <Button
            onClick={(e) => {
              e.preventDefault();
              const formEl = document.querySelector("form");
              formEl?.requestSubmit();
            }}
            disabled={createFinding.isPending}
            className="bg-orange-600 hover:bg-orange-500 text-white"
          >
            {createFinding.isPending ? "Creating…" : "Create Finding"}
          </Button>
        </div>
      </div>
    </>
  );
}

export default function FindingsPage() {
  const [viewMode, setViewMode] = useState<'active' | 'suppressed'>('active');
  const [filters, setFilters] = useState<FindingFilters>({ statuses: ["open", "in_progress"] });
  const [kevOnly, setKevOnly] = useState(false);
  const [confidenceFilter, setConfidenceFilter] = useState("");
  const [secretsOnly, setSecretsOnly] = useState(false);
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkLoading, setBulkLoading] = useState(false);

  // Build query params based on view mode + filters
  const activeQueryFilters: FindingFilters & { page?: number; per_page?: number; category?: string; overdue?: boolean } = viewMode === 'active'
    ? {
        ...filters,
        suppressed: false,
        kev_only: kevOnly || undefined,
        confidence: confidenceFilter || undefined,
        category: secretsOnly ? "exposed_secret" : undefined,
        overdue: overdueOnly || undefined,
        page,
        per_page: PER_PAGE,
      }
    : {
        suppressed: true,
        page,
        per_page: PER_PAGE,
      };

  const { data, isLoading } = useFindings(activeQueryFilters);
  const findings = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PER_PAGE);

  // Fetch suppressed count for the badge
  const { data: suppressedData } = useFindings({ suppressed: true, per_page: 1, page: 1 });
  const suppressedCount = suppressedData?.total ?? 0;

  const toggleSeverity = (severity: FindingSeverity) => {
    const current = filters.severities ?? [];
    const updated = current.includes(severity)
      ? current.filter((s) => s !== severity)
      : [...current, severity];
    setFilters((f) => ({ ...f, severities: updated.length > 0 ? updated : undefined }));
    setPage(1);
  };

  const toggleStatus = (status: FindingStatus) => {
    const current = filters.statuses ?? [];
    const updated = current.includes(status)
      ? current.filter((s) => s !== status)
      : [...current, status];
    setFilters((f) => ({ ...f, statuses: updated.length > 0 ? updated : undefined }));
    setPage(1);
  };

  const clearFilters = () => {
    setFilters({});
    setKevOnly(false);
    setConfidenceFilter("");
    setSecretsOnly(false);
    setOverdueOnly(false);
    setPage(1);
  };

  // Search filter applied client-side on the current page's findings
  const filteredFindings = searchQuery.trim()
    ? findings.filter((f) =>
        f.title?.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : findings;

  // Select all visible (filtered) findings on current page
  const allVisibleSelected =
    filteredFindings.length > 0 &&
    filteredFindings.every((f) => selectedIds.has(f.id));

  const toggleSelectAll = () => {
    if (allVisibleSelected) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        filteredFindings.forEach((f) => next.delete(f.id));
        return next;
      });
    } else {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        filteredFindings.forEach((f) => next.add(f.id));
        return next;
      });
    }
  };

  const toggleSelectOne = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleBulkStatus = async (status: string) => {
    if (selectedIds.size === 0) return;
    setBulkLoading(true);
    try {
      const token = localStorage.getItem("access_token") || "";
      const resp = await fetch(`${API_BASE}/findings/bulk-status`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ finding_ids: Array.from(selectedIds), status }),
      });
      if (!resp.ok) throw new Error("Bulk status update failed");
      toast.success(`Marked ${selectedIds.size} finding(s) as ${status.replace("_", " ")}`);
      setSelectedIds(new Set());
    } catch {
      toast.error("Failed to update findings");
    } finally {
      setBulkLoading(false);
    }
  };

  const handleExportSelected = async () => {
    if (selectedIds.size === 0) return;
    const token = localStorage.getItem("access_token") || "";
    const ids = Array.from(selectedIds).join(",");
    const url = `${API_BASE}/findings/export?fmt=csv&finding_ids=${encodeURIComponent(ids)}`;
    const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!resp.ok) { toast.error("Export failed"); return; }
    const blob = await resp.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "findings-selected.csv";
    a.click();
  };

  const handleExportAll = async () => {
    const token = localStorage.getItem("access_token") || "";
    const resp = await fetch(`${API_BASE}/findings/export?fmt=csv`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) { toast.error("Export failed"); return; }
    const blob = await resp.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "findings-all.csv";
    a.click();
  };

  const hasFilters =
    (filters.severities?.length ?? 0) > 0 ||
    (filters.statuses?.length ?? 0) > 0 ||
    !!filters.has_cve ||
    kevOnly ||
    !!confidenceFilter ||
    secretsOnly ||
    overdueOnly;

  const SEVERITY_COLORS: Record<FindingSeverity, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-blue-400",
    info: "text-gray-400",
  };

  const handleViewModeChange = (mode: 'active' | 'suppressed') => {
    setViewMode(mode);
    setPage(1);
  };

  return (
    <div className="flex gap-6 h-full">
      {/* Filter sidebar — only show in active mode */}
      {viewMode === 'active' && (
        <div className="w-52 shrink-0 space-y-5 rounded-lg border border-zinc-800 bg-zinc-900 p-4 self-start">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-zinc-300">Filters</h3>
            {hasFilters && (
              <Button
                variant="ghost"
                size="sm"
                onClick={clearFilters}
                className="h-6 text-xs text-zinc-500 gap-1 px-2"
              >
                <X className="h-3 w-3" />
                Clear
              </Button>
            )}
          </div>

          {/* KEV Only toggle */}
          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Threat Intel</Label>
            <button
              onClick={() => { setKevOnly(!kevOnly); setPage(1); }}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors w-full justify-start ${
                kevOnly
                  ? 'bg-red-900/50 border-red-500/50 text-red-300'
                  : 'border-zinc-600 text-zinc-400 hover:border-red-500/50 hover:text-red-300'
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${kevOnly ? 'bg-red-400 animate-pulse' : 'bg-zinc-600'}`} />
              KEV Only
            </button>

            {/* Secrets quick-filter */}
            <button
              onClick={() => { setSecretsOnly(!secretsOnly); setPage(1); }}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors w-full justify-start ${
                secretsOnly
                  ? 'bg-amber-900/50 border-amber-500/50 text-amber-300'
                  : 'border-zinc-600 text-zinc-400 hover:border-amber-500/50 hover:text-amber-300'
              }`}
            >
              <Lock className="h-3 w-3" />
              Secrets Only
            </button>

            {/* Overdue quick-filter */}
            <button
              onClick={() => { setOverdueOnly(!overdueOnly); setPage(1); }}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors w-full justify-start ${
                overdueOnly
                  ? 'bg-orange-900/50 border-orange-500/50 text-orange-300'
                  : 'border-zinc-600 text-zinc-400 hover:border-orange-500/50 hover:text-orange-300'
              }`}
            >
              <Clock className="h-3 w-3" />
              Overdue
            </button>
          </div>

          <Separator />

          {/* Confidence filter */}
          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Confidence</Label>
            <select
              value={confidenceFilter}
              onChange={(e) => { setConfidenceFilter(e.target.value); setPage(1); }}
              className="w-full rounded-lg border border-zinc-600 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-300"
            >
              <option value="">All Confidence</option>
              <option value="certain">Certain</option>
              <option value="firm">Firm</option>
              <option value="tentative">Tentative</option>
            </select>
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Severity</Label>
            {SEVERITIES.map((severity) => (
              <div key={severity} className="flex items-center gap-2">
                <Checkbox
                  id={`sev-${severity}`}
                  checked={(filters.severities ?? []).includes(severity)}
                  onCheckedChange={() => toggleSeverity(severity)}
                />
                <label
                  htmlFor={`sev-${severity}`}
                  className={`text-sm cursor-pointer capitalize font-medium ${SEVERITY_COLORS[severity]}`}
                >
                  {severity}
                </label>
              </div>
            ))}
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">Status</Label>
            {STATUSES.map((status) => (
              <div key={status} className="flex items-center gap-2">
                <Checkbox
                  id={`status-${status}`}
                  checked={(filters.statuses ?? []).includes(status)}
                  onCheckedChange={() => toggleStatus(status)}
                />
                <label
                  htmlFor={`status-${status}`}
                  className="text-sm cursor-pointer text-zinc-300 capitalize"
                >
                  {status.replace("_", " ")}
                </label>
              </div>
            ))}
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wider text-zinc-500">CVE / CVSS</Label>
            <div className="flex items-center gap-2">
              <Checkbox
                id="has-cve"
                checked={!!filters.has_cve}
                onCheckedChange={(checked) => {
                  setFilters((f) => ({ ...f, has_cve: checked ? true : undefined }));
                  setPage(1);
                }}
              />
              <label htmlFor="has-cve" className="text-sm cursor-pointer text-zinc-300">
                Has CVE ID
              </label>
            </div>
          </div>
        </div>
      )}

      {/* Main content */}
      <div className="flex-1 min-w-0 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Findings</h1>
            <p className="text-sm text-zinc-400 mt-0.5">
              {total.toLocaleString()} findings {hasFilters && viewMode === 'active' && "matching filters"}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {/* Search bar */}
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings..."
                className="pl-8 pr-3 py-1.5 rounded-md border border-zinc-700 bg-zinc-900 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 w-52"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
            {/* Export All CSV */}
            <Button
              variant="outline"
              size="sm"
              onClick={handleExportAll}
              className="gap-1.5 border-zinc-700 text-zinc-300 hover:text-zinc-100"
            >
              <Download className="h-3.5 w-3.5" />
              Export CSV
            </Button>
            <Button
              onClick={() => setDrawerOpen(true)}
              className="bg-orange-600 hover:bg-orange-500 text-white gap-1.5"
              size="sm"
            >
              <Plus className="h-4 w-4" />
              Create Finding
            </Button>
          </div>
        </div>

        {/* Active / Suppressed tab bar */}
        <div className="flex gap-1 rounded-lg bg-gray-800/50 p-1 w-fit">
          <button
            onClick={() => handleViewModeChange('active')}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              viewMode === 'active'
                ? 'bg-gray-700 text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Active Findings
          </button>
          <button
            onClick={() => handleViewModeChange('suppressed')}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              viewMode === 'suppressed'
                ? 'bg-gray-700 text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Suppressed
            {suppressedCount > 0 && (
              <span className="ml-1.5 rounded-full bg-gray-600 px-1.5 py-0.5 text-xs">
                {suppressedCount}
              </span>
            )}
          </button>
        </div>

        {isLoading ? (
          <div className="rounded-lg border border-zinc-800 divide-y divide-zinc-800">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3">
                <div className="h-3.5 w-3.5 rounded bg-zinc-800 animate-pulse shrink-0" />
                <div className="h-6 w-20 rounded bg-zinc-800 animate-pulse shrink-0" />
                <div className="flex-1 space-y-1.5">
                  <div className="h-4 w-64 rounded bg-zinc-800 animate-pulse" />
                  <div className="h-3 w-40 rounded bg-zinc-800 animate-pulse" />
                </div>
                <div className="h-6 w-24 rounded bg-zinc-800 animate-pulse shrink-0" />
              </div>
            ))}
          </div>
        ) : filteredFindings.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert className="h-8 w-8" />}
            title={
              searchQuery
                ? "No findings match your search"
                : viewMode === 'suppressed' ? "No suppressed findings" : "No findings"
            }
            description={
              searchQuery
                ? `No findings matched "${searchQuery}". Try a different search term.`
                : viewMode === 'suppressed'
                  ? "No findings have been suppressed or marked as false positive."
                  : "No findings match your current filters. Run a scan or create a manual finding."
            }
          />
        ) : (
          <div className="rounded-lg border border-zinc-800 overflow-hidden divide-y divide-zinc-800">
            {/* Select-all header row */}
            <div className="flex items-center gap-3 px-4 py-2 bg-zinc-900/60 border-b border-zinc-800">
              <Checkbox
                checked={allVisibleSelected}
                onCheckedChange={toggleSelectAll}
                aria-label="Select all findings"
              />
              <span className="text-xs text-zinc-500">
                {selectedIds.size > 0
                  ? `${selectedIds.size} selected`
                  : `Select all (${filteredFindings.length})`}
              </span>
            </div>
            {filteredFindings.map((f) => (
              <div key={f.id} className="flex items-start gap-3 px-4 group">
                <div className="flex items-center pt-3.5 shrink-0">
                  <Checkbox
                    checked={selectedIds.has(f.id)}
                    onCheckedChange={() => toggleSelectOne(f.id)}
                    aria-label={`Select finding ${f.title}`}
                  />
                </div>
                <div className="flex-1 min-w-0">
                  <FindingRow finding={f} />
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-sm text-zinc-500">
            <span>
              Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of{" "}
              {total.toLocaleString()}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="h-8"
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-zinc-400">
                {page} / {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="h-8"
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Floating bulk action bar */}
      {selectedIds.size > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 bg-zinc-800 border border-zinc-600 rounded-xl px-5 py-3 shadow-2xl">
          <span className="text-sm font-medium text-zinc-200 flex items-center gap-1.5">
            <CheckSquare className="h-4 w-4 text-blue-400" />
            {selectedIds.size} selected
          </span>
          <div className="w-px h-5 bg-zinc-600" />
          <button
            onClick={() => handleBulkStatus("remediated")}
            disabled={bulkLoading}
            className="px-3 py-1.5 rounded-md text-xs font-medium bg-green-700 hover:bg-green-600 text-white disabled:opacity-50 transition-colors"
          >
            Mark as Remediated
          </button>
          <button
            onClick={() => handleBulkStatus("accepted_risk")}
            disabled={bulkLoading}
            className="px-3 py-1.5 rounded-md text-xs font-medium bg-yellow-700 hover:bg-yellow-600 text-white disabled:opacity-50 transition-colors"
          >
            Mark as Accepted Risk
          </button>
          <button
            onClick={handleExportSelected}
            disabled={bulkLoading}
            className="px-3 py-1.5 rounded-md text-xs font-medium bg-zinc-700 hover:bg-zinc-600 text-zinc-200 disabled:opacity-50 transition-colors flex items-center gap-1"
          >
            <Download className="h-3.5 w-3.5" />
            Export Selected (CSV)
          </button>
          <div className="w-px h-5 bg-zinc-600" />
          <button
            onClick={() => setSelectedIds(new Set())}
            className="text-zinc-400 hover:text-zinc-200 transition-colors"
            aria-label="Clear selection"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      <CreateFindingDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} />
    </div>
  );
}
