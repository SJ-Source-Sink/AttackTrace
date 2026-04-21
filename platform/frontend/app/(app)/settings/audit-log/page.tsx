"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield, Search, RefreshCw, User, Terminal, Cpu, Globe,
  KeyRound, Settings, ChevronDown, ChevronUp, Clock, Download,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/page-header";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { fetchWithAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

interface AuditEntry {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  after_state: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
  user_id: string | null;
  user_name: string;
  user_email: string;
}

// ── Action metadata ───────────────────────────────────────────────────────────

type ActionMeta = { label: string; color: string; icon: React.ElementType; category: string };

function getActionMeta(action: string): ActionMeta {
  if (action.startsWith("tool.nmap"))      return { label: "Nmap Scan",       color: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",    icon: Terminal, category: "Tool" };
  if (action.startsWith("tool.nuclei"))    return { label: "Nuclei Scan",     color: "text-orange-400 bg-orange-400/10 border-orange-400/20", icon: Terminal, category: "Tool" };
  if (action.startsWith("tool.ffuf"))      return { label: "ffuf Fuzz",       color: "text-purple-400 bg-purple-400/10 border-purple-400/20", icon: Terminal, category: "Tool" };
  if (action.startsWith("tool.takeover"))  return { label: "Takeover Check",  color: "text-pink-400 bg-pink-400/10 border-pink-400/20",    icon: Terminal, category: "Tool" };
  if (action.startsWith("tool.attackmapper")) return { label: "Attack Mapper", color: "text-red-400 bg-red-400/10 border-red-400/20",      icon: Cpu,      category: "Tool" };
  if (action === "scan.created")           return { label: "Scan Started",    color: "text-blue-400 bg-blue-400/10 border-blue-400/20",    icon: Globe,    category: "Scan" };
  if (action === "scan.cancelled")         return { label: "Scan Cancelled",  color: "text-zinc-400 bg-zinc-400/10 border-zinc-400/20",    icon: Globe,    category: "Scan" };
  if (action.startsWith("finding."))       return { label: "Finding Updated", color: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20", icon: Shield, category: "Finding" };
  if (action.startsWith("member."))        return { label: action.replace("member.", "Member "), color: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20", icon: User, category: "Team" };
  if (action.startsWith("api_key."))       return { label: action.replace("api_key.", "API Key "), color: "text-amber-400 bg-amber-400/10 border-amber-400/20", icon: KeyRound, category: "Security" };
  if (action.startsWith("org."))           return { label: action.replace("org.", "Org "), color: "text-indigo-400 bg-indigo-400/10 border-indigo-400/20", icon: Settings, category: "Org" };
  return { label: action, color: "text-zinc-400 bg-zinc-800 border-zinc-700", icon: Shield, category: "Other" };
}

function getInitials(name: string) {
  return name.split(" ").map(n => n[0]).join("").toUpperCase().slice(0, 2) || "?";
}

function formatRelative(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return new Date(iso).toLocaleDateString();
}

function AuditRow({ entry }: { entry: AuditEntry }) {
  const [expanded, setExpanded] = useState(false);
  const meta = getActionMeta(entry.action);
  const Icon = meta.icon;
  const hasDetail = !!entry.after_state && Object.keys(entry.after_state).length > 0;

  return (
    <div className="border-b border-zinc-800 last:border-0">
      <button
        type="button"
        className={cn(
          "w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-zinc-800/30 transition-colors",
          expanded && "bg-zinc-800/20"
        )}
        onClick={() => hasDetail && setExpanded(e => !e)}
      >
        {/* Action badge */}
        <span className={cn("inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded-md border font-medium shrink-0 w-36", meta.color)}>
          <Icon className="h-3 w-3" />
          {meta.label}
        </span>

        {/* User */}
        <div className="flex items-center gap-2 w-40 shrink-0">
          <div className="h-6 w-6 rounded-full bg-zinc-700 flex items-center justify-center text-[10px] font-semibold text-zinc-300 shrink-0">
            {getInitials(entry.user_name)}
          </div>
          <div className="min-w-0">
            <p className="text-xs font-medium text-zinc-200 truncate">{entry.user_name}</p>
          </div>
        </div>

        {/* Detail summary */}
        <div className="flex-1 min-w-0">
          {entry.after_state?.target != null && (
            <span className="text-xs font-mono text-zinc-400 truncate block">
              {String(entry.after_state.target)}
            </span>
          )}
          {!entry.after_state?.target && entry.resource_id && (
            <span className="text-xs font-mono text-zinc-600 truncate block">{entry.resource_id}</span>
          )}
        </div>

        {/* IP */}
        {entry.ip_address && (
          <span className="text-xs text-zinc-600 font-mono hidden lg:block shrink-0">
            {entry.ip_address}
          </span>
        )}

        {/* Time */}
        <div className="flex items-center gap-1.5 text-xs text-zinc-500 shrink-0 w-20 justify-end">
          <Clock className="h-3 w-3" />
          {formatRelative(entry.created_at)}
        </div>

        {/* Expand indicator */}
        {hasDetail && (
          <span className="text-zinc-600 shrink-0">
            {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </span>
        )}
      </button>

      {expanded && entry.after_state && (
        <div className="px-4 pb-3 pl-[180px]">
          <pre className="text-xs font-mono text-zinc-400 bg-zinc-950 border border-zinc-800 rounded-md p-3 overflow-x-auto">
            {JSON.stringify(entry.after_state, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

const CATEGORIES = ["All", "Tool", "Scan", "Finding", "Team", "Security", "Org"];

export default function AuditLogPage() {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;

  function exportCsv() {
    const rows = (data?.items ?? []);
    if (rows.length === 0) return;
    const header = ["ID", "Action", "User", "Email", "Target", "IP Address", "Timestamp"];
    const lines = rows.map(e => [
      e.id,
      e.action,
      e.user_name,
      e.user_email,
      String(e.after_state?.target ?? ""),
      e.ip_address ?? "",
      e.created_at,
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(","));
    const csv = [header.join(","), ...lines].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-log-page${page + 1}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["audit-logs", page],
    queryFn: async () => {
      const res = await fetchWithAuth(
        `${API_BASE}/org/audit-logs?limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}`
      );
      if (!res.ok) throw new Error("Failed to load audit logs");
      return res.json() as Promise<{ items: AuditEntry[]; total: number }>;
    },
    staleTime: 30_000,
  });

  const filtered = (data?.items ?? []).filter(e => {
    const meta = getActionMeta(e.action);
    if (category !== "All" && meta.category !== category) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        e.action.includes(q) ||
        e.user_name.toLowerCase().includes(q) ||
        e.user_email.toLowerCase().includes(q) ||
        String(e.after_state?.target ?? "").toLowerCase().includes(q) ||
        (e.ip_address ?? "").includes(q)
      );
    }
    return true;
  });

  const totalPages = Math.ceil((data?.total ?? 0) / PAGE_SIZE);

  return (
    <div className="space-y-6 max-w-5xl">
      <PageHeader
        title="Audit Log"
        description="Track all actions performed across the platform"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={exportCsv}
          disabled={!data?.items?.length}
          className="gap-1.5 border-zinc-700"
        >
          <Download className="h-3.5 w-3.5" />
          Export CSV
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => refetch()}
          disabled={isFetching}
          className="gap-1.5 border-zinc-700"
        >
          <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
          Refresh
        </Button>
      </PageHeader>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500" />
          <Input
            placeholder="Search by user, action, target, IP..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-9 h-8 text-sm bg-zinc-950 border-zinc-700"
          />
        </div>
        <div className="flex gap-1">
          {CATEGORIES.map(c => (
            <button
              key={c}
              type="button"
              onClick={() => setCategory(c)}
              className={cn(
                "text-xs px-2.5 py-1.5 rounded-md border transition-colors",
                category === c
                  ? "bg-blue-500/15 border-blue-500/40 text-blue-400"
                  : "border-zinc-800 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
              )}
            >
              {c}
            </button>
          ))}
        </div>
        <span className="text-xs text-zinc-500 shrink-0">
          {data?.total?.toLocaleString() ?? "—"} total events
        </span>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-zinc-800 overflow-hidden">
        {/* Header */}
        <div className="flex items-center gap-3 px-4 py-2 bg-zinc-900 border-b border-zinc-800">
          <span className="text-xs font-semibold text-zinc-500 uppercase tracking-wider w-36">Action</span>
          <span className="text-xs font-semibold text-zinc-500 uppercase tracking-wider w-40">User</span>
          <span className="text-xs font-semibold text-zinc-500 uppercase tracking-wider flex-1">Target / Detail</span>
          <span className="text-xs font-semibold text-zinc-500 uppercase tracking-wider hidden lg:block w-24 text-right">IP</span>
          <span className="text-xs font-semibold text-zinc-500 uppercase tracking-wider w-20 text-right">When</span>
          <span className="w-3.5" />
        </div>

        {isLoading ? (
          <div className="divide-y divide-zinc-800">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3">
                <Skeleton className="h-6 w-36 rounded-md" />
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-4 flex-1" />
                <Skeleton className="h-4 w-20" />
              </div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-16 text-center">
            <Shield className="h-10 w-10 text-zinc-700 mx-auto mb-3" />
            <p className="text-sm text-zinc-500">No audit events found</p>
            <p className="text-xs text-zinc-600 mt-1">
              {data?.total === 0 ? "Actions will appear here as team members use the platform." : "Try adjusting your filters."}
            </p>
          </div>
        ) : (
          <div>
            {filtered.map(entry => (
              <AuditRow key={entry.id} entry={entry} />
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-zinc-500">
            Page {page + 1} of {totalPages}
          </span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setPage(p => p - 1)} disabled={page === 0} className="border-zinc-700">
              Previous
            </Button>
            <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={page >= totalPages - 1} className="border-zinc-700">
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
