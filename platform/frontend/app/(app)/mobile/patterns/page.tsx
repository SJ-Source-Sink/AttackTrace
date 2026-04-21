"use client";

import React, { useState } from "react";
import {
  BookOpen, Plus, Pencil, Trash2, ToggleLeft, ToggleRight,
  RefreshCw, Search, ChevronDown, ChevronRight, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const PLATFORM_COLORS: Record<string, string> = {
  android: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  ios:     "bg-blue-500/10 text-blue-400 border-blue-500/30",
  jar:     "bg-amber-500/10 text-amber-400 border-amber-500/30",
  exe:     "bg-violet-500/10 text-violet-400 border-violet-500/30",
  all:     "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

const SEV_COLORS: Record<string, string> = {
  Critical: "bg-red-500/10 text-red-400 border-red-500/30",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  Low:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
  Info:     "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

// MSRA rule fields
interface Pattern {
  id: string;
  title: string;
  platform: string;
  severity: string;
  category: string;
  description?: string;
  patterns?: Array<{ pattern?: string; name?: string }>;
  enabled: boolean;
  source?: string; // "builtin" | "custom"
}

interface RuleStats {
  total: number;
  enabled: number;
  disabled: number;
  by_source: { builtin: number; custom: number };
  by_severity: Record<string, number>;
}

const EMPTY_RULE = {
  title: "",
  platform: "android",
  severity: "Medium",
  category: "",
  description: "",
  pattern: "",
};

function RuleEditor({
  initial,
  onSave,
  onCancel,
  loading,
}: {
  initial: typeof EMPTY_RULE;
  onSave: (data: typeof EMPTY_RULE) => void;
  onCancel: () => void;
  loading: boolean;
}) {
  const [form, setForm] = useState(initial);
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm((p) => ({ ...p, [k]: e.target.value }));

  return (
    <div className="bg-zinc-950 rounded-lg border border-zinc-800 p-4 space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <Label className="text-xs text-zinc-400 mb-1 block">Rule Name</Label>
          <Input
            value={form.title}
            onChange={set("title")}
            placeholder="e.g. Hardcoded API Key"
            className="h-8 bg-zinc-900 border-zinc-700 text-sm text-zinc-200"
          />
        </div>
        <div>
          <Label className="text-xs text-zinc-400 mb-1 block">Platform</Label>
          <select
            value={form.platform}
            onChange={set("platform")}
            className="w-full h-8 rounded-md bg-zinc-900 border border-zinc-700 text-sm text-zinc-200 px-2"
          >
            {["android", "ios", "jar", "exe", "all"].map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>
        <div>
          <Label className="text-xs text-zinc-400 mb-1 block">Severity</Label>
          <select
            value={form.severity}
            onChange={set("severity")}
            className="w-full h-8 rounded-md bg-zinc-900 border border-zinc-700 text-sm text-zinc-200 px-2"
          >
            {["Critical", "High", "Medium", "Low", "Info"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div className="col-span-2">
          <Label className="text-xs text-zinc-400 mb-1 block">Category</Label>
          <Input
            value={form.category}
            onChange={set("category")}
            placeholder="e.g. Cryptography, Authentication"
            className="h-8 bg-zinc-900 border-zinc-700 text-sm text-zinc-200"
          />
        </div>
        <div className="col-span-2">
          <Label className="text-xs text-zinc-400 mb-1 block">Regex Pattern</Label>
          <Input
            value={form.pattern}
            onChange={set("pattern")}
            placeholder={"e.g. (api_key|apikey)\\s*=\\s*['\"]"}
            className="h-8 bg-zinc-900 border-zinc-700 text-sm text-zinc-200 font-mono"
          />
        </div>
        <div className="col-span-2">
          <Label className="text-xs text-zinc-400 mb-1 block">Description</Label>
          <textarea
            value={form.description}
            onChange={set("description")}
            rows={2}
            placeholder="What does this rule detect?"
            className="w-full rounded-md bg-zinc-900 border border-zinc-700 text-sm text-zinc-200 px-3 py-2 resize-none focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
      </div>
      <div className="flex gap-2 justify-end pt-1">
        <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          size="sm"
          className="h-8 text-xs bg-blue-600 hover:bg-blue-700"
          onClick={() => onSave(form)}
          disabled={loading || !form.title || !form.pattern}
        >
          {loading ? <RefreshCw className="h-3 w-3 animate-spin mr-1" /> : null}
          Save Rule
        </Button>
      </div>
    </div>
  );
}

function PatternRow({ pattern, onToggle, onEdit, onDelete }: {
  pattern: Pattern;
  onToggle: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const plat = pattern.platform?.toLowerCase() ?? "android";
  const sev = pattern.severity ?? "Info";
  const isCustom = pattern.source === "custom";

  // Extract first pattern string if available
  const patternStr = pattern.patterns?.[0]?.pattern ?? "";

  return (
    <div className={cn("hover:bg-zinc-800/30 transition-colors", !pattern.enabled && "opacity-50")}>
      <div className="flex items-center gap-3 px-4 py-2.5">
        <button onClick={() => setExpanded(!expanded)} className="text-zinc-600 hover:text-zinc-400 shrink-0">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </button>
        <Badge variant="outline" className={cn("text-xs capitalize shrink-0", PLATFORM_COLORS[plat] ?? PLATFORM_COLORS.android)}>
          {plat}
        </Badge>
        <Badge variant="outline" className={cn("text-xs w-20 justify-center shrink-0", SEV_COLORS[sev] ?? SEV_COLORS.Info)}>
          {sev}
        </Badge>
        <span className="flex-1 text-sm text-zinc-200 font-medium truncate">{pattern.title}</span>
        <span className="text-xs text-zinc-500 shrink-0 hidden md:block">{pattern.category}</span>
        {isCustom && (
          <Badge variant="outline" className="text-xs border-blue-800 text-blue-400 shrink-0">custom</Badge>
        )}
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={onToggle}
            title={pattern.enabled ? "Disable" : "Enable"}
            className={cn("transition-colors", pattern.enabled ? "text-emerald-400 hover:text-emerald-300" : "text-zinc-600 hover:text-zinc-400")}
          >
            {pattern.enabled ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
          </button>
          {isCustom && (
            <>
              <button onClick={onEdit} className="text-zinc-600 hover:text-zinc-300 p-1">
                <Pencil className="h-3.5 w-3.5" />
              </button>
              <button onClick={onDelete} className="text-zinc-600 hover:text-red-400 p-1">
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </>
          )}
        </div>
      </div>
      {expanded && (
        <div className="px-11 pb-3 space-y-1.5 border-t border-zinc-800/30">
          {pattern.description && (
            <p className="text-xs text-zinc-400 pt-2">{pattern.description}</p>
          )}
          {patternStr && (
            <code className="text-xs font-mono text-zinc-500 bg-zinc-950 px-2 py-1 rounded block border border-zinc-800 mt-1">
              {patternStr}
            </code>
          )}
        </div>
      )}
    </div>
  );
}

export default function PatternsPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [platFilter, setPlatFilter] = useState<string | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [editTarget, setEditTarget] = useState<Pattern | null>(null);
  const [savingRule, setSavingRule] = useState(false);

  const { data: stats } = useQuery<RuleStats>({
    queryKey: ["mobile", "rule-stats"],
    queryFn: async () => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/rules/stats`);
      return res.json();
    },
  });

  // MSRA returns a list directly
  const { data: patterns = [], isLoading, refetch } = useQuery<Pattern[]>({
    queryKey: ["mobile", "rules"],
    queryFn: async () => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/rules`);
      const data = await res.json();
      // Handle both list and {rules: [...]} shapes
      return Array.isArray(data) ? data : (data.rules ?? []);
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/rules/${id}/toggle`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      });
      if (!res.ok) throw new Error("Toggle failed");
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["mobile", "rules"] }),
    onError: () => toast.error("Failed to toggle rule"),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/rules/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Delete failed");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mobile", "rules"] });
      queryClient.invalidateQueries({ queryKey: ["mobile", "rule-stats"] });
      toast.success("Rule deleted");
    },
    onError: () => toast.error("Failed to delete rule"),
  });

  const saveRule = async (data: typeof EMPTY_RULE) => {
    setSavingRule(true);
    try {
      const url = editTarget
        ? `${API_BASE}/mobile/rules/${editTarget.id}`
        : `${API_BASE}/mobile/rules`;
      const method = editTarget ? "PUT" : "POST";
      const res = await fetchWithAuth(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error("Save failed");
      toast.success(editTarget ? "Rule updated" : "Rule created");
      queryClient.invalidateQueries({ queryKey: ["mobile", "rules"] });
      queryClient.invalidateQueries({ queryKey: ["mobile", "rule-stats"] });
      setShowEditor(false);
      setEditTarget(null);
    } catch {
      toast.error("Failed to save rule");
    } finally {
      setSavingRule(false);
    }
  };

  const filtered = patterns.filter((p) => {
    const matchSearch =
      !search ||
      (p.title ?? "").toLowerCase().includes(search.toLowerCase()) ||
      (p.category ?? "").toLowerCase().includes(search.toLowerCase());
    const matchPlat = !platFilter || p.platform?.toLowerCase() === platFilter;
    return matchSearch && matchPlat;
  });

  const PLATFORMS = ["android", "ios", "jar", "exe"];

  // Count per platform from live data
  const platformCounts = PLATFORMS.reduce<Record<string, number>>((acc, p) => {
    acc[p] = patterns.filter((r) => r.platform?.toLowerCase() === p).length;
    return acc;
  }, {});

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Pattern Library"
        description={`${stats?.total ?? patterns.length} detection patterns for Android, iOS, JAR, and Windows. Add custom rules to extend coverage.`}
      >
        <Button
          variant="ghost"
          size="sm"
          onClick={() => refetch()}
          className="text-zinc-400 hover:text-zinc-100"
        >
          <RefreshCw className="h-4 w-4" />
        </Button>
        <Button
          size="sm"
          className="bg-blue-600 hover:bg-blue-700 text-white"
          onClick={() => { setEditTarget(null); setShowEditor(true); }}
        >
          <Plus className="h-3.5 w-3.5 mr-1.5" /> New Rule
        </Button>
      </PageHeader>

      {/* Stats cards */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: "Android", key: "android", color: "text-emerald-400" },
          { label: "iOS",     key: "ios",     color: "text-blue-400" },
          { label: "JAR",     key: "jar",     color: "text-amber-400" },
          { label: "EXE",     key: "exe",     color: "text-violet-400" },
          { label: "Custom",  key: "custom",  color: "text-zinc-300" },
        ].map(({ label, key, color }) => (
          <div key={key} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <p className="text-xs text-zinc-500 mb-1">{label}</p>
            <p className={cn("text-2xl font-bold", color)}>
              {key === "custom"
                ? (stats?.by_source?.custom ?? 0)
                : (platformCounts[key] ?? 0)}
            </p>
          </div>
        ))}
      </div>

      {/* New / edit rule editor */}
      {showEditor && (
        <RuleEditor
          initial={
            editTarget
              ? {
                  title: editTarget.title,
                  platform: editTarget.platform,
                  severity: editTarget.severity,
                  category: editTarget.category ?? "",
                  description: editTarget.description ?? "",
                  pattern: editTarget.patterns?.[0]?.pattern ?? "",
                }
              : EMPTY_RULE
          }
          onSave={saveRule}
          onCancel={() => { setShowEditor(false); setEditTarget(null); }}
          loading={savingRule}
        />
      )}

      {/* Filter bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search patterns…"
            className="pl-9 h-8 bg-zinc-900 border-zinc-700 text-sm text-zinc-200"
          />
        </div>
        <div className="flex gap-1.5">
          {PLATFORMS.map((p) => (
            <button
              key={p}
              onClick={() => setPlatFilter(platFilter === p ? null : p)}
              className={cn(
                "px-2.5 py-1 rounded-md text-xs font-medium border transition-colors capitalize",
                platFilter === p
                  ? PLATFORM_COLORS[p]
                  : "border-zinc-700 text-zinc-500 hover:text-zinc-300 hover:border-zinc-600",
              )}
            >
              {p}
            </button>
          ))}
          {(platFilter || search) && (
            <button
              onClick={() => { setPlatFilter(null); setSearch(""); }}
              className="px-2 py-1 rounded-md text-xs text-zinc-500 hover:text-zinc-300"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
        <span className="ml-auto text-xs text-zinc-500">{filtered.length} patterns</span>
      </div>

      {/* Pattern list */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-6 text-center text-sm text-zinc-500">Loading patterns…</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center">
            <BookOpen className="h-10 w-10 text-zinc-700 mx-auto mb-3" />
            <p className="text-sm text-zinc-500">No patterns match your filters.</p>
          </div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {filtered.map((pattern) => (
              <PatternRow
                key={pattern.id}
                pattern={pattern}
                onToggle={() => toggleMutation.mutate({ id: pattern.id, enabled: !pattern.enabled })}
                onEdit={() => { setEditTarget(pattern); setShowEditor(true); }}
                onDelete={() => {
                  if (confirm("Delete this custom rule?")) deleteMutation.mutate(pattern.id);
                }}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
