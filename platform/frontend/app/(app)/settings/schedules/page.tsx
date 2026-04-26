"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Clock,
  Plus,
  Play,
  Edit2,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Loader2,
  Calendar,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/page-header";
import { schedulesApi } from "@/lib/api";
import type { ScheduledScan, CreateScheduleRequest } from "@/types";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// Common cron presets
const CRON_PRESETS = [
  { label: "Every 6 hours", value: "0 */6 * * *" },
  { label: "Daily at midnight", value: "0 0 * * *" },
  { label: "Daily at 6am", value: "0 6 * * *" },
  { label: "Weekly (Mon 9am)", value: "0 9 * * 1" },
  { label: "Monthly (1st, midnight)", value: "0 0 1 * *" },
];

interface ScheduleFormState {
  name: string;
  target_domains: string;
  company_name: string;
  cron_expression: string;
  is_active: boolean;
  intensity: string;
}

const EMPTY_FORM: ScheduleFormState = {
  name: "",
  target_domains: "",
  company_name: "",
  cron_expression: "0 0 * * *",
  is_active: true,
  intensity: "passive",
};

function formatDate(iso?: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function ScheduleDialog({
  open,
  onOpenChange,
  initial,
  onSubmit,
  isSubmitting,
  title,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  initial: ScheduleFormState;
  onSubmit: (data: ScheduleFormState) => void;
  isSubmitting: boolean;
  title: string;
}) {
  const [form, setForm] = useState<ScheduleFormState>(initial);

  // Reset form when dialog opens with new initial data
  React.useEffect(() => {
    if (open) setForm(initial);
  }, [open, initial]);

  function handleChange(key: keyof ScheduleFormState, value: string | boolean) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg bg-zinc-900 border-zinc-800 text-zinc-100">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription className="text-zinc-400">
            Configure a recurring scan schedule using cron syntax.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="sched-name">Schedule Name</Label>
            <Input
              id="sched-name"
              placeholder="Weekly production scan"
              value={form.name}
              onChange={(e) => handleChange("name", e.target.value)}
              className="bg-zinc-800 border-zinc-700"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="sched-domains">Target Domains</Label>
            <Input
              id="sched-domains"
              placeholder="example.com, api.example.com"
              value={form.target_domains}
              onChange={(e) => handleChange("target_domains", e.target.value)}
              className="bg-zinc-800 border-zinc-700"
            />
            <p className="text-xs text-zinc-500">Comma-separated list of domains</p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="sched-company">Company Name (optional)</Label>
            <Input
              id="sched-company"
              placeholder="Acme Corp"
              value={form.company_name}
              onChange={(e) => handleChange("company_name", e.target.value)}
              className="bg-zinc-800 border-zinc-700"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="sched-cron">Cron Expression</Label>
            <Input
              id="sched-cron"
              placeholder="0 0 * * *"
              value={form.cron_expression}
              onChange={(e) => handleChange("cron_expression", e.target.value)}
              className="bg-zinc-800 border-zinc-700 font-mono"
            />
            <div className="flex flex-wrap gap-1.5 mt-1">
              {CRON_PRESETS.map((p) => (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => handleChange("cron_expression", p.value)}
                  className={cn(
                    "text-xs px-2 py-0.5 rounded border transition-colors",
                    form.cron_expression === p.value
                      ? "border-blue-600 bg-blue-600/20 text-blue-400"
                      : "border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-300",
                  )}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <Label>Scan Intensity</Label>
            <div className="flex gap-2">
              {["passive", "normal", "aggressive"].map((level) => (
                <button
                  key={level}
                  type="button"
                  onClick={() => handleChange("intensity", level)}
                  className={cn(
                    "flex-1 py-1.5 rounded text-xs font-medium border transition-colors capitalize",
                    form.intensity === level
                      ? "border-blue-600 bg-blue-600/20 text-blue-400"
                      : "border-zinc-700 text-zinc-400 hover:border-zinc-600",
                  )}
                >
                  {level}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => handleChange("is_active", !form.is_active)}
              className="flex items-center gap-2 text-sm text-zinc-300 hover:text-zinc-100 transition-colors"
            >
              {form.is_active ? (
                <ToggleRight className="h-5 w-5 text-blue-400" />
              ) : (
                <ToggleLeft className="h-5 w-5 text-zinc-500" />
              )}
              {form.is_active ? "Active" : "Paused"}
            </button>
          </div>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            Cancel
          </Button>
          <Button
            onClick={() => onSubmit(form)}
            disabled={isSubmitting || !form.name.trim() || !form.target_domains.trim() || !form.cron_expression.trim()}
            className="bg-blue-600 hover:bg-blue-700"
          >
            {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Save Schedule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function SchedulesPage() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<ScheduledScan | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ScheduledScan | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["schedules"],
    queryFn: () => schedulesApi.list(),
  });

  const createMutation = useMutation({
    mutationFn: (payload: CreateScheduleRequest) => schedulesApi.create(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["schedules"] });
      setCreateOpen(false);
      toast.success("Schedule created");
    },
    onError: (err: Error) => toast.error(`Failed to create schedule: ${err.message}`),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CreateScheduleRequest> }) =>
      schedulesApi.update(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["schedules"] });
      setEditTarget(null);
      toast.success("Schedule updated");
    },
    onError: (err: Error) => toast.error(`Failed to update schedule: ${err.message}`),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => schedulesApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["schedules"] });
      setDeleteTarget(null);
      toast.success("Schedule deleted");
    },
    onError: (err: Error) => toast.error(`Failed to delete schedule: ${err.message}`),
  });

  const triggerMutation = useMutation({
    mutationFn: (id: string) => schedulesApi.trigger(id),
    onSuccess: (res) => {
      toast.success(`Scan started — job ID: ${res.scan_job_id.slice(0, 8)}…`);
    },
    onError: (err: Error) => toast.error(`Failed to trigger scan: ${err.message}`),
  });

  function handleCreate(form: ScheduleFormState) {
    const domains = form.target_domains
      .split(",")
      .map((d) => d.trim())
      .filter(Boolean);
    createMutation.mutate({
      name: form.name.trim(),
      target_domains: domains,
      company_name: form.company_name.trim() || undefined,
      cron_expression: form.cron_expression.trim(),
      is_active: form.is_active,
      scan_config: { intensity: form.intensity },
    });
  }

  function handleEdit(form: ScheduleFormState) {
    if (!editTarget) return;
    const domains = form.target_domains
      .split(",")
      .map((d) => d.trim())
      .filter(Boolean);
    updateMutation.mutate({
      id: editTarget.id,
      data: {
        name: form.name.trim(),
        target_domains: domains,
        company_name: form.company_name.trim() || undefined,
        cron_expression: form.cron_expression.trim(),
        is_active: form.is_active,
        scan_config: { intensity: form.intensity },
      },
    });
  }

  function handleToggle(sched: ScheduledScan) {
    updateMutation.mutate({
      id: sched.id,
      data: { is_active: !sched.is_active },
    });
  }

  const editFormInitial: ScheduleFormState = editTarget
    ? {
        name: editTarget.name,
        target_domains: editTarget.target_domains.join(", "),
        company_name: editTarget.company_name ?? "",
        cron_expression: editTarget.cron_expression,
        is_active: editTarget.is_active,
        intensity: String((editTarget.scan_config as Record<string, unknown>)?.intensity ?? "passive"),
      }
    : EMPTY_FORM;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scheduled Scans"
        description="Automate recurring scans using cron-based schedules."
      >
        <Button
          onClick={() => setCreateOpen(true)}
          className="bg-blue-600 hover:bg-blue-700"
        >
          <Plus className="mr-2 h-4 w-4" />
          New Schedule
        </Button>
      </PageHeader>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900">
        {isLoading ? (
          <div className="flex items-center justify-center py-16 text-zinc-500">
            <Loader2 className="mr-2 h-5 w-5 animate-spin" />
            Loading schedules…
          </div>
        ) : !data?.items?.length ? (
          <div className="flex flex-col items-center justify-center py-20 text-zinc-500">
            <Clock className="h-10 w-10 mb-3 text-zinc-600" />
            <p className="text-sm font-medium text-zinc-400">No scheduled scans yet</p>
            <p className="text-xs mt-1">Create a schedule to automate recurring scans.</p>
            <Button
              onClick={() => setCreateOpen(true)}
              variant="outline"
              className="mt-4 border-zinc-700 text-zinc-300 hover:bg-zinc-800"
            >
              <Plus className="mr-2 h-4 w-4" />
              Create First Schedule
            </Button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">Name</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">Domains</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">Cron</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">Next Run</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">Last Run</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">Status</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-zinc-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {data.items.map((sched) => (
                  <tr key={sched.id} className="hover:bg-zinc-800/40 transition-colors">
                    <td className="px-4 py-3 font-medium text-zinc-200">{sched.name}</td>
                    <td className="px-4 py-3 text-zinc-400 max-w-[180px] truncate">
                      {sched.target_domains.join(", ")}
                    </td>
                    <td className="px-4 py-3">
                      <code className="text-xs bg-zinc-800 text-zinc-300 px-1.5 py-0.5 rounded font-mono">
                        {sched.cron_expression}
                      </code>
                    </td>
                    <td className="px-4 py-3 text-zinc-400 text-xs">
                      <span className="flex items-center gap-1.5">
                        <Calendar className="h-3.5 w-3.5 text-zinc-500" />
                        {formatDate(sched.next_run)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-zinc-400 text-xs">
                      {formatDate(sched.last_run)}
                    </td>
                    <td className="px-4 py-3">
                      {sched.is_active ? (
                        <Badge className="bg-emerald-900/40 text-emerald-400 border-emerald-800">
                          <CheckCircle2 className="mr-1 h-3 w-3" />
                          Active
                        </Badge>
                      ) : (
                        <Badge className="bg-zinc-800 text-zinc-400 border-zinc-700">
                          <XCircle className="mr-1 h-3 w-3" />
                          Paused
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 w-7 p-0 text-zinc-400 hover:text-emerald-400 hover:bg-emerald-900/20"
                          title="Run now"
                          onClick={() => triggerMutation.mutate(sched.id)}
                          disabled={triggerMutation.isPending}
                        >
                          <Play className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 w-7 p-0 text-zinc-400 hover:text-blue-400 hover:bg-blue-900/20"
                          title={sched.is_active ? "Pause" : "Activate"}
                          onClick={() => handleToggle(sched)}
                          disabled={updateMutation.isPending}
                        >
                          {sched.is_active ? (
                            <ToggleRight className="h-3.5 w-3.5" />
                          ) : (
                            <ToggleLeft className="h-3.5 w-3.5" />
                          )}
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 w-7 p-0 text-zinc-400 hover:text-zinc-100 hover:bg-zinc-700"
                          title="Edit"
                          onClick={() => setEditTarget(sched)}
                        >
                          <Edit2 className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 w-7 p-0 text-zinc-400 hover:text-red-400 hover:bg-red-900/20"
                          title="Delete"
                          onClick={() => setDeleteTarget(sched)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create dialog */}
      <ScheduleDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        initial={EMPTY_FORM}
        onSubmit={handleCreate}
        isSubmitting={createMutation.isPending}
        title="New Scheduled Scan"
      />

      {/* Edit dialog */}
      <ScheduleDialog
        open={!!editTarget}
        onOpenChange={(v) => !v && setEditTarget(null)}
        initial={editFormInitial}
        onSubmit={handleEdit}
        isSubmitting={updateMutation.isPending}
        title="Edit Schedule"
      />

      {/* Delete confirmation */}
      <Dialog open={!!deleteTarget} onOpenChange={(v) => !v && setDeleteTarget(null)}>
        <DialogContent className="sm:max-w-sm bg-zinc-900 border-zinc-800 text-zinc-100">
          <DialogHeader>
            <DialogTitle>Delete Schedule</DialogTitle>
            <DialogDescription className="text-zinc-400">
              Are you sure you want to delete{" "}
              <span className="font-medium text-zinc-200">{deleteTarget?.name}</span>? This
              action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setDeleteTarget(null)}
              className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
