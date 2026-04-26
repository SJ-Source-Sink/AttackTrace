"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Bell,
  Plus,
  Trash2,
  Loader2,
  CheckCircle2,
  XCircle,
  Send,
  Settings2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { notificationsApi } from "@/lib/api";
import type {
  NotificationChannel,
  NotificationChannelType,
  NotificationEvent,
  CreateChannelRequest,
} from "@/types";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

const EVENT_LABELS: Record<NotificationEvent, string> = {
  "scan.completed": "Scan Completed",
  "finding.critical": "Critical Finding",
  "sla.breached": "SLA Breach",
};

const ALL_EVENTS: NotificationEvent[] = ["scan.completed", "finding.critical", "sla.breached"];

interface ChannelTypeConfig {
  type: NotificationChannelType;
  label: string;
  description: string;
  icon: string;
  fields: {
    key: string;
    label: string;
    placeholder: string;
    hint?: string;
    type?: "password" | "text" | "url";
  }[];
}

const CHANNEL_TYPES: ChannelTypeConfig[] = [
  {
    type: "slack",
    label: "Slack",
    description: "Send notifications to a Slack channel via incoming webhook.",
    icon: "💬",
    fields: [
      {
        key: "webhook_url",
        label: "Webhook URL",
        placeholder: "https://hooks.slack.com/services/...",
        hint: "Create an incoming webhook in your Slack app settings.",
        type: "url",
      },
    ],
  },
  {
    type: "teams",
    label: "Microsoft Teams",
    description: "Send adaptive card notifications to a Teams channel.",
    icon: "🟦",
    fields: [
      {
        key: "webhook_url",
        label: "Webhook URL",
        placeholder: "https://outlook.office.com/webhook/...",
        hint: "Create an Incoming Webhook connector in your Teams channel.",
        type: "url",
      },
    ],
  },
  {
    type: "jira",
    label: "Jira",
    description: "Create Jira issues automatically for critical findings.",
    icon: "🔵",
    fields: [
      {
        key: "jira_url",
        label: "Jira URL",
        placeholder: "https://yourorg.atlassian.net",
        type: "url",
      },
      {
        key: "email",
        label: "Email",
        placeholder: "you@yourorg.com",
      },
      {
        key: "api_token",
        label: "API Token",
        placeholder: "ATATT3xFfGF0...",
        hint: "Generate from https://id.atlassian.com/manage-profile/security/api-tokens",
        type: "password",
      },
      {
        key: "project_key",
        label: "Project Key",
        placeholder: "SEC",
        hint: "The Jira project key where issues will be created.",
      },
    ],
  },
  {
    type: "webhook",
    label: "Generic Webhook",
    description: "POST a JSON payload to any HTTP endpoint.",
    icon: "🔗",
    fields: [
      {
        key: "url",
        label: "Endpoint URL",
        placeholder: "https://your-service.com/webhook",
        type: "url",
      },
    ],
  },
];

interface AddChannelDialogProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  typeConfig: ChannelTypeConfig;
  onSubmit: (data: CreateChannelRequest) => void;
  isSubmitting: boolean;
}

function AddChannelDialog({
  open,
  onOpenChange,
  typeConfig,
  onSubmit,
  isSubmitting,
}: AddChannelDialogProps) {
  const [name, setName] = useState("");
  const [config, setConfig] = useState<Record<string, string>>({});
  const [events, setEvents] = useState<NotificationEvent[]>(["scan.completed"]);

  React.useEffect(() => {
    if (open) {
      setName("");
      setConfig({});
      setEvents(["scan.completed"]);
    }
  }, [open]);

  function toggleEvent(ev: NotificationEvent) {
    setEvents((prev) =>
      prev.includes(ev) ? prev.filter((e) => e !== ev) : [...prev, ev],
    );
  }

  const isValid =
    name.trim() &&
    typeConfig.fields.every((f) => config[f.key]?.trim()) &&
    events.length > 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg bg-zinc-900 border-zinc-800 text-zinc-100">
        <DialogHeader>
          <DialogTitle>
            {typeConfig.icon} Add {typeConfig.label} Channel
          </DialogTitle>
          <DialogDescription className="text-zinc-400">
            {typeConfig.description}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label>Channel Name</Label>
            <Input
              placeholder={`My ${typeConfig.label} channel`}
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="bg-zinc-800 border-zinc-700"
            />
          </div>

          {typeConfig.fields.map((field) => (
            <div key={field.key} className="space-y-1.5">
              <Label>{field.label}</Label>
              <Input
                type={field.type === "password" ? "password" : "text"}
                placeholder={field.placeholder}
                value={config[field.key] ?? ""}
                onChange={(e) =>
                  setConfig((prev) => ({ ...prev, [field.key]: e.target.value }))
                }
                className="bg-zinc-800 border-zinc-700"
              />
              {field.hint && (
                <p className="text-xs text-zinc-500">{field.hint}</p>
              )}
            </div>
          ))}

          <div className="space-y-2">
            <Label>Subscribe to Events</Label>
            <div className="space-y-2">
              {ALL_EVENTS.map((ev) => (
                <div key={ev} className="flex items-center gap-2">
                  <Checkbox
                    id={`ev-${ev}`}
                    checked={events.includes(ev)}
                    onCheckedChange={() => toggleEvent(ev)}
                    className="border-zinc-600"
                  />
                  <label
                    htmlFor={`ev-${ev}`}
                    className="text-sm text-zinc-300 cursor-pointer select-none"
                  >
                    {EVENT_LABELS[ev]}
                  </label>
                </div>
              ))}
            </div>
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
            onClick={() =>
              onSubmit({
                name: name.trim(),
                channel_type: typeConfig.type,
                config,
                is_active: true,
                events,
              })
            }
            disabled={isSubmitting || !isValid}
            className="bg-blue-600 hover:bg-blue-700"
          >
            {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Add Channel
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ChannelCard({
  channel,
  onTest,
  onDelete,
  isTesting,
  isDeleting,
}: {
  channel: NotificationChannel;
  onTest: () => void;
  onDelete: () => void;
  isTesting: boolean;
  isDeleting: boolean;
}) {
  const typeConf = CHANNEL_TYPES.find((t) => t.type === channel.channel_type);

  return (
    <div className="flex items-start justify-between rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
      <div className="flex items-start gap-3">
        <div className="text-2xl mt-0.5">{typeConf?.icon ?? "🔔"}</div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-medium text-zinc-200">{channel.name}</span>
            {channel.is_active ? (
              <Badge className="bg-emerald-900/40 text-emerald-400 border-emerald-800 text-xs">
                <CheckCircle2 className="mr-1 h-3 w-3" />
                Active
              </Badge>
            ) : (
              <Badge className="bg-zinc-800 text-zinc-400 border-zinc-700 text-xs">
                <XCircle className="mr-1 h-3 w-3" />
                Inactive
              </Badge>
            )}
          </div>
          <p className="text-xs text-zinc-500 mt-0.5">
            {typeConf?.label ?? channel.channel_type}
          </p>
          <div className="flex flex-wrap gap-1 mt-2">
            {channel.events.map((ev) => (
              <Badge
                key={ev}
                variant="outline"
                className="text-xs border-zinc-700 text-zinc-400 py-0"
              >
                {EVENT_LABELS[ev] ?? ev}
              </Badge>
            ))}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-1.5 shrink-0">
        <Button
          size="sm"
          variant="ghost"
          className="h-8 px-2 text-zinc-400 hover:text-blue-400 hover:bg-blue-900/20 text-xs"
          onClick={onTest}
          disabled={isTesting}
        >
          {isTesting ? (
            <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
          ) : (
            <Send className="mr-1.5 h-3.5 w-3.5" />
          )}
          Test
        </Button>
        <Button
          size="sm"
          variant="ghost"
          className="h-8 w-8 p-0 text-zinc-400 hover:text-red-400 hover:bg-red-900/20"
          onClick={onDelete}
          disabled={isDeleting}
        >
          {isDeleting ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Trash2 className="h-3.5 w-3.5" />
          )}
        </Button>
      </div>
    </div>
  );
}

export default function NotificationsPage() {
  const qc = useQueryClient();
  const [addType, setAddType] = useState<ChannelTypeConfig | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["notification-channels"],
    queryFn: () => notificationsApi.listChannels(),
  });

  const createMutation = useMutation({
    mutationFn: (payload: CreateChannelRequest) =>
      notificationsApi.createChannel(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels"] });
      setAddType(null);
      toast.success("Notification channel added");
    },
    onError: (err: Error) => toast.error(`Failed to add channel: ${err.message}`),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => notificationsApi.deleteChannel(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels"] });
      setDeletingId(null);
      toast.success("Channel deleted");
    },
    onError: (err: Error) => toast.error(`Failed to delete channel: ${err.message}`),
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => notificationsApi.testChannel(id),
    onSuccess: (res, id) => {
      setTestingId(null);
      if (res.success) {
        toast.success(`Test sent: ${res.message}`);
      } else {
        toast.error(`Test failed: ${res.message}`);
      }
    },
    onError: (err: Error) => {
      setTestingId(null);
      toast.error(`Test error: ${err.message}`);
    },
  });

  function handleTest(id: string) {
    setTestingId(id);
    testMutation.mutate(id);
  }

  function handleDelete(id: string) {
    setDeletingId(id);
    deleteMutation.mutate(id);
  }

  const channels = data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Notification Channels"
        description="Route scan alerts and critical findings to Slack, Jira, Microsoft Teams, or custom webhooks."
      />

      {/* Channel type cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {CHANNEL_TYPES.map((typeConf) => {
          const existing = channels.filter((c) => c.channel_type === typeConf.type);
          return (
            <Card
              key={typeConf.type}
              className="bg-zinc-900 border-zinc-800 hover:border-zinc-700 transition-colors"
            >
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="text-2xl">{typeConf.icon}</div>
                  {existing.length > 0 && (
                    <Badge className="bg-blue-900/40 text-blue-400 border-blue-800 text-xs">
                      {existing.length} configured
                    </Badge>
                  )}
                </div>
                <CardTitle className="text-zinc-200 text-base mt-2">
                  {typeConf.label}
                </CardTitle>
                <CardDescription className="text-zinc-500 text-xs">
                  {typeConf.description}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full border-zinc-700 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100"
                  onClick={() => setAddType(typeConf)}
                >
                  <Plus className="mr-1.5 h-3.5 w-3.5" />
                  Add {typeConf.label}
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Existing channels list */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Settings2 className="h-4 w-4 text-zinc-500" />
          <h2 className="text-sm font-semibold text-zinc-300">
            Configured Channels
            {channels.length > 0 && (
              <span className="ml-2 text-xs text-zinc-500 font-normal">
                ({channels.length})
              </span>
            )}
          </h2>
        </div>

        {isLoading ? (
          <div className="flex items-center gap-2 py-8 text-zinc-500 justify-center">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading channels…
          </div>
        ) : channels.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900/40 py-12 text-zinc-500">
            <Bell className="h-8 w-8 mb-2 text-zinc-600" />
            <p className="text-sm text-zinc-400 font-medium">No channels configured</p>
            <p className="text-xs mt-1">
              Add a channel above to start receiving notifications.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {channels.map((ch) => (
              <ChannelCard
                key={ch.id}
                channel={ch}
                onTest={() => handleTest(ch.id)}
                onDelete={() => handleDelete(ch.id)}
                isTesting={testingId === ch.id && testMutation.isPending}
                isDeleting={deletingId === ch.id && deleteMutation.isPending}
              />
            ))}
          </div>
        )}
      </div>

      {/* Add channel dialog */}
      {addType && (
        <AddChannelDialog
          open={!!addType}
          onOpenChange={(v) => !v && setAddType(null)}
          typeConfig={addType}
          onSubmit={(data) => createMutation.mutate(data)}
          isSubmitting={createMutation.isPending}
        />
      )}
    </div>
  );
}
