"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Activity, Loader2, ChevronDown, ChevronRight, Trash2, CheckCircle2, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { getAccessToken } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

interface ActivityEvent {
  id: string;
  timestamp: string;
  label: string;
  provider: string;
  model: string | null;
  system: string | null;
  messages: unknown[];
  tools: unknown[] | null;
  status: "success" | "error";
  response: string | null;
  tool_calls: unknown[] | null;
  error: string | null;
  latency_ms: number;
}

type ConnectionStatus = "connecting" | "connected" | "reconnecting" | "closed";

const LABEL_NAMES: Record<string, string> = {
  triage_finding: "Finding Triage",
  nl_to_filter: "Natural Language Search",
  attack_suite_planner: "Attack Suite Planner",
  attack_suite_finding_analysis: "Attack Suite Finding Analysis",
  ai_scanner_grader: "AI/LLM Scanner Grader",
  burp_analyzer_ai: "Burp Analyzer AI",
  test_case_generator: "Test Case Generator",
  attack_suite_agent: "Attack Suite AI Agent",
};

export default function AIActivityPage() {
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setStatus((prev) => (prev === "connected" ? "reconnecting" : "connecting"));

    try {
      const token = getAccessToken();
      const res = await fetch(`${API_BASE}/ai/activity/stream`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        signal: controller.signal,
      });
      if (!res.ok || !res.body) throw new Error(`stream failed: ${res.status}`);

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      setStatus("connected");

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          const eventMatch = part.match(/^event: (\S+)/m);
          const dataMatch = part.match(/^data: ([\s\S]+)/m);
          if (!eventMatch || !dataMatch) continue;
          if (eventMatch[1] !== "activity") continue;
          try {
            const evt = JSON.parse(dataMatch[1]) as ActivityEvent;
            setEvents((prev) => [evt, ...prev].slice(0, 500));
          } catch {
            continue;
          }
        }
      }
    } catch (e) {
      if ((e as Error).name === "AbortError") return;
    }

    if (mountedRef.current) {
      setStatus("closed");
      window.setTimeout(() => {
        if (mountedRef.current) connect();
      }, 2000);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
    };
  }, [connect]);

  return (
    <div className="space-y-6 max-w-5xl">
      <PageHeader
        title="AI Activity"
        description="Live feed of every AI/LLM call made in this org — provider, request, response, latency."
      >
        <div className="flex items-center gap-3">
          <ConnectionBadge status={status} />
          <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5" onClick={() => setEvents([])}>
            <Trash2 className="h-3 w-3" /> Clear
          </Button>
        </div>
      </PageHeader>

      <div className="rounded-lg border border-violet-500/20 bg-violet-500/5 p-4">
        <p className="text-sm text-violet-300">
          <strong>Live only:</strong> nothing here is saved — this is a real-time window into activity, not an
          audit log. Navigating away or reloading clears the list. Full prompts and responses are shown, visible
          to anyone in your org.
        </p>
      </div>

      <div className="space-y-2">
        {events.length === 0 && (
          <Card className="border-zinc-800">
            <CardContent className="py-10 text-center text-sm text-zinc-500">
              <Activity className="mx-auto mb-2 h-6 w-6 text-zinc-600" />
              Waiting for AI activity — trigger a scan, Attack Suite run, or AI Agent to see it appear here live.
            </CardContent>
          </Card>
        )}
        {events.map((evt) => (
          <ActivityRow
            key={evt.id}
            event={evt}
            expanded={expandedId === evt.id}
            onToggle={() => setExpandedId((prev) => (prev === evt.id ? null : evt.id))}
          />
        ))}
      </div>
    </div>
  );
}

function ConnectionBadge({ status }: { status: ConnectionStatus }) {
  const cfg: Record<ConnectionStatus, { label: string; className: string }> = {
    connecting: { label: "Connecting...", className: "text-zinc-400" },
    connected: { label: "Live", className: "text-emerald-400" },
    reconnecting: { label: "Reconnecting...", className: "text-yellow-400" },
    closed: { label: "Disconnected", className: "text-red-400" },
  };
  const c = cfg[status];
  return (
    <span className={cn("flex items-center gap-1.5 text-xs font-medium", c.className)}>
      {(status === "connecting" || status === "reconnecting") && <Loader2 className="h-3 w-3 animate-spin" />}
      {status === "connected" && <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />}
      {c.label}
    </span>
  );
}

function ActivityRow({ event, expanded, onToggle }: { event: ActivityEvent; expanded: boolean; onToggle: () => void }) {
  const time = new Date(event.timestamp).toLocaleTimeString();
  return (
    <Card className={cn("border transition-colors", event.status === "error" ? "border-red-800/40" : "border-zinc-800")}>
      <button type="button" onClick={onToggle} className="flex w-full items-center gap-3 px-4 py-3 text-left">
        {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-zinc-500" />}
        <span className="text-xs text-zinc-500 tabular-nums shrink-0">{time}</span>
        <Badge variant="outline" className="shrink-0 text-[10px]">{LABEL_NAMES[event.label] ?? event.label}</Badge>
        <span className="shrink-0 text-xs text-zinc-400">{event.provider}{event.model ? ` · ${event.model}` : ""}</span>
        <span className="ml-auto flex shrink-0 items-center gap-3">
          {event.status === "success" ? (
            <span className="flex items-center gap-1 text-xs text-emerald-400"><CheckCircle2 className="h-3 w-3" /> {event.latency_ms}ms</span>
          ) : (
            <span className="flex items-center gap-1 text-xs text-red-400"><XCircle className="h-3 w-3" /> error</span>
          )}
        </span>
      </button>
      {expanded && (
        <CardContent className="space-y-3 border-t border-zinc-800 pt-3">
          {event.system && (
            <Field label="System prompt" value={event.system} />
          )}
          <Field label="Messages sent" value={JSON.stringify(event.messages, null, 2)} />
          {event.tools && event.tools.length > 0 && (
            <Field label={`Tools offered (${event.tools.length})`} value={JSON.stringify(event.tools, null, 2)} />
          )}
          {event.tool_calls && event.tool_calls.length > 0 && (
            <Field label="Tool calls made" value={JSON.stringify(event.tool_calls, null, 2)} />
          )}
          {event.status === "success" ? (
            <Field label="Response" value={event.response ?? "(no text response)"} />
          ) : (
            <Field label="Error" value={event.error ?? "unknown error"} />
          )}
        </CardContent>
      )}
    </Card>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <div className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</div>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-zinc-950 p-2.5 text-[11px] text-zinc-300">
        {value}
      </pre>
    </div>
  );
}
