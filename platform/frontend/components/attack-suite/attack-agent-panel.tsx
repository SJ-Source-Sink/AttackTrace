"use client";

import { useCallback, useRef, useState } from "react";
import { Bot, Play, Square, Loader2, ShieldAlert, CheckCircle2, XCircle, Database } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { fetchWithAuth, getAccessToken } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

type AgentEvent =
  | { kind: "context"; asset_count: number; finding_count: number }
  | { kind: "reasoning"; turn: number; text: string }
  | { kind: "tool_call"; turn: number; tool: string; input: Record<string, unknown>; result: Record<string, unknown> }
  | { kind: "error"; message: string }
  | { kind: "stopped" }
  | { kind: "budget_exhausted"; turns: number; elapsed_seconds: number }
  | { kind: "done"; turns: number }
  | { kind: "summary"; turns: number; findings_recorded: number; status: string; elapsed_seconds: number };

type RunStatus = "idle" | "running" | "completed" | "stopped" | "error" | "budget_exhausted" | "rejected";

export function AttackAgentPanel({ defaultTarget }: { defaultTarget?: string }) {
  const [target, setTarget] = useState(defaultTarget ?? "");
  const [objective, setObjective] = useState("");
  const [maxTurns, setMaxTurns] = useState(100);
  const [maxSeconds, setMaxSeconds] = useState(3600);
  const [runId, setRunId] = useState<string | null>(null);
  const [status, setStatus] = useState<RunStatus>("idle");
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [turnCount, setTurnCount] = useState(0);
  const [findingsRecorded, setFindingsRecorded] = useState(0);
  const abortRef = useRef<AbortController | null>(null);
  const transcriptEndRef = useRef<HTMLDivElement>(null);

  const isRunning = status === "running";

  const start = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Enter a target first — it must already be a known asset for your org.");
      return;
    }
    setEvents([]);
    setTurnCount(0);
    setFindingsRecorded(0);
    setRunId(null);
    setStatus("running");
    abortRef.current = new AbortController();

    try {
      const token = getAccessToken();
      const res = await fetch(`${API_BASE}/attack-suite/agent/run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          target: target.trim(),
          objective: objective.trim() || undefined,
          max_turns: maxTurns,
          max_seconds: maxSeconds,
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok || !res.body) {
        const err = await res.json().catch(() => ({ detail: "Agent run failed to start" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

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
          const eventName = eventMatch[1];
          let data: Record<string, unknown>;
          try { data = JSON.parse(dataMatch[1]); } catch { continue; }

          if (eventName === "start") {
            setRunId(data.run_id as string);
          } else if (eventName === "context") {
            setEvents((p) => [...p, { kind: "context", asset_count: data.asset_count as number, finding_count: data.finding_count as number }]);
          } else if (eventName === "reasoning") {
            setTurnCount(data.turn as number);
            setEvents((p) => [...p, { kind: "reasoning", turn: data.turn as number, text: data.text as string }]);
          } else if (eventName === "tool_call") {
            setTurnCount(data.turn as number);
            setEvents((p) => [...p, {
              kind: "tool_call", turn: data.turn as number, tool: data.tool as string,
              input: data.input as Record<string, unknown>, result: data.result as Record<string, unknown>,
            }]);
            const result = data.result as Record<string, unknown>;
            if (data.tool === "record_finding" && result?.recorded) {
              setFindingsRecorded((n) => n + 1);
              toast.success(`Agent recorded a finding (confidence: ${result.confidence})`);
            }
          } else if (eventName === "error") {
            setEvents((p) => [...p, { kind: "error", message: data.message as string }]);
            setStatus("error");
            toast.error(data.message as string);
          } else if (eventName === "stopped") {
            setEvents((p) => [...p, { kind: "stopped" }]);
            setStatus("stopped");
          } else if (eventName === "budget_exhausted") {
            setEvents((p) => [...p, { kind: "budget_exhausted", turns: data.turns as number, elapsed_seconds: data.elapsed_seconds as number }]);
            setStatus("budget_exhausted");
          } else if (eventName === "done") {
            setEvents((p) => [...p, { kind: "done", turns: data.turns as number }]);
          } else if (eventName === "summary") {
            setEvents((p) => [...p, {
              kind: "summary", turns: data.turns as number, findings_recorded: data.findings_recorded as number,
              status: data.status as string, elapsed_seconds: data.elapsed_seconds as number,
            }]);
            setStatus((data.status as RunStatus) ?? "completed");
          }
        }
        window.setTimeout(() => transcriptEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError") {
        toast.error(`Agent run failed: ${(e as Error).message}`);
        setStatus("error");
      }
    }
  }, [target, objective, maxTurns, maxSeconds]);

  const stop = useCallback(async () => {
    if (!runId) {
      abortRef.current?.abort();
      return;
    }
    try {
      await fetchWithAuth(`${API_BASE}/attack-suite/agent/${runId}/stop`, { method: "POST" });
      toast.info("Stop requested — the agent will halt after its current tool call.");
    } catch {
      toast.error("Failed to send stop signal");
    }
  }, [runId]);

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
      <Card className="lg:col-span-1">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Bot className="h-4 w-4 text-violet-400" /> AI Agent
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg border border-violet-500/30 bg-violet-950/20 p-3 text-xs text-violet-200">
            <ShieldAlert className="mb-1 h-3.5 w-3.5" />
            Runs fully autonomously, calling real tools with no per-action approval. The target must already
            be a known asset for your org — enforced in code before any tool runs — and every tool call is
            logged to the audit trail.
          </div>

          <div className="space-y-2">
            <Label>Target</Label>
            <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="e.g. example.com" disabled={isRunning} />
          </div>

          <div className="space-y-2">
            <Label>Objective (optional)</Label>
            <textarea
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              disabled={isRunning}
              placeholder="e.g. Focus on IDOR and SSRF against the API surface"
              className="w-full min-h-[70px] rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label className="text-xs">Max tool turns</Label>
              <Input type="number" min={1} max={2000} value={maxTurns} disabled={isRunning}
                onChange={(e) => setMaxTurns(Math.max(1, Math.min(2000, Number(e.target.value) || 1)))} />
            </div>
            <div className="space-y-2">
              <Label className="text-xs">Max seconds</Label>
              <Input type="number" min={30} max={604800} value={maxSeconds} disabled={isRunning}
                onChange={(e) => setMaxSeconds(Math.max(30, Math.min(604800, Number(e.target.value) || 30)))} />
            </div>
          </div>
          <p className="text-[10px] text-zinc-500 -mt-1">
            The server enforces its own ceiling based on your active AI provider — much higher for a
            self-hosted model (no per-call cost) than for the Claude API.
          </p>

          {!isRunning ? (
            <Button className="w-full gap-2" onClick={start}>
              <Play className="h-4 w-4" /> Run AI Agent
            </Button>
          ) : (
            <Button className="w-full gap-2" variant="destructive" onClick={stop}>
              <Square className="h-4 w-4" /> Stop
            </Button>
          )}

          {status !== "idle" && (
            <div className="flex items-center justify-between rounded-lg border border-zinc-700 bg-zinc-900/60 px-3 py-2 text-xs">
              <StatusBadge status={status} />
              <span className="text-zinc-400">Turn {turnCount} · {findingsRecorded} finding(s) recorded</span>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="text-base">Live transcript</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="max-h-[70vh] space-y-3 overflow-y-auto">
            {events.length === 0 && (
              <p className="py-8 text-center text-sm text-zinc-500">
                Run the agent to see its enumeration context, reasoning, and tool calls here.
              </p>
            )}
            {events.map((ev, i) => <TranscriptItem key={i} event={ev} />)}
            <div ref={transcriptEndRef} />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function StatusBadge({ status }: { status: RunStatus }) {
  const cfg: Record<RunStatus, { label: string; className: string }> = {
    idle: { label: "Idle", className: "text-zinc-400" },
    running: { label: "Running", className: "text-blue-400" },
    completed: { label: "Completed", className: "text-emerald-400" },
    stopped: { label: "Stopped", className: "text-orange-400" },
    error: { label: "Error", className: "text-red-400" },
    budget_exhausted: { label: "Budget exhausted", className: "text-yellow-400" },
    rejected: { label: "Rejected (out of scope)", className: "text-red-400" },
  };
  const c = cfg[status] ?? cfg.idle;
  return (
    <span className={cn("flex items-center gap-1.5 font-medium", c.className)}>
      {status === "running" && <Loader2 className="h-3 w-3 animate-spin" />}
      {c.label}
    </span>
  );
}

function TranscriptItem({ event }: { event: AgentEvent }) {
  if (event.kind === "context") {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900/60 px-3 py-2 text-xs text-zinc-300">
        <Database className="h-3.5 w-3.5 text-zinc-500" />
        Loaded enumeration context — {event.asset_count} asset(s), {event.finding_count} open finding(s)
      </div>
    );
  }
  if (event.kind === "reasoning") {
    return (
      <div className="rounded-lg border border-blue-500/20 bg-blue-950/10 px-3 py-2 text-xs text-blue-100">
        <div className="mb-1 text-[10px] uppercase tracking-wider text-blue-400">Turn {event.turn} — reasoning</div>
        <p className="whitespace-pre-wrap">{event.text}</p>
      </div>
    );
  }
  if (event.kind === "tool_call") {
    const isRejected = event.result?.error === "out_of_scope";
    const isFinding = event.tool === "record_finding" && Boolean(event.result?.recorded);
    return (
      <div className={cn(
        "rounded-lg border px-3 py-2 text-xs",
        isRejected ? "border-red-500/30 bg-red-950/10" : isFinding ? "border-emerald-500/30 bg-emerald-950/10" : "border-zinc-700 bg-zinc-900/60"
      )}>
        <div className="mb-1 flex items-center gap-2">
          <Badge variant="outline" className="text-[10px]">{event.tool}</Badge>
          {isRejected && <span className="flex items-center gap-1 text-red-400"><XCircle className="h-3 w-3" /> blocked — out of scope</span>}
          {isFinding && <span className="flex items-center gap-1 text-emerald-400"><CheckCircle2 className="h-3 w-3" /> finding recorded</span>}
        </div>
        <pre className="overflow-x-auto whitespace-pre-wrap break-all text-[11px] text-zinc-400">{JSON.stringify(event.input)}</pre>
        <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all text-[11px] text-zinc-300">{JSON.stringify(event.result).slice(0, 800)}</pre>
      </div>
    );
  }
  if (event.kind === "error") {
    return <div className="rounded-lg border border-red-500/30 bg-red-950/20 px-3 py-2 text-xs text-red-300">{event.message}</div>;
  }
  if (event.kind === "stopped") {
    return <div className="rounded-lg border border-orange-500/30 bg-orange-950/20 px-3 py-2 text-xs text-orange-300">Run stopped.</div>;
  }
  if (event.kind === "budget_exhausted") {
    return (
      <div className="rounded-lg border border-yellow-500/30 bg-yellow-950/20 px-3 py-2 text-xs text-yellow-300">
        Budget exhausted after {event.turns} turn(s), {event.elapsed_seconds}s.
      </div>
    );
  }
  if (event.kind === "done") {
    return <div className="rounded-lg border border-zinc-700 bg-zinc-900/60 px-3 py-2 text-xs text-zinc-400">Agent stopped calling tools after {event.turns} turn(s).</div>;
  }
  if (event.kind === "summary") {
    return (
      <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/10 px-3 py-2 text-xs text-emerald-300">
        Run {event.status} — {event.turns} turn(s), {event.findings_recorded} finding(s) recorded, {event.elapsed_seconds}s elapsed.
      </div>
    );
  }
  return null;
}
