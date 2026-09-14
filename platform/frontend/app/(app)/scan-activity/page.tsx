"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Radar, Loader2, ChevronDown, ChevronRight, Trash2, CheckCircle2, XCircle, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { getAccessToken } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// Mirrors app/services/report_service.py's _SOURCE_LABELS / finding-detail.tsx's
// SOURCE_LABELS — keep in sync when a new scanner is added on the backend.
const SCANNER_LABELS: Record<string, string> = {
  nmap: "Nmap Port Scanner",
  nuclei: "Nuclei Template Scanner",
  ffuf: "FFUF Fuzzer",
  secrets: "Secret Scanner",
  js_scanner: "JavaScript Analysis Scanner",
  takeover: "Subdomain Takeover Scanner",
  attack_suite: "Attack Suite Scanner",
  attack_suite_agent: "Attack Suite AI Agent",
  attackmapper: "Attack Path Mapper",
  cspm: "Cloud Security Posture Management",
  container_scanner: "Container/Kubernetes Scanner",
  email_security: "Email Security Scanner",
  exposure_scanner: "Exposure Scanner",
  mcp_scanner: "MCP Scanner",
  supply_chain: "Supply Chain Scanner",
  api_scanner: "API Security Scanner",
  ai_scanner: "AI/LLM Red-Team Scanner",
  iac_scanner: "IaC Scanner",
  cloud: "Cloud Discovery Scanner",
  firewall_waf_bypass: "Firewall — WAF Bypass",
  firewall_port_map: "Firewall — Port Mapper",
  firewall_rules_analyze: "Firewall — Rule Analyzer",
  firewall_rate_limit: "Firewall — Rate-Limit Probe",
  firewall_smuggling: "Firewall — Request Smuggling",
};

interface RawScanEvent {
  type: "scan_started" | "scan_event" | "scan_finished";
  scanner: string;
  target: string;
  scan_id: string;
  event?: string;
  data?: Record<string, unknown>;
  timestamp: string;
  elapsed_seconds?: number;
  error?: string | null;
}

interface ScanRun {
  scan_id: string;
  scanner: string;
  target: string;
  startedAt: string;
  lastActivityAt: string;
  status: "running" | "completed" | "error";
  elapsedSeconds?: number;
  error?: string | null;
  events: RawScanEvent[];
}

type ConnectionStatus = "connecting" | "connected" | "reconnecting" | "closed";

const MAX_EVENTS_PER_RUN = 300;
const MAX_RUNS = 200;

export default function ScanActivityPage() {
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);

  const applyEvent = useCallback((evt: RawScanEvent) => {
    setRuns((prev) => {
      const idx = prev.findIndex((r) => r.scan_id === evt.scan_id);
      if (evt.type === "scan_started") {
        const newRun: ScanRun = {
          scan_id: evt.scan_id, scanner: evt.scanner, target: evt.target,
          startedAt: evt.timestamp, lastActivityAt: evt.timestamp, status: "running", events: [],
        };
        if (idx >= 0) {
          const copy = [...prev];
          copy[idx] = newRun;
          return copy;
        }
        return [newRun, ...prev].slice(0, MAX_RUNS);
      }

      if (idx < 0) return prev; // scan_event/scan_finished for a run we never saw start — drop it

      const run = prev[idx];
      const updated: ScanRun = evt.type === "scan_finished"
        ? { ...run, status: evt.error ? "error" : "completed", elapsedSeconds: evt.elapsed_seconds, error: evt.error, lastActivityAt: evt.timestamp }
        : { ...run, events: [evt, ...run.events].slice(0, MAX_EVENTS_PER_RUN), lastActivityAt: evt.timestamp };

      const withoutOld = prev.filter((_, i) => i !== idx);
      return [updated, ...withoutOld].slice(0, MAX_RUNS);
    });
  }, []);

  const connect = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setStatus((prev) => (prev === "connected" ? "reconnecting" : "connecting"));

    try {
      const token = getAccessToken();
      const res = await fetch(`${API_BASE}/activity/scans/stream`, {
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
            applyEvent(JSON.parse(dataMatch[1]) as RawScanEvent);
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
  }, [applyEvent]);

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
        title="Scan Activity"
        description="Live feed of every scanner run in this org — which tool, against what target, every request and response as it happens."
      >
        <div className="flex items-center gap-3">
          <ConnectionBadge status={status} />
          <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5" onClick={() => setRuns([])}>
            <Trash2 className="h-3 w-3" /> Clear
          </Button>
        </div>
      </PageHeader>

      <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
        <p className="text-sm text-blue-300">
          <strong>Live only:</strong> nothing here is saved — this is a real-time window into what&rsquo;s
          running, not an audit log. Navigating away or reloading clears the list. Each run groups its
          individual requests/probes together — expand a run to see the detail.
        </p>
      </div>

      <div className="space-y-2">
        {runs.length === 0 && (
          <Card className="border-zinc-800">
            <CardContent className="py-10 text-center text-sm text-zinc-500">
              <Radar className="mx-auto mb-2 h-6 w-6 text-zinc-600" />
              Waiting for scanner activity — trigger any scan to see it appear here live.
            </CardContent>
          </Card>
        )}
        {runs.map((run) => (
          <ScanRunRow
            key={run.scan_id}
            run={run}
            expanded={expandedId === run.scan_id}
            onToggle={() => setExpandedId((prev) => (prev === run.scan_id ? null : run.scan_id))}
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

function ScanRunRow({ run, expanded, onToggle }: { run: ScanRun; expanded: boolean; onToggle: () => void }) {
  const time = new Date(run.startedAt).toLocaleTimeString();
  return (
    <Card className={cn("border transition-colors", run.status === "error" ? "border-red-800/40" : "border-zinc-800")}>
      <button type="button" onClick={onToggle} className="flex w-full items-center gap-3 px-4 py-3 text-left">
        {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-zinc-500" />}
        <span className="text-xs text-zinc-500 tabular-nums shrink-0">{time}</span>
        <Badge variant="outline" className="shrink-0 text-[10px]">{SCANNER_LABELS[run.scanner] ?? run.scanner}</Badge>
        <span className="truncate text-xs text-zinc-400 font-mono">{run.target}</span>
        <span className="ml-auto flex shrink-0 items-center gap-3">
          <span className="text-[10px] text-zinc-500">{run.events.length} event{run.events.length === 1 ? "" : "s"}</span>
          {run.status === "running" && (
            <span className="flex items-center gap-1 text-xs text-blue-400"><Loader2 className="h-3 w-3 animate-spin" /> running</span>
          )}
          {run.status === "completed" && (
            <span className="flex items-center gap-1 text-xs text-emerald-400">
              <CheckCircle2 className="h-3 w-3" /> {run.elapsedSeconds != null ? `${run.elapsedSeconds}s` : "done"}
            </span>
          )}
          {run.status === "error" && (
            <span className="flex items-center gap-1 text-xs text-red-400"><XCircle className="h-3 w-3" /> error</span>
          )}
        </span>
      </button>
      {expanded && (
        <CardContent className="space-y-2 border-t border-zinc-800 pt-3">
          {run.error && <Field label="Error" value={run.error} />}
          {run.events.length === 0 && (
            <p className="flex items-center gap-1.5 text-xs text-zinc-500">
              <Clock className="h-3 w-3" /> No individual events yet.
            </p>
          )}
          {run.events.map((evt, i) => (
            <div key={i} className="rounded-md bg-zinc-950 border border-zinc-800 p-2.5">
              <div className="mb-1 flex items-center gap-2">
                <Badge variant="outline" className="text-[9px]">{evt.event}</Badge>
                <span className="text-[10px] text-zinc-600">{new Date(evt.timestamp).toLocaleTimeString()}</span>
              </div>
              <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words text-[11px] text-zinc-300">
                {JSON.stringify(evt.data, null, 2)}
              </pre>
            </div>
          ))}
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
