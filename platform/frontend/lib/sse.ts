"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import type { ScanStatus } from "@/types";
import { fetchWithAuth } from "@/lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// Total registered modules (mirrors scan_worker._register_modules)
const TOTAL_MODULES = 10;

export interface ModuleStatusEntry {
  name: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  findings_count: number;
  assets_count: number;
  items_discovered: number;
}

export interface RecentFinding {
  title: string;
  severity: string;
  category: string;
  affected_asset: string;
}

interface ScanStreamState {
  moduleStatuses: Record<string, ModuleStatusEntry>;
  recentFindings: RecentFinding[];
  progress: number;
  isConnected: boolean;
  scanStatus: ScanStatus | null;
  latestPhase: string | null;
  error: string | null;
}

export function useScanStream(scanId: string | null): ScanStreamState & { disconnect: () => void } {
  const [state, setState] = useState<ScanStreamState>({
    moduleStatuses: {},
    recentFindings: [],
    progress: 0,
    isConnected: false,
    scanStatus: null,
    latestPhase: null,
    error: null,
  });

  // reconnectKey increments to force the effect to re-run and open a new EventSource
  const [reconnectKey, setReconnectKey] = useState(0);

  const eventSourceRef = useRef<EventSource | null>(null);
  const completedModulesRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Track whether this is a reconnect for the same scanId so we preserve progress state
  const prevScanIdRef = useRef<string | null>(null);
  // Snapshot of last good state — preserved across reconnects so the UI doesn't flash zero
  const lastGoodStateRef = useRef<Partial<ScanStreamState>>({});
  // Exponential backoff state: attempt count resets when scan changes or on successful connect
  const reconnectAttemptRef = useRef(0);
  // Deduplicate replayed events: track highest event_id seen to skip already-applied events
  const lastSeenEventIdRef = useRef<number | null>(null);

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    reconnectAttemptRef.current = 0;
    setState((prev) => ({ ...prev, isConnected: false }));
  }, []);

  useEffect(() => {
    if (!scanId) {
      disconnect();
      return;
    }

    const isSameScan = prevScanIdRef.current === scanId;
    prevScanIdRef.current = scanId;

    if (!isSameScan) {
      // Switching to a different scan — clear everything
      completedModulesRef.current = 0;
      lastGoodStateRef.current = {};
      reconnectAttemptRef.current = 0;
      lastSeenEventIdRef.current = null;
    } else {
      // Reconnecting to the same scan — seed state from last known snapshot so
      // the UI doesn't flash back to zero while replayed events stream in.
      setState((prev) => ({
        ...prev,
        ...lastGoodStateRef.current,
        isConnected: false,
      }));
    }

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    // EventSource can't send headers, so the URL carries a token. Use a short-lived (60s),
    // scan-bound one, never the real access token (URLs end up in logs and Referer headers).
    let cancelled = false;
    let eventSource: EventSource | null = null;

    const connect = async () => {
    let streamToken = "";
    try {
      const res = await fetchWithAuth(`${API_BASE}/scans/${scanId}/stream-token`, { method: "POST" });
      if (res.ok) streamToken = (await res.json()).token ?? "";
    } catch {
      // fall through: the stream will 401 and the normal backoff/retry path handles it
    }
    if (cancelled) return;
    const url = `${API_BASE}/scans/${scanId}/stream${streamToken ? `?token=${encodeURIComponent(streamToken)}` : ""}`;

    const es = new EventSource(url);
    eventSource = es;
    eventSourceRef.current = es;

    es.onopen = () => {
      // Successful connection — reset backoff
      reconnectAttemptRef.current = 0;
      setState((prev) => ({ ...prev, isConnected: true, error: null }));
    };

    es.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as {
          event_type: string;
          event_id?: number;
          scan_id: string;
          timestamp: string;
          data: Record<string, unknown>;
        };

        const { event_type, event_id, data } = msg;

        // Deduplicate: the backend sends id: fields and replays events on reconnect.
        // Skip events we've already applied to avoid double-counting module completions
        // or duplicate findings when the EventSource reconnects without Last-Event-ID.
        if (event_id !== undefined) {
          if (lastSeenEventIdRef.current !== null && event_id <= lastSeenEventIdRef.current) {
            return; // already applied
          }
          lastSeenEventIdRef.current = event_id;
        }

        setState((prev) => {
          const newModuleStatuses = { ...prev.moduleStatuses };
          let newFindings = [...prev.recentFindings];
          let newProgress = prev.progress;
          let newScanStatus = prev.scanStatus;
          let newPhase = prev.latestPhase;

          switch (event_type) {
            case "connected":
              break;

            case "status_change": {
              const newStatus = data.status as string;
              if (newStatus === "running") newScanStatus = "running";
              else if (newStatus === "completed") { newScanStatus = "completed"; newProgress = 100; }
              else if (newStatus === "failed") newScanStatus = "failed";
              else if (newStatus === "cancelled") newScanStatus = "cancelled";
              break;
            }

            case "module_start": {
              const mod = data.module as string;
              if (mod) {
                newPhase = mod;
                newModuleStatuses[mod] = {
                  name: mod,
                  status: "running",
                  findings_count: newModuleStatuses[mod]?.findings_count ?? 0,
                  assets_count: newModuleStatuses[mod]?.assets_count ?? 0,
                  items_discovered: 0,
                };
              }
              break;
            }

            case "module_complete": {
              const mod = data.module as string;
              const succeeded = data.success as boolean;
              const discovered = (data.items_discovered as number) ?? 0;
              if (mod) {
                newModuleStatuses[mod] = {
                  name: mod,
                  status: succeeded ? "completed" : "failed",
                  findings_count: newModuleStatuses[mod]?.findings_count ?? 0,
                  assets_count: newModuleStatuses[mod]?.assets_count ?? 0,
                  items_discovered: discovered,
                };
                completedModulesRef.current += 1;
                newProgress = Math.min(95, Math.round((completedModulesRef.current / TOTAL_MODULES) * 95));
              }
              break;
            }

            case "finding": {
              const finding: RecentFinding = {
                title: (data.title as string) ?? "Unknown",
                severity: (data.severity as string) ?? "info",
                category: (data.category as string) ?? "",
                affected_asset: (data.affected_asset as string) ?? "",
              };
              const runningMod = Object.entries(newModuleStatuses).find(
                ([, v]) => v.status === "running"
              )?.[0];
              if (runningMod) {
                newModuleStatuses[runningMod] = {
                  ...newModuleStatuses[runningMod],
                  findings_count: (newModuleStatuses[runningMod].findings_count ?? 0) + 1,
                };
              }
              newFindings = [finding, ...newFindings.slice(0, 49)];
              break;
            }

            case "complete":
              newScanStatus = "completed";
              newProgress = 100;
              eventSourceRef.current?.close();
              break;

            case "error":
              newScanStatus = "failed";
              eventSourceRef.current?.close();
              break;
          }

          const next = {
            ...prev,
            moduleStatuses: newModuleStatuses,
            recentFindings: newFindings,
            progress: newProgress,
            scanStatus: newScanStatus,
            latestPhase: newPhase,
          };
          // Keep a snapshot so reconnects don't flash back to zero
          lastGoodStateRef.current = {
            moduleStatuses: newModuleStatuses,
            progress: newProgress,
            scanStatus: newScanStatus,
            latestPhase: newPhase,
            // don't snapshot recentFindings — they'll be replayed from backend
          };
          return next;
        });

        if (event_type === "complete" || event_type === "error") {
          setState((prev) => ({ ...prev, isConnected: false }));
        }
      } catch {
        // ignore parse errors
      }
    };

    es.onerror = () => {
      setState((prev) => ({
        ...prev,
        isConnected: false,
        error: "Connection lost. Retrying...",
      }));
      es.close();
      if (eventSourceRef.current === es) {
        eventSourceRef.current = null;
      }
      // Exponential backoff: 3s → 6s → 12s → 24s → max 30s
      const attempt = reconnectAttemptRef.current;
      reconnectAttemptRef.current = attempt + 1;
      const delay = Math.min(3000 * Math.pow(2, attempt), 30_000);
      reconnectTimerRef.current = setTimeout(() => {
        reconnectTimerRef.current = null;
        setReconnectKey((k) => k + 1);
      }, delay);
    };
    };
    void connect();

    return () => {
      cancelled = true;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      eventSource?.close();
      if (eventSourceRef.current === eventSource) {
        eventSourceRef.current = null;
      }
    };
  }, [scanId, reconnectKey, disconnect]);

  return { ...state, disconnect };
}
