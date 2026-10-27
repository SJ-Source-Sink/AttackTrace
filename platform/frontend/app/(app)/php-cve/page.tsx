"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  ShieldAlert, Play, Square, Loader2, History, Trash2, ChevronRight, ChevronDown,
  AlertTriangle, CheckCircle2, HelpCircle, EyeOff, Info,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

type Status = "vulnerable" | "likely_vulnerable" | "unverified" | "version_hidden" | "patched" | "not_affected";

interface HostResult {
  label: string;
  ip: string;
  port: number;
  scheme: string;
  url: string;
  php_detected: boolean;
  version: string | null;
  version_source: string | null;
  server_header: string | null;
  powered_by: string | null;
  distro: string | null;
  sapi: string | null;
  phpinfo_url: string | null;
  upload_progress: string | null;
  memory_limit: string | null;
  signals: string[];
  assessment: { status: Status; branch: string | null; fixed_in: string | null; reason: string } | null;
}

interface Summary {
  scan_id: string;
  total_hosts: number;
  web_services: number;
  php_services: number;
  vulnerable: number;
  likely_vulnerable: number;
  unverified: number;
  version_hidden: number;
  patched: number;
  not_affected: number;
  phpinfo_exposed: number;
  errors: { target: string; error: string }[];
}

interface HistoryItem { id: string; target: string; started_at: string; summary: Partial<Summary> }
interface HistoryDetail extends HistoryItem { results: HostResult[] }

const STATUS_META: Record<Status, { label: string; cls: string; icon: React.ElementType }> = {
  vulnerable:        { label: "Vulnerable",          cls: "border-red-700 bg-red-950/40 text-red-300",       icon: AlertTriangle },
  likely_vulnerable: { label: "Likely vulnerable",   cls: "border-orange-700 bg-orange-950/40 text-orange-300", icon: AlertTriangle },
  unverified:        { label: "Backport unverified", cls: "border-yellow-700 bg-yellow-950/40 text-yellow-300", icon: HelpCircle },
  version_hidden:    { label: "Version hidden",      cls: "border-yellow-700 bg-yellow-950/40 text-yellow-300", icon: EyeOff },
  patched:           { label: "Patched",             cls: "border-green-700 bg-green-950/40 text-green-300",  icon: CheckCircle2 },
  not_affected:      { label: "Not affected",        cls: "border-zinc-700 bg-zinc-900 text-zinc-300",        icon: CheckCircle2 },
};
const RANK: Record<string, number> = { vulnerable: 0, likely_vulnerable: 1, unverified: 2, version_hidden: 3, patched: 4, not_affected: 5 };

function StatusBadge({ status }: { status: Status | undefined }) {
  if (!status) return <Badge variant="outline" className="text-zinc-500 border-zinc-700">No PHP detected</Badge>;
  const m = STATUS_META[status];
  const Icon = m.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] font-medium", m.cls)}>
      <Icon className="h-3 w-3" /> {m.label}
    </span>
  );
}

function ResultRow({ r }: { r: HostResult }) {
  const [open, setOpen] = useState(false);
  const status = r.assessment?.status;
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/50">
      <button
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        aria-label={`Toggle details for ${r.label}:${r.port}`}
        className="flex w-full items-center gap-3 px-3 py-2 text-left"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
        <span className="font-mono text-xs text-zinc-200 w-56 truncate">{r.label}:{r.port}</span>
        <span className="font-mono text-xs text-zinc-400 w-44 truncate">{r.version ? `PHP ${r.version}` : r.php_detected ? "PHP (version hidden)" : "—"}</span>
        <StatusBadge status={status} />
        {r.phpinfo_url && <Badge variant="outline" className="ml-auto text-[10px] border-orange-800 text-orange-400">phpinfo exposed</Badge>}
      </button>
      {open && (
        <div className="border-t border-zinc-800 px-4 py-3 space-y-2 text-xs text-zinc-400">
          {r.assessment && <p className="text-zinc-300">{r.assessment.reason}</p>}
          <dl className="grid grid-cols-[9rem_1fr] gap-y-1">
            {r.version_source && (<><dt className="text-zinc-500">Version source</dt><dd className="font-mono">{r.version_source}</dd></>)}
            {r.assessment?.fixed_in && (<><dt className="text-zinc-500">Fixed in</dt><dd className="font-mono">{r.assessment.fixed_in}</dd></>)}
            {r.server_header && (<><dt className="text-zinc-500">Server header</dt><dd className="font-mono break-all">{r.server_header}</dd></>)}
            {r.powered_by && (<><dt className="text-zinc-500">X-Powered-By</dt><dd className="font-mono">{r.powered_by}</dd></>)}
            {r.distro && (<><dt className="text-zinc-500">Distro hint</dt><dd className="font-mono">{r.distro}</dd></>)}
            {r.sapi && (<><dt className="text-zinc-500">SAPI</dt><dd className="font-mono">{r.sapi}</dd></>)}
            {r.upload_progress && (<><dt className="text-zinc-500">upload_progress</dt><dd className={cn("font-mono", r.upload_progress === "On" && "text-orange-400")}>{r.upload_progress}</dd></>)}
            {r.memory_limit && (<><dt className="text-zinc-500">memory_limit</dt><dd className="font-mono">{r.memory_limit}</dd></>)}
            {r.phpinfo_url && (<><dt className="text-zinc-500">phpinfo()</dt><dd className="font-mono break-all">{r.phpinfo_url}</dd></>)}
          </dl>
        </div>
      )}
    </div>
  );
}

function SummaryCards({ s }: { s: Partial<Summary> }) {
  const cards: [string, number | undefined, string][] = [
    ["Vulnerable", s.vulnerable, "text-red-400"],
    ["Likely vulnerable", s.likely_vulnerable, "text-orange-400"],
    ["Needs verification", (s.unverified ?? 0) + (s.version_hidden ?? 0), "text-yellow-400"],
    ["Patched", s.patched, "text-green-400"],
    ["Web services", s.web_services, "text-zinc-300"],
  ];
  return (
    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
      {cards.map(([label, n, cls]) => (
        <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900 p-3 text-center">
          <p className={cn("text-2xl font-bold", cls)}>{n ?? 0}</p>
          <p className="text-[10px] text-zinc-500 mt-0.5">{label}</p>
        </div>
      ))}
    </div>
  );
}

function HistoryTab({ onRestore }: { onRestore: (t: string) => void }) {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [detail, setDetail] = useState<HistoryDetail | null>(null);

  const load = useCallback(async () => {
    const r = await fetchWithAuth(`${API_BASE}/php-cve/history`);
    if (r.ok) setItems((await r.json()).items ?? []);
  }, []);
  useEffect(() => { load(); }, [load]);

  const open = async (id: string) => {
    const r = await fetchWithAuth(`${API_BASE}/php-cve/history/${id}`);
    if (r.ok) setDetail(await r.json());
  };
  const del = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const r = await fetchWithAuth(`${API_BASE}/php-cve/history/${id}`, { method: "DELETE" });
    if (r.ok) { setItems(p => p.filter(i => i.id !== id)); toast.success("Scan deleted"); }
  };

  if (detail) {
    const sorted = [...(detail.results ?? [])].sort((a, b) => (RANK[a.assessment?.status ?? ""] ?? 9) - (RANK[b.assessment?.status ?? ""] ?? 9));
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <button onClick={() => setDetail(null)} className="text-xs text-zinc-500 hover:text-zinc-300 flex items-center gap-1">
            <ChevronRight className="h-3 w-3 rotate-180" /> Back
          </button>
          <span className="font-mono text-xs text-blue-400 truncate">{detail.target}</span>
          <button onClick={() => { onRestore(detail.target); setDetail(null); }} className="ml-auto text-xs text-blue-400 hover:text-blue-300">
            Restore targets
          </button>
        </div>
        <SummaryCards s={detail.summary} />
        <div className="space-y-2">{sorted.map((r, i) => <ResultRow key={`${r.ip}:${r.port}:${i}`} r={r} />)}</div>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center py-16 text-zinc-500">
        <History className="h-10 w-10 text-zinc-700 mb-3" />
        <p className="text-sm font-medium">No scan history yet</p>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {items.map(i => (
        <div key={i.id} onClick={() => open(i.id)} role="button" tabIndex={0}
          onKeyDown={e => { if (e.key === "Enter") open(i.id); }}
          className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900/50 px-3 py-2 cursor-pointer hover:border-zinc-700">
          <span className="font-mono text-xs text-zinc-300 truncate flex-1">{i.target}</span>
          <span className="text-[11px] text-red-400">{(i.summary.vulnerable ?? 0) + (i.summary.likely_vulnerable ?? 0)} vulnerable</span>
          <span className="text-[11px] text-zinc-500">{i.started_at ? new Date(i.started_at).toLocaleString() : ""}</span>
          <button onClick={e => del(i.id, e)} aria-label="Delete scan" className="text-zinc-600 hover:text-red-400">
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}

export default function PhpCvePage() {
  const [tab, setTab] = useState<"scan" | "history">("scan");
  const [targets, setTargets] = useState("");
  const [ports, setPorts] = useState("80,443,8080,8443");
  const [probePhpinfo, setProbePhpinfo] = useState(true);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState({ checked: 0, total: 0 });
  const [results, setResults] = useState<HostResult[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [startErrors, setStartErrors] = useState<{ target: string; error: string }[]>([]);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    try { setTargets(localStorage.getItem("php_cve_targets") ?? ""); } catch { /* ignore */ }
  }, []);

  const start = async () => {
    const list = targets.split(/[\s,;]+/).filter(Boolean);
    if (list.length === 0) { toast.error("Enter at least one IP, CIDR or hostname"); return; }
    const portList = ports.split(/[\s,;]+/).map(Number).filter(n => Number.isInteger(n) && n > 0 && n < 65536);
    if (portList.length === 0) { toast.error("Enter at least one valid port"); return; }
    try { localStorage.setItem("php_cve_targets", targets); } catch { /* ignore */ }

    setRunning(true); setResults([]); setSummary(null); setStartErrors([]); setProgress({ checked: 0, total: 0 });
    abortRef.current = new AbortController();
    try {
      const res = await fetchWithAuth(`${API_BASE}/php-cve/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets: list, ports: portList, probe_phpinfo: probePhpinfo }),
        signal: abortRef.current.signal,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Scan failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail ?? err));
      }
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() ?? "";
        for (const part of parts) {
          const ev = part.match(/^event:\s*(\S+)/m)?.[1];
          const raw = part.match(/^data:\s*([\s\S]+)/m)?.[1];
          if (!ev || !raw) continue;
          let d: Record<string, unknown>;
          try { d = JSON.parse(raw); } catch { continue; }
          if (ev === "start") {
            setProgress({ checked: 0, total: (d.total as number) ?? 0 });
            setStartErrors((d.errors as { target: string; error: string }[]) ?? []);
          } else if (ev === "progress") {
            setProgress({ checked: d.checked as number, total: d.total as number });
          } else if (ev === "host_result") {
            setResults(p => [...p, d as unknown as HostResult]);
          } else if (ev === "complete") {
            const s = d as unknown as Summary;
            setSummary(s);
            const bad = s.vulnerable + s.likely_vulnerable;
            if (bad > 0) toast.error(`${bad} host${bad === 1 ? "" : "s"} vulnerable to PHP2Shell`);
            else toast.success("Scan complete — no vulnerable PHP versions found");
          }
        }
      }
    } catch (e) {
      if (e instanceof Error && e.name !== "AbortError") toast.error(`Scan failed: ${e.message}`);
    } finally {
      setRunning(false);
    }
  };

  const stop = () => { abortRef.current?.abort(); setRunning(false); toast.info("Scan stopped"); };
  const sorted = [...results].sort((a, b) => (RANK[a.assessment?.status ?? ""] ?? 9) - (RANK[b.assessment?.status ?? ""] ?? 9));
  const pct = progress.total > 0 ? Math.round((progress.checked / progress.total) * 100) : 0;
  const live: Partial<Summary> = summary ?? {
    vulnerable: results.filter(r => r.assessment?.status === "vulnerable").length,
    likely_vulnerable: results.filter(r => r.assessment?.status === "likely_vulnerable").length,
    unverified: results.filter(r => r.assessment?.status === "unverified").length,
    version_hidden: results.filter(r => r.assessment?.status === "version_hidden").length,
    patched: results.filter(r => r.assessment?.status === "patched").length,
    web_services: results.length,
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="PHP2Shell Scanner"
        description="CVE-2026-109618 / CVE-2026-109619 — unauthenticated PHP RCE (CVSS 9.2, CISA KEV)"
      />

      <div className="flex gap-1 border-b border-zinc-800">
        {([["scan", ShieldAlert, "Scanner"], ["history", History, "History"]] as const).map(([id, Icon, label]) => (
          <button key={id} onClick={() => setTab(id)}
            className={cn("flex items-center gap-1.5 px-4 py-2 text-sm border-b-2 -mb-px",
              tab === id ? "border-blue-500 text-blue-400" : "border-transparent text-zinc-500 hover:text-zinc-300")}>
            <Icon className="h-3.5 w-3.5" /> {label}
          </button>
        ))}
      </div>

      {tab === "history" ? (
        <HistoryTab onRestore={t => { setTargets(t.replace(/, /g, "\n")); setTab("scan"); }} />
      ) : (
        <>
          <Card className="border-amber-800/50 bg-amber-950/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-amber-300 flex items-center gap-2">
                <Info className="h-4 w-4" /> How this check works
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-zinc-400 space-y-1.5">
              <p>
                Fixed in PHP <span className="font-mono text-zinc-300">8.2.35 · 8.3.36 · 8.4.27 · 8.5.12</span>. 7.4/8.0/8.1 have only
                source backports; 5.4–7.3 have no fix. Every known trigger is a memory-corrupting multipart request, so this scanner
                sends <strong className="text-zinc-300">no exploit traffic</strong>: it reads the PHP version a host volunteers
                (X-Powered-By, Server, an exposed phpinfo()) and judges it against the fixed releases.
              </p>
              <p>
                Distro packages (Ubuntu, Debian, RHEL…) backport fixes without changing the version, so those show as
                <em> backport unverified</em>; hosts hiding their version show as <em>version hidden</em>. Neither means safe — check the
                package changelog on the host.
              </p>
            </CardContent>
          </Card>

          <div className="grid gap-4 md:grid-cols-[1fr_16rem]">
            <div className="space-y-2">
              <Label htmlFor="php-targets">Targets — IPs, CIDR ranges or hostnames (one per line or comma-separated)</Label>
              <textarea
                id="php-targets"
                value={targets}
                onChange={e => setTargets(e.target.value)}
                rows={6}
                placeholder={"203.0.113.10\n198.51.100.0/28\nwww.example.com"}
                className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-blue-600"
              />
            </div>
            <div className="space-y-3">
              <div className="space-y-2">
                <Label htmlFor="php-ports">Ports</Label>
                <Input id="php-ports" value={ports} onChange={e => setPorts(e.target.value)} className="font-mono text-xs" />
              </div>
              <label className="flex items-start gap-2 text-xs text-zinc-400">
                <input type="checkbox" checked={probePhpinfo} onChange={e => setProbePhpinfo(e.target.checked)} className="mt-0.5" />
                <span>Look for exposed phpinfo() pages (reveals exact version and config)</span>
              </label>
              {running ? (
                <Button variant="destructive" onClick={stop} className="w-full"><Square className="h-4 w-4 mr-2" />Stop</Button>
              ) : (
                <Button onClick={start} className="w-full"><Play className="h-4 w-4 mr-2" />Scan for PHP2Shell</Button>
              )}
            </div>
          </div>

          {startErrors.length > 0 && (
            <div className="rounded-lg border border-yellow-800/60 bg-yellow-950/10 p-3 text-xs space-y-1">
              <p className="font-medium text-yellow-300">Skipped targets</p>
              {startErrors.map((e, i) => (
                <p key={i} className="text-zinc-400"><span className="font-mono text-zinc-300">{e.target}</span> — {e.error}</p>
              ))}
            </div>
          )}

          {(running || results.length > 0 || summary) && (
            <div className="space-y-4">
              {running && (
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-xs text-zinc-400">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" /> Checked {progress.checked} of {progress.total} host:port pairs ({pct}%)
                  </div>
                  <div className="h-1.5 rounded bg-zinc-800 overflow-hidden"><div className="h-full bg-blue-500 transition-all" style={{ width: `${pct}%` }} /></div>
                </div>
              )}
              <SummaryCards s={live} />
              {summary && results.length === 0 && (
                <p className="text-sm text-zinc-500">No web service answered on the scanned ports.</p>
              )}
              <div className="space-y-2">{sorted.map((r, i) => <ResultRow key={`${r.ip}:${r.port}:${i}`} r={r} />)}</div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
