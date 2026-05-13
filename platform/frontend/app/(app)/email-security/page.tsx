"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Mail, Play, Square, CheckCircle2, XCircle, AlertTriangle,
  Shield, Loader2, Clock, History, Trash2, Info, Globe,
  ChevronDown, ChevronRight, ShieldAlert, Link2, Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ── Types ─────────────────────────────────────────────────────────────────────

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface Finding {
  phase: string;
  severity: Severity;
  title: string;
  detail: string;
}

interface PhaseResult {
  phase: string;
  detail: Record<string, unknown>;
  count: number;
  error?: string;
}

interface LookalikeDomain {
  domain: string;
  ips: string[];
  serves_http: boolean;
  severity: Severity;
  detail: string;
}

interface ScanComplete {
  scan_id: string;
  domain: string;
  score: number;
  total_findings: number;
  by_severity: Record<string, number>;
  by_phase: Record<string, number>;
  lookalikes_found: number;
}

interface HistoryItem {
  id: string;
  domain: string;
  started_at: string;
  completed_at: string;
  score: number;
  total_findings: number;
  by_severity: Record<string, number>;
  lookalikes_found: number;
}

interface HistoryDetail extends HistoryItem {
  findings: Finding[];
  lookalikes: LookalikeDomain[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SEV_STYLES: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/10 text-blue-400 border-blue-500/20",
  info:     "bg-zinc-700/30 text-zinc-400 border-zinc-700/50",
};

const SEV_BORDER: Record<string, string> = {
  critical: "border-red-600/40 bg-red-600/5",
  high:     "border-orange-500/40 bg-orange-500/5",
  medium:   "border-yellow-500/40 bg-yellow-500/5",
  low:      "border-blue-500/20 bg-blue-500/5",
  info:     "border-zinc-700/50 bg-zinc-900/20",
};

const PHASE_LABELS: Record<string, string> = {
  spf:        "SPF",
  dmarc:      "DMARC",
  dkim:       "DKIM",
  mx:         "MX / SMTP",
  lookalikes: "Lookalike Domains",
  breaches:   "Breach Check",
};

const PHASE_ICONS: Record<string, React.ReactNode> = {
  spf:        <Shield className="h-4 w-4 text-blue-400" />,
  dmarc:      <ShieldAlert className="h-4 w-4 text-purple-400" />,
  dkim:       <Eye className="h-4 w-4 text-teal-400" />,
  mx:         <Globe className="h-4 w-4 text-green-400" />,
  lookalikes: <Link2 className="h-4 w-4 text-orange-400" />,
  breaches:   <AlertTriangle className="h-4 w-4 text-red-400" />,
};

// ── Score ring ────────────────────────────────────────────────────────────────

function ScoreRing({ score }: { score: number }) {
  const color =
    score >= 80 ? "text-emerald-400" :
    score >= 60 ? "text-yellow-400" :
    score >= 40 ? "text-orange-400" : "text-red-400";

  const strokeColor =
    score >= 80 ? "#34d399" :
    score >= 60 ? "#facc15" :
    score >= 40 ? "#fb923c" : "#f87171";

  const r = 28;
  const circ = 2 * Math.PI * r;
  const dash = circ * (score / 100);

  return (
    <div className="relative flex items-center justify-center w-[72px] h-[72px]">
      <svg width="72" height="72" viewBox="0 0 72 72" className="-rotate-90 absolute inset-0">
        <circle cx="36" cy="36" r={r} fill="none" stroke="#27272a" strokeWidth="6" />
        <circle
          cx="36" cy="36" r={r}
          fill="none"
          stroke={strokeColor}
          strokeWidth="6"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          className="transition-all duration-700"
        />
      </svg>
      <div className="relative flex flex-col items-center">
        <span className={cn("text-xl font-bold tabular-nums leading-none", color)}>{score}</span>
        <span className="text-[9px] text-zinc-500">/100</span>
      </div>
    </div>
  );
}

// ── Finding row ───────────────────────────────────────────────────────────────

function FindingRow({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  const isPass = finding.severity === "info" && finding.title.toLowerCase().includes("properly");

  return (
    <div className={cn("rounded-md border transition-colors", SEV_BORDER[finding.severity] ?? SEV_BORDER.info)}>
      <button
        className="w-full flex items-center gap-2.5 px-3 py-2 text-left"
        onClick={() => setExpanded(v => !v)}
      >
        {finding.severity === "critical" || finding.severity === "high"
          ? <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
          : finding.severity === "medium" || finding.severity === "low"
            ? <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 shrink-0" />
            : isPass
              ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
              : <Info className="h-3.5 w-3.5 text-blue-400 shrink-0" />
        }
        <div className="flex-1 min-w-0 flex items-center gap-2">
          <span className="text-xs text-zinc-300 truncate">{finding.title}</span>
          <Badge className={cn("text-[10px] border h-4 py-0 capitalize shrink-0", SEV_STYLES[finding.severity])}>
            {finding.severity}
          </Badge>
        </div>
        {finding.detail && (
          expanded
            ? <ChevronDown className="h-3 w-3 text-zinc-600 shrink-0" />
            : <ChevronRight className="h-3 w-3 text-zinc-600 shrink-0" />
        )}
      </button>
      {expanded && finding.detail && (
        <div className="border-t border-zinc-800 px-3 pb-2.5 pt-2">
          <p className="text-[11px] text-zinc-400 leading-relaxed">{finding.detail}</p>
        </div>
      )}
    </div>
  );
}

// ── Phase section ─────────────────────────────────────────────────────────────

function PhaseSection({
  phase,
  findings,
  phaseResult,
  lookalikes,
}: {
  phase: string;
  findings: Finding[];
  phaseResult: PhaseResult | null;
  lookalikes?: LookalikeDomain[];
}) {
  const [collapsed, setCollapsed] = useState(false);
  const hasFindings = findings.length > 0;
  const worstSev = findings.reduce<string>((worst, f) => {
    const order = ["critical", "high", "medium", "low", "info"];
    return order.indexOf(f.severity) < order.indexOf(worst) ? f.severity : worst;
  }, "info");

  return (
    <Card className={cn(
      "transition-colors",
      worstSev === "critical" ? "border-red-600/30" :
      worstSev === "high"     ? "border-orange-500/30" :
      worstSev === "medium"   ? "border-yellow-500/20" : "border-zinc-800"
    )}>
      <CardHeader className="pb-2">
        <button
          className="flex items-center gap-2 w-full text-left"
          onClick={() => setCollapsed(v => !v)}
        >
          {PHASE_ICONS[phase] ?? <Shield className="h-4 w-4 text-zinc-500" />}
          <CardTitle className="text-sm font-semibold text-zinc-300 flex-1">
            {PHASE_LABELS[phase] ?? phase}
          </CardTitle>
          {hasFindings && (
            <Badge className={cn("text-[10px] border h-4 py-0 capitalize mr-2", SEV_STYLES[worstSev])}>
              {findings.length} finding{findings.length !== 1 ? "s" : ""}
            </Badge>
          )}
          {!hasFindings && phaseResult && !phaseResult.error && (
            <CheckCircle2 className="h-4 w-4 text-emerald-400 mr-2" />
          )}
          {collapsed
            ? <ChevronRight className="h-3.5 w-3.5 text-zinc-600" />
            : <ChevronDown className="h-3.5 w-3.5 text-zinc-600" />
          }
        </button>
      </CardHeader>

      {!collapsed && (
        <CardContent className="space-y-2 pt-0">
          {phaseResult?.error && (
            <p className="text-[10px] text-red-400 font-mono">{phaseResult.error}</p>
          )}

          {/* SPF / DMARC record details */}
          {(phase === "spf" || phase === "dmarc") && phaseResult?.detail && (
            <div className="rounded-md bg-zinc-950 border border-zinc-800 px-2.5 py-2">
              {(phaseResult.detail as Record<string, string>).record ? (
                <code className="text-[10px] font-mono text-zinc-400 break-all">
                  {(phaseResult.detail as Record<string, string>).record}
                </code>
              ) : (
                <p className="text-[10px] text-zinc-600 italic">No record found</p>
              )}
            </div>
          )}

          {/* DKIM selectors */}
          {phase === "dkim" && phaseResult?.detail && (
            (() => {
              const detail = phaseResult.detail as { selectors_found?: Array<{ selector: string; key_bits: number; severity: string }> };
              const sels = detail?.selectors_found ?? [];
              return sels.length > 0 ? (
                <div className="space-y-1">
                  {sels.map((s) => (
                    <div key={s.selector} className="flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-1.5">
                      <span className="font-mono text-xs text-zinc-400">{s.selector}._domainkey</span>
                      <span className="text-[10px] text-zinc-600">{s.key_bits > 0 ? `~${s.key_bits} bits` : "key found"}</span>
                      <Badge className={cn("text-[10px] border h-4 py-0 ml-auto", SEV_STYLES[s.severity] ?? SEV_STYLES.info)}>
                        {s.severity}
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : null;
            })()
          )}

          {/* MX records */}
          {phase === "mx" && phaseResult?.detail && (
            (() => {
              const detail = phaseResult.detail as { mx_records?: Array<{ preference: number; host: string; starttls: boolean; banner: string; ptr: string | null }> };
              const recs = detail?.mx_records ?? [];
              return recs.length > 0 ? (
                <div className="space-y-1">
                  {recs.map((mx) => (
                    <div key={mx.host} className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-zinc-600">{mx.preference}</span>
                        <span className="font-mono text-xs text-zinc-300">{mx.host}</span>
                        {mx.starttls
                          ? <Badge className="text-[10px] border h-4 py-0 bg-emerald-500/10 text-emerald-400 border-emerald-500/30 ml-auto">STARTTLS</Badge>
                          : <Badge className="text-[10px] border h-4 py-0 bg-yellow-500/10 text-yellow-400 border-yellow-500/30 ml-auto">No STARTTLS</Badge>
                        }
                      </div>
                      {mx.ptr && (
                        <p className="text-[10px] text-zinc-600 font-mono">PTR: {mx.ptr}</p>
                      )}
                      {mx.banner && mx.banner !== "(connection refused or timeout)" && (
                        <p className="text-[10px] text-zinc-600 font-mono truncate">{mx.banner}</p>
                      )}
                    </div>
                  ))}
                </div>
              ) : null;
            })()
          )}

          {/* Lookalike table */}
          {phase === "lookalikes" && lookalikes && lookalikes.length > 0 && (
            <div className="rounded-md border border-zinc-800 overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900/50">
                    <th className="text-left px-3 py-1.5 text-[10px] text-zinc-500 font-medium">Domain</th>
                    <th className="text-left px-3 py-1.5 text-[10px] text-zinc-500 font-medium">IPs</th>
                    <th className="text-left px-3 py-1.5 text-[10px] text-zinc-500 font-medium">HTTP</th>
                    <th className="text-left px-3 py-1.5 text-[10px] text-zinc-500 font-medium">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {lookalikes.map((lk, i) => (
                    <tr key={i} className="border-b border-zinc-800/50 last:border-0">
                      <td className="px-3 py-1.5 font-mono text-zinc-300">{lk.domain}</td>
                      <td className="px-3 py-1.5 text-zinc-500">{lk.ips.join(", ") || "—"}</td>
                      <td className="px-3 py-1.5">
                        {lk.serves_http
                          ? <span className="text-red-400">Yes</span>
                          : <span className="text-zinc-600">No</span>
                        }
                      </td>
                      <td className="px-3 py-1.5">
                        <Badge className={cn("text-[10px] border h-4 py-0 capitalize", SEV_STYLES[lk.severity])}>
                          {lk.severity}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Findings list */}
          {findings.map((f, i) => (
            <FindingRow key={i} finding={f} />
          ))}

          {findings.length === 0 && !phaseResult?.error && (
            <div className="flex items-center gap-2 text-emerald-400 py-1">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span className="text-xs">No issues found</span>
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}

// ── History Tab ───────────────────────────────────────────────────────────────

function HistoryTab({ onRestore }: { onRestore: (domain: string) => void }) {
  const [items, setItems]               = useState<HistoryItem[]>([]);
  const [loading, setLoading]           = useState(false);
  const [detail, setDetail]             = useState<HistoryDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [deleting, setDeleting]         = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetchWithAuth(`${API_BASE}/email-security/history`);
      if (r.ok) {
        const d = await r.json();
        setItems(d.items ?? []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const openDetail = async (id: string) => {
    setLoadingDetail(true);
    try {
      const r = await fetchWithAuth(`${API_BASE}/email-security/history/${id}`);
      if (r.ok) setDetail(await r.json());
    } finally {
      setLoadingDetail(false);
    }
  };

  const deleteScan = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeleting(id);
    try {
      const r = await fetchWithAuth(`${API_BASE}/email-security/history/${id}`, { method: "DELETE" });
      if (r.ok) {
        setItems(p => p.filter(s => s.id !== id));
        if (detail?.id === id) setDetail(null);
        toast.success("Scan deleted");
      }
    } finally {
      setDeleting(null);
    }
  };

  const scoreColor = (s: number) =>
    s >= 80 ? "text-emerald-400" : s >= 60 ? "text-yellow-400" : s >= 40 ? "text-orange-400" : "text-red-400";

  if (detail) {
    const phaseFindings = (detail.findings ?? []).reduce<Record<string, Finding[]>>((acc, f) => {
      (acc[f.phase] ??= []).push(f);
      return acc;
    }, {});

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setDetail(null)}
            className="text-xs text-zinc-500 hover:text-zinc-300 flex items-center gap-1"
          >
            <ChevronRight className="h-3 w-3 rotate-180" /> Back
          </button>
          <span className="font-mono text-xs text-blue-400">{detail.domain}</span>
          <button
            onClick={() => { onRestore(detail.domain); setDetail(null); }}
            className="ml-auto text-xs text-blue-400 hover:text-blue-300"
          >
            Restore domain
          </button>
        </div>
        <div className="flex items-center gap-4">
          <div className="shrink-0">
            <ScoreRing score={detail.score} />
          </div>
          <div className="flex gap-3 flex-wrap">
            {Object.entries(detail.by_severity ?? {}).filter(([, v]) => v > 0).map(([sev, count]) => (
              <div key={sev} className={cn("rounded border px-2.5 py-1.5", SEV_BORDER[sev] ?? "border-zinc-800")}>
                <span className={cn("text-sm font-bold", sev === "critical" ? "text-red-400" : sev === "high" ? "text-orange-400" : sev === "medium" ? "text-yellow-400" : sev === "low" ? "text-blue-400" : "text-zinc-400")}>{count}</span>
                <span className="text-[10px] text-zinc-500 ml-1 capitalize">{sev}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="space-y-3">
          {Object.entries(PHASE_LABELS).map(([phase]) => {
            const pf = phaseFindings[phase] ?? [];
            if (pf.length === 0 && phase !== "lookalikes") return null;
            const lookalikes = phase === "lookalikes" ? (detail.lookalikes ?? []) : undefined;
            return (
              <PhaseSection
                key={phase}
                phase={phase}
                findings={pf}
                phaseResult={null}
                lookalikes={lookalikes}
              />
            );
          })}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-zinc-500">{items.length} scan{items.length !== 1 ? "s" : ""} on record</p>
        <button onClick={load} className="text-[10px] text-zinc-500 hover:text-zinc-300 flex items-center gap-1">
          <Clock className="h-3 w-3" /> Refresh
        </button>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-6 w-6 animate-spin text-zinc-600" />
        </div>
      )}

      {!loading && items.length === 0 && (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-16 text-center">
          <History className="h-10 w-10 text-zinc-700 mb-3" />
          <p className="text-sm font-medium text-zinc-500">No scan history yet</p>
          <p className="text-xs text-zinc-600 mt-1">Completed scans will appear here automatically.</p>
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="space-y-2">
          {items.map(scan => (
            <div
              key={scan.id}
              onClick={() => openDetail(scan.id)}
              className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-4 cursor-pointer transition-colors hover:border-zinc-600"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0 space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs text-blue-400">{scan.domain}</span>
                    <span className={cn("text-sm font-bold tabular-nums", scoreColor(scan.score))}>{scan.score}</span>
                    <span className="text-[10px] text-zinc-600">/100</span>
                    {loadingDetail && <Loader2 className="h-3 w-3 animate-spin text-zinc-500" />}
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-zinc-500">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(scan.completed_at).toLocaleString()}
                    </span>
                    <span>{scan.total_findings} findings</span>
                    {scan.lookalikes_found > 0 && (
                      <span>{scan.lookalikes_found} lookalikes</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {(scan.by_severity?.critical ?? 0) > 0 && (
                      <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 rounded px-1.5 py-0.5">
                        {scan.by_severity.critical} critical
                      </span>
                    )}
                    {(scan.by_severity?.high ?? 0) > 0 && (
                      <span className="text-[10px] bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded px-1.5 py-0.5">
                        {scan.by_severity.high} high
                      </span>
                    )}
                    {(scan.by_severity?.medium ?? 0) > 0 && (
                      <span className="text-[10px] bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded px-1.5 py-0.5">
                        {scan.by_severity.medium} medium
                      </span>
                    )}
                    {scan.total_findings === 0 && (
                      <span className="text-[10px] text-emerald-400">No issues</span>
                    )}
                  </div>
                </div>
                <button
                  onClick={e => deleteScan(scan.id, e)}
                  disabled={deleting === scan.id}
                  className="shrink-0 text-zinc-600 hover:text-red-400 transition-colors p-1"
                >
                  {deleting === scan.id
                    ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    : <Trash2 className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function EmailSecurityPage() {
  const [tab, setTab] = useState<"scan" | "history">("scan");

  // Config
  const [domain, setDomain]               = useState(() => localStorage.getItem("email_security_domain") ?? "");
  const [checkLookalikes, setCheckLookalikes] = useState(() =>
    localStorage.getItem("email_security_lookalikes") !== "false"
  );
  const [maxLookalikes, setMaxLookalikes] = useState(50);

  // Scan state
  const [isScanning, setIsScanning]     = useState(false);
  const [scanStatus, setScanStatus]     = useState<"idle" | "running" | "done" | "failed">("idle");
  const [currentPhase, setCurrentPhase] = useState("");
  const [phaseMessage, setPhaseMessage] = useState("");
  const [findings, setFindings]         = useState<Finding[]>([]);
  const [phaseResults, setPhaseResults] = useState<Record<string, PhaseResult>>({});
  const [lookalikes, setLookalikes]     = useState<LookalikeDomain[]>([]);
  const [complete, setComplete]         = useState<ScanComplete | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  const startScan = useCallback(async () => {
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
    if (!d) { toast.error("Please enter a domain"); return; }

    localStorage.setItem("email_security_domain", d);
    localStorage.setItem("email_security_lookalikes", String(checkLookalikes));

    setIsScanning(true);
    setScanStatus("running");
    setCurrentPhase("");
    setPhaseMessage("");
    setFindings([]);
    setPhaseResults({});
    setLookalikes([]);
    setComplete(null);
    abortRef.current = new AbortController();

    try {
      const res = await fetchWithAuth(`${API_BASE}/email-security/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: d,
          check_lookalikes: checkLookalikes,
          max_lookalikes: maxLookalikes,
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Scan failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }

      const reader  = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          const eventMatch = part.match(/^event:\s*(\S+)/m);
          const dataMatch  = part.match(/^data:\s*([\s\S]+)/m);
          if (!dataMatch) continue;
          const event = eventMatch?.[1] ?? "unknown";
          let data: Record<string, unknown>;
          try { data = JSON.parse(dataMatch[1]); } catch { continue; }

          if (event === "start") {
            // scan started
          } else if (event === "phase") {
            setCurrentPhase(data.phase as string);
            setPhaseMessage(data.message as string ?? "");
          } else if (event === "finding") {
            setFindings(p => [...p, data as unknown as Finding]);
          } else if (event === "phase_result") {
            const pr = data as unknown as PhaseResult;
            setPhaseResults(p => ({ ...p, [pr.phase]: pr }));
          } else if (event === "lookalike_found") {
            setLookalikes(p => [...p, data as unknown as LookalikeDomain]);
          } else if (event === "complete") {
            const d2 = data as unknown as ScanComplete;
            setComplete(d2);
            setScanStatus("done");
            setIsScanning(false);
            const score = d2.score;
            const label = score >= 80 ? "Good" : score >= 60 ? "Fair" : score >= 40 ? "Poor" : "Critical";
            toast.success(`Analysis complete — Score: ${score}/100 (${label})`);
          } else if (event === "error") {
            setScanStatus("failed");
            setIsScanning(false);
            toast.error(`Scan error: ${data.message}`);
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") {
        setScanStatus("failed");
        toast.error(`Scan failed: ${err.message}`);
      }
      setIsScanning(false);
    }
  }, [domain, checkLookalikes, maxLookalikes]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  const findingsByPhase = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    (acc[f.phase] ??= []).push(f);
    return acc;
  }, {});

  const handleRestore = (d: string) => {
    setDomain(d);
    setTab("scan");
    toast.success(`Restored: ${d}`);
  };

  const scoreColor =
    !complete ? "text-zinc-400" :
    complete.score >= 80 ? "text-emerald-400" :
    complete.score >= 60 ? "text-yellow-400" :
    complete.score >= 40 ? "text-orange-400" : "text-red-400";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Email Security Scanner"
        description="SPF · DMARC · DKIM · MX/STARTTLS · Lookalike domain detection · Breach check"
      >
        {isScanning && (
          <Button variant="destructive" size="sm" onClick={stopScan} className="gap-1.5">
            <Square className="h-3.5 w-3.5" /> Stop
          </Button>
        )}
      </PageHeader>

      {/* Tab switcher */}
      <div className="flex gap-1 rounded-lg border border-zinc-800 bg-zinc-900/50 p-1 w-fit">
        {([["scan", Mail, "Scanner"], ["history", History, "History"]] as const).map(([id, Icon, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              tab === id ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {tab === "history" && <HistoryTab onRestore={handleRestore} />}

      {tab === "scan" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">

          {/* ── Config Panel ── */}
          <div className="space-y-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <Globe className="h-4 w-4 text-blue-400" /> Target Domain
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Domain</Label>
                  <Input
                    placeholder="example.com"
                    value={domain}
                    onChange={e => setDomain(e.target.value)}
                    disabled={isScanning}
                    onKeyDown={e => e.key === "Enter" && !isScanning && startScan()}
                    className="font-mono text-xs"
                  />
                  <p className="text-[10px] text-zinc-600">Enter domain only — no https://</p>
                </div>

                {/* Options */}
                <div className="space-y-2 pt-1">
                  <label className={cn(
                    "flex items-center gap-2.5 rounded-md border p-2.5 cursor-pointer transition-colors",
                    checkLookalikes ? "border-blue-500/30 bg-blue-500/5" : "border-zinc-800 bg-zinc-900/30"
                  )}>
                    <input
                      type="checkbox"
                      checked={checkLookalikes}
                      onChange={e => setCheckLookalikes(e.target.checked)}
                      disabled={isScanning}
                      className="h-3.5 w-3.5 accent-blue-500"
                    />
                    <div>
                      <p className="text-xs font-medium text-zinc-300">Lookalike Domain Detection</p>
                      <p className="text-[10px] text-zinc-600 mt-0.5">Typos, substitutions, prefix/suffix variations</p>
                    </div>
                  </label>

                  {checkLookalikes && (
                    <div className="space-y-1.5 pl-1">
                      <Label className="text-xs text-zinc-400">Max lookalikes to check</Label>
                      <input
                        type="range"
                        min={10}
                        max={200}
                        step={10}
                        value={maxLookalikes}
                        onChange={e => setMaxLookalikes(Number(e.target.value))}
                        disabled={isScanning}
                        className="w-full accent-blue-500"
                      />
                      <p className="text-[10px] text-zinc-600">{maxLookalikes} domains</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* What gets checked */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <Shield className="h-4 w-4 text-zinc-400" /> Checks Performed
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5">
                {Object.entries(PHASE_LABELS).map(([phase, label]) => (
                  <div key={phase} className="flex items-center gap-2">
                    {PHASE_ICONS[phase]}
                    <span className="text-xs text-zinc-400">{label}</span>
                    {phase === "lookalikes" && !checkLookalikes && (
                      <span className="text-[10px] text-zinc-600 ml-auto">disabled</span>
                    )}
                    {isScanning && currentPhase === phase && (
                      <Loader2 className="h-3 w-3 animate-spin text-blue-400 ml-auto" />
                    )}
                    {phaseResults[phase] && !isScanning && (
                      <CheckCircle2 className="h-3 w-3 text-emerald-400 ml-auto" />
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>

            <Button
              className="w-full gap-2"
              onClick={startScan}
              disabled={isScanning}
            >
              {isScanning
                ? <><Loader2 className="h-4 w-4 animate-spin" /> Analysing...</>
                : <><Play className="h-4 w-4" /> Analyze Email Security</>}
            </Button>
          </div>

          {/* ── Results Panel ── */}
          <div className="lg:col-span-2 space-y-4">

            {/* Score card */}
            {(isScanning || scanStatus === "done") && (
              <Card>
                <CardContent className="pt-5">
                  <div className="flex items-center gap-6">
                    {/* Score ring */}
                    <div className="shrink-0">
                      {complete
                        ? <ScoreRing score={complete.score} />
                        : (
                          <div className="flex flex-col items-center w-[72px] h-[72px] justify-center">
                            <Loader2 className="h-6 w-6 animate-spin text-zinc-600" />
                            <span className="text-[10px] text-zinc-600 mt-1">Scanning</span>
                          </div>
                        )
                      }
                    </div>

                    <div className="flex-1 space-y-2">
                      {complete ? (
                        <>
                          <div>
                            <span className={cn("text-2xl font-bold tabular-nums", scoreColor)}>{complete.score}</span>
                            <span className="text-zinc-600 text-sm"> / 100</span>
                            <span className="ml-2 text-sm text-zinc-400">
                              {complete.score >= 80 ? "Good" : complete.score >= 60 ? "Fair" : complete.score >= 40 ? "Poor" : "Critical"}
                            </span>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            {Object.entries(complete.by_severity).filter(([, v]) => v > 0).map(([sev, count]) => (
                              <span key={sev} className={cn("text-[10px] rounded border px-1.5 py-0.5", SEV_STYLES[sev])}>
                                {count} {sev}
                              </span>
                            ))}
                          </div>
                          {complete.lookalikes_found > 0 && (
                            <p className="text-[10px] text-orange-400">{complete.lookalikes_found} lookalike domain{complete.lookalikes_found !== 1 ? "s" : ""} found</p>
                          )}
                        </>
                      ) : (
                        <div className="space-y-1">
                          <p className="text-sm font-medium text-zinc-300">Analysing {domain}...</p>
                          {phaseMessage && (
                            <p className="text-[11px] text-zinc-500">{phaseMessage}</p>
                          )}
                          <div className="flex gap-1.5 flex-wrap mt-1">
                            {Object.keys(PHASE_LABELS).map(ph => (
                              <span key={ph} className={cn(
                                "text-[10px] rounded px-1.5 py-0.5 border",
                                phaseResults[ph]
                                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                                  : currentPhase === ph
                                    ? "border-blue-500/30 bg-blue-500/10 text-blue-400"
                                    : "border-zinc-800 text-zinc-600"
                              )}>
                                {PHASE_LABELS[ph]}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Phase sections */}
            {(isScanning || scanStatus === "done") && (
              <div className="space-y-3">
                {Object.keys(PHASE_LABELS).map(phase => {
                  const pf = findingsByPhase[phase] ?? [];
                  const pr = phaseResults[phase] ?? null;
                  const phaseLookalikes = phase === "lookalikes" ? lookalikes : undefined;

                  // Only show if we've reached this phase
                  if (!isScanning && !pr && pf.length === 0) return null;
                  const phaseOrder = Object.keys(PHASE_LABELS);
                  const phaseIdx = phaseOrder.indexOf(phase);
                  const currentIdx = phaseOrder.indexOf(currentPhase);
                  if (isScanning && phaseIdx > currentIdx) return null;

                  return (
                    <PhaseSection
                      key={phase}
                      phase={phase}
                      findings={pf}
                      phaseResult={pr}
                      lookalikes={phaseLookalikes}
                    />
                  );
                })}
              </div>
            )}

            {/* Empty state */}
            {scanStatus === "idle" && (
              <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-20 text-center">
                <Mail className="h-12 w-12 text-zinc-700 mb-3" />
                <p className="text-sm font-medium text-zinc-500">Enter a domain to analyse email security</p>
                <p className="text-xs text-zinc-600 mt-1">
                  SPF · DMARC · DKIM · MX/STARTTLS · Lookalikes · HIBP breaches
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
