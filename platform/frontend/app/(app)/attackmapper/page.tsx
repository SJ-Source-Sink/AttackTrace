"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Map,
  Play,
  Square,
  ChevronDown,
  ChevronUp,
  Clock,
  AlertTriangle,
  CheckCircle2,
  History,
  Shield,
  Zap,
  Link2,
  Terminal,
  BookOpen,
  AlertCircle,
  Layers,
  Target,
  Bug,
  RefreshCw,
  Database,
  Globe,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth, refreshAccessToken, getAccessToken } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const INFRA_OPTIONS = [
  {
    value: "ad",
    label: "Active Directory",
    desc: "Domain controllers, Kerberos, LDAP, GPOs",
    icon: "🏢",
  },
  {
    value: "aws",
    label: "Amazon Web Services",
    desc: "IAM, S3, EC2, Lambda, CloudTrail",
    icon: "☁️",
  },
  {
    value: "azure",
    label: "Microsoft Azure",
    desc: "Entra ID, Storage, Functions, RBAC",
    icon: "🔷",
  },
  {
    value: "gcp",
    label: "Google Cloud Platform",
    desc: "IAM, GCS, Compute Engine, Cloud Run",
    icon: "🌐",
  },
  {
    value: "network",
    label: "Network Infrastructure",
    desc: "Routers, firewalls, switches, protocols",
    icon: "🔗",
  },
];

const RISK_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  info: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
};

const PHASE_COLORS: Record<string, string> = {
  reconnaissance: "bg-purple-500/10 text-purple-400",
  "initial-access": "bg-red-500/10 text-red-400",
  execution: "bg-orange-500/10 text-orange-400",
  persistence: "bg-yellow-500/10 text-yellow-400",
  "privilege-escalation": "bg-pink-500/10 text-pink-400",
  "defense-evasion": "bg-indigo-500/10 text-indigo-400",
  "credential-access": "bg-cyan-500/10 text-cyan-400",
  discovery: "bg-teal-500/10 text-teal-400",
  "lateral-movement": "bg-blue-500/10 text-blue-400",
  collection: "bg-emerald-500/10 text-emerald-400",
  exfiltration: "bg-rose-500/10 text-rose-400",
  impact: "bg-red-500/10 text-red-400",
};

interface Technique {
  id: string;
  mitre_id: string;
  name: string;
  phase: string;
  infrastructure: string;
  description: string;
  prerequisites: string[];
  tools: string[];
  commands: string[];
  detection: string;
  references: string[];
  next_techniques: string[];
  risk_level: string;
}

interface ChainStep {
  step_number: number;
  technique: Technique;
}

interface AttackChain {
  id: string;
  name: string;
  infrastructure: string;
  start_phase: string;
  end_phase: string;
  steps: ChainStep[];
}

interface CVE {
  cve_id: string;
  description: string;
  cvss_score: number;
  severity: string;
  affected_products: string[];
  exploitation_status: string;
  references: string[];
  published_date: string;
}

interface ThreatIntel {
  infrastructure: string;
  critical_cves: CVE[];
  [key: string]: unknown;
}

interface CorrelationMatch {
  technique: Technique;
  score: number;
  confidence: "high" | "medium" | "low";
  matched_keywords: string[];
}

interface CorrelationEntry {
  cve: CVE & { not_found?: boolean };
  techniques: CorrelationMatch[];
  error?: string;
}

interface ScanResult {
  scan_id: string;
  infrastructure_type: string;
  infrastructure_label: string;
  technique_count: number;
  chain_steps: number;
  critical_cves: number;
  techniques: Technique[];
  attack_chain: AttackChain | null;
  threat_intel: ThreatIntel | null;
}

interface HistoryEntry {
  id: string;
  infrastructure_type: string;
  infrastructure_label: string;
  status: string;
  started_at: string;
  completed_at?: string;
  technique_count: number;
  chain_steps: number;
  critical_cves: number;
}

function TechniqueCard({ technique }: { technique: Technique }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-zinc-800 rounded-lg overflow-hidden">
      <button
        type="button"
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-zinc-800/30 transition-colors"
        onClick={() => setExpanded((e) => !e)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className="text-zinc-100 font-medium text-sm">{technique.name}</span>
            <Badge variant="outline" className="font-mono text-xs text-blue-400 border-blue-500/30">
              {technique.mitre_id}
            </Badge>
            <span
              className={cn(
                "text-xs px-2 py-0.5 rounded-full capitalize",
                PHASE_COLORS[technique.phase] ?? "bg-zinc-700 text-zinc-300"
              )}
            >
              {technique.phase.replace(/-/g, " ")}
            </span>
            <span
              className={cn(
                "text-xs px-2 py-0.5 rounded-full border capitalize font-medium",
                RISK_COLORS[technique.risk_level] ?? RISK_COLORS.info
              )}
            >
              {technique.risk_level}
            </span>
          </div>
          <p className="text-zinc-400 text-xs line-clamp-2">{technique.description}</p>
          {!expanded && technique.tools.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {technique.tools.slice(0, 4).map((tool) => (
                <span key={tool} className="text-xs bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded">
                  {tool}
                </span>
              ))}
              {technique.tools.length > 4 && (
                <span className="text-xs text-zinc-500">+{technique.tools.length - 4} more</span>
              )}
            </div>
          )}
        </div>
        <div className="shrink-0 mt-0.5">
          {expanded ? (
            <ChevronUp className="h-4 w-4 text-zinc-500" />
          ) : (
            <ChevronDown className="h-4 w-4 text-zinc-500" />
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-zinc-800 p-4 space-y-4 bg-zinc-900/40">
          {technique.prerequisites.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Prerequisites</p>
              <ul className="space-y-1">
                {technique.prerequisites.map((p, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-zinc-400">
                    <span className="text-zinc-600 mt-0.5">•</span>
                    {p}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {technique.tools.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Tools</p>
              <div className="flex flex-wrap gap-1.5">
                {technique.tools.map((tool) => (
                  <span key={tool} className="text-xs bg-zinc-800 border border-zinc-700 text-zinc-300 px-2 py-0.5 rounded">
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          )}

          {technique.commands.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Commands</p>
              <div className="bg-zinc-950 border border-zinc-800 rounded p-3 max-h-48 overflow-y-auto">
                {technique.commands.map((cmd, i) => (
                  <div
                    key={i}
                    className={cn(
                      "text-xs font-mono",
                      cmd.startsWith("#") ? "text-zinc-500 mt-2 first:mt-0" : "text-emerald-400 break-all"
                    )}
                  >
                    {cmd}
                  </div>
                ))}
              </div>
            </div>
          )}

          {technique.detection && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Detection</p>
              <p className="text-xs text-zinc-400">{technique.detection}</p>
            </div>
          )}

          {technique.next_techniques.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Leads To</p>
              <div className="flex flex-wrap gap-1.5">
                {technique.next_techniques.map((t) => (
                  <span key={t} className="text-xs font-mono bg-blue-500/10 border border-blue-500/20 text-blue-400 px-2 py-0.5 rounded">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {technique.references.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">References</p>
              <div className="space-y-0.5">
                {technique.references.map((ref) => (
                  <p key={ref} className="text-xs text-blue-400 truncate">{ref}</p>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Threat Intel Tab — fetches full CVE list from cache ──────────────────────

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

function ThreatIntelTab({ infraType }: { infraType: string }) {
  const [cves, setCves] = useState<CVE[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [limit, setLimit] = useState(50);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ infra: infraType, limit: String(limit) });
    if (severityFilter !== "all") params.set("severity", severityFilter);
    fetchWithAuth(API_BASE + "/attackmapper/cves?" + params.toString())
      .then(r => r.json())
      .then(d => { setCves(d.items ?? []); setTotal(d.total ?? 0); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [infraType, severityFilter, limit]);

  const filtered = cves.filter(c => {
    if (!search) return true;
    const q = search.toLowerCase();
    return c.cve_id.toLowerCase().includes(q) || c.description.toLowerCase().includes(q);
  });

  const severityCounts = cves.reduce<Record<string, number>>((acc, c) => {
    acc[c.severity] = (acc[c.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-3">
      {/* Filters row */}
      <div className="flex gap-2 items-center flex-wrap">
        <Input
          placeholder="Search CVE ID or description..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="h-8 text-sm bg-zinc-950 border-zinc-700 flex-1 min-w-48"
        />
        <div className="flex gap-1">
          {["all", "critical", "high", "medium"].map(s => (
            <button
              key={s}
              type="button"
              onClick={() => setSeverityFilter(s)}
              className={cn(
                "text-xs px-2.5 py-1 rounded border capitalize transition-colors",
                severityFilter === s
                  ? s === "critical" ? "bg-red-500/20 border-red-500/40 text-red-400"
                    : s === "high" ? "bg-orange-500/20 border-orange-500/40 text-orange-400"
                    : s === "medium" ? "bg-yellow-500/20 border-yellow-500/40 text-yellow-400"
                    : "bg-blue-500/20 border-blue-500/40 text-blue-400"
                  : "border-zinc-700 text-zinc-500 hover:border-zinc-600"
              )}
            >
              {s === "all" ? "All" : s}
              {s !== "all" && severityCounts[s] ? ` (${severityCounts[s]})` : ""}
            </button>
          ))}
        </div>
        <span className="text-xs text-zinc-500 shrink-0">{total.toLocaleString()} total CVEs</span>
      </div>

      {loading ? (
        <div className="text-center py-8 text-zinc-500 text-sm">Loading CVEs from cache...</div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-8 text-zinc-500 text-sm">No CVEs match your filter.</div>
      ) : (
        <>
          <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
            {filtered.map(cve => <CVECard key={cve.cve_id} cve={cve} />)}
          </div>
          {filtered.length >= limit && (
            <button
              type="button"
              onClick={() => setLimit(l => l + 50)}
              className="w-full text-xs text-zinc-500 border border-zinc-800 rounded py-2 hover:bg-zinc-800 transition-colors"
            >
              Load more ({total - limit > 0 ? total - limit : "remaining"} more)
            </button>
          )}
        </>
      )}
    </div>
  );
}


// ── Attack Chain Graph ────────────────────────────────────────────────────────

const PHASE_COLOR_MAP: Record<string, string> = {
  reconnaissance:         "#a855f7",
  "initial-access":       "#ef4444",
  initial_access:         "#ef4444",
  execution:              "#f97316",
  persistence:            "#eab308",
  "privilege-escalation": "#ec4899",
  privilege_escalation:   "#ec4899",
  "defense-evasion":      "#6366f1",
  defense_evasion:        "#6366f1",
  "credential-access":    "#06b6d4",
  credential_access:      "#06b6d4",
  discovery:              "#14b8a6",
  "lateral-movement":     "#3b82f6",
  lateral_movement:       "#3b82f6",
  collection:             "#10b981",
  exfiltration:           "#f43f5e",
  impact:                 "#dc2626",
};

const RISK_COLOR_MAP: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#3b82f6",
};

// Layout constants
const NW   = 200;  // node width
const NH   = 90;   // node height (fixed for edge math)
const HGAP = 72;   // gap between phase columns
const VGAP = 18;   // gap between nodes in a column
const HDR  = 48;   // phase header height above nodes
const PAD  = 36;   // canvas padding

interface NodePos {
  id: string;
  technique: Technique;
  step: number;
  x: number;
  y: number;
  phaseColor: string;
  riskColor: string;
}

function buildLayout(chain: AttackChain) {
  const phaseOrder: string[] = [];
  const phaseGroups: Record<string, ChainStep[]> = {};
  for (const s of chain.steps) {
    const ph = s.technique.phase;
    if (!phaseGroups[ph]) { phaseGroups[ph] = []; phaseOrder.push(ph); }
    phaseGroups[ph].push(s);
  }

  const maxColH = Math.max(
    ...phaseOrder.map(p => phaseGroups[p].length * NH + (phaseGroups[p].length - 1) * VGAP)
  );
  const canvasW = PAD * 2 + phaseOrder.length * NW + (phaseOrder.length - 1) * HGAP;
  const canvasH = PAD + HDR + maxColH + PAD;

  const nodes: NodePos[] = [];
  const nodeMap: Record<string, NodePos> = {};

  phaseOrder.forEach((phase, col) => {
    const steps = phaseGroups[phase];
    const colH  = steps.length * NH + (steps.length - 1) * VGAP;
    const startY = PAD + HDR + (maxColH - colH) / 2;
    const x = PAD + col * (NW + HGAP);
    steps.forEach((step, row) => {
      const n: NodePos = {
        id: step.technique.id,
        technique: step.technique,
        step: step.step_number,
        x,
        y: startY + row * (NH + VGAP),
        phaseColor: PHASE_COLOR_MAP[phase] ?? "#71717a",
        riskColor: RISK_COLOR_MAP[step.technique.risk_level] ?? "#3b82f6",
      };
      nodes.push(n);
      nodeMap[step.technique.id] = n;
    });
  });

  const edges = chain.steps.slice(0, -1).map((step, i) => ({
    from: nodeMap[step.technique.id],
    to:   nodeMap[chain.steps[i + 1].technique.id],
    i,
  })).filter(e => e.from && e.to);

  return { phaseOrder, phaseGroups, nodes, nodeMap, edges, canvasW, canvasH, maxColH };
}

function AttackChainGraph({ chain }: { chain: AttackChain }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [vp, setVp] = useState({ x: 0, y: 0, scale: 1 });
  const containerRef = useRef<HTMLDivElement>(null);
  const drag = useRef({ on: false, x0: 0, y0: 0, tx: 0, ty: 0, moved: false });

  const layout = React.useMemo(() => buildLayout(chain), [chain]);
  const { phaseOrder, phaseGroups, nodes, edges, canvasW, canvasH, maxColH } = layout;

  // Auto-fit on mount
  useEffect(() => {
    if (!containerRef.current) return;
    const { width, height } = containerRef.current.getBoundingClientRect();
    const scale = Math.min((width - 40) / canvasW, (height - 40) / canvasH, 1);
    setVp({ x: (width - canvasW * scale) / 2, y: (height - canvasH * scale) / 2, scale });
  }, [canvasW, canvasH]);

  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const f = e.deltaY < 0 ? 1.1 : 0.91;
    const rect = containerRef.current!.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    setVp(p => {
      const s = Math.min(2.8, Math.max(0.2, p.scale * f));
      const r = s / p.scale;
      return { x: mx - r * (mx - p.x), y: my - r * (my - p.y), scale: s };
    });
  }, []);

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    drag.current = { on: true, x0: e.clientX, y0: e.clientY, tx: vp.x, ty: vp.y, moved: false };
  }, [vp.x, vp.y]);

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (!drag.current.on) return;
    const dx = e.clientX - drag.current.x0, dy = e.clientY - drag.current.y0;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) drag.current.moved = true;
    setVp(p => ({ ...p, x: drag.current.tx + dx, y: drag.current.ty + dy }));
  }, []);

  const onMouseUp = useCallback(() => { drag.current.on = false; }, []);

  const zoomIn  = () => setVp(p => ({ ...p, scale: Math.min(2.8, p.scale * 1.2) }));
  const zoomOut = () => setVp(p => ({ ...p, scale: Math.max(0.2, p.scale * 0.8) }));
  const fitView = useCallback(() => {
    if (!containerRef.current) return;
    const { width, height } = containerRef.current.getBoundingClientRect();
    const s = Math.min((width - 40) / canvasW, (height - 40) / canvasH, 1);
    setVp({ x: (width - canvasW * s) / 2, y: (height - canvasH * s) / 2, scale: s });
  }, [canvasW, canvasH]);

  const selectedNode = selected ? layout.nodeMap[selected] : null;

  return (
    <div className="-mx-4 -mb-4">
      {/* ── Canvas ── */}
      <div
        ref={containerRef}
        className="relative overflow-hidden select-none"
        style={{
          height: selectedNode ? 440 : 560,
          background: "#070709",
          backgroundImage:
            "radial-gradient(circle, #1c1c22 1.2px, transparent 1.2px)",
          backgroundSize: "26px 26px",
          cursor: drag.current.on ? "grabbing" : "grab",
          borderTop: "1px solid #1f1f27",
        }}
        onWheel={onWheel}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onClick={(e) => {
          if (e.target === containerRef.current) setSelected(null);
        }}
      >
        {/* Panning + zoom layer */}
        <div
          style={{
            position: "absolute",
            transformOrigin: "0 0",
            transform: `translate(${vp.x}px,${vp.y}px) scale(${vp.scale})`,
            width: canvasW,
            height: canvasH,
          }}
        >
          {/* ── SVG: column backgrounds + edges ── */}
          <svg
            style={{ position: "absolute", inset: 0, width: canvasW, height: canvasH, overflow: "visible", pointerEvents: "none" }}
          >
            <defs>
              <marker id="cag-arrow" markerWidth={9} markerHeight={9} refX={7} refY={4} orient="auto">
                <path d="M1,1 L1,7 L8,4 z" fill="#3f3f50" />
              </marker>
              {edges.map(({ from, to, i }) => (
                <linearGradient
                  key={i}
                  id={`cag-g${i}`}
                  x1={from.x + NW} y1={from.y + NH / 2}
                  x2={to.x}       y2={to.y + NH / 2}
                  gradientUnits="userSpaceOnUse"
                >
                  <stop offset="0%"   stopColor={from.phaseColor} stopOpacity={0.55} />
                  <stop offset="100%" stopColor={to.phaseColor}   stopOpacity={0.55} />
                </linearGradient>
              ))}
            </defs>

            {/* Column lane backgrounds */}
            {phaseOrder.map((phase, col) => {
              const steps  = phaseGroups[phase];
              const colH   = steps.length * NH + (steps.length - 1) * VGAP;
              const startY = PAD + HDR + (maxColH - colH) / 2;
              const x      = PAD + col * (NW + HGAP);
              const color  = PHASE_COLOR_MAP[phase] ?? "#71717a";
              return (
                <rect
                  key={phase}
                  x={x - 10} y={startY - 10}
                  width={NW + 20} height={colH + 20}
                  rx={14}
                  fill={color} fillOpacity={0.045}
                  stroke={color} strokeOpacity={0.12} strokeWidth={1}
                />
              );
            })}

            {/* Edges */}
            {edges.map(({ from, to, i }) => {
              const x1 = from.x + NW, y1 = from.y + NH / 2;
              const x2 = to.x,        y2 = to.y + NH / 2;
              const cx = (x1 + x2) / 2;
              const isHot = selected === from.id || selected === to.id;
              return (
                <path
                  key={i}
                  d={`M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}`}
                  fill="none"
                  stroke={isHot ? `url(#cag-g${i})` : "#2a2a35"}
                  strokeWidth={isHot ? 2.5 : 1.5}
                  markerEnd="url(#cag-arrow)"
                  style={{ transition: "stroke 0.15s, stroke-width 0.15s" }}
                />
              );
            })}
          </svg>

          {/* ── Phase column headers ── */}
          {phaseOrder.map((phase, col) => {
            const x     = PAD + col * (NW + HGAP);
            const color = PHASE_COLOR_MAP[phase] ?? "#71717a";
            const label = phase.replace(/[_-]/g, " ").toUpperCase();
            return (
              <div
                key={phase + "-hdr"}
                style={{
                  position: "absolute",
                  left: x, top: PAD - 4,
                  width: NW,
                  textAlign: "center",
                  pointerEvents: "none",
                }}
              >
                <span style={{
                  display: "inline-flex", alignItems: "center", gap: 5,
                  fontSize: 9, fontWeight: 700, letterSpacing: "0.08em",
                  color,
                  background: color + "14",
                  border: `1px solid ${color}28`,
                  borderRadius: 20,
                  padding: "3px 10px",
                }}>
                  <span style={{ width: 5, height: 5, borderRadius: "50%", background: color, flexShrink: 0 }} />
                  {label}
                </span>
              </div>
            );
          })}

          {/* ── HTML Nodes ── */}
          {nodes.map((n) => {
            const isSel = selected === n.id;
            return (
              <div
                key={n.id}
                style={{
                  position: "absolute",
                  left: n.x, top: n.y,
                  width: NW,
                  cursor: "pointer",
                  zIndex: isSel ? 20 : 1,
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  if (drag.current.moved) return;
                  setSelected(isSel ? null : n.id);
                }}
              >
                {/* Selection glow */}
                {isSel && (
                  <div style={{
                    position: "absolute", inset: -5, borderRadius: 18,
                    background: n.phaseColor, opacity: 0.18,
                    filter: "blur(10px)", pointerEvents: "none",
                  }} />
                )}
                <div style={{
                  borderRadius: 12,
                  overflow: "hidden",
                  border: isSel ? `1.5px solid ${n.phaseColor}` : "1.5px solid #222228",
                  background: isSel
                    ? "linear-gradient(160deg,#1b1b24,#13131a)"
                    : "linear-gradient(160deg,#111115,#0d0d11)",
                  boxShadow: isSel
                    ? `0 0 0 1px ${n.phaseColor}20, 0 12px 32px rgba(0,0,0,0.7)`
                    : "0 2px 10px rgba(0,0,0,0.5)",
                  transition: "border-color 0.15s, box-shadow 0.15s, background 0.15s",
                }}>
                  {/* Top phase stripe */}
                  <div style={{
                    height: 3,
                    background: `linear-gradient(90deg,${n.phaseColor},${n.phaseColor}30)`,
                  }} />

                  <div style={{ padding: "10px 11px 9px" }}>
                    {/* Step + name + risk */}
                    <div style={{ display: "flex", alignItems: "flex-start", gap: 8, marginBottom: 5 }}>
                      <div style={{
                        flexShrink: 0, width: 19, height: 19, borderRadius: "50%",
                        display: "flex", alignItems: "center", justifyContent: "center",
                        fontSize: 8.5, fontWeight: 700, marginTop: 1,
                        background: n.phaseColor + "22",
                        color: n.phaseColor,
                        border: `1px solid ${n.phaseColor}40`,
                      }}>{n.step}</div>
                      <span style={{
                        flex: 1, fontSize: 12, fontWeight: 600, lineHeight: 1.3,
                        color: isSel ? "#eeeef2" : "#c4c4cc",
                        display: "-webkit-box",
                        WebkitLineClamp: 2,
                        WebkitBoxOrient: "vertical" as const,
                        overflow: "hidden",
                      }}>{n.technique.name}</span>
                      <span style={{
                        flexShrink: 0, fontSize: 7.5, fontWeight: 700,
                        padding: "2px 5px", borderRadius: 4, marginTop: 1,
                        letterSpacing: "0.05em",
                        background: n.riskColor + "1c",
                        color: n.riskColor,
                        border: `1px solid ${n.riskColor}30`,
                      }}>{n.technique.risk_level.toUpperCase()}</span>
                    </div>

                    {/* MITRE + phase */}
                    <div style={{ paddingLeft: 27, display: "flex", alignItems: "center", gap: 6, marginBottom: 5 }}>
                      <span style={{ fontFamily: "monospace", fontSize: 9.5, color: "#606070" }}>{n.technique.mitre_id}</span>
                      <span style={{ fontSize: 8, color: "#44444e", textTransform: "capitalize" }}>
                        {n.technique.phase.replace(/[_-]/g, " ")}
                      </span>
                    </div>

                    {/* Tool pills */}
                    {n.technique.tools.length > 0 && (
                      <div style={{ paddingLeft: 27, display: "flex", gap: 3, flexWrap: "wrap" }}>
                        {n.technique.tools.slice(0, 3).map(t => (
                          <span key={t} style={{
                            fontSize: 8.5, padding: "1px 6px", borderRadius: 4,
                            background: "#1a1a22", color: "#606070",
                            border: "1px solid #26262e",
                          }}>{t}</span>
                        ))}
                        {n.technique.tools.length > 3 && (
                          <span style={{ fontSize: 8.5, color: "#44444e" }}>+{n.technique.tools.length - 3}</span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* ── Controls overlay ── */}
        <div className="absolute top-3 right-3 flex items-center gap-0.5 rounded-lg border border-zinc-800/80 bg-black/70 p-1 backdrop-blur-sm z-30">
          <button type="button" onClick={zoomIn} className="h-7 w-7 flex items-center justify-center rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 text-[15px] font-light transition-colors">+</button>
          <span className="text-[10px] text-zinc-600 w-[38px] text-center tabular-nums">{Math.round(vp.scale * 100)}%</span>
          <button type="button" onClick={zoomOut} className="h-7 w-7 flex items-center justify-center rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 text-[15px] font-light transition-colors">−</button>
          <div className="w-px h-4 bg-zinc-800 mx-0.5" />
          <button type="button" onClick={fitView} className="h-7 px-2 text-[10px] text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800 rounded transition-colors">Fit</button>
        </div>

        {/* ── Chain info badge ── */}
        <div className="absolute top-3 left-3 z-30 pointer-events-none">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-zinc-800/60 bg-black/65 backdrop-blur-sm">
            <span className="text-xs font-semibold text-zinc-300">{chain.name}</span>
            <span className="text-zinc-700 text-xs">·</span>
            <span className="text-[11px] text-zinc-600">{chain.steps.length} steps</span>
          </div>
        </div>

        {/* ── Scroll hint ── */}
        <div className="absolute bottom-3 left-1/2 -translate-x-1/2 z-30 pointer-events-none">
          <span className="text-[10px] text-zinc-700">Scroll to zoom · Drag to pan · Click node for details</span>
        </div>
      </div>

      {/* ── Detail panel (expands below canvas when node selected) ── */}
      {selectedNode && (
        <div
          className="border-t border-zinc-800"
          style={{ background: "#0d0d10" }}
        >
          {/* Compact header bar */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-zinc-800/60">
            <div
              className="w-1 h-10 rounded-full shrink-0"
              style={{ background: selectedNode.phaseColor }}
            />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold text-zinc-100">{selectedNode.technique.name}</span>
                <span className="font-mono text-[10px] text-zinc-500">{selectedNode.technique.mitre_id}</span>
                <span
                  className="text-[8.5px] font-bold px-1.5 py-0.5 rounded tracking-wide"
                  style={{
                    background: selectedNode.riskColor + "20",
                    color: selectedNode.riskColor,
                    border: `1px solid ${selectedNode.riskColor}30`,
                  }}
                >
                  {selectedNode.technique.risk_level.toUpperCase()}
                </span>
                <span
                  className="text-[10px] px-2 py-0.5 rounded-full capitalize"
                  style={{
                    background: selectedNode.phaseColor + "16",
                    color: selectedNode.phaseColor,
                    border: `1px solid ${selectedNode.phaseColor}28`,
                  }}
                >
                  {selectedNode.technique.phase.replace(/[_-]/g, " ")}
                </span>
              </div>
              <p className="text-xs text-zinc-500 mt-0.5 line-clamp-1">{selectedNode.technique.description}</p>
            </div>
            <button
              type="button"
              onClick={() => setSelected(null)}
              className="shrink-0 text-zinc-600 hover:text-zinc-300 transition-colors p-1 rounded hover:bg-zinc-800"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Content grid */}
          <div className="grid grid-cols-2 gap-0 divide-x divide-zinc-800/60">
            {/* Left: description + tools + prerequisites */}
            <div className="p-4 space-y-4">
              <p className="text-xs text-zinc-400 leading-relaxed">{selectedNode.technique.description}</p>

              {selectedNode.technique.tools.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600 mb-2">Tools</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedNode.technique.tools.map(t => (
                      <span key={t} className="text-[11px] bg-zinc-900 border border-zinc-700/60 text-zinc-300 px-2 py-0.5 rounded">{t}</span>
                    ))}
                  </div>
                </div>
              )}

              {selectedNode.technique.prerequisites.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600 mb-2">Prerequisites</p>
                  <ul className="space-y-1">
                    {selectedNode.technique.prerequisites.map((p, i) => (
                      <li key={i} className="flex gap-2 text-xs text-zinc-400">
                        <span className="text-zinc-700 shrink-0">›</span>{p}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Right: commands + detection + leads-to */}
            <div className="p-4 space-y-4">
              {selectedNode.technique.commands.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600 mb-2">Commands</p>
                  <div className="bg-zinc-950 border border-zinc-800/80 rounded-lg p-3 max-h-40 overflow-y-auto">
                    {selectedNode.technique.commands.map((cmd, i) => (
                      <div key={i} className={cn(
                        "text-[11px] font-mono leading-relaxed",
                        cmd.startsWith("#") ? "text-zinc-700 mt-1.5 first:mt-0" : "text-emerald-400 break-all"
                      )}>{cmd}</div>
                    ))}
                  </div>
                </div>
              )}

              {selectedNode.technique.detection && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600 mb-1.5">Detection</p>
                  <p className="text-xs text-zinc-400 leading-relaxed">{selectedNode.technique.detection}</p>
                </div>
              )}

              {selectedNode.technique.next_techniques.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600 mb-1.5">Leads To</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedNode.technique.next_techniques.map(t => (
                      <span key={t} className="text-[11px] font-mono bg-blue-500/10 border border-blue-500/20 text-blue-400 px-2 py-0.5 rounded">{t}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


function CVECard({ cve }: { cve: CVE }) {
  const severityColor =
    cve.severity === "critical"
      ? "border-red-500/30 bg-red-500/5"
      : cve.severity === "high"
      ? "border-orange-500/30 bg-orange-500/5"
      : "border-yellow-500/30 bg-yellow-500/5";

  const scoreColor =
    cve.cvss_score >= 9
      ? "text-red-400"
      : cve.cvss_score >= 7
      ? "text-orange-400"
      : "text-yellow-400";

  return (
    <div className={cn("border rounded-lg p-4", severityColor)}>
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-sm font-semibold text-zinc-100">{cve.cve_id}</span>
          <Badge
            variant="outline"
            className={cn("text-xs capitalize", RISK_COLORS[cve.severity] ?? RISK_COLORS.info)}
          >
            {cve.severity}
          </Badge>
          {cve.exploitation_status === "in-the-wild" && (
            <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/20">
              In-the-Wild
            </Badge>
          )}
        </div>
        <span className={cn("text-lg font-bold shrink-0", scoreColor)}>
          {cve.cvss_score.toFixed(1)}
        </span>
      </div>
      <p className="text-sm text-zinc-300 mb-2">{cve.description}</p>
      <div className="flex flex-wrap gap-1 mt-2">
        {cve.affected_products.map((p) => (
          <span key={p} className="text-xs bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded">
            {p}
          </span>
        ))}
      </div>
      {cve.published_date && (
        <p className="text-xs text-zinc-500 mt-2">Published: {cve.published_date}</p>
      )}
    </div>
  );
}

// ── CVE Correlation ───────────────────────────────────────────────────────────

const CONFIDENCE_STYLES: Record<string, string> = {
  high: "bg-red-500/10 text-red-400 border-red-500/20",
  medium: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  low: "bg-zinc-700/30 text-zinc-500 border-zinc-700",
};

function CorrelationResultCard({ result }: { result: CorrelationEntry }) {
  const [expanded, setExpanded] = useState(true);
  const { cve, techniques, error } = result;

  const headerColor = cve.severity === "critical"
    ? "border-red-500/30 bg-red-500/5"
    : cve.severity === "high"
    ? "border-orange-500/30 bg-orange-500/5"
    : "border-zinc-800 bg-zinc-900/60";

  return (
    <div className={cn("border rounded-lg overflow-hidden", headerColor)}>
      <button
        type="button"
        className="w-full flex items-start justify-between gap-3 p-3 text-left"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-sm font-semibold text-zinc-100">{cve.cve_id}</span>
          {!cve.not_found && (
            <>
              <Badge variant="outline" className={cn("text-xs capitalize", RISK_COLORS[cve.severity] ?? RISK_COLORS.info)}>{cve.severity}</Badge>
              {(cve as CVE).cvss_score > 0 && (
                <span className={cn("text-xs font-bold", (cve as CVE).cvss_score >= 9 ? "text-red-400" : (cve as CVE).cvss_score >= 7 ? "text-orange-400" : "text-yellow-400")}>
                  {(cve as CVE).cvss_score.toFixed(1)}
                </span>
              )}
              {(cve as CVE).exploitation_status === "in-the-wild" && (
                <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/20">In-the-Wild</Badge>
              )}
            </>
          )}
          {cve.not_found && <Badge variant="outline" className="text-xs text-zinc-500 border-zinc-700">Not in cache</Badge>}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {techniques.length > 0 && (
            <span className="text-xs text-zinc-500">{techniques.length} technique{techniques.length !== 1 ? "s" : ""}</span>
          )}
          {expanded ? <ChevronUp className="h-4 w-4 text-zinc-500" /> : <ChevronDown className="h-4 w-4 text-zinc-500" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-zinc-800 p-3 space-y-3 bg-zinc-950/40">
          {error ? (
            <p className="text-xs text-zinc-500 italic">{error}</p>
          ) : (
            <>
              {!cve.not_found && (cve as CVE).description && (
                <p className="text-xs text-zinc-400 line-clamp-3">{(cve as CVE).description}</p>
              )}
              {techniques.length === 0 ? (
                <p className="text-xs text-zinc-500">No relevant techniques found — try broader CVE descriptions or run Update Intel.</p>
              ) : (
                <div className="space-y-2">
                  {techniques.map((match, i) => (
                    <div key={match.technique.id} className="flex gap-3 border border-zinc-800 rounded-lg p-3 bg-zinc-900">
                      <div className="w-5 shrink-0 text-xs text-zinc-600 font-mono pt-0.5">#{i + 1}</div>
                      <div className="flex-1 min-w-0 space-y-1.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium text-zinc-200">{match.technique.name}</span>
                          <Badge variant="outline" className="font-mono text-xs text-blue-400 border-blue-500/30">{match.technique.mitre_id}</Badge>
                          <Badge variant="outline" className={cn("text-xs capitalize", CONFIDENCE_STYLES[match.confidence] ?? CONFIDENCE_STYLES.low)}>
                            {match.confidence} confidence
                          </Badge>
                          <span className={cn("text-xs px-2 py-0.5 rounded-full capitalize", PHASE_COLORS[match.technique.phase] ?? "bg-zinc-700 text-zinc-300")}>
                            {match.technique.phase.replace(/[_-]/g, " ")}
                          </span>
                        </div>
                        <p className="text-xs text-zinc-500 line-clamp-2">{match.technique.description}</p>
                        {match.matched_keywords.length > 0 && (
                          <div className="flex flex-wrap items-center gap-1">
                            <span className="text-xs text-zinc-600">Matched:</span>
                            {match.matched_keywords.map(k => (
                              <span key={k} className="text-xs bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded font-mono">{k}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function CVECorrelationTab({ infraType }: { infraType: string }) {
  const [cveInput, setCveInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<CorrelationEntry[]>([]);
  const [correlateError, setCorrelateError] = useState<string | null>(null);

  const handleCorrelate = useCallback(async () => {
    const ids = cveInput
      .split(/[\n,\s]+/)
      .map(s => s.trim().toUpperCase())
      .filter(s => /^CVE-\d{4}-\d+$/.test(s));

    if (!ids.length) {
      toast.error("Enter at least one valid CVE ID (format: CVE-YYYY-NNNNN)");
      return;
    }

    setLoading(true);
    setCorrelateError(null);
    setResults([]);

    try {
      const res = await fetchWithAuth(`${API_BASE}/attackmapper/correlate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cve_ids: ids, infrastructure_type: infraType }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(String(err.detail ?? "Correlation failed"));
      }
      const data = await res.json();
      setResults(data.results ?? []);
      toast.success(`Analyzed ${ids.length} CVE${ids.length !== 1 ? "s" : ""}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Correlation failed";
      setCorrelateError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }, [cveInput, infraType]);

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <p className="text-xs text-zinc-500">
          Enter CVE IDs to find the most relevant attack techniques based on keyword overlap, infrastructure context, and severity scoring.
        </p>
        <Label className="text-xs text-zinc-400">CVE IDs (one per line or comma-separated)</Label>
        <textarea
          value={cveInput}
          onChange={e => setCveInput(e.target.value)}
          placeholder={"CVE-2023-23397\nCVE-2024-21413\nCVE-2023-28252"}
          className="w-full h-28 bg-zinc-950 border border-zinc-700 rounded-md p-3 text-sm font-mono text-zinc-300 placeholder:text-zinc-600 resize-none focus:outline-none focus:ring-1 focus:ring-blue-500/50"
        />
        <div className="flex items-center gap-3">
          <Button
            onClick={handleCorrelate}
            disabled={loading || !cveInput.trim()}
            className="bg-blue-600 hover:bg-blue-500 text-white h-8 text-xs gap-2"
          >
            {loading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
            {loading ? "Correlating..." : "Find Techniques"}
          </Button>
          {results.length > 0 && !loading && (
            <span className="text-xs text-zinc-500">{results.length} CVE{results.length !== 1 ? "s" : ""} analyzed against <span className="text-zinc-300">{infraType.toUpperCase()}</span> techniques</span>
          )}
        </div>
      </div>

      {correlateError && (
        <div className="border border-red-500/20 bg-red-500/5 rounded-lg p-3 text-sm text-red-400">{correlateError}</div>
      )}

      {results.length > 0 && (
        <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
          {results.map(r => (
            <CorrelationResultCard key={r.cve.cve_id} result={r} />
          ))}
        </div>
      )}

      {!loading && !results.length && !correlateError && (
        <div className="flex flex-col items-center py-10 text-zinc-500 text-sm gap-2">
          <Bug className="h-8 w-8 opacity-25" />
          <p>Paste CVE IDs above and click <span className="text-zinc-400">Find Techniques</span></p>
          <p className="text-xs text-zinc-600 text-center max-w-sm">
            Techniques are ranked by keyword overlap with CVE description and boosted by infrastructure match, CVSS score, and active exploitation status
          </p>
        </div>
      )}
    </div>
  );
}


export default function AttackMapperPage() {
  const [infraType, setInfraType] = useState("ad");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [phaseFilter, setPhaseFilter] = useState("");
  const [searchFilter, setSearchFilter] = useState("");

  const [isRunning, setIsRunning] = useState(false);
  const [progressLog, setProgressLog] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [activeTab, setActiveTab] = useState<"techniques" | "chain" | "intel" | "correlate">("techniques");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [techniqueSearch, setTechniqueSearch] = useState("");
  const [techniquePhaseFilter, setTechniquePhaseFilter] = useState("all");

  // Intel update state
  const [isUpdatingIntel, setIsUpdatingIntel] = useState(false);
  const [intelLog, setIntelLog] = useState<Array<{ icon: string; line: string }>>([]);
  const [showIntelPanel, setShowIntelPanel] = useState(false);
  const [intelStats, setIntelStats] = useState<{
    cached_cves: number;
    cached_threat_actors: number;
    last_updated: string | null;
    techniques: Record<string, number>;
  } | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);
  const intelLogEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadHistory();
    loadStats();
  }, []);

  useEffect(() => {
    intelLogEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [intelLog]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [progressLog]);

  async function loadHistory() {
    try {
      const res = await fetchWithAuth(`${API_BASE}/attackmapper/scans`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.items ?? []);
      }
    } catch {
      // silently ignore
    }
  }

  async function loadStats() {
    try {
      const res = await fetchWithAuth(`${API_BASE}/attackmapper/stats`);
      if (res.ok) {
        const data = await res.json();
        setIntelStats(data);
      }
    } catch {
      // silently ignore
    }
  }

  const handleUpdateIntel = useCallback(async () => {
    setIsUpdatingIntel(true);
    setIntelLog([]);
    setShowIntelPanel(true);

    try {
      let token = await refreshAccessToken();
      if (!token) token = getAccessToken();
      const res = await fetch(`${API_BASE}/attackmapper/update-intel`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(String(err.detail ?? "Update failed"));
      }

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          let eventType = "";
          let dataStr = "";
          for (const line of part.split("\n")) {
            if (line.startsWith("event: ")) eventType = line.slice(7).trim();
            else if (line.startsWith("data: ")) dataStr = line.slice(6);
          }
          if (!dataStr) continue;
          let payload: Record<string, unknown>;
          try { payload = JSON.parse(dataStr); } catch { continue; }

          if (eventType === "start") {
            setIntelLog((p) => [...p, { icon: "⟳", line: String(payload.message ?? "") }]);
          } else if (eventType === "progress") {
            setIntelLog((p) => [...p, { icon: String(payload.icon ?? "⟳"), line: String(payload.line ?? "") }]);
          } else if (eventType === "complete") {
            setIntelLog((p) => [...p, {
              icon: "✓",
              line: `Update complete — ${payload.items_fetched} items fetched, ${payload.cached_cves} CVEs cached`,
            }]);
            toast.success("Threat intelligence updated from internet");
            loadStats();
          } else if (eventType === "error") {
            setIntelLog((p) => [...p, { icon: "✗", line: `Error: ${payload.message}` }]);
            toast.error(String(payload.message ?? "Update failed"));
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error) {
        toast.error(err.message);
        setIntelLog((p) => [...p, { icon: "✗", line: `Error: ${err.message}` }]);
      }
    } finally {
      setIsUpdatingIntel(false);
    }
  }, []);

  const handleStop = useCallback(() => {
    abortRef.current?.abort();
    setIsRunning(false);
    setProgressLog((p) => [...p, "Scan aborted by user."]);
  }, []);

  const handleRun = useCallback(async () => {
    setIsRunning(true);
    setProgressLog([]);
    setResult(null);
    setActiveTab("techniques");

    abortRef.current = new AbortController();

    try {
      // Always refresh to guarantee a non-expired token for the SSE stream
      let token = await refreshAccessToken();
      if (!token) token = getAccessToken();
      const res = await fetch(`${API_BASE}/attackmapper/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          infrastructure_type: infraType,
          category: categoryFilter || undefined,
          phase: phaseFilter || undefined,
          search: searchFilter || undefined,
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail ?? "Scan failed");
      }

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      let currentEvent = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          let eventType = currentEvent;
          let dataStr = "";

          for (const line of part.split("\n")) {
            if (line.startsWith("event: ")) {
              eventType = line.slice(7).trim();
            } else if (line.startsWith("data: ")) {
              dataStr = line.slice(6);
            }
          }

          if (!dataStr) continue;

          let payload: Record<string, unknown>;
          try {
            payload = JSON.parse(dataStr);
          } catch {
            continue;
          }

          if (eventType === "progress") {
            setProgressLog((p) => [...p, String(payload.message ?? "")]);
          } else if (eventType === "start") {
            setProgressLog((p) => [
              ...p,
              `Starting ${payload.infrastructure_label} attack path analysis...`,
            ]);
          } else if (eventType === "complete") {
            setResult(payload as unknown as ScanResult);
            setProgressLog((p) => [
              ...p,
              `Complete — ${payload.technique_count} techniques, ${payload.chain_steps} chain steps, ${payload.critical_cves} critical CVEs`,
            ]);
            loadHistory();
          } else if (eventType === "error") {
            toast.error(String(payload.message ?? "Scan error"));
            setProgressLog((p) => [...p, `Error: ${payload.message}`]);
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") {
        toast.error(err.message);
        setProgressLog((p) => [...p, `Error: ${err.message}`]);
      }
    } finally {
      setIsRunning(false);
    }
  }, [infraType, categoryFilter, phaseFilter, searchFilter]);

  // Filtered techniques for the techniques tab
  const filteredTechniques = (result?.techniques ?? []).filter((t) => {
    if (techniquePhaseFilter !== "all" && t.phase !== techniquePhaseFilter) return false;
    if (techniqueSearch) {
      const q = techniqueSearch.toLowerCase();
      return (
        t.name.toLowerCase().includes(q) ||
        t.mitre_id.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.tools.some((tool) => tool.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const uniquePhases = Array.from(new Set((result?.techniques ?? []).map((t) => t.phase)));

  const selectedInfra = INFRA_OPTIONS.find((o) => o.value === infraType);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-start justify-between gap-4 pb-2">
        <PageHeader
          title="Attack Path Mapper"
          description="Visualize attack paths for AD, Cloud, and Network infrastructure mapped to MITRE ATT&CK"
          className="pb-0"
        />
        <div className="flex items-center gap-2 shrink-0 mt-1">
          {intelStats?.last_updated && (
            <span className="text-xs text-zinc-500 hidden sm:block">
              Updated {new Date(intelStats.last_updated).toLocaleDateString()}
            </span>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={handleUpdateIntel}
            disabled={isUpdatingIntel}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 gap-2"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isUpdatingIntel && "animate-spin")} />
            {isUpdatingIntel ? "Updating..." : "Update Intel"}
          </Button>
        </div>
      </div>

      {/* Intel Update Panel */}
      {showIntelPanel && (
        <Card className="border-zinc-700 bg-zinc-900">
          <CardHeader className="pb-2 pt-3 px-4">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-2">
                <Globe className="h-3.5 w-3.5 text-blue-400" />
                Internet Intel Update
                {isUpdatingIntel && <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />}
              </CardTitle>
              {!isUpdatingIntel && (
                <button type="button" onClick={() => setShowIntelPanel(false)} className="text-zinc-600 hover:text-zinc-400">
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-3">
            <div className="bg-zinc-950 border border-zinc-800 rounded p-3 max-h-40 overflow-y-auto font-mono text-xs space-y-0.5">
              {intelLog.map((entry, i) => (
                <div key={i} className={cn(
                  "flex items-start gap-2",
                  entry.icon === "✓" ? "text-emerald-400" :
                  entry.icon === "✗" ? "text-red-400" :
                  entry.icon === "⚠" ? "text-yellow-400" : "text-zinc-400"
                )}>
                  <span className="shrink-0 w-4">{entry.icon}</span>
                  <span>{entry.line}</span>
                </div>
              ))}
              <div ref={intelLogEndRef} />
            </div>
            {intelStats && !isUpdatingIntel && (
              <div className="flex gap-4 mt-3 text-xs text-zinc-400">
                <span className="flex items-center gap-1"><Database className="h-3 w-3" />{intelStats.cached_cves.toLocaleString()} CVEs cached</span>
                <span className="flex items-center gap-1"><Shield className="h-3 w-3" />{intelStats.cached_threat_actors} threat actors</span>
                {Object.entries(intelStats.techniques).map(([k, v]) => (
                  <span key={k} className="capitalize">{k}: {v} techniques</span>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* ── Left: Config panel ──────────────────────────────────────────── */}
        <div className="xl:col-span-1 space-y-4">
          <Card className="border-zinc-800 bg-zinc-900">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                <Layers className="h-4 w-4 text-blue-400" />
                Infrastructure Type
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {INFRA_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setInfraType(opt.value)}
                  className={cn(
                    "w-full flex items-start gap-3 p-3 rounded-lg border text-left transition-all",
                    infraType === opt.value
                      ? "border-blue-500/50 bg-blue-500/10"
                      : "border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800/50"
                  )}
                >
                  <span className="text-lg shrink-0">{opt.icon}</span>
                  <div className="min-w-0">
                    <p
                      className={cn(
                        "text-sm font-medium",
                        infraType === opt.value ? "text-blue-300" : "text-zinc-300"
                      )}
                    >
                      {opt.label}
                    </p>
                    <p className="text-xs text-zinc-500 mt-0.5">{opt.desc}</p>
                  </div>
                </button>
              ))}
            </CardContent>
          </Card>

          <Card className="border-zinc-800 bg-zinc-900">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-zinc-300">Filters (Optional)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Search Techniques</Label>
                <Input
                  placeholder="e.g. kerberoast, privilege escalation"
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="h-8 text-sm bg-zinc-950 border-zinc-700"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Phase Filter</Label>
                <Input
                  placeholder="e.g. reconnaissance, persistence"
                  value={phaseFilter}
                  onChange={(e) => setPhaseFilter(e.target.value)}
                  className="h-8 text-sm bg-zinc-950 border-zinc-700"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Category Filter</Label>
                <Input
                  placeholder="e.g. credential-access"
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="h-8 text-sm bg-zinc-950 border-zinc-700"
                />
              </div>
            </CardContent>
          </Card>

          <div className="flex gap-2">
            <Button
              onClick={handleRun}
              disabled={isRunning}
              className="flex-1 bg-blue-600 hover:bg-blue-500 text-white"
            >
              <Play className="h-4 w-4 mr-2" />
              {isRunning ? "Mapping..." : "Run Analysis"}
            </Button>
            {isRunning && (
              <Button
                variant="outline"
                onClick={handleStop}
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
              >
                <Square className="h-4 w-4" />
              </Button>
            )}
          </div>

          {/* History */}
          {history.length > 0 && (
            <Card className="border-zinc-800 bg-zinc-900">
              <button
                type="button"
                className="w-full flex items-center justify-between p-4"
                onClick={() => setShowHistory((s) => !s)}
              >
                <span className="flex items-center gap-2 text-sm font-medium text-zinc-300">
                  <History className="h-4 w-4 text-zinc-500" />
                  History ({history.length})
                </span>
                {showHistory ? (
                  <ChevronUp className="h-4 w-4 text-zinc-500" />
                ) : (
                  <ChevronDown className="h-4 w-4 text-zinc-500" />
                )}
              </button>
              {showHistory && (
                <div className="border-t border-zinc-800 divide-y divide-zinc-800 max-h-64 overflow-y-auto">
                  {history.map((h) => (
                    <div key={h.id} className="p-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm text-zinc-300 font-medium">
                          {h.infrastructure_label}
                        </span>
                        <Badge
                          variant="outline"
                          className={cn(
                            "text-xs",
                            h.status === "completed"
                              ? "text-emerald-400 border-emerald-500/20"
                              : h.status === "failed"
                              ? "text-red-400 border-red-500/20"
                              : "text-yellow-400 border-yellow-500/20"
                          )}
                        >
                          {h.status}
                        </Badge>
                      </div>
                      <div className="flex gap-3 mt-1 text-xs text-zinc-500">
                        <span>{h.technique_count} techniques</span>
                        <span>{h.chain_steps} steps</span>
                        <span>{h.critical_cves} CVEs</span>
                      </div>
                      <p className="text-xs text-zinc-600 mt-0.5">
                        {new Date(h.started_at).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}
        </div>

        {/* ── Right: Results ────────────────────────────────────────────────── */}
        <div className="xl:col-span-2 space-y-4">
          {/* Progress log */}
          {(isRunning || progressLog.length > 0) && (
            <Card className="border-zinc-800 bg-zinc-900">
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-2">
                  <Terminal className="h-3.5 w-3.5" />
                  Progress
                  {isRunning && (
                    <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3">
                <div className="bg-zinc-950 border border-zinc-800 rounded p-3 h-28 overflow-y-auto font-mono text-xs">
                  {progressLog.map((line, i) => (
                    <div
                      key={i}
                      className={cn(
                        line.startsWith("Error:") ? "text-red-400" : "text-zinc-300"
                      )}
                    >
                      <span className="text-zinc-600 mr-2">$</span>
                      {line}
                    </div>
                  ))}
                  <div ref={logEndRef} />
                </div>
              </CardContent>
            </Card>
          )}

          {/* Summary stats */}
          {result && (
            <div className="grid grid-cols-3 gap-3">
              <Card className="border-zinc-800 bg-zinc-900">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <Target className="h-4 w-4 text-blue-400" />
                    <span className="text-xs text-zinc-500">Techniques</span>
                  </div>
                  <p className="text-2xl font-bold text-zinc-100">{result.technique_count}</p>
                  <p className="text-xs text-zinc-500 mt-0.5">{result.infrastructure_label}</p>
                </CardContent>
              </Card>
              <Card className="border-zinc-800 bg-zinc-900">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <Link2 className="h-4 w-4 text-purple-400" />
                    <span className="text-xs text-zinc-500">Chain Steps</span>
                  </div>
                  <p className="text-2xl font-bold text-zinc-100">{result.chain_steps}</p>
                  <p className="text-xs text-zinc-500 mt-0.5">Full attack path</p>
                </CardContent>
              </Card>
              <Card className="border-zinc-800 bg-zinc-900">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <Bug className="h-4 w-4 text-red-400" />
                    <span className="text-xs text-zinc-500">Critical CVEs</span>
                  </div>
                  <p className="text-2xl font-bold text-zinc-100">{intelStats?.cached_cves?.toLocaleString() ?? result.critical_cves}</p>
                  <p className="text-xs text-zinc-500 mt-0.5">{intelStats?.cached_cves ? "In local cache" : "Active threats"}</p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Tabs */}
          {result && (
            <Card className="border-zinc-800 bg-zinc-900">
              {/* Tab bar */}
              <div className="flex border-b border-zinc-800 px-4">
                {(
                  [
                    { key: "techniques", label: "Techniques", icon: Shield, count: result.technique_count },
                    { key: "chain", label: "Attack Chain", icon: Link2, count: result.chain_steps },
                    { key: "intel", label: "Threat Intel", icon: AlertTriangle, count: intelStats?.cached_cves ?? result.critical_cves },
                    { key: "correlate", label: "CVE Correlation", icon: Bug, count: null },
                  ] as const
                ).map(({ key, label, icon: Icon, count }) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setActiveTab(key)}
                    className={cn(
                      "flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors",
                      activeTab === key
                        ? "border-blue-500 text-blue-400"
                        : "border-transparent text-zinc-500 hover:text-zinc-300"
                    )}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    {label}
                    {count !== null && (
                      <span
                        className={cn(
                          "text-xs px-1.5 py-0.5 rounded-full",
                          activeTab === key ? "bg-blue-500/20 text-blue-400" : "bg-zinc-800 text-zinc-500"
                        )}
                      >
                        {count}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              <CardContent className="p-4">
                {/* ── Techniques tab ── */}
                {activeTab === "techniques" && (
                  <div className="space-y-3">
                    {/* Search + phase filter */}
                    <div className="flex gap-2">
                      <Input
                        placeholder="Search techniques, tools, MITRE IDs..."
                        value={techniqueSearch}
                        onChange={(e) => setTechniqueSearch(e.target.value)}
                        className="h-8 text-sm bg-zinc-950 border-zinc-700 flex-1"
                      />
                      <select
                        value={techniquePhaseFilter}
                        onChange={(e) => setTechniquePhaseFilter(e.target.value)}
                        className="h-8 text-sm bg-zinc-950 border border-zinc-700 rounded-md px-2 text-zinc-300"
                      >
                        <option value="all">All phases</option>
                        {uniquePhases.map((p) => (
                          <option key={p} value={p}>
                            {p.replace(/-/g, " ")}
                          </option>
                        ))}
                      </select>
                    </div>

                    {filteredTechniques.length === 0 ? (
                      <div className="text-center py-8 text-zinc-500 text-sm">
                        No techniques match your filter.
                      </div>
                    ) : (
                      <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                        {filteredTechniques.map((t) => (
                          <TechniqueCard key={t.id} technique={t} />
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* ── Full Chain tab ── */}
                {activeTab === "chain" && result.attack_chain && (
                  <AttackChainGraph chain={result.attack_chain} />
                )}

                {activeTab === "chain" && !result.attack_chain && (
                  <div className="text-center py-8 text-zinc-500 text-sm">
                    No attack chain data available.
                  </div>
                )}

                {/* ── Threat Intel tab ── */}
                {activeTab === "intel" && (
                  <ThreatIntelTab infraType={result.infrastructure_type} />
                )}

                {/* ── CVE Correlation tab ── */}
                {activeTab === "correlate" && (
                  <CVECorrelationTab infraType={result.infrastructure_type} />
                )}
              </CardContent>
            </Card>
          )}

          {/* Empty state */}
          {!result && !isRunning && progressLog.length === 0 && (
            <Card className="border-zinc-800 bg-zinc-900 border-dashed">
              <CardContent className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="h-12 w-12 rounded-full bg-zinc-800 flex items-center justify-center">
                  <Map className="h-6 w-6 text-zinc-500" />
                </div>
                <p className="text-zinc-400 font-medium">Select an infrastructure type and run the analysis</p>
                <p className="text-zinc-600 text-sm text-center max-w-sm">
                  AttackMapper generates attack path visualizations mapped to MITRE ATT&CK with active threat intelligence
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
