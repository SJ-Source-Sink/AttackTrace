"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
  BackgroundVariant,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Network,
  Search,
  Download,
  RefreshCw,
  Loader2,
  Shield,
  Globe,
  Cpu,
  Cloud,
  GitBranch,
  Zap,
  ChevronRight,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { fetchWithAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GraphNode {
  id: string;
  type: string;
  label: string;
  severity: string;
  finding_count: number;
  risk_score: number | null;
  scan_id: string | null;
  metadata: Record<string, any>;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
}

interface GraphStats {
  total_nodes: number;
  total_edges: number;
  critical_nodes: number;
  high_nodes: number;
  asset_types: Record<string, number>;
}

interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: GraphStats;
  scan_id: string | null;
}

interface TimelineSnapshot {
  scan_id: string;
  scan_name: string;
  completed_at: string;
  asset_count: number;
  finding_counts: Record<string, number>;
}

// ---------------------------------------------------------------------------
// SecurityNode custom node
// ---------------------------------------------------------------------------

const SEV_COLORS: Record<string, string> = {
  critical: "border-red-500 shadow-red-500/30",
  high: "border-orange-500 shadow-orange-500/20",
  medium: "border-yellow-500 shadow-yellow-500/20",
  low: "border-blue-400 shadow-blue-400/20",
  info: "border-zinc-600",
  none: "border-zinc-700",
};

const TYPE_ICON: Record<string, string> = {
  domain: "◆",
  subdomain: "●",
  ip: "■",
  webapp: "◉",
  cloud: "☁",
};

const SEV_BADGE_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400",
  high: "bg-orange-500/20 text-orange-400",
  medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-blue-400/20 text-blue-400",
  info: "bg-zinc-700 text-zinc-400",
  none: "bg-zinc-800 text-zinc-500",
};

interface SecurityNodeData {
  label: string;
  nodeType: string;
  severity: string;
  findingCount: number;
  riskScore: number | null;
  metadata: Record<string, any>;
  scan_id: string | null;
  [key: string]: unknown;
}

function SecurityNode({ data }: NodeProps) {
  const d = data as SecurityNodeData;
  const borderClass = SEV_COLORS[d.severity] ?? SEV_COLORS.none;
  const icon = TYPE_ICON[d.nodeType] ?? "●";

  return (
    <div
      className={`bg-zinc-900 border-2 rounded-lg p-2.5 shadow-lg min-w-[120px] max-w-[200px] ${borderClass}`}
    >
      <Handle type="target" position={Position.Top} className="!bg-zinc-600 !border-zinc-500" />
      <Handle type="source" position={Position.Bottom} className="!bg-zinc-600 !border-zinc-500" />

      {/* Type row */}
      <div className="flex items-center gap-1 mb-1">
        <span className="text-zinc-500 text-xs">{icon}</span>
        <span className="text-zinc-400 text-[10px] uppercase tracking-wide font-medium">
          {d.nodeType}
        </span>
      </div>

      {/* Label */}
      <p
        className="text-white font-medium text-sm leading-tight truncate"
        title={d.label}
      >
        {d.label}
      </p>

      {/* Bottom row */}
      <div className="flex items-center gap-1.5 mt-1.5">
        {d.findingCount > 0 && (
          <span className="inline-flex items-center rounded px-1 py-0.5 text-[10px] font-semibold bg-red-500/20 text-red-400">
            {d.findingCount} finding{d.findingCount !== 1 ? "s" : ""}
          </span>
        )}
        {d.riskScore !== null && d.riskScore !== undefined && (
          <span className="text-[10px] text-zinc-500">
            risk {d.riskScore}
          </span>
        )}
      </div>
    </div>
  );
}

// nodeTypes must be outside the component to avoid recreation on render
const nodeTypes = { securityNode: SecurityNode };

// ---------------------------------------------------------------------------
// Edge colour helper
// ---------------------------------------------------------------------------

function edgeStroke(type: string): string {
  if (type === "resolves_to") return "#3b82f6";
  if (type === "hosted_on") return "#8b5cf6";
  if (type === "parent_domain") return "#6b7280";
  return "#374151";
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return iso;
  }
}

function severityLabel(sev: string): string {
  return sev.charAt(0).toUpperCase() + sev.slice(1);
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

export default function NetworkMapPage() {
  const router = useRouter();

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [scanId, setScanId] = useState<string>("");
  const [timeline, setTimeline] = useState<TimelineSnapshot[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterType, setFilterType] = useState<string>("all");
  const [showAttackPaths, setShowAttackPaths] = useState(false);

  // -------------------------------------------------------------------------
  // Load graph
  // -------------------------------------------------------------------------

  const loadGraph = useCallback(
    async (selectedScanId?: string) => {
      setLoading(true);
      try {
        const url = selectedScanId
          ? `${API_BASE}/network/graph?scan_id=${selectedScanId}`
          : `${API_BASE}/network/graph`;
        const res = await fetchWithAuth(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: GraphResponse = await res.json();

        // Build type groups for layout
        const typeOrder: Record<string, number> = {
          domain: 0,
          subdomain: 200,
          ip: 400,
          webapp: 400,
          cloud: 600,
        };
        const typeGroups: Record<string, GraphNode[]> = {};
        data.nodes.forEach((n) => {
          if (!typeGroups[n.type]) typeGroups[n.type] = [];
          typeGroups[n.type].push(n);
        });

        const flowNodes: Node[] = data.nodes.map((n) => {
          const sameType = typeGroups[n.type] || [];
          const posInGroup = sameType.indexOf(n);
          const spacing = 220;
          const x = (posInGroup - sameType.length / 2) * spacing;
          const y = typeOrder[n.type] ?? 600;
          return {
            id: n.id,
            type: "securityNode",
            position: { x, y },
            data: {
              label: n.label,
              nodeType: n.type,
              severity: n.severity,
              findingCount: n.finding_count,
              riskScore: n.risk_score,
              metadata: n.metadata,
              scan_id: n.scan_id,
            },
          };
        });

        const flowEdges: Edge[] = data.edges.map((e) => ({
          id: `${e.source}-${e.target}-${e.type}`,
          source: e.source,
          target: e.target,
          label: e.label,
          type: "smoothstep",
          animated: showAttackPaths && e.type === "attack_path",
          data: { edgeType: e.type },
          style: {
            stroke:
              showAttackPaths && e.type === "attack_path"
                ? "#ef4444"
                : edgeStroke(e.type),
            strokeWidth: 1.5,
          },
          labelStyle: { fontSize: 10, fill: "#6b7280" },
          labelBgStyle: { fill: "#18181b", fillOpacity: 0.8 },
        }));

        setNodes(flowNodes);
        setEdges(flowEdges);
        setStats(data.stats);
      } catch {
        toast.error("Failed to load network graph");
      } finally {
        setLoading(false);
      }
    },
    [showAttackPaths, setNodes, setEdges]
  );

  const loadTimeline = async () => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/network/graph/timeline`);
      if (!res.ok) return;
      const data = await res.json();
      setTimeline(data.snapshots || []);
    } catch {}
  };

  useEffect(() => {
    loadGraph();
    loadTimeline();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // -------------------------------------------------------------------------
  // Search / filter — derive filtered nodes & edges
  // -------------------------------------------------------------------------

  const filteredNodes = useMemo(() => {
    return nodes.map((node) => {
      const d = node.data as SecurityNodeData;
      const label = d.label?.toLowerCase() ?? "";
      const q = searchQuery.toLowerCase();

      const matchSearch = !q || label.includes(q);
      const matchSev = filterSeverity === "all" || d.severity === filterSeverity;
      const matchType = filterType === "all" || d.nodeType === filterType;
      const visible = matchSearch && matchSev && matchType;

      return {
        ...node,
        style: {
          ...(node.style ?? {}),
          opacity: visible ? 1 : 0.15,
        },
      };
    });
  }, [nodes, searchQuery, filterSeverity, filterType]);

  // Re-animate edges when showAttackPaths changes
  useEffect(() => {
    setEdges((prev) =>
      prev.map((e) => {
        const edgeType = (e.data as any)?.edgeType ?? "";
        const isAttack = edgeType === "attack_path";
        return {
          ...e,
          animated: showAttackPaths && isAttack,
          style: {
            ...e.style,
            stroke:
              showAttackPaths && isAttack ? "#ef4444" : edgeStroke(edgeType),
          },
        };
      })
    );
  }, [showAttackPaths, setEdges]);

  // -------------------------------------------------------------------------
  // Export
  // -------------------------------------------------------------------------

  const exportJSON = () => {
    const exportData = {
      nodes: nodes.map((n) => n.data),
      edges: edges.map((e) => ({
        source: e.source,
        target: e.target,
        type: (e.data as any)?.edgeType,
      })),
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "network-graph.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  // -------------------------------------------------------------------------
  // Scan selector change
  // -------------------------------------------------------------------------

  const handleScanChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    setScanId(val);
    loadGraph(val || undefined);
  };

  // -------------------------------------------------------------------------
  // Selected node data
  // -------------------------------------------------------------------------

  const selectedData = selectedNode?.data as SecurityNodeData | undefined;

  // -------------------------------------------------------------------------
  // Unique types for filter dropdown
  // -------------------------------------------------------------------------

  const uniqueTypes = useMemo(() => {
    const types = new Set<string>();
    nodes.forEach((n) => {
      const d = n.data as SecurityNodeData;
      if (d.nodeType) types.add(d.nodeType);
    });
    return Array.from(types).sort();
  }, [nodes]);

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  const hasNodes = nodes.length > 0;

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)] bg-zinc-950">
      {/* ------------------------------------------------------------------ */}
      {/* TOOLBAR                                                             */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex flex-wrap items-center gap-2 px-4 py-2 bg-zinc-900 border-b border-zinc-800 shrink-0">
        {/* Title */}
        <div className="flex items-center gap-2 mr-2">
          <Network className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-semibold text-zinc-100">Network Map</span>
        </div>

        {/* Scan selector */}
        <select
          value={scanId}
          onChange={handleScanChange}
          className="h-8 rounded border border-zinc-700 bg-zinc-800 px-2 text-xs text-zinc-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          <option value="">Global (All Scans)</option>
          {timeline.map((snap) => (
            <option key={snap.scan_id} value={snap.scan_id}>
              {snap.scan_name} ({formatDate(snap.completed_at)})
            </option>
          ))}
        </select>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500 pointer-events-none" />
          <input
            type="text"
            placeholder="Search nodes…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-8 w-44 rounded border border-zinc-700 bg-zinc-800 pl-7 pr-2 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        {/* Severity filter */}
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="h-8 rounded border border-zinc-700 bg-zinc-800 px-2 text-xs text-zinc-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
          <option value="none">None</option>
        </select>

        {/* Type filter */}
        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="h-8 rounded border border-zinc-700 bg-zinc-800 px-2 text-xs text-zinc-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          <option value="all">All Types</option>
          {uniqueTypes.map((t) => (
            <option key={t} value={t}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </option>
          ))}
        </select>

        {/* Attack Paths toggle */}
        <button
          onClick={() => setShowAttackPaths((p) => !p)}
          className={`flex items-center gap-1.5 h-8 px-3 rounded border text-xs font-medium transition-colors ${
            showAttackPaths
              ? "border-red-500 bg-red-500/10 text-red-400"
              : "border-zinc-700 bg-zinc-800 text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <Zap className="h-3.5 w-3.5" />
          Attack Paths
        </button>

        <div className="ml-auto flex items-center gap-2">
          {/* Refresh */}
          <button
            onClick={() => loadGraph(scanId || undefined)}
            disabled={loading}
            className="flex items-center gap-1.5 h-8 px-3 rounded border border-zinc-700 bg-zinc-800 text-xs text-zinc-400 hover:text-zinc-200 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>

          {/* Export JSON */}
          <button
            onClick={exportJSON}
            disabled={!hasNodes}
            className="flex items-center gap-1.5 h-8 px-3 rounded border border-zinc-700 bg-zinc-800 text-xs text-zinc-400 hover:text-zinc-200 transition-colors disabled:opacity-50"
          >
            <Download className="h-3.5 w-3.5" />
            Export JSON
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* MAIN CONTENT                                                        */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex flex-1 min-h-0">
        {/* React Flow Canvas */}
        <div className="flex-1 relative">
          {/* Loading overlay */}
          {loading && (
            <div className="absolute inset-0 z-10 flex items-center justify-center bg-zinc-950/70">
              <div className="flex flex-col items-center gap-3">
                <Loader2 className="h-8 w-8 animate-spin text-blue-400" />
                <span className="text-sm text-zinc-400">Loading network graph…</span>
              </div>
            </div>
          )}

          {/* Empty state */}
          {!loading && !hasNodes && (
            <div className="absolute inset-0 z-10 flex flex-col items-center justify-center text-zinc-500">
              <Network className="h-16 w-16 mb-4 opacity-20" />
              <p className="text-lg font-medium">No network data yet</p>
              <p className="text-sm mt-1">Run a scan to populate the network map</p>
              <Button
                onClick={() => router.push("/scans")}
                className="mt-4"
              >
                Go to Scans
              </Button>
            </div>
          )}

          <ReactFlow
            nodes={filteredNodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={(_, node) => setSelectedNode(node)}
            onPaneClick={() => setSelectedNode(null)}
            nodeTypes={nodeTypes}
            fitView
            className="bg-zinc-950"
            defaultEdgeOptions={{ type: "smoothstep" }}
          >
            <Background
              variant={BackgroundVariant.Dots}
              color="#3f3f46"
              gap={20}
              size={1}
            />
            <Controls className="bg-zinc-900 border-zinc-700 [&>button]:bg-zinc-900 [&>button]:border-zinc-700 [&>button]:text-zinc-400 [&>button:hover]:bg-zinc-800" />
            <MiniMap
              className="bg-zinc-900 border border-zinc-700 rounded"
              nodeColor={(node) => {
                const sev = (node.data as any)?.severity;
                if (sev === "critical") return "#ef4444";
                if (sev === "high") return "#f97316";
                if (sev === "medium") return "#eab308";
                return "#3b82f6";
              }}
              maskColor="rgba(0,0,0,0.8)"
            />
          </ReactFlow>
        </div>

        {/* ---------------------------------------------------------------- */}
        {/* DETAIL PANEL                                                      */}
        {/* ---------------------------------------------------------------- */}
        {selectedNode && selectedData && (
          <div className="w-72 bg-zinc-900 border-l border-zinc-800 flex flex-col overflow-y-auto shrink-0">
            {/* Header */}
            <div className="flex items-start justify-between p-4 border-b border-zinc-800">
              <div className="flex-1 min-w-0">
                <p className="text-white font-semibold text-base truncate" title={selectedData.label}>
                  {selectedData.label}
                </p>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {/* Type badge */}
                  <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium bg-zinc-800 text-zinc-300">
                    {TYPE_ICON[selectedData.nodeType] ?? "●"} {selectedData.nodeType}
                  </span>
                  {/* Severity badge */}
                  <span
                    className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${
                      SEV_BADGE_COLORS[selectedData.severity] ?? SEV_BADGE_COLORS.none
                    }`}
                  >
                    {severityLabel(selectedData.severity)}
                  </span>
                  {/* Finding count */}
                  {selectedData.findingCount > 0 && (
                    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium bg-red-500/20 text-red-400">
                      {selectedData.findingCount} finding{selectedData.findingCount !== 1 ? "s" : ""}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="ml-2 text-zinc-500 hover:text-zinc-300 transition-colors shrink-0"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Risk score */}
            {selectedData.riskScore !== null && selectedData.riskScore !== undefined && (
              <div className="px-4 py-3 border-b border-zinc-800">
                <p className="text-[11px] text-zinc-500 mb-1 uppercase tracking-wide">Risk Score</p>
                <p className="text-2xl font-bold text-zinc-100">{selectedData.riskScore}</p>
              </div>
            )}

            {/* Metadata */}
            {selectedData.metadata && Object.keys(selectedData.metadata).length > 0 && (
              <div className="px-4 py-3 border-b border-zinc-800">
                <p className="text-[11px] text-zinc-500 mb-2 uppercase tracking-wide">Metadata</p>
                <div className="space-y-1.5">
                  {Object.entries(selectedData.metadata).map(([key, val]) => (
                    <div key={key} className="flex gap-2">
                      <span className="text-xs text-zinc-500 shrink-0 w-24 truncate" title={key}>
                        {key}
                      </span>
                      <span className="text-xs text-zinc-300 break-all">
                        {typeof val === "object" ? JSON.stringify(val) : String(val ?? "")}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="p-4 flex flex-col gap-2">
              <p className="text-[11px] text-zinc-500 uppercase tracking-wide mb-1">Actions</p>

              <button
                onClick={() =>
                  router.push(
                    `/findings?asset=${encodeURIComponent(selectedData.label)}`
                  )
                }
                className="flex items-center justify-between w-full h-8 px-3 rounded border border-zinc-700 bg-zinc-800 text-xs text-zinc-300 hover:bg-zinc-700 transition-colors"
              >
                <span className="flex items-center gap-2">
                  <Shield className="h-3.5 w-3.5 text-zinc-400" />
                  View Findings
                </span>
                <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />
              </button>

              <button
                onClick={() =>
                  router.push(
                    `/nmap?target=${encodeURIComponent(selectedData.label)}`
                  )
                }
                className="flex items-center justify-between w-full h-8 px-3 rounded border border-zinc-700 bg-zinc-800 text-xs text-zinc-300 hover:bg-zinc-700 transition-colors"
              >
                <span className="flex items-center gap-2">
                  <Cpu className="h-3.5 w-3.5 text-zinc-400" />
                  Run Nmap
                </span>
                <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />
              </button>

              <button
                onClick={() =>
                  router.push(
                    `/firewall?target=${encodeURIComponent(selectedData.label)}`
                  )
                }
                className="flex items-center justify-between w-full h-8 px-3 rounded border border-zinc-700 bg-zinc-800 text-xs text-zinc-300 hover:bg-zinc-700 transition-colors"
              >
                <span className="flex items-center gap-2">
                  <Globe className="h-3.5 w-3.5 text-zinc-400" />
                  Check WAF
                </span>
                <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />
              </button>

              {(selectedData.nodeType === "subdomain" ||
                selectedData.nodeType === "domain") && (
                <button
                  onClick={() =>
                    router.push(
                      `/takeover?hosts=${encodeURIComponent(selectedData.label)}`
                    )
                  }
                  className="flex items-center justify-between w-full h-8 px-3 rounded border border-zinc-700 bg-zinc-800 text-xs text-zinc-300 hover:bg-zinc-700 transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <GitBranch className="h-3.5 w-3.5 text-zinc-400" />
                    Check Takeover
                  </span>
                  <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* STATS BAR                                                           */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex items-center gap-6 px-4 py-2 bg-zinc-900 border-t border-zinc-800 text-xs text-zinc-400 shrink-0 flex-wrap">
        <span>
          Nodes:{" "}
          <strong className="text-zinc-200">{stats?.total_nodes ?? 0}</strong>
        </span>
        <span>
          Edges:{" "}
          <strong className="text-zinc-200">{stats?.total_edges ?? 0}</strong>
        </span>
        <span>
          Critical:{" "}
          <strong className="text-red-400">{stats?.critical_nodes ?? 0}</strong>
        </span>
        <span>
          High:{" "}
          <strong className="text-orange-400">{stats?.high_nodes ?? 0}</strong>
        </span>
        {Object.entries(stats?.asset_types ?? {}).map(([type, count]) => (
          <span key={type}>
            {type}:{" "}
            <strong className="text-zinc-200">{count}</strong>
          </span>
        ))}
        {loading && (
          <span className="ml-auto flex items-center gap-1 text-zinc-500">
            <Loader2 className="h-3 w-3 animate-spin" />
            Loading…
          </span>
        )}
      </div>
    </div>
  );
}
