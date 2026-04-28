"use client";

import React, { useState, useRef, useCallback } from "react";
import {
  Link2,
  Play,
  Square,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
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

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface MCPServer {
  url: string;
  probe: string;
  severity: Severity;
  description: string;
  exposed_tools: string[];
  authenticated: boolean;
  version?: string;
}

interface ScanResult {
  servers: MCPServer[];
  summary: {
    total_found: number;
    unauthenticated: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-zinc-700/50 text-zinc-400 border-zinc-600/30",
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function MCPScannerPage() {
  const [target, setTarget] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [rawLines, setRawLines] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [showRaw, setShowRaw] = useState(false);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const rawEndRef = useRef<HTMLDivElement>(null);

  const startScan = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target URL");
      return;
    }

    setIsScanning(true);
    setScanStatus("running");
    setRawLines([]);
    setResult(null);
    setExpandedRow(null);
    abortRef.current = new AbortController();

    try {
      const res = await fetchWithAuth(`${API_BASE}/mcp-scanner/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Scan failed" }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
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
          const eventMatch = part.match(/^event: (\w+)/m);
          const dataMatch = part.match(/^data: ([\s\S]+)/m);
          if (!eventMatch || !dataMatch) continue;

          const event = eventMatch[1];
          let data: any;
          try { data = JSON.parse(dataMatch[1]); } catch { continue; }

          if (event === "progress" || event === "output") {
            setRawLines((prev) => {
              const next = [...prev, data.message ?? data.line ?? JSON.stringify(data)];
              setTimeout(() => rawEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
              return next;
            });
          } else if (event === "complete") {
            setResult(data);
            setScanStatus("completed");
            setIsScanning(false);
            const total = data.summary?.total_found ?? 0;
            const crit = data.summary?.critical ?? 0;
            toast.success(`Scan completed — ${total} MCP server(s) found, ${crit} critical`);
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
  }, [target]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  const sortedServers = result
    ? [...result.servers].sort(
        (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
      )
    : [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="MCP Scanner"
        description="Detect unauthenticated Model Context Protocol (MCP) servers and exposed tool endpoints"
      >
        {scanStatus === "running" && (
          <Button variant="destructive" size="sm" onClick={stopScan} className="gap-1.5">
            <Square className="h-3.5 w-3.5" /> Stop
          </Button>
        )}
      </PageHeader>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Config panel */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Link2 className="h-4 w-4 text-blue-400" />
                Scan Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Target URL</Label>
                <Input
                  placeholder="https://example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={isScanning}
                  onKeyDown={(e) => e.key === "Enter" && !isScanning && startScan()}
                  className="font-mono text-xs"
                />
                <p className="text-[10px] text-zinc-600">
                  Base URL — scanner will probe common MCP paths (/.well-known/mcp, /mcp, /api/mcp, etc.)
                </p>
              </div>

              <div className="rounded-md bg-zinc-800/50 border border-zinc-700/50 p-3 space-y-1.5">
                <p className="text-xs font-semibold text-zinc-400">What it detects</p>
                <ul className="space-y-1 text-[10px] text-zinc-500 list-disc list-inside">
                  <li>Unauthenticated MCP server endpoints</li>
                  <li>Exposed tool manifests listing available actions</li>
                  <li>Unprotected SSE streams</li>
                  <li>Misconfigured CORS allowing tool invocation</li>
                </ul>
              </div>

              <Button
                onClick={isScanning ? stopScan : startScan}
                className={cn("w-full gap-2", isScanning ? "bg-red-600 hover:bg-red-700" : "")}
                disabled={!target.trim() && !isScanning}
              >
                {isScanning ? (
                  <>
                    <Square className="h-4 w-4" /> Stop Scan
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" /> Start Scan
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Status */}
          {scanStatus !== "idle" && (
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-2">
                  {scanStatus === "running" && (
                    <>
                      <div className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
                      <span className="text-xs text-blue-400">Scanning in progress...</span>
                    </>
                  )}
                  {scanStatus === "completed" && (
                    <>
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                      <span className="text-xs text-emerald-400">Scan completed</span>
                    </>
                  )}
                  {scanStatus === "failed" && (
                    <>
                      <XCircle className="h-4 w-4 text-red-400" />
                      <span className="text-xs text-red-400">Scan failed</span>
                    </>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Summary counts */}
          {result && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                  Findings Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {(["critical", "high", "medium", "low"] as Severity[]).map((sev) => (
                  <div key={sev} className="flex items-center justify-between">
                    <Badge className={cn("text-xs border", SEVERITY_STYLES[sev])}>
                      {sev.toUpperCase()}
                    </Badge>
                    <span className="text-sm font-semibold text-zinc-300">
                      {result.summary[sev as keyof typeof result.summary]}
                    </span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Results panel */}
        <div className="lg:col-span-2 space-y-4">
          {/* Top summary cards */}
          {result && (
            <div className="grid grid-cols-2 gap-3">
              <Card>
                <CardContent className="pt-4 pb-3">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">MCP Servers Found</p>
                  <p className="text-2xl font-bold text-zinc-100">{result.summary.total_found}</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4 pb-3">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Unauthenticated</p>
                  <p className="text-2xl font-bold text-red-400">{result.summary.unauthenticated}</p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Results table */}
          {sortedServers.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-orange-400" />
                  Detected MCP Servers ({sortedServers.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-zinc-800">
                        <th className="pb-2 text-left font-semibold text-zinc-500">URL</th>
                        <th className="pb-2 text-left font-semibold text-zinc-500">Probe</th>
                        <th className="pb-2 text-left font-semibold text-zinc-500">Severity</th>
                        <th className="pb-2 text-left font-semibold text-zinc-500">Auth</th>
                        <th className="pb-2 text-left font-semibold text-zinc-500">Exposed Tools</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/50">
                      {sortedServers.map((srv, i) => (
                        <React.Fragment key={i}>
                          <tr
                            className="hover:bg-zinc-800/30 transition-colors cursor-pointer"
                            onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                          >
                            <td className="py-2 pr-3 font-mono text-blue-400 break-all max-w-[200px]">{srv.url}</td>
                            <td className="py-2 pr-3 text-zinc-400 font-mono">{srv.probe}</td>
                            <td className="py-2 pr-3">
                              <Badge className={cn("text-xs border", SEVERITY_STYLES[srv.severity])}>
                                {srv.severity.toUpperCase()}
                              </Badge>
                            </td>
                            <td className="py-2 pr-3">
                              {srv.authenticated ? (
                                <span className="flex items-center gap-1 text-emerald-400">
                                  <CheckCircle2 className="h-3 w-3" /> Auth
                                </span>
                              ) : (
                                <span className="flex items-center gap-1 text-red-400">
                                  <XCircle className="h-3 w-3" /> Open
                                </span>
                              )}
                            </td>
                            <td className="py-2">
                              {srv.exposed_tools.length > 0 ? (
                                <div className="flex flex-wrap gap-1">
                                  {srv.exposed_tools.slice(0, 3).map((tool) => (
                                    <Badge key={tool} variant="outline" className="text-[10px] font-mono py-0">
                                      {tool}
                                    </Badge>
                                  ))}
                                  {srv.exposed_tools.length > 3 && (
                                    <Badge variant="outline" className="text-[10px] py-0">
                                      +{srv.exposed_tools.length - 3}
                                    </Badge>
                                  )}
                                </div>
                              ) : (
                                <span className="text-zinc-600">—</span>
                              )}
                            </td>
                          </tr>
                          {expandedRow === i && (
                            <tr>
                              <td colSpan={5} className="pb-3 pt-1">
                                <div className="rounded-md bg-zinc-900/80 border border-zinc-800 p-3 space-y-2">
                                  <p className="text-xs text-zinc-300">
                                    <span className="font-semibold text-zinc-400">Description: </span>
                                    {srv.description}
                                  </p>
                                  {srv.version && (
                                    <p className="text-xs text-zinc-400">
                                      <span className="font-semibold">Version: </span>
                                      <span className="font-mono">{srv.version}</span>
                                    </p>
                                  )}
                                  {srv.exposed_tools.length > 0 && (
                                    <div>
                                      <p className="text-xs font-semibold text-zinc-400 mb-1">All Exposed Tools:</p>
                                      <div className="flex flex-wrap gap-1">
                                        {srv.exposed_tools.map((tool) => (
                                          <Badge key={tool} variant="outline" className="text-[10px] font-mono">
                                            {tool}
                                          </Badge>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Live output */}
          {rawLines.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <button
                  className="flex w-full items-center justify-between"
                  onClick={() => setShowRaw((v) => !v)}
                >
                  <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                    <Link2 className="h-4 w-4 text-zinc-400" />
                    Live Output ({rawLines.length} lines)
                  </CardTitle>
                  {showRaw ? <ChevronUp className="h-4 w-4 text-zinc-500" /> : <ChevronDown className="h-4 w-4 text-zinc-500" />}
                </button>
              </CardHeader>
              {showRaw && (
                <CardContent>
                  <div className="bg-zinc-950 rounded-md p-3 max-h-64 overflow-y-auto font-mono text-xs text-zinc-400">
                    {rawLines.map((line, i) => (
                      <div key={i} className="leading-5">{line}</div>
                    ))}
                    <div ref={rawEndRef} />
                  </div>
                </CardContent>
              )}
            </Card>
          )}

          {scanStatus === "idle" && rawLines.length === 0 && (
            <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 py-16 text-center">
              <Link2 className="h-10 w-10 text-zinc-700 mb-3" />
              <p className="text-sm font-medium text-zinc-500">No scan running</p>
              <p className="text-xs text-zinc-600 mt-1">
                Enter a target URL and click Start Scan to detect MCP servers
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
