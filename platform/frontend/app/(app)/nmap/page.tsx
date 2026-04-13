"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Network, Play, Square, Download, RotateCcw, ChevronDown, ChevronUp,
  Terminal, Table2, Clock, Wifi, WifiOff, AlertCircle, CheckCircle2,
  History, Trash2, ArrowRight, ShieldAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const SCAN_TYPES = [
  { value: "quick", label: "Quick Scan", desc: "-T4 -F (top 100 ports)" },
  { value: "full_port", label: "Full Port Scan", desc: "-p- (all 65535 ports)" },
  { value: "service_version", label: "Service/Version Detection", desc: "-sV (service versions)" },
  { value: "os_detection", label: "OS Detection", desc: "-O (requires root)" },
  { value: "stealth_syn", label: "Stealth SYN Scan", desc: "-sS (requires root)" },
  { value: "aggressive", label: "Aggressive Scan", desc: "-A (OS + version + scripts)" },
  { value: "custom", label: "Custom Flags", desc: "Specify your own nmap flags" },
];

const TIMING_TEMPLATES = [
  { value: "T0", label: "T0 — Paranoid (slowest)" },
  { value: "T1", label: "T1 — Sneaky" },
  { value: "T2", label: "T2 — Polite" },
  { value: "T3", label: "T3 — Normal" },
  { value: "T4", label: "T4 — Aggressive (recommended)" },
  { value: "T5", label: "T5 — Insane (fastest)" },
];

interface PortResult {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

interface HostResult {
  host: string;
  status: string;
  os: string | null;
  ports: PortResult[];
}

interface ScanHistoryEntry {
  id: string;
  target: string;
  command: string;
  status: string;
  started_at: string;
  hosts: HostResult[];
  raw: string;
}

const STATE_COLOR: Record<string, string> = {
  open: "text-emerald-400",
  closed: "text-zinc-500",
  filtered: "text-yellow-400",
};

interface PortSuggestion {
  port: number;
  title: string;
  description: string;
  href: (host: string) => string;
}

const PORT_SUGGESTIONS: PortSuggestion[] = [
  { port: 22,   title: "SSH Audit",           description: "Run Nuclei SSH templates",         href: (h) => `/nuclei?target=${encodeURIComponent(h)}&tags=ssh` },
  { port: 80,   title: "Web Fuzzing",          description: "Discover paths with ffuf",         href: (h) => `/ffuf?target=${encodeURIComponent(`http://${h}/FUZZ`)}` },
  { port: 443,  title: "SSL/TLS Analysis",     description: "Run Nuclei SSL templates",         href: (h) => `/nuclei?target=${encodeURIComponent(`https://${h}`)}&tags=ssl` },
  { port: 3306, title: "Database Exposure",    description: "Run Nuclei database templates",    href: (h) => `/nuclei?target=${encodeURIComponent(h)}&tags=databases` },
  { port: 5432, title: "PostgreSQL Exposure",  description: "Run Nuclei database templates",    href: (h) => `/nuclei?target=${encodeURIComponent(h)}&tags=databases` },
  { port: 6379, title: "Redis Exposure",       description: "Run Nuclei network templates",     href: (h) => `/nuclei?target=${encodeURIComponent(h)}&tags=network` },
  { port: 8443, title: "SSL/TLS Analysis",     description: "Run Nuclei SSL templates",         href: (h) => `/nuclei?target=${encodeURIComponent(`https://${h}`)}&tags=ssl` },
];

export default function NmapPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [target, setTarget] = useState("");

  useEffect(() => {
    const t = searchParams.get("target");
    if (t) setTarget(decodeURIComponent(t));
  }, [searchParams]);
  const [scanType, setScanType] = useState("quick");
  const [ports, setPorts] = useState("");
  const [timing, setTiming] = useState("T4");
  const [customFlags, setCustomFlags] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [rawLines, setRawLines] = useState<string[]>([]);
  const [hosts, setHosts] = useState<HostResult[]>([]);
  const [showRaw, setShowRaw] = useState(false);
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [scanCommand, setScanCommand] = useState("");
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");

  const abortRef = useRef<AbortController | null>(null);
  const rawEndRef = useRef<HTMLDivElement>(null);

  const startScan = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target");
      return;
    }

    setIsScanning(true);
    setScanStatus("running");
    setRawLines([]);
    setHosts([]);
    setScanCommand("");

    abortRef.current = new AbortController();

    try {
      const res = await fetchWithAuth(`${API_BASE}/nmap/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          scan_type: scanType,
          ports: ports.trim() || null,
          timing,
          custom_flags: scanType === "custom" ? customFlags.trim() || null : null,
        }),
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
          const data = JSON.parse(dataMatch[1]);

          if (event === "start") {
            setScanCommand(data.command);
          } else if (event === "output") {
            setRawLines((prev) => {
              const next = [...prev, data.line];
              setTimeout(() => rawEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
              return next;
            });
          } else if (event === "complete") {
            setHosts(data.hosts ?? []);
            setScanStatus("completed");
            setIsScanning(false);
            toast.success(`Scan completed — ${data.hosts?.length ?? 0} host(s) found`);

            // Add to history
            setHistory((prev) => [
              {
                id: crypto.randomUUID(),
                target: target.trim(),
                command: scanCommand,
                status: "completed",
                started_at: new Date().toISOString(),
                hosts: data.hosts ?? [],
                raw: rawLines.join("\n"),
              },
              ...prev.slice(0, 19),
            ]);
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
  }, [target, scanType, ports, timing, customFlags, scanCommand, rawLines]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify({ command: scanCommand, hosts }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `nmap-${target}-${Date.now()}.json`;
    a.click();
  };

  const exportText = () => {
    const blob = new Blob([rawLines.join("\n")], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `nmap-${target}-${Date.now()}.txt`;
    a.click();
  };

  const openCount = hosts.reduce((n, h) => n + h.ports.filter((p) => p.state === "open").length, 0);

  return (
    <div className="space-y-6">
      <PageHeader title="Nmap Network Scanner" description="Run nmap scans directly from the platform">
        <div className="flex items-center gap-2">
          {hosts.length > 0 && (
            <>
              <Button variant="outline" size="sm" onClick={exportJSON} className="gap-1.5">
                <Download className="h-3.5 w-3.5" /> JSON
              </Button>
              <Button variant="outline" size="sm" onClick={exportText} className="gap-1.5">
                <Download className="h-3.5 w-3.5" /> TXT
              </Button>
            </>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowHistory(!showHistory)}
            className="gap-1.5"
          >
            <History className="h-3.5 w-3.5" /> History ({history.length})
          </Button>
        </div>
      </PageHeader>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Config panel */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Network className="h-4 w-4 text-blue-400" />
                Scan Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Target</Label>
                <Input
                  placeholder="192.168.1.1, 10.0.0.0/24, example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={isScanning}
                  onKeyDown={(e) => e.key === "Enter" && !isScanning && startScan()}
                  className="font-mono text-xs"
                />
                <p className="text-[10px] text-zinc-600">IP, CIDR range, or hostname</p>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Scan Type</Label>
                <Select value={scanType} onValueChange={setScanType} disabled={isScanning}>
                  <SelectTrigger className="text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SCAN_TYPES.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        <div>
                          <p className="font-medium">{t.label}</p>
                          <p className="text-[10px] text-zinc-500">{t.desc}</p>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {scanType === "custom" && (
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Custom Flags</Label>
                  <Input
                    placeholder="-sU -sV --script vuln"
                    value={customFlags}
                    onChange={(e) => setCustomFlags(e.target.value)}
                    disabled={isScanning}
                    className="font-mono text-xs"
                  />
                </div>
              )}

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Port Range</Label>
                <Input
                  placeholder="80,443,1-1024 (leave blank for default)"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  disabled={isScanning}
                  className="font-mono text-xs"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Timing Template</Label>
                <Select value={timing} onValueChange={setTiming} disabled={isScanning}>
                  <SelectTrigger className="text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TIMING_TEMPLATES.map((t) => (
                      <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {isScanning ? (
                <Button onClick={stopScan} variant="destructive" className="w-full gap-2">
                  <Square className="h-4 w-4" /> Stop Scan
                </Button>
              ) : (
                <Button onClick={startScan} className="w-full gap-2">
                  <Play className="h-4 w-4" /> Start Scan
                </Button>
              )}
            </CardContent>
          </Card>

          {/* Stats */}
          {(scanStatus !== "idle" || hosts.length > 0) && (
            <Card>
              <CardContent className="pt-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-zinc-500">Status</span>
                  <div className="flex items-center gap-1.5">
                    {scanStatus === "running" && <Wifi className="h-3.5 w-3.5 text-blue-400 animate-pulse" />}
                    {scanStatus === "completed" && <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />}
                    {scanStatus === "failed" && <AlertCircle className="h-3.5 w-3.5 text-red-400" />}
                    {scanStatus === "idle" && <WifiOff className="h-3.5 w-3.5 text-zinc-500" />}
                    <span className={cn("text-xs capitalize font-medium",
                      scanStatus === "running" && "text-blue-400",
                      scanStatus === "completed" && "text-emerald-400",
                      scanStatus === "failed" && "text-red-400",
                      scanStatus === "idle" && "text-zinc-500",
                    )}>{scanStatus}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-zinc-500">Hosts up</span>
                  <span className="text-xs font-medium text-zinc-300">{hosts.length}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-zinc-500">Open ports</span>
                  <span className="text-xs font-medium text-emerald-400">{openCount}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-zinc-500">Lines output</span>
                  <span className="text-xs font-medium text-zinc-300">{rawLines.length}</span>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Results panel */}
        <div className="lg:col-span-2 space-y-4">
          {scanCommand && (
            <div className="flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2">
              <Terminal className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
              <code className="text-xs text-zinc-400 font-mono break-all">{scanCommand}</code>
            </div>
          )}

          {/* View toggle */}
          {(rawLines.length > 0 || hosts.length > 0) && (
            <div className="flex gap-2">
              <Button
                variant={!showRaw ? "default" : "outline"}
                size="sm"
                onClick={() => setShowRaw(false)}
                className="gap-1.5"
              >
                <Table2 className="h-3.5 w-3.5" /> Parsed Table
              </Button>
              <Button
                variant={showRaw ? "default" : "outline"}
                size="sm"
                onClick={() => setShowRaw(true)}
                className="gap-1.5"
              >
                <Terminal className="h-3.5 w-3.5" /> Raw Output
              </Button>
            </div>
          )}

          {/* Raw output */}
          {showRaw && rawLines.length > 0 && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-950">
              <div className="flex items-center justify-between border-b border-zinc-800 px-3 py-2">
                <span className="text-xs text-zinc-500 font-mono">raw output</span>
                <Button variant="ghost" size="sm" onClick={() => setRawLines([])} className="h-6 w-6 p-0">
                  <RotateCcw className="h-3 w-3" />
                </Button>
              </div>
              <div className="h-[480px] overflow-y-auto p-3 space-y-0.5 font-mono text-xs">
                {rawLines.map((line, i) => (
                  <div key={i} className={cn("leading-5",
                    line.includes("open") ? "text-emerald-400" :
                    line.includes("filtered") ? "text-yellow-400" :
                    line.includes("closed") ? "text-zinc-600" :
                    line.startsWith("Nmap scan") ? "text-blue-400 font-semibold" :
                    "text-zinc-400"
                  )}>
                    {line}
                  </div>
                ))}
                <div ref={rawEndRef} />
              </div>
            </div>
          )}

          {/* Parsed table */}
          {!showRaw && hosts.length > 0 && (
            <div className="space-y-4">
              {hosts.map((host, hi) => (
                <Card key={hi}>
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                        <span className="text-sm font-semibold text-zinc-200 font-mono">{host.host}</span>
                        <Badge variant="secondary" className="text-[10px] text-emerald-400 border-emerald-400/30">
                          {host.status}
                        </Badge>
                      </div>
                      {host.os && (
                        <span className="text-xs text-zinc-500">{host.os}</span>
                      )}
                    </div>
                  </CardHeader>
                  <CardContent className="pt-0">
                    {host.ports.length === 0 ? (
                      <p className="text-xs text-zinc-600 py-2">No ports found</p>
                    ) : (
                      <div className="rounded-md border border-zinc-800 overflow-hidden">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="bg-zinc-900 border-b border-zinc-800">
                              <th className="px-3 py-2 text-left font-semibold text-zinc-400 uppercase tracking-wider">Port</th>
                              <th className="px-3 py-2 text-left font-semibold text-zinc-400 uppercase tracking-wider">Proto</th>
                              <th className="px-3 py-2 text-left font-semibold text-zinc-400 uppercase tracking-wider">State</th>
                              <th className="px-3 py-2 text-left font-semibold text-zinc-400 uppercase tracking-wider">Service</th>
                              <th className="px-3 py-2 text-left font-semibold text-zinc-400 uppercase tracking-wider">Version</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-zinc-800">
                            {host.ports.map((p, pi) => (
                              <tr key={pi} className="hover:bg-zinc-800/40">
                                <td className="px-3 py-2 font-mono font-semibold text-zinc-200">{p.port}</td>
                                <td className="px-3 py-2 text-zinc-500">{p.protocol}</td>
                                <td className={cn("px-3 py-2 font-medium", STATE_COLOR[p.state] ?? "text-zinc-400")}>{p.state}</td>
                                <td className="px-3 py-2 text-zinc-300">{p.service}</td>
                                <td className="px-3 py-2 text-zinc-500 max-w-[200px] truncate">{p.version}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* Suggested next steps */}
          {!showRaw && scanStatus === "completed" && hosts.length > 0 && (() => {
            const suggestions: Array<{ suggestion: PortSuggestion; host: string }> = [];
            for (const host of hosts) {
              const openPorts = new Set(
                host.ports.filter((p) => p.state === "open").map((p) => p.port)
              );
              for (const s of PORT_SUGGESTIONS) {
                if (openPorts.has(s.port)) {
                  // Avoid duplicate title+host combos
                  if (!suggestions.some((x) => x.host === host.host && x.suggestion.title === s.title)) {
                    suggestions.push({ suggestion: s, host: host.host });
                  }
                }
              }
            }
            if (suggestions.length === 0) return null;
            return (
              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-blue-400" />
                  Suggested Next Steps
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {suggestions.map(({ suggestion, host }, i) => (
                    <div
                      key={i}
                      className="flex items-start justify-between gap-3 rounded-lg border border-zinc-800 bg-zinc-900/60 px-4 py-3"
                    >
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-zinc-200">{suggestion.title}</p>
                        <p className="text-xs text-zinc-500 mt-0.5">{suggestion.description}</p>
                        <p className="text-[10px] text-zinc-600 font-mono mt-1">{host}</p>
                      </div>
                      <Button
                        size="sm"
                        variant="outline"
                        className="shrink-0 h-7 text-xs gap-1"
                        onClick={() => router.push(suggestion.href(host))}
                      >
                        Run <ArrowRight className="h-3 w-3" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}

          {/* Empty state while scanning */}
          {isScanning && !showRaw && rawLines.length > 0 && hosts.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500 space-y-3">
              <Network className="h-8 w-8 animate-pulse text-blue-400" />
              <p className="text-sm">Scanning {target}…</p>
              <p className="text-xs">{rawLines.length} lines received</p>
            </div>
          )}

          {!isScanning && rawLines.length === 0 && (
            <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
              <Network className="h-12 w-12" />
              <p className="text-sm">Configure a target and run a scan</p>
            </div>
          )}
        </div>
      </div>

      {/* History panel */}
      {showHistory && (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <History className="h-4 w-4 text-zinc-400" />
                Scan History
              </CardTitle>
              {history.length > 0 && (
                <Button variant="ghost" size="sm" onClick={() => setHistory([])} className="gap-1.5 text-xs text-zinc-500">
                  <Trash2 className="h-3 w-3" /> Clear
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {history.length === 0 ? (
              <p className="text-sm text-zinc-600 py-4 text-center">No scans yet</p>
            ) : (
              <div className="space-y-2">
                {history.map((entry) => (
                  <button
                    key={entry.id}
                    className="w-full flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 p-3 hover:border-zinc-700 transition-colors text-left"
                    onClick={() => {
                      setHosts(entry.hosts);
                      setRawLines(entry.raw.split("\n"));
                      setScanCommand(entry.command);
                      setScanStatus("completed");
                      setShowHistory(false);
                    }}
                  >
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono text-zinc-200">{entry.target}</p>
                      <p className="text-[10px] text-zinc-500 truncate">{entry.command}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <p className="text-xs text-zinc-400">{entry.hosts.length} host(s)</p>
                      <p className="text-[10px] text-zinc-600">
                        {new Date(entry.started_at).toLocaleTimeString()}
                      </p>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
