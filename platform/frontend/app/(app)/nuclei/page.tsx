"use client";

import React, { useState, useCallback, useEffect, useRef } from "react";
import { useSearchParams } from "next/navigation";
import {
  Crosshair, Play, Square, Download, CheckCircle2,
  Wifi, Shield, ChevronDown, ChevronRight, Search,
  Tag, User, Link as LinkIcon, History, Trash2, FileText, X, RotateCcw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const CATEGORIES: { value: string; label: string; description: string }[] = [
  { value: "cves",             label: "CVEs",                description: "Known CVE vulnerabilities" },
  { value: "exposures",        label: "Exposures",           description: "Sensitive file/data exposure" },
  { value: "misconfiguration", label: "Misconfigurations",   description: "Security misconfigurations" },
  { value: "takeovers",        label: "Subdomain Takeovers", description: "Dangling DNS / takeover candidates" },
  { value: "technologies",     label: "Tech Detection",      description: "Identify running technologies" },
  { value: "default-logins",   label: "Default Logins",      description: "Default credentials check" },
  { value: "fuzzing",          label: "Fuzzing",             description: "Input fuzzing checks" },
  { value: "workflows",        label: "Workflows",           description: "Multi-step detection workflows" },
  { value: "network",          label: "Network",             description: "Network-level checks" },
  { value: "dns",              label: "DNS",                 description: "DNS record analysis" },
  { value: "ssl",              label: "SSL/TLS",             description: "Certificate and TLS checks" },
  { value: "headless",         label: "Browser Checks",      description: "Headless browser-based checks" },
  { value: "file",             label: "File Exposure",       description: "Exposed files and paths" },
  { value: "code",             label: "Code Execution",      description: "Code execution indicators" },
];

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info:     "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-400",
  info:     "bg-zinc-500",
};

type TemplateMode = "all" | "categories" | "specific";

interface NucleiFinding {
  template_id: string;
  name: string;
  severity: string;
  matched_url: string;
  extracted_results: string[];
  matcher_name: string;
  type: string;
  ip: string;
  timestamp: string;
  tags: string[];
  author: string[];
  reference: string[];
  curl_command: string;
}

interface NucleiTemplate {
  id: string;
  path: string;
  name: string;
  severity: string;
  tags: string[];
  author: string[];
  description: string;
}

interface ScanHistoryEntry {
  id: string;
  target: string;
  command?: string;
  status?: string;
  started_at: string;
  completed_at?: string;
  counts: Record<string, number>;
  total?: number;
  findings?: NucleiFinding[];
}

function FindingCard({ finding }: { finding: NucleiFinding }) {
  const [expanded, setExpanded] = useState(false);
  const sev = finding.severity?.toLowerCase() ?? "info";

  return (
    <div className={cn(
      "rounded-lg border transition-colors",
      sev === "critical" ? "border-red-500/20 bg-red-500/5" :
      sev === "high"     ? "border-orange-500/20 bg-orange-500/5" :
      sev === "medium"   ? "border-yellow-500/20" :
      "border-zinc-800"
    )}>
      <button
        className="w-full flex items-start gap-3 p-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={cn("mt-0.5 h-2 w-2 rounded-full shrink-0", SEV_DOT[sev] ?? "bg-zinc-500")} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-zinc-200">{finding.name}</span>
            <Badge className={cn("text-[10px] border capitalize py-0 h-4", SEV_COLORS[sev])}>
              {finding.severity}
            </Badge>
            {finding.matcher_name && (
              <Badge variant="outline" className="text-[10px] py-0 h-4 text-zinc-500">
                {finding.matcher_name}
              </Badge>
            )}
          </div>
          <p className="text-xs text-zinc-500 font-mono mt-0.5 truncate">{finding.matched_url}</p>
          <p className="text-[10px] text-zinc-600 mt-0.5">{finding.template_id}</p>
        </div>
        {expanded
          ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500 shrink-0 mt-0.5" />
          : <ChevronRight className="h-3.5 w-3.5 text-zinc-500 shrink-0 mt-0.5" />}
      </button>

      {expanded && (
        <div className="px-8 pb-4 space-y-3 border-t border-zinc-800/60">
          <div className="grid grid-cols-2 gap-3 pt-3 text-xs">
            {finding.ip && (
              <div>
                <p className="text-zinc-500 mb-0.5">IP</p>
                <p className="text-zinc-300 font-mono">{finding.ip}</p>
              </div>
            )}
            {finding.type && (
              <div>
                <p className="text-zinc-500 mb-0.5">Type</p>
                <p className="text-zinc-300 capitalize">{finding.type}</p>
              </div>
            )}
            {finding.author?.length > 0 && (
              <div>
                <p className="text-zinc-500 mb-0.5 flex items-center gap-1"><User className="h-2.5 w-2.5" /> Author</p>
                <p className="text-zinc-300">{finding.author.join(", ")}</p>
              </div>
            )}
            <div>
              <p className="text-zinc-500 mb-0.5 flex items-center gap-1"><Tag className="h-2.5 w-2.5" /> Tags</p>
              <div className="flex flex-wrap gap-1 mt-0.5">
                {finding.tags?.length > 0 ? finding.tags.map((t) => (
                  <Badge key={t} variant="outline" className="text-[10px] py-0 h-4">{t}</Badge>
                )) : <span className="text-zinc-600">—</span>}
              </div>
            </div>
          </div>

          {finding.extracted_results?.length > 0 && (
            <div>
              <p className="text-xs text-zinc-500 mb-1">Extracted Data</p>
              <div className="rounded-md bg-zinc-950 border border-zinc-800 p-2 space-y-0.5">
                {finding.extracted_results.map((r, i) => (
                  <p key={i} className="text-xs text-emerald-400 font-mono break-all">{r}</p>
                ))}
              </div>
            </div>
          )}

          {finding.curl_command && (
            <div>
              <p className="text-xs text-zinc-500 mb-1">cURL</p>
              <pre className="rounded-md bg-zinc-950 border border-zinc-800 p-2 text-[10px] text-zinc-400 font-mono overflow-x-auto whitespace-pre-wrap break-all">
                {finding.curl_command}
              </pre>
            </div>
          )}

          {finding.reference?.length > 0 && (
            <div>
              <p className="text-xs text-zinc-500 mb-1 flex items-center gap-1">
                <LinkIcon className="h-2.5 w-2.5" /> References
              </p>
              {finding.reference.slice(0, 3).map((r, i) => (
                <a key={i} href={r} target="_blank" rel="noopener noreferrer"
                  className="block text-[10px] text-blue-400 hover:underline truncate">
                  {r}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function NucleiPage() {
  const searchParams = useSearchParams();

  // Scan config
  const [target, setTarget]               = useState("");
  const [concurrency, setConcurrency]     = useState("25");
  const [rateLimit, setRateLimit]         = useState("150");
  const [timeout, setTimeout2]            = useState("10");
  const [followRedirects, setFollowRedirects] = useState(true);

  // Template selection
  const [templateMode, setTemplateMode]           = useState<TemplateMode>("all");
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
  const [customTemplateDir, setCustomTemplateDir]   = useState("");

  // Template browser (specific mode)
  const [templateSearch, setTemplateSearch]         = useState("");
  const [templateSevFilter, setTemplateSevFilter]   = useState("");
  const [templates, setTemplates]                   = useState<NucleiTemplate[]>([]);
  const [templatesTotal, setTemplatesTotal]         = useState(0);
  const [templatesPage, setTemplatesPage]           = useState(1);
  const [templatesLoading, setTemplatesLoading]     = useState(false);
  const [selectedTemplates, setSelectedTemplates]   = useState<string[]>([]);
  const templateSearchTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Scan state
  const [isScanning, setIsScanning]     = useState(false);
  const [findings, setFindings]         = useState<NucleiFinding[]>([]);
  const [counts, setCounts]             = useState<Record<string, number>>({});
  const [scanStatus, setScanStatus]     = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [filterSev, setFilterSev]       = useState<string | null>(null);
  const [searchQuery, setSearchQuery]   = useState("");
  const [history, setHistory]           = useState<ScanHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [showHistory, setShowHistory]   = useState(false);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await fetchWithAuth(`${API_BASE}/nuclei/history`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.items ?? []);
      }
    } catch {
      // silently ignore — history is best-effort
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const loadHistoryEntry = useCallback(async (id: string) => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/nuclei/history/${id}`);
      if (res.ok) {
        const full = await res.json();
        setFindings(full.findings ?? []);
        setCounts(full.counts ?? {});
        setTarget(full.target ?? "");
        setScanStatus("completed");
        setShowHistory(false);
      }
    } catch {
      toast.error("Failed to load scan");
    }
  }, []);

  const deleteHistoryEntry = useCallback(async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const res = await fetchWithAuth(`${API_BASE}/nuclei/history/${id}`, { method: "DELETE" });
      if (res.ok) {
        setHistory((prev) => prev.filter((h) => h.id !== id));
      }
    } catch {
      toast.error("Failed to delete scan");
    }
  }, []);
  const [progressLog, setProgressLog]   = useState<string[]>([]);
  const [runningCmd, setRunningCmd]     = useState<string>("");
  // nuclei's periodic `-stats` JSON lines drive a progress bar instead of cluttering the log
  const [scanStats, setScanStats]       = useState<{ percent: number; requests: string; matched: string; errors: string; templates: string } | null>(null);
  const progressEndRef                  = useRef<HTMLDivElement | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  // Pre-populate from URL params (?target=URL&tags=ssh,ssl)
  useEffect(() => {
    const urlTarget = searchParams.get("target");
    const urlTags   = searchParams.get("tags");
    if (urlTarget) {
      setTarget(urlTarget);
    }
    if (urlTags) {
      const tagList = urlTags.split(",").map((t) => t.trim()).filter(Boolean);
      // Map tag names to known CATEGORIES values
      const validCats = CATEGORIES.map((c) => c.value);
      const matched = tagList.filter((t) => validCats.includes(t));
      if (matched.length > 0) {
        setTemplateMode("categories");
        setSelectedCategories(matched);
      }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-scroll progress log
  useEffect(() => {
    progressEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [progressLog]);

  const toggleCategory = (cat: string) =>
    setSelectedCategories((prev) => prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]);

  const toggleSeverity = (sev: string) =>
    setSelectedSeverities((prev) => prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]);

  const toggleTemplate = (id: string) =>
    setSelectedTemplates((prev) => prev.includes(id) ? prev.filter((t) => t !== id) : [...prev, id]);

  // Fetch template list for "Specific" mode
  const fetchTemplates = useCallback(async (search: string, sevFilter: string, page: number) => {
    setTemplatesLoading(true);
    try {
      const params = new URLSearchParams({ page: String(page), per_page: "30" });
      if (search) params.set("search", search);
      if (sevFilter) params.set("severity", sevFilter);
      const res = await fetchWithAuth(`${API_BASE}/nuclei/templates?${params}`);
      if (res.ok) {
        const data = await res.json();
        setTemplates(data.items ?? []);
        setTemplatesTotal(data.total ?? 0);
      }
    } catch {
      // silent
    } finally {
      setTemplatesLoading(false);
    }
  }, []);

  useEffect(() => {
    if (templateMode !== "specific") return;
    if (templateSearchTimeout.current) clearTimeout(templateSearchTimeout.current);
    templateSearchTimeout.current = setTimeout(() => {
      fetchTemplates(templateSearch, templateSevFilter, templatesPage);
    }, 300);
    return () => { if (templateSearchTimeout.current) clearTimeout(templateSearchTimeout.current); };
  }, [templateMode, templateSearch, templateSevFilter, templatesPage, fetchTemplates]);

  const startScan = useCallback(async () => {
    if (!target.trim()) { toast.error("Please enter a target"); return; }

    setIsScanning(true);
    setScanStatus("running");
    setFindings([]);
    setCounts({});
    setFilterSev(null);
    setProgressLog([]);
    setScanStats(null);
    setRunningCmd("");

    abortRef.current = new AbortController();

    const body: Record<string, unknown> = {
      target: target.trim(),
      concurrency: parseInt(concurrency) || 25,
      rate_limit: parseInt(rateLimit) || 150,
      timeout: parseInt(timeout) || 10,
      follow_redirects: followRedirects,
    };

    if (customTemplateDir.trim()) {
      body.custom_template_dir = customTemplateDir.trim();
    } else if (templateMode === "specific" && selectedTemplates.length > 0) {
      body.templates = selectedTemplates;
    } else if (templateMode === "categories" && selectedCategories.length > 0) {
      body.categories = selectedCategories;
    }

    if (selectedSeverities.length > 0) body.severity = selectedSeverities;

    const allFindings: NucleiFinding[] = [];
    const allCounts: Record<string, number> = {};

    try {
      const res = await fetchWithAuth(`${API_BASE}/nuclei/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
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
          const dataMatch  = part.match(/^data: ([\s\S]+)/m);
          if (!eventMatch || !dataMatch) continue;
          const event = eventMatch[1];
          const data  = JSON.parse(dataMatch[1]);

          if (event === "start") {
            setRunningCmd(data.command ?? "");
          } else if (event === "progress") {
            const msg: string = data.message ?? "";
            if (msg.startsWith('{"duration"')) {
              try {
                const st = JSON.parse(msg);
                setScanStats({
                  percent: Math.min(100, Number(st.percent) || 0),
                  requests: String(st.requests ?? "0"),
                  matched: String(st.matched ?? "0"),
                  errors: String(st.errors ?? "0"),
                  templates: String(st.templates ?? "0"),
                });
              } catch {
                setProgressLog((prev) => [...prev.slice(-199), msg]);
              }
            } else {
              setProgressLog((prev) => [...prev.slice(-199), msg]);
            }
          } else if (event === "finding") {
            allFindings.push(data as NucleiFinding);
            const sev = (data.severity ?? "info").toLowerCase();
            allCounts[sev] = (allCounts[sev] ?? 0) + 1;
            setFindings([...allFindings]);
            setCounts({ ...allCounts });
          } else if (event === "complete") {
            setScanStatus("completed");
            setIsScanning(false);
            toast.success(`Nuclei scan complete — ${data.total ?? allFindings.length} finding(s)`);
            // Backend persists the completed scan to disk — just refresh the list.
            loadHistory();
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
  }, [target, templateMode, selectedCategories, selectedSeverities, selectedTemplates,
      concurrency, rateLimit, timeout, followRedirects, customTemplateDir, loadHistory]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify({ target, findings, counts }, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `nuclei-${target}-${Date.now()}.json`; a.click();
  };

  const exportCSV = () => {
    const rows = [
      ["template_id", "name", "severity", "matched_url", "ip", "tags"],
      ...findings.map((f) => [f.template_id, f.name, f.severity, f.matched_url, f.ip, (f.tags ?? []).join("|")]),
    ];
    const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `nuclei-${target}-${Date.now()}.csv`; a.click();
  };

  const filteredFindings = findings.filter((f) => {
    if (filterSev && f.severity?.toLowerCase() !== filterSev) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return f.name?.toLowerCase().includes(q) ||
        f.template_id?.toLowerCase().includes(q) ||
        f.matched_url?.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <PageHeader title="Nuclei Scanner" description="Template-based vulnerability scanner">
        <div className="flex items-center gap-2">
          {findings.length > 0 && (
            <>
              <Button variant="outline" size="sm" onClick={exportJSON} className="gap-1.5">
                <Download className="h-3.5 w-3.5" /> JSON
              </Button>
              <Button variant="outline" size="sm" onClick={exportCSV} className="gap-1.5">
                <Download className="h-3.5 w-3.5" /> CSV
              </Button>
            </>
          )}
          <Button variant="outline" size="sm" onClick={() => setShowHistory(!showHistory)} className="gap-1.5">
            <History className="h-3.5 w-3.5" /> History ({history.length})
          </Button>
        </div>
      </PageHeader>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-4">

        {/* ── Left config panel ─────────────────────────────────────── */}
        <div className="space-y-4">

          {/* Scan Configuration */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-blue-400" />
                Scan Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Target URL / Host</Label>
                <Input
                  placeholder="https://example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && !isScanning && startScan()}
                  disabled={isScanning}
                  className="font-mono text-xs"
                />
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div className="space-y-1">
                  <Label className="text-[10px] text-zinc-500">Concurrency</Label>
                  <Input value={concurrency} onChange={(e) => setConcurrency(e.target.value)} disabled={isScanning} className="text-xs h-8" />
                </div>
                <div className="space-y-1">
                  <Label className="text-[10px] text-zinc-500">Rate Limit</Label>
                  <Input value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} disabled={isScanning} className="text-xs h-8" />
                </div>
                <div className="space-y-1">
                  <Label className="text-[10px] text-zinc-500">Timeout (s)</Label>
                  <Input value={timeout} onChange={(e) => setTimeout2(e.target.value)} disabled={isScanning} className="text-xs h-8" />
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Checkbox
                  id="follow-redirects"
                  checked={followRedirects}
                  onCheckedChange={(v) => setFollowRedirects(!!v)}
                  disabled={isScanning}
                />
                <Label htmlFor="follow-redirects" className="text-xs text-zinc-400 cursor-pointer">
                  Follow redirects
                </Label>
              </div>

              {isScanning ? (
                <Button onClick={stopScan} variant="destructive" className="w-full gap-2">
                  <Square className="h-4 w-4" /> Stop Scan
                </Button>
              ) : (
                <Button onClick={startScan} className="w-full gap-2">
                  <Play className="h-4 w-4" /> Run Nuclei
                </Button>
              )}
            </CardContent>
          </Card>

          {/* Template Selection */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <FileText className="h-4 w-4 text-purple-400" />
                Templates
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {/* Mode selector */}
              <div className="flex rounded-md border border-zinc-800 overflow-hidden text-xs">
                {(["all", "categories", "specific"] as TemplateMode[]).map((mode) => (
                  <button
                    key={mode}
                    onClick={() => setTemplateMode(mode)}
                    disabled={isScanning}
                    className={cn(
                      "flex-1 py-1.5 text-center transition-colors capitalize",
                      templateMode === mode
                        ? "bg-zinc-700 text-zinc-100"
                        : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50"
                    )}
                  >
                    {mode === "all" ? "All" : mode === "categories" ? "Categories" : "Specific"}
                  </button>
                ))}
              </div>

              {/* All mode */}
              {templateMode === "all" && (
                <p className="text-xs text-zinc-500 py-1">
                  Runs all nuclei templates. You can still filter by severity below.
                </p>
              )}

              {/* Categories mode */}
              {templateMode === "categories" && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-zinc-500">
                      {selectedCategories.length === 0 ? "None selected — will run all" : `${selectedCategories.length} selected`}
                    </span>
                    <div className="flex gap-2">
                      <button onClick={() => setSelectedCategories(CATEGORIES.map(c => c.value))} className="text-[10px] text-blue-400 hover:text-blue-300">All</button>
                      <button onClick={() => setSelectedCategories([])} className="text-[10px] text-zinc-500 hover:text-zinc-300">Clear</button>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    {CATEGORIES.map((cat) => (
                      <div key={cat.value} className="flex items-start gap-2">
                        <Checkbox
                          id={`cat-${cat.value}`}
                          checked={selectedCategories.includes(cat.value)}
                          onCheckedChange={() => toggleCategory(cat.value)}
                          disabled={isScanning}
                          className="mt-0.5 shrink-0"
                        />
                        <label htmlFor={`cat-${cat.value}`} className="cursor-pointer flex-1 min-w-0">
                          <span className="text-xs text-zinc-200 block">{cat.label}</span>
                          <span className="text-[10px] text-zinc-600 block leading-tight">{cat.description}</span>
                        </label>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Specific templates mode */}
              {templateMode === "specific" && (
                <div className="space-y-2">
                  {/* Custom template dir override */}
                  <div className="space-y-1">
                    <Label className="text-[10px] text-zinc-500">Custom Template Directory (optional)</Label>
                    <Input
                      placeholder="/path/to/templates"
                      value={customTemplateDir}
                      onChange={(e) => setCustomTemplateDir(e.target.value)}
                      disabled={isScanning}
                      className="font-mono text-xs h-7"
                    />
                  </div>

                  <Separator />

                  {/* Selected chips */}
                  {selectedTemplates.length > 0 && (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-zinc-500">{selectedTemplates.length} selected</span>
                        <button onClick={() => setSelectedTemplates([])} className="text-[10px] text-zinc-500 hover:text-zinc-300">Clear all</button>
                      </div>
                      <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
                        {selectedTemplates.map((id) => (
                          <button
                            key={id}
                            onClick={() => toggleTemplate(id)}
                            className="flex items-center gap-0.5 text-[10px] bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded px-1.5 py-0.5 hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/30 transition-colors"
                          >
                            {id.length > 28 ? `…${id.slice(-26)}` : id}
                            <X className="h-2.5 w-2.5 ml-0.5" />
                          </button>
                        ))}
                      </div>
                      <Separator />
                    </div>
                  )}

                  {/* Search + severity filter */}
                  <div className="relative">
                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-zinc-500" />
                    <Input
                      placeholder="Search templates…"
                      value={templateSearch}
                      onChange={(e) => { setTemplateSearch(e.target.value); setTemplatesPage(1); }}
                      className="pl-6 h-7 text-xs"
                    />
                  </div>
                  <div className="flex gap-1 flex-wrap">
                    {["", ...SEVERITIES].map((s) => (
                      <button
                        key={s || "all"}
                        onClick={() => { setTemplateSevFilter(s); setTemplatesPage(1); }}
                        className={cn(
                          "text-[10px] px-1.5 py-0.5 rounded border transition-colors",
                          templateSevFilter === s
                            ? s ? SEV_COLORS[s] : "bg-zinc-700 text-zinc-100 border-zinc-600"
                            : "text-zinc-500 border-zinc-800 hover:border-zinc-700"
                        )}
                      >
                        {s || "All"}
                      </button>
                    ))}
                  </div>

                  {/* Template list */}
                  <div className="space-y-1 max-h-64 overflow-y-auto pr-0.5">
                    {templatesLoading ? (
                      Array.from({ length: 5 }).map((_, i) => (
                        <div key={i} className="h-8 rounded bg-zinc-800 animate-pulse" />
                      ))
                    ) : templates.length === 0 ? (
                      <p className="text-xs text-zinc-600 py-3 text-center">No templates found</p>
                    ) : (
                      templates.map((tmpl) => (
                        <div
                          key={tmpl.id}
                          onClick={() => toggleTemplate(tmpl.id)}
                          className={cn(
                            "flex items-start gap-2 rounded p-1.5 cursor-pointer transition-colors",
                            selectedTemplates.includes(tmpl.id)
                              ? "bg-blue-500/10 border border-blue-500/20"
                              : "hover:bg-zinc-800/60"
                          )}
                        >
                          <Checkbox
                            checked={selectedTemplates.includes(tmpl.id)}
                            onCheckedChange={() => toggleTemplate(tmpl.id)}
                            disabled={isScanning}
                            className="mt-0.5 shrink-0"
                          />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className="text-xs text-zinc-200 truncate max-w-[140px]">{tmpl.name}</span>
                              <Badge className={cn("text-[9px] border capitalize py-0 h-3.5 shrink-0", SEV_COLORS[tmpl.severity] ?? SEV_COLORS.info)}>
                                {tmpl.severity}
                              </Badge>
                            </div>
                            <p className="text-[10px] text-zinc-600 font-mono truncate">{tmpl.id}</p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  {templatesTotal > 30 && (
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-[10px] text-zinc-600">{templatesTotal} templates</span>
                      <div className="flex gap-1">
                        <button
                          disabled={templatesPage <= 1}
                          onClick={() => setTemplatesPage((p) => p - 1)}
                          className="text-[10px] px-1.5 py-0.5 border border-zinc-800 rounded text-zinc-500 hover:border-zinc-700 disabled:opacity-40"
                        >Prev</button>
                        <span className="text-[10px] text-zinc-600 px-1">p.{templatesPage}</span>
                        <button
                          disabled={templatesPage * 30 >= templatesTotal}
                          onClick={() => setTemplatesPage((p) => p + 1)}
                          className="text-[10px] px-1.5 py-0.5 border border-zinc-800 rounded text-zinc-500 hover:border-zinc-700 disabled:opacity-40"
                        >Next</button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              <Separator />

              {/* Severity filter — always visible */}
              <div className="space-y-2">
                <p className="text-[10px] text-zinc-500 uppercase tracking-wider font-medium">Severity Filter</p>
                <div className="space-y-1.5">
                  {SEVERITIES.map((sev) => (
                    <div key={sev} className="flex items-center gap-2">
                      <Checkbox
                        id={`sev-${sev}`}
                        checked={selectedSeverities.includes(sev)}
                        onCheckedChange={() => toggleSeverity(sev)}
                        disabled={isScanning}
                      />
                      <label htmlFor={`sev-${sev}`} className="flex items-center gap-2 cursor-pointer flex-1">
                        <div className={cn("h-2 w-2 rounded-full", SEV_DOT[sev])} />
                        <span className="text-xs text-zinc-300 capitalize">{sev}</span>
                      </label>
                      {counts[sev] !== undefined && (
                        <span className="text-xs text-zinc-500">{counts[sev]}</span>
                      )}
                    </div>
                  ))}
                  {selectedSeverities.length === 0 && (
                    <p className="text-[10px] text-zinc-600">All severities (no filter)</p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ── Results panel ─────────────────────────────────────────── */}
        <div className="xl:col-span-3 space-y-4">

          {/* Severity summary pills */}
          {(scanStatus !== "idle" || findings.length > 0) && (
            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setFilterSev(null)}
                className={cn(
                  "rounded-md px-2.5 py-1 text-xs font-medium border transition-colors",
                  filterSev === null
                    ? "bg-zinc-700 text-zinc-100 border-zinc-600"
                    : "text-zinc-400 border-zinc-800 hover:border-zinc-700"
                )}
              >
                All ({findings.length})
              </button>
              {SEVERITIES.map((sev) => {
                const count = counts[sev] ?? 0;
                if (count === 0 && scanStatus !== "running") return null;
                return (
                  <button
                    key={sev}
                    onClick={() => setFilterSev(filterSev === sev ? null : sev)}
                    className={cn(
                      "rounded-md px-2.5 py-1 text-xs font-medium border transition-colors capitalize",
                      filterSev === sev ? SEV_COLORS[sev] : "text-zinc-400 border-zinc-800 hover:border-zinc-700"
                    )}
                  >
                    {sev} ({count})
                  </button>
                );
              })}
              {isScanning && (
                <div className="flex items-center gap-1.5 ml-auto text-blue-400">
                  <Wifi className="h-3.5 w-3.5 animate-pulse" />
                  <span className="text-xs">Scanning…</span>
                </div>
              )}
              {scanStatus === "completed" && (
                <div className="flex items-center gap-1.5 ml-auto text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span className="text-xs">Complete</span>
                </div>
              )}
            </div>
          )}

          {/* Search bar */}
          {findings.length > 0 && (
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500" />
              <Input
                placeholder="Search findings by name, template ID, or URL…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 text-sm"
              />
            </div>
          )}

          {/* Live progress log — visible while scanning or if there are messages */}
          {(isScanning || progressLog.length > 0) && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 overflow-hidden">
              <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
                <div className="flex items-center gap-2">
                  {isScanning && <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />}
                  <span className="text-xs text-zinc-400 font-medium">
                    {isScanning ? "Scan in progress…" : "Scan output"}
                  </span>
                </div>
                {runningCmd && (
                  <span className="text-[10px] text-zinc-600 font-mono truncate max-w-xs" title={runningCmd}>
                    {runningCmd.length > 60 ? `…${runningCmd.slice(-58)}` : runningCmd}
                  </span>
                )}
              </div>
              {scanStats && (
                <div className="px-3 py-2 border-b border-zinc-800 space-y-1.5">
                  <div className="h-1.5 w-full rounded-full bg-zinc-800 overflow-hidden">
                    <div className="h-full bg-blue-500 transition-all" style={{ width: `${scanStats.percent}%` }} />
                  </div>
                  <div className="flex gap-4 text-[11px] text-zinc-500 font-mono">
                    <span>{scanStats.percent}%</span>
                    <span>{scanStats.templates} templates</span>
                    <span>{scanStats.requests} requests</span>
                    <span>{scanStats.matched} matched</span>
                    {scanStats.errors !== "0" && <span className="text-amber-500">{scanStats.errors} errors</span>}
                  </div>
                </div>
              )}
              <div className="max-h-48 overflow-y-auto p-3 space-y-0.5">
                {progressLog.length === 0 ? (
                  <p className="text-xs text-zinc-600">Waiting for nuclei output…</p>
                ) : (
                  progressLog.map((msg, i) => (
                    <p key={i} className="text-[11px] text-zinc-400 font-mono leading-relaxed">{msg}</p>
                  ))
                )}
                <div ref={progressEndRef} />
              </div>
            </div>
          )}

          {/* Findings */}
          {filteredFindings.length > 0 ? (
            <div className="space-y-2">
              {filteredFindings.map((finding, i) => (
                <FindingCard key={`${finding.template_id}-${i}`} finding={finding} />
              ))}
            </div>
          ) : isScanning ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-16 w-full rounded-lg" />
              ))}
            </div>
          ) : scanStatus === "completed" ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-600 space-y-3">
              <Shield className="h-10 w-10" />
              <p className="text-sm">No findings matched the current filter</p>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
              <Crosshair className="h-12 w-12" />
              <p className="text-sm">Enter a target and run a scan</p>
              <p className="text-xs text-zinc-700">Leaving templates on "All" runs every template</p>
            </div>
          )}
        </div>
      </div>

      {/* ── History ───────────────────────────────────────────────── */}
      {showHistory && (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <History className="h-4 w-4 text-zinc-400" />
                Scan History
              </CardTitle>
              <Button variant="ghost" size="sm" onClick={loadHistory} disabled={historyLoading} className="gap-1.5 text-xs text-zinc-500">
                <RotateCcw className={cn("h-3 w-3", historyLoading && "animate-spin")} /> Refresh
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {historyLoading ? (
              <p className="text-sm text-zinc-600 py-4 text-center">Loading...</p>
            ) : history.length === 0 ? (
              <p className="text-sm text-zinc-600 py-4 text-center">No scans yet</p>
            ) : (
              <div className="space-y-2">
                {history.map((entry) => (
                  <div key={entry.id} className="relative group">
                    <button
                      className="w-full flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 p-3 hover:border-zinc-700 transition-colors text-left"
                      onClick={() => loadHistoryEntry(entry.id)}
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-zinc-300 font-mono truncate">{entry.target}</p>
                        <p className="text-xs text-zinc-600">{new Date(entry.started_at).toLocaleString()}</p>
                      </div>
                      <div className="flex gap-1.5 shrink-0">
                        {SEVERITIES.map((sev) => entry.counts?.[sev] ? (
                          <Badge key={sev} className={cn("text-[10px] border capitalize py-0 h-4", SEV_COLORS[sev])}>
                            {entry.counts[sev]} {sev}
                          </Badge>
                        ) : null)}
                      </div>
                    </button>
                    <button
                      onClick={(e) => deleteHistoryEntry(entry.id, e)}
                      className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded text-zinc-600 hover:text-red-400"
                      title="Delete scan"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
