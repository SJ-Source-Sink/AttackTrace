"use client";

import React, { useState, useCallback, useRef, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import {
  Zap, Play, Square, AlertCircle, CheckCircle2, ChevronDown,
  ChevronRight, ExternalLink, History, Trash2, Settings2, Plus, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

const STATUS_COLORS: Record<number, string> = {
  200: "text-emerald-400",
  204: "text-emerald-400",
  301: "text-blue-400",
  302: "text-blue-400",
  307: "text-blue-400",
  400: "text-yellow-400",
  401: "text-orange-400",
  403: "text-orange-400",
  404: "text-zinc-500",
  405: "text-yellow-400",
  500: "text-red-400",
};

function statusColor(code: number): string {
  return STATUS_COLORS[code] ?? (code >= 500 ? "text-red-400" : code >= 400 ? "text-yellow-400" : code >= 300 ? "text-blue-400" : "text-emerald-400");
}

interface FfufResult {
  url: string;
  input: string;
  status: number;
  length: number;
  words: number;
  lines: number;
  content_type: string;
  redirect_location: string;
}

interface WordlistOption {
  label: string;
  path: string;
  category: string;
  line_count: number;
  size_bytes: number;
}

interface ScanHistoryEntry {
  id: string;
  url: string;
  results: FfufResult[];
  total: number;
  started_at: string;
}

function ResultRow({ result }: { result: FfufResult }) {
  return (
    <tr className="border-b border-zinc-800 hover:bg-zinc-800/40 transition-colors font-mono text-xs">
      <td className={cn("px-4 py-2.5 font-semibold tabular-nums", statusColor(result.status))}>
        {result.status}
      </td>
      <td className="px-4 py-2.5 text-zinc-300 max-w-xs truncate">
        {result.input || result.url}
      </td>
      <td className="px-4 py-2.5 text-zinc-400 max-w-sm truncate">
        {result.url}
        {result.url && (
          <a
            href={result.url}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-1.5 inline-flex items-center text-zinc-600 hover:text-zinc-300"
            onClick={(e) => e.stopPropagation()}
          >
            <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </td>
      <td className="px-4 py-2.5 text-zinc-500 tabular-nums">{result.length}</td>
      <td className="px-4 py-2.5 text-zinc-500 tabular-nums">{result.words}</td>
      <td className="px-4 py-2.5 text-zinc-500 tabular-nums">{result.lines}</td>
      <td className="px-4 py-2.5 text-zinc-600 max-w-xs truncate">
        {result.redirect_location || result.content_type || "—"}
      </td>
    </tr>
  );
}

export default function FfufPage() {
  const searchParams = useSearchParams();
  const [url, setUrl] = useState("http://FUZZ.example.com");
  const [method, setMethod] = useState("GET");
  const [wordlist, setWordlist] = useState("");           // selected path (or "" = auto)
  const [customWordlist, setCustomWordlist] = useState(""); // manual path when "custom" selected
  const [wordlistMode, setWordlistMode] = useState<"auto" | "pick" | "custom">("auto");
  const [availableWordlists, setAvailableWordlists] = useState<WordlistOption[]>([]);
  const [threads, setThreads] = useState(40);
  const [timeout, setTimeoutSec] = useState(10);
  const [followRedirects, setFollowRedirects] = useState(false);
  const [recursion, setRecursion] = useState(false);
  const [recursionDepth, setRecursionDepth] = useState(2);
  const [extensions, setExtensions] = useState("");
  const [matchCodes, setMatchCodes] = useState("200,204,301,302,307,401,403");
  const [filterCodes, setFilterCodes] = useState("");
  const [filterSize, setFilterSize] = useState("");
  const [postData, setPostData] = useState("");
  const [extraHeaders, setExtraHeaders] = useState<Array<{ key: string; value: string }>>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<FfufResult[]>([]);
  const [statusMsg, setStatusMsg] = useState("");
  const [progressLog, setProgressLog] = useState<string[]>([]);
  const [runningWordlist, setRunningWordlist] = useState("");
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);
  const [selectedHistoryScan, setSelectedHistoryScan] = useState<ScanHistoryEntry | null>(null);

  const esRef = useRef<EventSource | null>(null);
  const currentScanIdRef = useRef<string | null>(null);
  const progressEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    progressEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [progressLog]);

  // Pre-populate from URL params (?target=URL/FUZZ)
  useEffect(() => {
    const urlTarget = searchParams.get("target");
    if (urlTarget) {
      setUrl(urlTarget);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch available wordlists on mount
  useEffect(() => {
    fetchWithAuth(`${API_BASE}/ffuf/wordlists`)
      .then((r) => r.json())
      .then((list: WordlistOption[]) => {
        setAvailableWordlists(list);
        if (list.length > 0) {
          setWordlistMode("pick");
          setWordlist(list[0].path);
        }
      })
      .catch(() => {/* no wordlists found — stay in auto mode */});
  }, []);

  const addHeader = () => setExtraHeaders((h) => [...h, { key: "", value: "" }]);
  const removeHeader = (i: number) => setExtraHeaders((h) => h.filter((_, idx) => idx !== i));
  const updateHeader = (i: number, field: "key" | "value", val: string) =>
    setExtraHeaders((h) => h.map((hdr, idx) => idx === i ? { ...hdr, [field]: val } : hdr));

  const stopScan = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setRunning(false);
    setStatusMsg("Scan stopped.");
  }, []);

  const startScan = useCallback(async () => {
    if (!url.trim()) {
      toast.error("URL is required");
      return;
    }
    if (!url.includes("FUZZ")) {
      toast.error("URL must contain the FUZZ keyword", { description: "e.g. http://FUZZ.example.com or http://example.com/FUZZ" });
      return;
    }

    setRunning(true);
    setResults([]);
    setProgressLog([]);
    setRunningWordlist("");
    setStatusMsg("Starting scan…");
    setSelectedHistoryScan(null);

    const headers: Record<string, string> = {};
    for (const h of extraHeaders) {
      if (h.key.trim()) headers[h.key.trim()] = h.value;
    }

    const parseCodes = (s: string) =>
      s.split(",").map((c) => parseInt(c.trim(), 10)).filter((n) => !isNaN(n));
    const parseSizes = (s: string) =>
      s.split(",").map((c) => parseInt(c.trim(), 10)).filter((n) => !isNaN(n));

    const body: Record<string, unknown> = {
      url: url.trim(),
      method,
      threads,
      timeout,
      follow_redirects: followRedirects,
      recursion,
      recursion_depth: recursionDepth,
    };

    const resolvedWordlist =
      wordlistMode === "custom" ? customWordlist.trim() :
      wordlistMode === "pick" ? wordlist :
      ""; // auto
    if (resolvedWordlist) body.wordlist = resolvedWordlist;
    if (matchCodes.trim()) body.match_codes = parseCodes(matchCodes);
    if (filterCodes.trim()) body.filter_codes = parseCodes(filterCodes);
    if (filterSize.trim()) body.filter_size = parseSizes(filterSize);
    if (extensions.trim()) body.extensions = extensions.split(",").map((e) => e.trim()).filter(Boolean);
    if (Object.keys(headers).length) body.headers = headers;
    if (postData.trim() && ["POST", "PUT", "PATCH"].includes(method)) body.data = postData.trim();

    try {
      const resp = await fetchWithAuth(`${API_BASE}/ffuf/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        const detail = err.detail;
        let msg: string;
        if (typeof detail === "string") {
          msg = detail;
        } else if (typeof detail?.error?.message === "string") {
          msg = detail.error.message;
        } else if (typeof detail?.message === "string") {
          msg = detail.message;
        } else if (Array.isArray(detail) && detail[0]?.msg) {
          // Pydantic 422 validation errors
          msg = detail.map((e: { loc?: string[]; msg: string }) =>
            e.loc ? `${e.loc.slice(1).join(".")}: ${e.msg}` : e.msg
          ).join("; ");
        } else {
          msg = resp.statusText || "Scan failed";
        }
        throw new Error(msg);
      }
      if (!resp.body) throw new Error("No response body");

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let scanId = "";
      const localResults: FfufResult[] = [];

      const processChunk = (chunk: string) => {
        buffer += chunk;
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";
        for (const part of parts) {
          const lines = part.split("\n");
          let event = "";
          let data = "";
          for (const line of lines) {
            if (line.startsWith("event: ")) event = line.slice(7).trim();
            if (line.startsWith("data: ")) data = line.slice(6).trim();
          }
          if (!data) continue;
          try {
            const payload = JSON.parse(data);
            if (event === "start") {
              scanId = payload.scan_id;
              currentScanIdRef.current = scanId;
              setRunningWordlist(payload.wordlist_name ?? payload.wordlist ?? "");
              setStatusMsg(`Scanning with ${payload.wordlist_name ?? "wordlist"}…`);
            } else if (event === "progress") {
              setProgressLog((prev) => [...prev.slice(-199), payload.message]);
            } else if (event === "result") {
              localResults.push(payload as FfufResult);
              setResults([...localResults]);
            } else if (event === "complete") {
              setStatusMsg(`Done — ${payload.total} results found.`);
              setRunning(false);
              setScanHistory((prev) => [
                { id: scanId, url: url.trim(), results: localResults, total: localResults.length, started_at: new Date().toISOString() },
                ...prev.slice(0, 19),
              ]);
            } else if (event === "error") {
              toast.error("Scan error", { description: payload.message });
              setStatusMsg(`Error: ${payload.message}`);
              setRunning(false);
            }
          } catch {
            // ignore parse errors
          }
        }
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        processChunk(decoder.decode(value, { stream: true }));
      }
      if (!running) return;
      setRunning(false);
    } catch (err: unknown) {
      const raw = err instanceof Error ? err.message : String(err);
      const msg = raw && raw !== "[object Object]" ? raw : "Unknown error";
      toast.error("Failed to start scan", { description: msg });
      setStatusMsg(`Error: ${msg}`);
      setRunning(false);
    }
  }, [url, method, wordlist, wordlistMode, customWordlist, threads, timeout, followRedirects, recursion, recursionDepth, extensions, matchCodes, filterCodes, filterSize, postData, extraHeaders, running]);

  const displayResults = selectedHistoryScan ? selectedHistoryScan.results : results;

  return (
    <div className="space-y-6">
      <PageHeader
        title="ffuf"
        description="Fast web fuzzer for directory, subdomain, and parameter discovery"
      >
        {running ? (
          <Button variant="destructive" onClick={stopScan} className="gap-2">
            <Square className="h-4 w-4" />
            Stop
          </Button>
        ) : (
          <Button onClick={startScan} className="gap-2">
            <Play className="h-4 w-4" />
            Start Fuzzing
          </Button>
        )}
      </PageHeader>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Config panel */}
        <div className="lg:col-span-1 space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Target Configuration</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs">
                  URL{" "}
                  <span className="text-zinc-500 font-normal">(use FUZZ as placeholder)</span>
                </Label>
                <Input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="http://FUZZ.example.com"
                  className="font-mono text-xs h-8"
                  disabled={running}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label className="text-xs">Method</Label>
                  <select
                    value={method}
                    onChange={(e) => setMethod(e.target.value)}
                    disabled={running}
                    className="w-full h-8 rounded-md border border-zinc-700 bg-zinc-900 px-2 text-xs text-zinc-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
                  >
                    {HTTP_METHODS.map((m) => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Threads</Label>
                  <Input
                    type="number"
                    min={1}
                    max={200}
                    value={threads}
                    onChange={(e) => setThreads(parseInt(e.target.value, 10) || 40)}
                    className="h-8 text-xs"
                    disabled={running}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs">Wordlist</Label>
                <div className="space-y-1.5">
                  {/* Mode selector */}
                  <div className="flex gap-1.5">
                    {(["auto", "pick", "custom"] as const).map((mode) => (
                      <button
                        key={mode}
                        type="button"
                        onClick={() => setWordlistMode(mode)}
                        disabled={running || (mode === "pick" && availableWordlists.length === 0)}
                        className={`px-2.5 py-1 rounded text-xs font-medium transition-colors disabled:opacity-40 ${
                          wordlistMode === mode
                            ? "bg-blue-600 text-white"
                            : "bg-zinc-800 text-zinc-400 hover:text-zinc-200"
                        }`}
                      >
                        {mode === "auto" ? "Auto-detect" : mode === "pick" ? `Choose (${availableWordlists.length})` : "Custom path"}
                      </button>
                    ))}
                  </div>

                  {wordlistMode === "pick" && availableWordlists.length > 0 && (
                    <select
                      value={wordlist}
                      onChange={(e) => setWordlist(e.target.value)}
                      disabled={running}
                      className="w-full bg-zinc-900 border border-zinc-700 text-zinc-200 text-xs rounded-md px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:opacity-50"
                    >
                      {/* Group by category */}
                      {Array.from(new Set(availableWordlists.map((w) => w.category))).map((cat) => (
                        <optgroup key={cat} label={cat}>
                          {availableWordlists
                            .filter((w) => w.category === cat)
                            .map((w) => (
                              <option key={w.path} value={w.path}>
                                {w.label} — {w.line_count.toLocaleString()} lines
                              </option>
                            ))}
                        </optgroup>
                      ))}
                    </select>
                  )}

                  {wordlistMode === "custom" && (
                    <Input
                      value={customWordlist}
                      onChange={(e) => setCustomWordlist(e.target.value)}
                      placeholder="/path/to/wordlist.txt"
                      className="font-mono text-xs h-8"
                      disabled={running}
                    />
                  )}

                  {wordlistMode === "auto" && (
                    <p className="text-xs text-zinc-500">
                      Server will use the first available wordlist from common locations.
                    </p>
                  )}
                </div>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs">Match Status Codes</Label>
                <Input
                  value={matchCodes}
                  onChange={(e) => setMatchCodes(e.target.value)}
                  placeholder="200,204,301,302,307,401,403"
                  className="font-mono text-xs h-8"
                  disabled={running}
                />
              </div>

              {/* Advanced toggle */}
              <button
                className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
                onClick={() => setShowAdvanced((v) => !v)}
              >
                <Settings2 className="h-3.5 w-3.5" />
                Advanced options
                {showAdvanced ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              </button>

              {showAdvanced && (
                <div className="space-y-3 pt-1 border-t border-zinc-800">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs">Filter Codes</Label>
                      <Input
                        value={filterCodes}
                        onChange={(e) => setFilterCodes(e.target.value)}
                        placeholder="404,500"
                        className="font-mono text-xs h-8"
                        disabled={running}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs">Filter Size</Label>
                      <Input
                        value={filterSize}
                        onChange={(e) => setFilterSize(e.target.value)}
                        placeholder="0,1234"
                        className="font-mono text-xs h-8"
                        disabled={running}
                      />
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <Label className="text-xs">Extensions (comma-separated)</Label>
                    <Input
                      value={extensions}
                      onChange={(e) => setExtensions(e.target.value)}
                      placeholder="php,html,txt,js"
                      className="font-mono text-xs h-8"
                      disabled={running}
                    />
                  </div>

                  <div className="space-y-1.5">
                    <Label className="text-xs">Timeout (s)</Label>
                    <Input
                      type="number"
                      min={1}
                      max={60}
                      value={timeout}
                      onChange={(e) => setTimeoutSec(parseInt(e.target.value, 10) || 10)}
                      className="h-8 text-xs"
                      disabled={running}
                    />
                  </div>

                  {["POST", "PUT", "PATCH"].includes(method) && (
                    <div className="space-y-1.5">
                      <Label className="text-xs">POST Data</Label>
                      <Input
                        value={postData}
                        onChange={(e) => setPostData(e.target.value)}
                        placeholder="key=FUZZ&other=value"
                        className="font-mono text-xs h-8"
                        disabled={running}
                      />
                    </div>
                  )}

                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-2">
                      <Checkbox
                        id="follow-redirects"
                        checked={followRedirects}
                        onCheckedChange={(v) => setFollowRedirects(!!v)}
                        disabled={running}
                      />
                      <Label htmlFor="follow-redirects" className="text-xs cursor-pointer">Follow redirects</Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <Checkbox
                        id="recursion"
                        checked={recursion}
                        onCheckedChange={(v) => setRecursion(!!v)}
                        disabled={running}
                      />
                      <Label htmlFor="recursion" className="text-xs cursor-pointer">Recursion</Label>
                    </div>
                  </div>

                  {recursion && (
                    <div className="space-y-1.5">
                      <Label className="text-xs">Recursion Depth</Label>
                      <Input
                        type="number"
                        min={1}
                        max={10}
                        value={recursionDepth}
                        onChange={(e) => setRecursionDepth(parseInt(e.target.value, 10) || 2)}
                        className="h-8 text-xs"
                        disabled={running}
                      />
                    </div>
                  )}

                  {/* Custom headers */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label className="text-xs">Custom Headers</Label>
                      <button
                        className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"
                        onClick={addHeader}
                        disabled={running}
                      >
                        <Plus className="h-3 w-3" />
                        Add
                      </button>
                    </div>
                    {extraHeaders.map((h, i) => (
                      <div key={i} className="flex gap-1.5">
                        <Input
                          value={h.key}
                          onChange={(e) => updateHeader(i, "key", e.target.value)}
                          placeholder="Header"
                          className="font-mono text-xs h-7 w-28"
                          disabled={running}
                        />
                        <Input
                          value={h.value}
                          onChange={(e) => updateHeader(i, "value", e.target.value)}
                          placeholder="Value"
                          className="font-mono text-xs h-7 flex-1"
                          disabled={running}
                        />
                        <button
                          onClick={() => removeHeader(i)}
                          disabled={running}
                          className="text-zinc-600 hover:text-zinc-400"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Scan History */}
          {scanHistory.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <History className="h-4 w-4 text-zinc-500" />
                    History
                  </CardTitle>
                  <button
                    className="text-xs text-zinc-500 hover:text-red-400 transition-colors"
                    onClick={() => { setScanHistory([]); setSelectedHistoryScan(null); }}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </CardHeader>
              <CardContent className="space-y-1 p-3">
                {scanHistory.map((s) => (
                  <button
                    key={s.id}
                    className={cn(
                      "w-full text-left rounded px-2 py-1.5 transition-colors text-xs",
                      selectedHistoryScan?.id === s.id
                        ? "bg-blue-600/10 text-blue-300 border border-blue-600/20"
                        : "hover:bg-zinc-800 text-zinc-400"
                    )}
                    onClick={() => setSelectedHistoryScan(selectedHistoryScan?.id === s.id ? null : s)}
                  >
                    <div className="font-mono truncate">{s.url}</div>
                    <div className="text-zinc-600 mt-0.5">{s.total} results</div>
                  </button>
                ))}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Results panel */}
        <div className="lg:col-span-2 space-y-4">
          {/* Status bar */}
          <div className="flex items-center gap-3">
            {running ? (
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
                <span className="text-xs text-zinc-400">{statusMsg}</span>
              </div>
            ) : statusMsg ? (
              <div className="flex items-center gap-2">
                {statusMsg.startsWith("Error") ? (
                  <AlertCircle className="h-4 w-4 text-red-400 shrink-0" />
                ) : (
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                )}
                <span className="text-xs text-zinc-400">{statusMsg}</span>
              </div>
            ) : null}

            {displayResults.length > 0 && (
              <Badge variant="secondary" className="ml-auto text-xs">
                {displayResults.length} result{displayResults.length !== 1 ? "s" : ""}
              </Badge>
            )}
          </div>

          {/* Live progress log */}
          {(running || progressLog.length > 0) && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 overflow-hidden">
              <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
                <div className="flex items-center gap-2">
                  {running && <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />}
                  <span className="text-xs text-zinc-400 font-medium">
                    {running ? "Fuzzing in progress…" : "Scan output"}
                  </span>
                </div>
                {runningWordlist && (
                  <span className="text-[10px] text-zinc-600 font-mono">{runningWordlist}</span>
                )}
              </div>
              <div className="max-h-40 overflow-y-auto p-3 space-y-0.5">
                {progressLog.length === 0 ? (
                  <p className="text-xs text-zinc-600">Waiting for ffuf output…</p>
                ) : (
                  progressLog.map((msg, i) => (
                    <p key={i} className="text-[11px] text-zinc-400 font-mono leading-relaxed">{msg}</p>
                  ))
                )}
                <div ref={progressEndRef} />
              </div>
            </div>
          )}

          {/* Results table */}
          {displayResults.length > 0 ? (
            <div className="rounded-lg border border-zinc-800 overflow-hidden overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900">
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-zinc-400 uppercase">Status</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-zinc-400 uppercase">Fuzz Value</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-zinc-400 uppercase">URL</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-zinc-400 uppercase">Size</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-zinc-400 uppercase">Words</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-zinc-400 uppercase">Lines</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-zinc-400 uppercase">Redirect / Type</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50">
                  {displayResults.map((r, i) => (
                    <ResultRow key={i} result={r} />
                  ))}
                </tbody>
              </table>
            </div>
          ) : !running && progressLog.length === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900/50 py-16 text-center">
              <Zap className="h-10 w-10 text-zinc-700 mb-3" />
              <p className="text-sm font-medium text-zinc-400">No results yet</p>
              <p className="text-xs text-zinc-600 mt-1 max-w-xs">
                Enter a URL with <code className="font-mono text-zinc-500">FUZZ</code> keyword and click Start Fuzzing
              </p>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
