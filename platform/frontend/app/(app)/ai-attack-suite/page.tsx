"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  BrainCircuit, Play, Square, Download, ChevronDown, ChevronRight,
  CheckCircle2, XCircle, AlertTriangle, Loader2, History,
  Plus, X, ExternalLink, Terminal, Clock, FileText,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

interface Requirements {
  shannon: boolean;
  docker: boolean;
  anthropic_key: boolean;
}

interface HistoryEntry {
  id: string;
  target_url: string;
  started_at: string;
  status: string;
  duration_seconds?: number;
}

type LoginType = "form" | "basic" | "token";

// ─── Simple Markdown Renderer ────────────────────────────────────────────────

function renderMarkdown(content: string): React.ReactNode[] {
  const lines = content.split("\n");
  const nodes: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Code block
    if (line.trimStart().startsWith("```")) {
      const lang = line.trimStart().slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      nodes.push(
        <div key={`code-${i}`} className="my-3 rounded-lg border border-zinc-700 overflow-hidden">
          {lang && (
            <div className="bg-zinc-800 px-3 py-1 text-[10px] text-zinc-500 font-mono border-b border-zinc-700">
              {lang}
            </div>
          )}
          <pre className="bg-zinc-950 p-3 overflow-x-auto text-xs text-zinc-300 font-mono whitespace-pre">
            {codeLines.join("\n")}
          </pre>
        </div>
      );
      i++;
      continue;
    }

    // H1
    if (/^# /.test(line)) {
      nodes.push(
        <h1 key={`h1-${i}`} className="text-xl font-bold text-zinc-100 mt-6 mb-3 border-b border-zinc-700 pb-2">
          {renderInline(line.slice(2))}
        </h1>
      );
      i++;
      continue;
    }

    // H2
    if (/^## /.test(line)) {
      nodes.push(
        <h2 key={`h2-${i}`} className="text-base font-bold text-zinc-100 mt-5 mb-2">
          {renderInline(line.slice(3))}
        </h2>
      );
      i++;
      continue;
    }

    // H3
    if (/^### /.test(line)) {
      nodes.push(
        <h3 key={`h3-${i}`} className="text-sm font-semibold text-zinc-200 mt-4 mb-1.5">
          {renderInline(line.slice(4))}
        </h3>
      );
      i++;
      continue;
    }

    // List item
    if (/^[-*] /.test(line)) {
      const listItems: string[] = [];
      while (i < lines.length && /^[-*] /.test(lines[i])) {
        listItems.push(lines[i].slice(2));
        i++;
      }
      nodes.push(
        <ul key={`ul-${i}`} className="my-2 ml-4 space-y-1 list-none">
          {listItems.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2 text-sm text-zinc-300">
              <span className="mt-1.5 h-1 w-1 rounded-full bg-zinc-500 shrink-0" />
              <span>{renderInline(item)}</span>
            </li>
          ))}
        </ul>
      );
      continue;
    }

    // Horizontal rule
    if (/^---+$/.test(line.trim())) {
      nodes.push(<hr key={`hr-${i}`} className="my-4 border-zinc-700" />);
      i++;
      continue;
    }

    // Empty line
    if (line.trim() === "") {
      nodes.push(<div key={`br-${i}`} className="h-2" />);
      i++;
      continue;
    }

    // Paragraph
    nodes.push(
      <p key={`p-${i}`} className="text-sm text-zinc-300 leading-relaxed my-1">
        {renderInline(line)}
      </p>
    );
    i++;
  }

  return nodes;
}

function renderInline(text: string): React.ReactNode {
  // Split on **bold**, `code`, and plain text
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return (
    <>
      {parts.map((part, i) => {
        if (/^\*\*[^*]+\*\*$/.test(part)) {
          return <strong key={i} className="font-semibold text-zinc-100">{part.slice(2, -2)}</strong>;
        }
        if (/^`[^`]+`$/.test(part)) {
          return <code key={i} className="font-mono text-[12px] bg-zinc-800 text-zinc-300 px-1 py-0.5 rounded">{part.slice(1, -1)}</code>;
        }
        return <span key={i}>{part}</span>;
      })}
    </>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AIAttackSuitePage() {
  // Requirements
  const [requirements, setRequirements] = useState<Requirements | null>(null);
  const [reqLoading, setReqLoading] = useState(true);

  // Config state
  const [targetUrl, setTargetUrl] = useState("");
  const [repoPath, setRepoPath] = useState("");
  const [appDescription, setAppDescription] = useState("");
  const [loginType, setLoginType] = useState<LoginType>("form");
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("");
  const [showAuth, setShowAuth] = useState(true);
  const [showRules, setShowRules] = useState(false);
  const [avoidPaths, setAvoidPaths] = useState<string[]>([]);
  const [focusPaths, setFocusPaths] = useState<string[]>([]);
  const [maxPipelines, setMaxPipelines] = useState(2);
  const [newAvoidPath, setNewAvoidPath] = useState("");
  const [newFocusPath, setNewFocusPath] = useState("");

  // Scan state
  const [scanPhase, setScanPhase] = useState<"idle" | "running" | "complete" | "failed">("idle");
  const [logLines, setLogLines] = useState<string[]>([]);
  const [reportContent, setReportContent] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [scanId, setScanId] = useState<string | null>(null);

  // History
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  const abortRef = useRef<AbortController | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startTimeRef = useRef<number>(0);

  // Fetch requirements on mount
  useEffect(() => {
    fetchWithAuth(`${API_BASE}/ai-attack-suite/requirements`)
      .then((r) => r.ok ? r.json() : null)
      .then((data) => {
        if (data) setRequirements(data);
      })
      .catch(() => {})
      .finally(() => setReqLoading(false));

    fetchWithAuth(`${API_BASE}/ai-attack-suite/scans`)
      .then((r) => r.ok ? r.json() : [])
      .then((data) => { if (Array.isArray(data)) setHistory(data); })
      .catch(() => {});
  }, []);

  // Elapsed timer
  useEffect(() => {
    if (scanPhase === "running") {
      startTimeRef.current = Date.now();
      timerRef.current = setInterval(() => {
        setElapsedSeconds(Math.floor((Date.now() - startTimeRef.current) / 1000));
      }, 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [scanPhase]);

  const addAvoidPath = () => {
    if (newAvoidPath.trim()) {
      setAvoidPaths((prev) => [...prev, newAvoidPath.trim()]);
      setNewAvoidPath("");
    }
  };
  const addFocusPath = () => {
    if (newFocusPath.trim()) {
      setFocusPaths((prev) => [...prev, newFocusPath.trim()]);
      setNewFocusPath("");
    }
  };

  const formatElapsed = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${m}:${sec.toString().padStart(2, "0")}`;
  };

  const startScan = useCallback(async () => {
    if (!targetUrl.trim()) {
      toast.error("Please enter a target URL");
      return;
    }
    if (!repoPath.trim()) {
      toast.error("Please enter the local repository path");
      return;
    }

    setScanPhase("running");
    setLogLines([]);
    setReportContent(null);
    setScanId(null);
    setElapsedSeconds(0);

    abortRef.current = new AbortController();

    try {
      const payload: Record<string, unknown> = {
        target_url: targetUrl.trim(),
        repo_path: repoPath.trim(),
        app_description: appDescription.trim(),
        login_url: loginUrl.trim() || undefined,
        login_type: loginType,
        username: loginType !== "token" ? username : undefined,
        password: loginType !== "token" ? password : undefined,
        token: loginType === "token" ? token : undefined,
        avoid_paths: avoidPaths,
        focus_paths: focusPaths,
        max_concurrent_pipelines: maxPipelines,
      };

      const res = await fetchWithAuth(`${API_BASE}/ai-attack-suite/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
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
          const eventMatch = part.match(/^event: (\S+)/m);
          const dataMatch = part.match(/^data: ([\s\S]+)/m);
          if (!eventMatch || !dataMatch) continue;

          const event = eventMatch[1];
          let data: Record<string, unknown>;
          try {
            data = JSON.parse(dataMatch[1]);
          } catch {
            continue;
          }

          if (event === "start") {
            setScanId(data.scan_id as string);
            toast.success("Shannon AI pentest started");
          } else if (event === "progress") {
            const line = data.message as string;
            setLogLines((prev) => {
              const next = [...prev, line];
              setTimeout(() => logEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
              return next;
            });
          } else if (event === "report_ready") {
            setReportContent(data.content as string);
          } else if (event === "complete") {
            setScanPhase("complete");
            toast.success(`Shannon scan complete — ${Math.round((data.duration_seconds as number) / 60)}m elapsed`);
            fetchWithAuth(`${API_BASE}/ai-attack-suite/scans`)
              .then((r) => r.ok ? r.json() : [])
              .then((d) => { if (Array.isArray(d)) setHistory(d); })
              .catch(() => {});
          } else if (event === "error") {
            setScanPhase("failed");
            toast.error(`Shannon error: ${data.message}`);
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") {
        setScanPhase("failed");
        toast.error(`Scan failed: ${err.message}`);
      } else if (err instanceof Error && err.name === "AbortError") {
        setScanPhase("idle");
      }
    }
  }, [targetUrl, repoPath, appDescription, loginUrl, loginType, username, password, token, avoidPaths, focusPaths, maxPipelines]);

  const stopScan = () => {
    abortRef.current?.abort();
    setScanPhase("idle");
    toast.info("Shannon scan stopped");
  };

  const downloadReport = () => {
    if (!reportContent) return;
    const blob = new Blob([reportContent], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `shannon-report-${targetUrl.replace(/[^a-z0-9]/gi, "_")}-${Date.now()}.md`;
    a.click();
  };

  const allRequirementsMet = requirements
    ? requirements.shannon && requirements.docker && requirements.anthropic_key
    : false;

  return (
    <div className="space-y-6">
      <PageHeader title="AI Attack Suite" description="Shannon — autonomous AI pentester with real exploit execution">
        <div className="flex items-center gap-2">
          {reportContent && (
            <Button variant="outline" size="sm" onClick={downloadReport} className="gap-1.5">
              <Download className="h-3.5 w-3.5" /> Download Report
            </Button>
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

      {/* Requirements Banner */}
      {!reqLoading && requirements && (
        <div className={cn(
          "rounded-lg border p-3 flex items-center gap-4 flex-wrap",
          allRequirementsMet ? "border-emerald-600/20 bg-emerald-600/5" : "border-yellow-600/20 bg-yellow-600/5"
        )}>
          <span className="text-xs font-semibold text-zinc-400 shrink-0">Requirements:</span>
          <RequirementItem
            label="Shannon"
            ok={requirements.shannon}
            fixHint="npm install -g @keygraph/shannon"
          />
          <RequirementItem
            label="Docker"
            ok={requirements.docker}
            fixHint="Start Docker Desktop"
          />
          <RequirementItem
            label="Anthropic API Key"
            ok={requirements.anthropic_key}
            fixHint="Set ANTHROPIC_API_KEY in env"
          />
          {!allRequirementsMet && (
            <span className="text-[11px] text-yellow-400 ml-auto">
              Missing requirements — scan may fail
            </span>
          )}
        </div>
      )}
      {reqLoading && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3 flex items-center gap-2">
          <Loader2 className="h-3.5 w-3.5 text-zinc-500 animate-spin" />
          <span className="text-xs text-zinc-500">Checking requirements…</span>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Config Panel */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <BrainCircuit className="h-4 w-4 text-blue-400" />
                Shannon Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-5">
              {/* Target */}
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Target URL <span className="text-red-400">*</span></Label>
                  <Input
                    placeholder="https://your-app.com"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    disabled={scanPhase === "running"}
                    className="font-mono text-xs"
                  />
                </div>

                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">
                    Repo Path <span className="text-red-400">*</span>
                  </Label>
                  <Input
                    placeholder="/Users/you/your-project"
                    value={repoPath}
                    onChange={(e) => setRepoPath(e.target.value)}
                    disabled={scanPhase === "running"}
                    className="font-mono text-xs"
                  />
                  <p className="text-[10px] text-zinc-600">Absolute path to local source code</p>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs text-zinc-400">App Description</Label>
                    <span className={cn("text-[10px]", appDescription.length > 480 ? "text-yellow-400" : "text-zinc-600")}>
                      {appDescription.length}/500
                    </span>
                  </div>
                  <Textarea
                    placeholder="Describe your app for Shannon's context (optional)"
                    value={appDescription}
                    onChange={(e) => setAppDescription(e.target.value.slice(0, 500))}
                    disabled={scanPhase === "running"}
                    rows={3}
                    className="text-xs resize-none"
                  />
                </div>
              </div>

              {/* Authentication */}
              <div className="space-y-2">
                <button
                  className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors w-full"
                  onClick={() => setShowAuth(!showAuth)}
                >
                  {showAuth ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                  Authentication
                </button>
                {showAuth && (
                  <div className="space-y-3 pl-4 border-l border-zinc-800">
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Login Type</Label>
                      <Select
                        value={loginType}
                        onValueChange={(v) => setLoginType(v as LoginType)}
                        disabled={scanPhase === "running"}
                      >
                        <SelectTrigger className="text-xs h-8">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="form">Form Login</SelectItem>
                          <SelectItem value="basic">HTTP Basic Auth</SelectItem>
                          <SelectItem value="token">Bearer Token</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Login URL</Label>
                      <Input
                        placeholder="https://your-app.com/login"
                        value={loginUrl}
                        onChange={(e) => setLoginUrl(e.target.value)}
                        disabled={scanPhase === "running"}
                        className="font-mono text-xs h-8"
                      />
                    </div>

                    {loginType !== "token" ? (
                      <>
                        <div className="space-y-1.5">
                          <Label className="text-xs text-zinc-400">Username</Label>
                          <Input
                            placeholder="admin"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            disabled={scanPhase === "running"}
                            className="text-xs h-8"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <Label className="text-xs text-zinc-400">Password</Label>
                          <Input
                            type="password"
                            placeholder="••••••••"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            disabled={scanPhase === "running"}
                            className="text-xs h-8"
                          />
                        </div>
                      </>
                    ) : (
                      <div className="space-y-1.5">
                        <Label className="text-xs text-zinc-400">Bearer Token</Label>
                        <Input
                          placeholder="eyJhbGciOiJIUzI1NiIs..."
                          value={token}
                          onChange={(e) => setToken(e.target.value)}
                          disabled={scanPhase === "running"}
                          className="font-mono text-xs h-8"
                        />
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Rules */}
              <div className="space-y-2">
                <button
                  className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors w-full"
                  onClick={() => setShowRules(!showRules)}
                >
                  {showRules ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                  Rules & Scope
                </button>
                {showRules && (
                  <div className="space-y-4 pl-4 border-l border-zinc-800">
                    {/* Avoid paths */}
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Paths to Avoid</Label>
                      <div className="flex gap-1.5">
                        <Input
                          placeholder="/admin, /logout"
                          value={newAvoidPath}
                          onChange={(e) => setNewAvoidPath(e.target.value)}
                          onKeyDown={(e) => e.key === "Enter" && addAvoidPath()}
                          disabled={scanPhase === "running"}
                          className="font-mono text-xs h-7 text-[11px]"
                        />
                        <Button variant="outline" size="sm" onClick={addAvoidPath} disabled={scanPhase === "running"} className="h-7 px-2">
                          <Plus className="h-3 w-3" />
                        </Button>
                      </div>
                      {avoidPaths.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {avoidPaths.map((p, i) => (
                            <div key={i} className="flex items-center gap-1 rounded bg-zinc-800 px-2 py-0.5">
                              <span className="text-[10px] font-mono text-zinc-300">{p}</span>
                              <button onClick={() => setAvoidPaths((prev) => prev.filter((_, idx) => idx !== i))} className="text-zinc-500 hover:text-zinc-300">
                                <X className="h-2.5 w-2.5" />
                              </button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Focus paths */}
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Paths to Focus</Label>
                      <div className="flex gap-1.5">
                        <Input
                          placeholder="/api/v1, /user"
                          value={newFocusPath}
                          onChange={(e) => setNewFocusPath(e.target.value)}
                          onKeyDown={(e) => e.key === "Enter" && addFocusPath()}
                          disabled={scanPhase === "running"}
                          className="font-mono text-xs h-7 text-[11px]"
                        />
                        <Button variant="outline" size="sm" onClick={addFocusPath} disabled={scanPhase === "running"} className="h-7 px-2">
                          <Plus className="h-3 w-3" />
                        </Button>
                      </div>
                      {focusPaths.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {focusPaths.map((p, i) => (
                            <div key={i} className="flex items-center gap-1 rounded bg-zinc-800 px-2 py-0.5">
                              <span className="text-[10px] font-mono text-zinc-300">{p}</span>
                              <button onClick={() => setFocusPaths((prev) => prev.filter((_, idx) => idx !== i))} className="text-zinc-500 hover:text-zinc-300">
                                <X className="h-2.5 w-2.5" />
                              </button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Max pipelines */}
                    <div className="space-y-1.5">
                      <Label className="text-xs text-zinc-400">Max Concurrent Pipelines</Label>
                      <div className="flex items-center gap-2">
                        <Input
                          type="number"
                          min={1}
                          max={4}
                          value={maxPipelines}
                          onChange={(e) => setMaxPipelines(Math.min(4, Math.max(1, parseInt(e.target.value) || 1)))}
                          disabled={scanPhase === "running"}
                          className="font-mono text-xs h-8 w-20"
                        />
                        <span className="text-[10px] text-zinc-500">1–4 parallel tasks</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Launch Button */}
              <div className="space-y-2">
                <div className="rounded-md border border-yellow-600/20 bg-yellow-600/5 p-2.5">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 shrink-0 mt-0.5" />
                    <p className="text-[11px] text-yellow-300 leading-relaxed">
                      This will execute real exploit attempts against the target. Only use on authorized systems.
                    </p>
                  </div>
                </div>

                {scanPhase === "running" ? (
                  <Button onClick={stopScan} variant="destructive" className="w-full gap-2">
                    <Square className="h-4 w-4" /> Stop Shannon
                  </Button>
                ) : (
                  <Button
                    onClick={startScan}
                    className="w-full gap-2 bg-blue-600 hover:bg-blue-700"
                  >
                    <BrainCircuit className="h-4 w-4" /> Launch AI Pentest
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Panel */}
        <div className="lg:col-span-2 space-y-4">
          {/* Idle info card */}
          {scanPhase === "idle" && !reportContent && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                  <BrainCircuit className="h-4 w-4 text-blue-400" />
                  About Shannon
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-zinc-400 leading-relaxed">
                  Shannon is an autonomous AI pentester that analyzes your source code and executes real exploits to find vulnerabilities. It combines static code analysis with dynamic testing to produce comprehensive security reports.
                </p>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3 text-center">
                    <Clock className="h-5 w-5 text-blue-400 mx-auto mb-1.5" />
                    <p className="text-xs font-semibold text-zinc-200">60–90 min</p>
                    <p className="text-[10px] text-zinc-500">Runtime per scan</p>
                  </div>
                  <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3 text-center">
                    <FileText className="h-5 w-5 text-emerald-400 mx-auto mb-1.5" />
                    <p className="text-xs font-semibold text-zinc-200">~$50 / scan</p>
                    <p className="text-[10px] text-zinc-500">Claude API usage</p>
                  </div>
                  <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3 text-center">
                    <BrainCircuit className="h-5 w-5 text-purple-400 mx-auto mb-1.5" />
                    <p className="text-xs font-semibold text-zinc-200">PoC Exploits</p>
                    <p className="text-[10px] text-zinc-500">Working proof-of-concepts</p>
                  </div>
                </div>

                <div className="rounded-md border border-zinc-800 bg-zinc-900 p-3">
                  <p className="text-xs text-zinc-400 mb-2">Shannon produces:</p>
                  <ul className="space-y-1 text-xs text-zinc-300">
                    {[
                      "Comprehensive security report with CVSS scores",
                      "Working proof-of-concept exploit code",
                      "Step-by-step reproduction guides",
                      "Prioritized remediation recommendations",
                    ].map((item, i) => (
                      <li key={i} className="flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-emerald-400 shrink-0" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="rounded-md border border-red-600/20 bg-red-600/5 p-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-3.5 w-3.5 text-red-400 shrink-0 mt-0.5" />
                    <p className="text-xs text-red-300">
                      Shannon executes real exploits. Only run against systems you are authorized to test. Unauthorized testing is illegal.
                    </p>
                  </div>
                </div>

                <a
                  href="https://github.com/KeygraphHQ/shannon"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  <ExternalLink className="h-3 w-3" />
                  KeygraphHQ/shannon on GitHub
                </a>
              </CardContent>
            </Card>
          )}

          {/* Running: live terminal */}
          {scanPhase === "running" && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-emerald-400" />
                    Shannon Live Output
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1.5">
                      <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      <span className="text-xs text-emerald-400 font-mono">{formatElapsed(elapsedSeconds)}</span>
                    </div>
                    <Button onClick={stopScan} variant="destructive" size="sm" className="gap-1.5 h-7">
                      <Square className="h-3 w-3" /> Stop
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <div className="h-[500px] overflow-y-auto bg-zinc-950 rounded-b-lg p-4 font-mono">
                  {logLines.length === 0 ? (
                    <div className="flex items-center gap-2 text-emerald-400">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span className="text-sm">Initializing Shannon…</span>
                    </div>
                  ) : (
                    logLines.map((line, i) => (
                      <div key={i} className="text-xs leading-5 text-emerald-400 whitespace-pre-wrap break-all">
                        {line}
                      </div>
                    ))
                  )}
                  <div ref={logEndRef} />
                </div>
              </CardContent>
            </Card>
          )}

          {/* Complete: report viewer */}
          {(scanPhase === "complete" || (scanPhase !== "running" && reportContent)) && reportContent && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                    <FileText className="h-4 w-4 text-blue-400" />
                    Shannon Security Report
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    {scanId && (
                      <span className="text-[10px] text-zinc-600 font-mono">{scanId}</span>
                    )}
                    <Button variant="outline" size="sm" onClick={downloadReport} className="gap-1.5 h-7">
                      <Download className="h-3.5 w-3.5" /> Download .md
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-5 max-h-[700px] overflow-y-auto">
                  {renderMarkdown(reportContent)}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Failed state */}
          {scanPhase === "failed" && !reportContent && (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500 space-y-3">
              <XCircle className="h-10 w-10 text-red-400" />
              <p className="text-sm text-red-400">Shannon scan failed</p>
              <p className="text-xs text-zinc-500">Check the error notification for details</p>
            </div>
          )}
        </div>
      </div>

      {/* History Panel */}
      {showHistory && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <History className="h-4 w-4 text-zinc-400" />
              Scan History
            </CardTitle>
          </CardHeader>
          <CardContent>
            {history.length === 0 ? (
              <p className="text-sm text-zinc-600 py-4 text-center">No past Shannon scans</p>
            ) : (
              <div className="space-y-2">
                {history.map((entry) => (
                  <div
                    key={entry.id}
                    className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 p-3"
                  >
                    <div className={cn(
                      "h-2 w-2 rounded-full shrink-0",
                      entry.status === "completed" ? "bg-emerald-400" :
                      entry.status === "failed" ? "bg-red-400" :
                      "bg-yellow-400"
                    )} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono text-zinc-200 truncate">{entry.target_url}</p>
                      <p className="text-[10px] text-zinc-500">
                        {new Date(entry.started_at).toLocaleString()}
                      </p>
                    </div>
                    <div className="text-right shrink-0">
                      {entry.duration_seconds && (
                        <p className="text-xs text-zinc-400">{Math.round(entry.duration_seconds / 60)}m</p>
                      )}
                      <p className={cn("text-[10px] capitalize",
                        entry.status === "completed" ? "text-emerald-400" :
                        entry.status === "failed" ? "text-red-400" :
                        "text-yellow-400"
                      )}>{entry.status}</p>
                    </div>
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

// ─── Helper component ─────────────────────────────────────────────────────────

function RequirementItem({ label, ok, fixHint }: { label: string; ok: boolean; fixHint: string }) {
  return (
    <div className="flex items-center gap-1.5">
      {ok ? (
        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
      ) : (
        <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
      )}
      <span className={cn("text-xs font-medium", ok ? "text-emerald-400" : "text-red-400")}>
        {label}
      </span>
      {!ok && (
        <span className="text-[10px] text-zinc-500 font-mono">({fixHint})</span>
      )}
    </div>
  );
}
