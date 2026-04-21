"use client";

import React, { useState, useRef, useCallback } from "react";
import {
  FlaskConical, Sparkles, ChevronDown, ChevronUp, Download,
  Copy, Check, AlertTriangle, Shield, Terminal, Globe,
  Cloud, Network, Smartphone, Layers, RefreshCw, Upload,
  X, BookOpen, Wrench, Rss, DatabaseZap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/page-header";
import { fetchWithAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// ── Types ─────────────────────────────────────────────────────────────────────

interface TestCase {
  id: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  attack_pattern: string;
  steps: string[];
  expected_result: string;
  cwe?: string | null;
  owasp?: string | null;
  tools?: {
    nuclei_tags?: string[];
    nmap?: string[];
    ffuf_wordlist?: string;
  };
  applicable_to: string[];
  tags: string[];
}

type Mode = "standard" | "ai";

// ── Severity styling ──────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
  critical: "text-red-400 bg-red-400/10 border-red-400/30",
  high:     "text-orange-400 bg-orange-400/10 border-orange-400/30",
  medium:   "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  low:      "text-blue-400 bg-blue-400/10 border-blue-400/30",
  info:     "text-zinc-400 bg-zinc-800 border-zinc-700",
};

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-red-400",
  high:     "bg-orange-400",
  medium:   "bg-yellow-400",
  low:      "bg-blue-400",
  info:     "bg-zinc-500",
};

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  "Reconnaissance":       Globe,
  "Authentication":       Shield,
  "Web Application":      Layers,
  "API Security":         Terminal,
  "Infrastructure":       Network,
  "Cloud Security":       Cloud,
  "Information Disclosure": BookOpen,
};

// ── Target type options ───────────────────────────────────────────────────────

const TARGET_TYPES = [
  { id: "web",     label: "Web App",  icon: Globe },
  { id: "api",     label: "API",      icon: Terminal },
  { id: "network", label: "Network",  icon: Network },
  { id: "cloud",   label: "Cloud",    icon: Cloud },
  { id: "mobile",  label: "Mobile",   icon: Smartphone },
];

const TECH_STACK_OPTIONS = [
  "React", "Next.js", "Vue", "Angular",
  "Node.js", "Django", "Flask", "FastAPI", "Rails", "Laravel", "Spring",
  "PostgreSQL", "MySQL", "MongoDB", "Redis",
  "AWS", "GCP", "Azure",
  "Nginx", "Apache", "Kubernetes", "Docker",
  "GraphQL", "REST", "gRPC",
  "WordPress", "Drupal",
];

// ── Components ────────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={cn(
      "inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border font-medium capitalize",
      SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info
    )}>
      <span className={cn("w-1.5 h-1.5 rounded-full", SEVERITY_DOT[severity] ?? "bg-zinc-500")} />
      {severity}
    </span>
  );
}

function TestCaseCard({ tc, index }: { tc: TestCase; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const CategoryIcon = CATEGORY_ICONS[tc.category] ?? Shield;

  return (
    <div className={cn(
      "border border-zinc-800 rounded-xl overflow-hidden transition-colors",
      expanded ? "border-zinc-700" : "hover:border-zinc-700"
    )}>
      {/* Header */}
      <button
        type="button"
        className="w-full flex items-start gap-3 px-4 py-3.5 text-left"
        onClick={() => setExpanded(e => !e)}
      >
        {/* Index */}
        <span className="text-xs text-zinc-600 font-mono w-7 shrink-0 pt-0.5">
          {String(index + 1).padStart(2, "0")}
        </span>

        {/* Icon + Title */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-zinc-100">{tc.title}</span>
            <SeverityBadge severity={tc.severity} />
          </div>
          <div className="flex items-center gap-2 mt-1">
            <CategoryIcon className="h-3 w-3 text-zinc-600 shrink-0" />
            <span className="text-xs text-zinc-500">{tc.category}</span>
            {tc.cwe && (
              <span className="text-xs text-zinc-600 font-mono">{tc.cwe}</span>
            )}
            {tc.owasp && (
              <span className="text-xs text-zinc-600">{tc.owasp}</span>
            )}
          </div>
        </div>

        {/* Expand */}
        <span className="text-zinc-600 shrink-0 mt-0.5">
          {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </span>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-zinc-800 pt-4">
          {/* Description */}
          <div>
            <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Description</p>
            <p className="text-sm text-zinc-300 leading-relaxed">{tc.description}</p>
          </div>

          {/* Attack Pattern */}
          <div>
            <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Attack Pattern</p>
            <p className="text-sm text-zinc-400">{tc.attack_pattern}</p>
          </div>

          {/* Steps */}
          <div>
            <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Steps to Execute</p>
            <ol className="space-y-2">
              {tc.steps.map((step, i) => (
                <li key={i} className="flex gap-2.5">
                  <span className="flex-shrink-0 h-5 w-5 rounded-full bg-zinc-800 border border-zinc-700 text-[10px] text-zinc-400 flex items-center justify-center font-mono">
                    {i + 1}
                  </span>
                  <span className="text-sm text-zinc-300 leading-relaxed">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {/* Expected Result */}
          <div className="bg-zinc-900 rounded-lg p-3 border border-zinc-800">
            <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-1">Expected Result</p>
            <p className="text-sm text-zinc-300">{tc.expected_result}</p>
          </div>

          {/* Tools */}
          {tc.tools && Object.keys(tc.tools).length > 0 && (
            <div>
              <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Recommended Tools</p>
              <div className="flex flex-wrap gap-2">
                {tc.tools.nuclei_tags && tc.tools.nuclei_tags.length > 0 && (
                  <div className="flex items-center gap-1.5 bg-orange-400/5 border border-orange-400/20 rounded-md px-2.5 py-1.5">
                    <Terminal className="h-3 w-3 text-orange-400" />
                    <span className="text-xs text-orange-400">nuclei -tags {tc.tools.nuclei_tags.join(",")}</span>
                  </div>
                )}
                {tc.tools.nmap && tc.tools.nmap.length > 0 && (
                  <div className="flex items-center gap-1.5 bg-cyan-400/5 border border-cyan-400/20 rounded-md px-2.5 py-1.5">
                    <Network className="h-3 w-3 text-cyan-400" />
                    <span className="text-xs text-cyan-400">nmap {tc.tools.nmap.join(" ")}</span>
                  </div>
                )}
                {tc.tools.ffuf_wordlist && (
                  <div className="flex items-center gap-1.5 bg-purple-400/5 border border-purple-400/20 rounded-md px-2.5 py-1.5">
                    <Wrench className="h-3 w-3 text-purple-400" />
                    <span className="text-xs text-purple-400">ffuf -w {tc.tools.ffuf_wordlist}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tags */}
          {tc.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {tc.tags.map(tag => (
                <span key={tag} className="text-xs text-zinc-500 bg-zinc-900 border border-zinc-800 rounded px-2 py-0.5">
                  #{tag}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SeveritySummary({ cases }: { cases: TestCase[] }) {
  const counts = cases.reduce((acc, tc) => {
    acc[tc.severity] = (acc[tc.severity] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const items = [
    { key: "critical", label: "Critical", color: "text-red-400" },
    { key: "high",     label: "High",     color: "text-orange-400" },
    { key: "medium",   label: "Medium",   color: "text-yellow-400" },
    { key: "low",      label: "Low",      color: "text-blue-400" },
    { key: "info",     label: "Info",     color: "text-zinc-400" },
  ];

  return (
    <div className="flex items-center gap-5">
      {items.map(({ key, label, color }) =>
        counts[key] ? (
          <div key={key} className="flex items-center gap-1.5">
            <span className={cn("text-xl font-bold", color)}>{counts[key]}</span>
            <span className="text-xs text-zinc-500">{label}</span>
          </div>
        ) : null
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function TestGeneratorPage() {
  const [mode, setMode] = useState<Mode>("standard");

  // Form state
  const [target, setTarget] = useState("");
  const [targetTypes, setTargetTypes] = useState<string[]>(["web"]);
  const [techStack, setTechStack] = useState<string[]>([]);
  const [scope, setScope] = useState("");
  const [threatModel, setThreatModel] = useState("");
  const [threatModelFileName, setThreatModelFileName] = useState("");

  // Results state
  const [cases, setCases] = useState<TestCase[]>([]);
  const [liveCases, setLiveCases] = useState<TestCase[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshStatus, setRefreshStatus] = useState("");
  const [aiStreamText, setAiStreamText] = useState("");
  const [filterCategory, setFilterCategory] = useState("All");
  const [filterSeverity, setFilterSeverity] = useState("All");
  const [showLive, setShowLive] = useState(false);
  const [copied, setCopied] = useState(false);
  const [expandAll, setExpandAll] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const toggleTargetType = (id: string) => {
    setTargetTypes(prev =>
      prev.includes(id) ? prev.filter(t => t !== id) : [...prev, id]
    );
  };

  const toggleTech = (t: string) => {
    setTechStack(prev =>
      prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t]
    );
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setThreatModelFileName(file.name);
    const reader = new FileReader();
    reader.onload = ev => setThreatModel(ev.target?.result as string ?? "");
    reader.readAsText(file);
  };

  const handleStandard = async () => {
    setLoading(true);
    setCases([]);
    setAiStreamText("");
    try {
      const res = await fetchWithAuth(`${API_BASE}/test-generator/standard`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, target_types: targetTypes, tech_stack: techStack, scope }),
      });
      if (!res.ok) throw new Error("Failed to generate test cases");
      const data = await res.json();
      setCases(data.items ?? []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleAI = useCallback(async () => {
    setLoading(true);
    setCases([]);
    setAiStreamText("");

    try {
      const res = await fetchWithAuth(`${API_BASE}/test-generator/ai`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          target_types: targetTypes,
          tech_stack: techStack,
          scope,
          threat_model: threatModel || null,
        }),
      });

      if (!res.ok) throw new Error("Failed to start AI generation");
      if (!res.body) throw new Error("No response body");

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let accumulated = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (line.startsWith("event: token")) continue;
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.text !== undefined) {
                accumulated += data.text;
                setAiStreamText(accumulated);
              } else if (data.items) {
                setCases(data.items);
                setAiStreamText("");
              } else if (data.message && !data.items) {
                // error or start event
              }
            } catch {}
          }
        }
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [target, targetTypes, techStack, scope, threatModel]);

  const handleGenerate = () => {
    if (mode === "standard") handleStandard();
    else handleAI();
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    setRefreshStatus("Connecting to NVD NIST CVE database…");
    try {
      const res = await fetchWithAuth(`${API_BASE}/test-generator/refresh`);
      if (!res.ok || !res.body) throw new Error("Refresh failed");

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.message) setRefreshStatus(data.message);
              if (data.items) {
                setLiveCases(data.items);
                setShowLive(true);
                setRefreshStatus(`Fetched ${data.total} live CVE test cases from NVD`);
              }
            } catch {}
          }
        }
      }
    } catch (err) {
      setRefreshStatus("Refresh failed — check network connection");
    } finally {
      setRefreshing(false);
    }
  };

  // Derived: categories & filters
  const activeCases = showLive ? [...cases, ...liveCases] : cases;
  const categories = ["All", ...Array.from(new Set(activeCases.map(c => c.category))).sort()];
  const severities = ["All", "critical", "high", "medium", "low", "info"];

  const filtered = activeCases.filter(tc => {
    if (filterCategory !== "All" && tc.category !== filterCategory) return false;
    if (filterSeverity !== "All" && tc.severity !== filterSeverity) return false;
    return true;
  });

  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(activeCases, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-test-cases-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportMarkdown = () => {
    const lines: string[] = ["# Security Test Cases\n"];
    for (const tc of activeCases) {
      lines.push(`## ${tc.id} — ${tc.title}`);
      lines.push(`**Severity:** ${tc.severity} | **Category:** ${tc.category}`);
      if (tc.cwe) lines.push(`**CWE:** ${tc.cwe}`);
      if (tc.owasp) lines.push(`**OWASP:** ${tc.owasp}`);
      lines.push(`\n**Description:** ${tc.description}`);
      lines.push(`\n**Attack Pattern:** ${tc.attack_pattern}`);
      lines.push(`\n**Steps:**`);
      tc.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
      lines.push(`\n**Expected Result:** ${tc.expected_result}\n`);
      lines.push("---\n");
    }
    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-test-cases-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyAll = async () => {
    await navigator.clipboard.writeText(JSON.stringify(activeCases, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-5xl">
      <PageHeader
        title="Security Test Case Generator"
        description="Generate comprehensive security test cases based on OWASP WSTG, PayloadsAllTheThings, and pentester.land patterns"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={handleRefresh}
          disabled={refreshing}
          className="gap-1.5 border-zinc-700"
        >
          <Rss className={cn("h-3.5 w-3.5 text-emerald-400", refreshing && "animate-pulse")} />
          {refreshing ? "Fetching CVEs…" : "Refresh from NVD"}
        </Button>
      </PageHeader>

      {/* Refresh status */}
      {(refreshing || (liveCases.length > 0)) && (
        <div className={cn(
          "flex items-center gap-3 px-4 py-2.5 rounded-lg border text-sm",
          liveCases.length > 0
            ? "bg-emerald-500/5 border-emerald-500/20 text-emerald-400"
            : "bg-zinc-900 border-zinc-800 text-zinc-400"
        )}>
          <DatabaseZap className="h-4 w-4 shrink-0" />
          <span className="flex-1">{refreshStatus}</span>
          {liveCases.length > 0 && (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowLive(v => !v)}
                className="text-xs underline"
              >
                {showLive ? "Hide CVEs" : `Show ${liveCases.length} live CVEs`}
              </button>
              <button type="button" onClick={() => { setLiveCases([]); setRefreshStatus(""); setShowLive(false); }} className="text-zinc-600 hover:text-zinc-400">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* Mode selector */}
      <div className="flex gap-1 p-1 bg-zinc-900 border border-zinc-800 rounded-xl w-fit">
        <button
          type="button"
          onClick={() => setMode("standard")}
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all",
            mode === "standard"
              ? "bg-zinc-800 text-zinc-100 shadow-sm"
              : "text-zinc-500 hover:text-zinc-300"
          )}
        >
          <FlaskConical className="h-4 w-4" />
          Standard
          <span className="text-xs text-zinc-600 font-normal">Rule-based</span>
        </button>
        <button
          type="button"
          onClick={() => setMode("ai")}
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all",
            mode === "ai"
              ? "bg-zinc-800 text-zinc-100 shadow-sm"
              : "text-zinc-500 hover:text-zinc-300"
          )}
        >
          <Sparkles className="h-4 w-4 text-purple-400" />
          AI-Assisted
          <span className="text-xs text-zinc-600 font-normal">Claude-powered</span>
        </button>
      </div>

      {/* Input form */}
      <div className="rounded-xl border border-zinc-800 p-5 space-y-5">
        {/* Target */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs font-semibold text-zinc-400 uppercase tracking-wider block mb-1.5">
              Target
            </label>
            <Input
              placeholder="e.g. app.example.com or 10.0.0.1"
              value={target}
              onChange={e => setTarget(e.target.value)}
              className="h-9 bg-zinc-950 border-zinc-700 text-sm"
            />
          </div>

          {/* Scope */}
          <div>
            <label className="text-xs font-semibold text-zinc-400 uppercase tracking-wider block mb-1.5">
              Scope / Notes
            </label>
            <Input
              placeholder="e.g. authenticated user features, payment flow"
              value={scope}
              onChange={e => setScope(e.target.value)}
              className="h-9 bg-zinc-950 border-zinc-700 text-sm"
            />
          </div>
        </div>

        {/* Target types */}
        <div>
          <label className="text-xs font-semibold text-zinc-400 uppercase tracking-wider block mb-2">
            Target Type
          </label>
          <div className="flex flex-wrap gap-2">
            {TARGET_TYPES.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => toggleTargetType(id)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all",
                  targetTypes.includes(id)
                    ? "bg-blue-500/15 border-blue-500/40 text-blue-400"
                    : "border-zinc-800 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Tech stack */}
        <div>
          <label className="text-xs font-semibold text-zinc-400 uppercase tracking-wider block mb-2">
            Technology Stack
            <span className="text-zinc-600 font-normal normal-case ml-1">(optional)</span>
          </label>
          <div className="flex flex-wrap gap-1.5">
            {TECH_STACK_OPTIONS.map(tech => (
              <button
                key={tech}
                type="button"
                onClick={() => toggleTech(tech)}
                className={cn(
                  "px-2.5 py-1 rounded-md border text-xs transition-all",
                  techStack.includes(tech)
                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                    : "border-zinc-800 text-zinc-600 hover:border-zinc-700 hover:text-zinc-400"
                )}
              >
                {tech}
              </button>
            ))}
          </div>
        </div>

        {/* AI-only: threat model upload */}
        {mode === "ai" && (
          <div>
            <label className="text-xs font-semibold text-zinc-400 uppercase tracking-wider block mb-2">
              Threat Model Document
              <span className="text-zinc-600 font-normal normal-case ml-1">(optional — paste or upload)</span>
            </label>
            <div className="space-y-2">
              {threatModelFileName ? (
                <div className="flex items-center gap-2 text-sm text-zinc-400 bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2">
                  <Upload className="h-4 w-4 text-zinc-500" />
                  {threatModelFileName}
                  <button
                    type="button"
                    onClick={() => { setThreatModel(""); setThreatModelFileName(""); }}
                    className="ml-auto text-zinc-600 hover:text-zinc-400"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              ) : (
                <Textarea
                  placeholder="Paste your threat model, architecture description, or security requirements here..."
                  value={threatModel}
                  onChange={e => setThreatModel(e.target.value)}
                  className="min-h-24 bg-zinc-950 border-zinc-700 text-sm resize-y"
                />
              )}
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="text-xs text-zinc-500 hover:text-zinc-300 flex items-center gap-1"
                >
                  <Upload className="h-3 w-3" />
                  Upload file (.txt, .md, .json)
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".txt,.md,.json,.pdf"
                  className="hidden"
                  onChange={handleFileUpload}
                />
              </div>
            </div>
          </div>
        )}

        {/* Generate button */}
        <div className="flex items-center gap-3 pt-1">
          <Button
            onClick={handleGenerate}
            disabled={loading}
            className={cn(
              "gap-2",
              mode === "ai"
                ? "bg-purple-600 hover:bg-purple-500 text-white"
                : "bg-blue-600 hover:bg-blue-500 text-white"
            )}
          >
            {loading ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : mode === "ai" ? (
              <Sparkles className="h-4 w-4" />
            ) : (
              <FlaskConical className="h-4 w-4" />
            )}
            {loading
              ? mode === "ai" ? "Generating with AI…" : "Generating…"
              : mode === "ai" ? "Generate with AI" : "Generate Test Cases"
            }
          </Button>
          {cases.length > 0 && (
            <span className="text-xs text-zinc-500">
              {cases.length} test cases generated
              {liveCases.length > 0 && showLive && ` + ${liveCases.length} live CVEs`}
            </span>
          )}
        </div>
      </div>

      {/* AI streaming preview */}
      {mode === "ai" && loading && aiStreamText && (
        <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Sparkles className="h-4 w-4 text-purple-400 animate-pulse" />
            <span className="text-sm text-purple-400 font-medium">AI is generating test cases…</span>
          </div>
          <pre className="text-xs text-zinc-400 font-mono whitespace-pre-wrap max-h-48 overflow-y-auto">
            {aiStreamText}
          </pre>
        </div>
      )}

      {/* Results */}
      {activeCases.length > 0 && (
        <div className="space-y-4">
          {/* Results header */}
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h2 className="text-sm font-semibold text-zinc-200">
                  {filtered.length} Test Cases
                  {filtered.length !== activeCases.length && (
                    <span className="text-zinc-500 font-normal"> (filtered from {activeCases.length})</span>
                  )}
                </h2>
                {mode === "ai" && (
                  <Badge variant="secondary" className="text-xs py-0 px-1.5 h-5 gap-1">
                    <Sparkles className="h-2.5 w-2.5 text-purple-400" />
                    AI
                  </Badge>
                )}
              </div>
              <SeveritySummary cases={activeCases} />
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={handleCopyAll} className="gap-1.5 border-zinc-700 text-xs">
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                {copied ? "Copied" : "Copy JSON"}
              </Button>
              <Button variant="outline" size="sm" onClick={handleExportMarkdown} className="gap-1.5 border-zinc-700 text-xs">
                <Download className="h-3.5 w-3.5" />
                Markdown
              </Button>
              <Button variant="outline" size="sm" onClick={handleExportJSON} className="gap-1.5 border-zinc-700 text-xs">
                <Download className="h-3.5 w-3.5" />
                JSON
              </Button>
            </div>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            {/* Category filter */}
            <div className="flex gap-1 flex-wrap">
              {categories.map(c => (
                <button
                  key={c}
                  type="button"
                  onClick={() => setFilterCategory(c)}
                  className={cn(
                    "text-xs px-2.5 py-1 rounded-md border transition-colors",
                    filterCategory === c
                      ? "bg-blue-500/15 border-blue-500/40 text-blue-400"
                      : "border-zinc-800 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
                  )}
                >
                  {c}
                </button>
              ))}
            </div>

            {/* Severity filter */}
            <div className="flex gap-1">
              {severities.map(s => {
                const style = s === "All" ? "" : SEVERITY_STYLES[s];
                return (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setFilterSeverity(s)}
                    className={cn(
                      "text-xs px-2.5 py-1 rounded-md border capitalize transition-colors",
                      filterSeverity === s
                        ? s === "All"
                          ? "bg-blue-500/15 border-blue-500/40 text-blue-400"
                          : cn("border opacity-100", style)
                        : "border-zinc-800 text-zinc-600 hover:border-zinc-700"
                    )}
                  >
                    {s}
                  </button>
                );
              })}
            </div>

            <button
              type="button"
              onClick={() => setExpandAll(e => !e)}
              className="ml-auto text-xs text-zinc-500 hover:text-zinc-300 flex items-center gap-1"
            >
              {expandAll ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              {expandAll ? "Collapse all" : "Expand all"}
            </button>
          </div>

          {/* Test case list */}
          <div className="space-y-2">
            {filtered.map((tc, i) => (
              <TestCaseCard key={tc.id} tc={tc} index={i} />
            ))}
          </div>

          {filtered.length === 0 && (
            <div className="py-12 text-center">
              <AlertTriangle className="h-8 w-8 text-zinc-700 mx-auto mb-3" />
              <p className="text-sm text-zinc-500">No test cases match the selected filters</p>
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!loading && activeCases.length === 0 && (
        <div className="py-16 text-center border border-dashed border-zinc-800 rounded-xl">
          <FlaskConical className="h-10 w-10 text-zinc-700 mx-auto mb-3" />
          <p className="text-sm text-zinc-500 mb-1">No test cases generated yet</p>
          <p className="text-xs text-zinc-600">
            {mode === "standard"
              ? "Select your target type and click Generate Test Cases"
              : "Provide target details and optionally upload a threat model, then click Generate with AI"
            }
          </p>
        </div>
      )}
    </div>
  );
}
