"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Swords, Play, Square, Download, ChevronDown, ChevronRight,
  Shield, AlertTriangle, CheckCircle2, XCircle,
  History, Plus, X, Loader2, Globe, LogIn, Users, BrainCircuit,
  Network, Search, Eye, EyeOff, Key,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { PageHeader } from "@/components/shared/page-header";
import { BurpImport } from "@/components/attack-suite/burp-import";
import { AttackAgentPanel } from "@/components/attack-suite/attack-agent-panel";
import { cn } from "@/lib/utils";
import { fetchWithAuth, getAccessToken } from "@/lib/auth";
import { toast } from "sonner";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const MODULES = [
  { id: "crawl",          label: "Web Crawler",           category: "Recon",      description: "BFS crawl: discovers all endpoints, forms, params, and IDs before testing" },
  { id: "headers",        label: "Security Headers",       category: "Hardening",  description: "Missing/misconfigured HTTP security headers (CSP, HSTS, CORS, X-Frame-Options)" },
  { id: "cors",           label: "CORS Misconfiguration",  category: "Access",     description: "Reflected origin, null origin, subdomain bypass — #2 in dataset (1050 reports)" },
  { id: "csrf",           label: "CSRF Bypass",            category: "Access",     description: "SameSite bypass, missing tokens, login CSRF — #3 in dataset (660 reports)" },
  { id: "xss",            label: "XSS Scanner",            category: "Injection",  description: "Reflected & stored XSS in discovered forms and URL params (611 stored XSS reports)" },
  { id: "sqli",           label: "SQL Injection",          category: "Injection",  description: "Time-based blind and error-based SQLi across all discovered parameters" },
  { id: "nosql",          label: "NoSQL Injection",        category: "Injection",  description: "MongoDB operator injection, auth bypass — 43 reports" },
  { id: "ssti",           label: "SSTI Detection",         category: "Injection",  description: "Server-side template injection in Jinja2, Freemarker, Twig, SpEL, ERB" },
  { id: "xxe",            label: "XXE Injection",          category: "Injection",  description: "XML External Entity attacks on XML-accepting endpoints and file uploads" },
  { id: "ssrf",           label: "SSRF Prober",            category: "Injection",  description: "Cloud metadata, internal services — 79 SSRF + 18 blind SSRF reports" },
  { id: "idor",           label: "IDOR Scanner",           category: "Access",     description: "Cross-account access on crawled endpoints — #1 in dataset (1854 reports)" },
  { id: "privilege",      label: "Privilege Escalation",   category: "Access",     description: "Mass assignment, role tampering, admin paths — 276 reports" },
  { id: "account",        label: "Account Takeover",       category: "Auth",       description: "Password reset host injection, email change, OAuth flow — 167 reports" },
  { id: "broken_auth",    label: "Broken Authentication",  category: "Auth",       description: "Weak/default credentials, password strength, brute-force protection" },
  { id: "rate_limit",     label: "Rate Limit / Lockout",   category: "Auth",       description: "Brute-force protection, account lockout, OTP rate limiting, X-Forwarded-For bypass" },
  { id: "session",        label: "Session Management",     category: "Auth",       description: "Session fixation, cookie flags (HttpOnly/Secure/SameSite), logout invalidation" },
  { id: "2fa_bypass",     label: "2FA/MFA Bypass",         category: "Auth",       description: "OTP null code, brute force, step skip — common in auth-heavy apps" },
  { id: "oauth",          label: "OAuth Misconfiguration", category: "Auth",       description: "Open redirect in callback, missing state parameter, PKCE bypass, token leakage" },
  { id: "jwt",            label: "JWT Analyzer",           category: "Auth",       description: "alg:none, weak secrets, kid injection, RS256→HS256 confusion, expired acceptance" },
  { id: "auth_bypass",    label: "Auth Bypass",            category: "Auth",       description: "Admin paths, X-Forwarded-For, X-Original-URL, method override, path traversal" },
  { id: "http_method",    label: "HTTP Method Tampering",  category: "Access",     description: "PUT/DELETE/PATCH on GET-only endpoints, X-HTTP-Method-Override, TRACE" },
  { id: "cache",          label: "Cache Poisoning",        category: "Injection",  description: "Unkeyed header injection (X-Forwarded-Host, X-Host) — 104 reports" },
  { id: "redirect",       label: "Open Redirect",          category: "Access",     description: "OAuth redirect_uri, redirect param bypass — 168 reports, chains to ATO" },
  { id: "graphql",        label: "GraphQL Inspector",      category: "API",        description: "Introspection, batch abuse, auth bypass — 175 reports" },
  { id: "race",           label: "Race Conditions",        category: "Logic",      description: "Parallel request attacks on state-changing endpoints — 39 reports" },
  { id: "business",       label: "Business Logic",         category: "Logic",      description: "Negative price, quantity overflow, coupon stacking — 51 reports" },
  { id: "file_upload",    label: "File Upload Bypass",     category: "Injection",  description: "Extension bypass, null-byte, size limit, type restriction bypass" },
  { id: "info_disclosure", label: "Info Disclosure",       category: "Recon",      description: "Backup files, .env, Git exposure, FTP directory, log files" },
  { id: "deserialization", label: "Deserialization",       category: "Injection",  description: "Prototype pollution, zip bomb, XML billion laughs" },
  // Hunt-skill modules
  { id: "smuggling",       label: "HTTP Smuggling",         category: "Injection",  description: "CL.TE/TE.CL/CL.0 desync — high-value reverse proxy target ($30k–$46k)" },
  { id: "crlf",            label: "CRLF Injection",         category: "Injection",  description: "Response splitting → XSS past CSP script-src 'self', log poisoning" },
  { id: "hpp",             label: "HTTP Param Pollution",   category: "Access",     description: "ACL IDOR bypass via duplicate params, WAF evasion ($13.5k confirmed)" },
  { id: "saml",            label: "SAML Attacks",           category: "Auth",       description: "Signature wrapping, XXE in SAMLResponse, attribute pollution → admin ATO" },
  { id: "websocket",       label: "WebSocket / CSWSH",      category: "Access",     description: "Cross-Site WebSocket Hijacking — no CORS protection, Origin not checked" },
  // Principal engineer additions
  { id: "host_header",     label: "Host Header Injection",  category: "Access",     description: "Password reset poisoning, cache deception, routing bypass via Host/X-Forwarded-Host" },
  { id: "path_traversal",  label: "Path Traversal / LFI",   category: "Injection",  description: "Directory traversal (../), null-byte, double-encoding, PHP wrapper exploitation" },
  { id: "oauth_advanced",  label: "OAuth Advanced Attacks", category: "Auth",       description: "PKCE bypass, scope escalation, token leakage via referrer, authorization code interception" },
  { id: "type_confusion",  label: "JSON Type Confusion",    category: "Injection",  description: "Array/object injection bypassing string checks, null coercion, integer vs string auth" },
  { id: "api_versioning",  label: "API Version Downgrade",  category: "Access",     description: "Older API versions with relaxed security, version enumeration, auth bypass on legacy routes" },
  // Tier 3/4 additions
  { id: "graphql_deep",    label: "GraphQL Deep Testing",   category: "API",        description: "Schema-driven SQLi/SSTI/NoSQL injection into real query & mutation args, GraphQL IDOR, mutation auth-bypass, CSRF surface" },
  { id: "custom_templates", label: "Custom Detection Templates", category: "Custom", description: "Declarative, data-driven checks defined as YAML — add new detection coverage without writing Python" },
];

const PRESETS: Record<string, { label: string; description: string; modules: string[] }> = {
  quick: {
    label: "Quick",
    description: "Fast surface scan (~2 min)",
    modules: ["crawl", "headers", "cors", "xss", "sqli", "idor", "auth_bypass", "info_disclosure", "crlf"],
  },
  standard: {
    label: "Standard",
    description: "Comprehensive scan (~10 min)",
    modules: ["crawl", "headers", "cors", "csrf", "xss", "sqli", "nosql", "ssrf", "idor",
              "privilege", "account", "broken_auth", "rate_limit", "session", "jwt",
              "auth_bypass", "http_method", "redirect", "graphql", "file_upload", "info_disclosure",
              "crlf", "hpp", "websocket"],
  },
  auth_focus: {
    label: "Auth Deep-Dive",
    description: "All auth & access modules",
    modules: ["crawl", "cors", "csrf", "idor", "privilege", "account", "broken_auth",
              "rate_limit", "session", "2fa_bypass", "oauth", "jwt", "auth_bypass",
              "http_method", "redirect", "saml", "hpp"],
  },
  full: {
    label: "Full Scan",
    // Derived from MODULES.length rather than hardcoded — a hardcoded count
    // here silently went stale by 7 modules (this text still said "34" with
    // 41 real modules registered) since nothing kept it in sync as modules
    // were added. Found via live testing (2026-09-15).
    description: `All ${MODULES.length} modules (~20 min)`,
    modules: MODULES.map((m) => m.id),
  },
};

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-600/10 text-red-400 border-red-600/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-zinc-500",
};

const SEV_BADGE_TEXT: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-zinc-400",
};

interface AttackFinding {
  id: string;
  module: string;
  test_name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: string;
  title: string;
  description: string;
  evidence: string;
  url: string;
  is_vulnerable: boolean;
  remediation: string;
  ai_analysis?: string;
}

interface ScanCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface CrawlStats {
  pages: number;
  forms: number;
  endpoints: number;
  tech_stack: string[];
}

interface WafInfo {
  detected: boolean;
  vendor: string | null;
  confidence: string;
}

interface HistoryEntry {
  id: string;
  target: string;
  started_at: string;
  total_findings: number;
  status: string;
}

function FindingCard({ finding }: { finding: AttackFinding }) {
  const [expanded, setExpanded] = useState(false);
  const [remExpanded, setRemExpanded] = useState(false);
  const sev = finding.severity ?? "info";

  return (
    <div className={cn(
      "rounded-lg border transition-colors",
      sev === "critical" ? "border-red-600/20 bg-red-600/5" :
      sev === "high"     ? "border-orange-500/20 bg-orange-500/5" :
      sev === "medium"   ? "border-yellow-500/20 bg-yellow-500/5" :
                           "border-zinc-800"
    )}>
      <button
        className="w-full flex items-start gap-3 p-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={cn("mt-1 h-2 w-2 rounded-full shrink-0", SEV_DOT[sev] ?? "bg-zinc-500")} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-zinc-200">{finding.title}</span>
            <Badge className={cn("text-[10px] border capitalize py-0 h-4", SEV_COLORS[sev])}>
              {finding.severity}
            </Badge>
            <Badge variant="outline" className="text-[10px] py-0 h-4 text-zinc-500">
              {finding.module}
            </Badge>
            {finding.confidence && finding.confidence !== "medium" && (
              <Badge variant="outline" className="text-[10px] py-0 h-4 text-zinc-600">
                {finding.confidence} conf
              </Badge>
            )}
            {finding.is_vulnerable ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-red-600/10 border border-red-600/30 px-2 py-0 text-[10px] text-red-400 h-4">
                <XCircle className="h-2.5 w-2.5" /> Vulnerable
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 px-2 py-0 text-[10px] text-emerald-400 h-4">
                <CheckCircle2 className="h-2.5 w-2.5" /> Not Vulnerable
              </span>
            )}
          </div>
          <p className="text-[10px] text-zinc-500 mt-0.5">{finding.test_name}</p>
          {finding.url && (
            <p className="text-xs text-zinc-500 font-mono mt-0.5 truncate">{finding.url}</p>
          )}
        </div>
        {expanded
          ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500 shrink-0 mt-0.5" />
          : <ChevronRight className="h-3.5 w-3.5 text-zinc-500 shrink-0 mt-0.5" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-zinc-800/60">
          {finding.description && (
            <div className="pt-3">
              <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Description</p>
              <p className="text-xs text-zinc-300">{finding.description}</p>
            </div>
          )}
          {finding.evidence && (
            <div>
              <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Evidence</p>
              <div className="rounded-md border border-zinc-800 bg-zinc-950 p-2 max-h-[200px] overflow-y-auto">
                <pre className="text-xs text-zinc-300 font-mono whitespace-pre-wrap break-all">{finding.evidence}</pre>
              </div>
            </div>
          )}
          {finding.ai_analysis && (
            <div className="rounded-md border border-purple-600/30 bg-purple-600/5 p-2.5">
              <div className="flex items-center gap-1.5 mb-1">
                <BrainCircuit className="h-3 w-3 text-purple-400" />
                <p className="text-[10px] text-purple-400 font-medium uppercase tracking-wider">Claude Analysis</p>
              </div>
              <p className="text-xs text-zinc-300 leading-relaxed">{finding.ai_analysis}</p>
            </div>
          )}
          {finding.remediation && (
            <div>
              <button
                className="flex items-center gap-1 text-[10px] text-zinc-500 uppercase tracking-wider hover:text-zinc-300 transition-colors"
                onClick={(e) => { e.stopPropagation(); setRemExpanded(!remExpanded); }}
              >
                {remExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                Remediation
              </button>
              {remExpanded && (
                <p className="text-xs text-zinc-300 mt-1 pl-3 border-l border-zinc-700">{finding.remediation}</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Section header used in config panel
// ─────────────────────────────────────────────────────────────
function SectionToggle({
  icon, label, enabled, onToggle, children, badge,
}: {
  icon: React.ReactNode;
  label: string;
  enabled: boolean;
  onToggle: () => void;
  children: React.ReactNode;
  badge?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-zinc-800">
      <div className="flex items-center gap-2 px-3 py-2">
        <button
          className="flex items-center gap-2 flex-1 text-left"
          onClick={() => setOpen(!open)}
        >
          {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
          <span className="text-zinc-400">{icon}</span>
          <span className="text-xs font-medium text-zinc-300">{label}</span>
          {badge && <Badge variant="secondary" className="text-[10px] py-0 h-4">{badge}</Badge>}
        </button>
        <Switch checked={enabled} onCheckedChange={onToggle} />
      </div>
      {open && enabled && (
        <div className="px-4 pb-4 pt-1 border-t border-zinc-800 space-y-3">
          {children}
        </div>
      )}
      {open && !enabled && (
        <div className="px-4 pb-3 pt-1 border-t border-zinc-800">
          <p className="text-[11px] text-zinc-600 italic">Enable to configure</p>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────
export default function AttackSuitePage() {
  const [activeTab, setActiveTab] = useState<"scanner" | "burp" | "agent">("scanner");

  // Target + basic options
  const [target, setTarget] = useState("");
  const [followRedirects, setFollowRedirects] = useState(true);
  const [timeout, setTimeoutVal] = useState(15);
  const [aiAnalysis, setAiAnalysis] = useState(false);
  const [anthropicKey, setAnthropicKey] = useState(() =>
    typeof window !== "undefined" ? (localStorage.getItem("attack_suite_anthropic_key") ?? "") : ""
  );
  const [showApiKey, setShowApiKey] = useState(false);

  // Modules
  const [selectedModules, setSelectedModules] = useState<Set<string>>(
    new Set(MODULES.map((m) => m.id))
  );

  // Auth headers (manual key-value)
  const [authHeaders, setAuthHeaders] = useState<{ key: string; value: string }[]>([]);
  const [showAuthHeaders, setShowAuthHeaders] = useState(false);

  // Crawler config
  const [crawlerEnabled, setCrawlerEnabled] = useState(true);
  const [crawlerDepth, setCrawlerDepth] = useState(3);
  const [crawlerPages, setCrawlerPages] = useState(50);
  const [crawlerRobots, setCrawlerRobots] = useState(true);

  // Login config
  const [loginEnabled, setLoginEnabled] = useState(false);
  const [loginUrl, setLoginUrl] = useState("");
  const [loginType, setLoginType] = useState<"form" | "bearer" | "basic" | "cookie" | "rest_json">("form");
  const [loginTokenPath, setLoginTokenPath] = useState("access_token");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginBearerToken, setLoginBearerToken] = useState("");
  const [loginCookie, setLoginCookie] = useState("");
  const [loginUsernameField, setLoginUsernameField] = useState("username");
  const [loginPasswordField, setLoginPasswordField] = useState("password");

  // Account 2 config (IDOR)
  const [account2Enabled, setAccount2Enabled] = useState(false);
  const [account2Bearer, setAccount2Bearer] = useState("");
  const [account2Cookie, setAccount2Cookie] = useState("");
  const [account2LoginType, setAccount2LoginType] = useState<"bearer" | "cookie" | "rest_json">("rest_json");
  const [account2LoginUrl, setAccount2LoginUrl] = useState("");
  const [account2Username, setAccount2Username] = useState("");
  const [account2Password, setAccount2Password] = useState("");
  const [account2TokenPath, setAccount2TokenPath] = useState("access_token");

  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [progressMessages, setProgressMessages] = useState<{ module: string; message: string }[]>([]);
  const [showProgress, setShowProgress] = useState(true);
  const [findings, setFindings] = useState<AttackFinding[]>([]);
  const [counts, setCounts] = useState<ScanCounts>({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  const [crawlStats, setCrawlStats] = useState<CrawlStats | null>(null);
  const [aiPlan, setAiPlan] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [wafInfo, setWafInfo] = useState<WafInfo | null>(null);

  // Test auth state
  const [testAuthResult, setTestAuthResult] = useState<{
    reachable?: boolean;
    auth_success?: boolean;
    auth_type?: string;
    tech_stack?: string[];
    error?: string;
  } | null>(null);
  const [testingAuth, setTestingAuth] = useState(false);

  // History
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  const abortRef = useRef<AbortController | null>(null);
  const progressEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchWithAuth(`${API_BASE}/attack-suite/scans`)
      .then((r) => r.ok ? r.json() : [])
      .then((data) => { if (Array.isArray(data)) setHistory(data); })
      .catch(() => {});
  }, []);

  const toggleModule = (id: string) => {
    setSelectedModules((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const addAuthHeader = () => setAuthHeaders((p) => [...p, { key: "", value: "" }]);
  const removeAuthHeader = (i: number) => setAuthHeaders((p) => p.filter((_, idx) => idx !== i));
  const updateAuthHeader = (i: number, field: "key" | "value", val: string) =>
    setAuthHeaders((p) => p.map((h, idx) => idx === i ? { ...h, [field]: val } : h));

  const startScan = useCallback(async () => {
    if (!target.trim()) { toast.error("Please enter a target URL"); return; }
    if (selectedModules.size === 0) { toast.error("Select at least one module"); return; }

    setIsScanning(true);
    setScanStatus("running");
    setProgressMessages([]);
    setFindings([]);
    setCounts({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    setCrawlStats(null);
    setAiPlan(null);
    setScanId(null);
    setWafInfo(null);

    abortRef.current = new AbortController();

    const builtHeaders: Record<string, string> = {};
    for (const h of authHeaders) {
      if (h.key.trim()) builtHeaders[h.key.trim()] = h.value;
    }

    const body = {
      target: target.trim(),
      modules: Array.from(selectedModules),
      auth_headers: builtHeaders,
      follow_redirects: followRedirects,
      timeout,
      ai_analysis: aiAnalysis,
      anthropic_api_key: anthropicKey.trim() || undefined,
      crawler: {
        enabled: crawlerEnabled,
        max_depth: crawlerDepth,
        max_pages: crawlerPages,
        respect_robots: crawlerRobots,
      },
      login: {
        enabled: loginEnabled,
        login_url: loginUrl,
        login_type: loginType,
        username: loginUsername,
        password: loginPassword,
        username_field: loginUsernameField,
        password_field: loginPasswordField,
        bearer_token: loginBearerToken,
        cookie: loginCookie,
        token_path: loginTokenPath,
      },
      account2: {
        enabled: account2Enabled,
        login_type: account2LoginType,
        login_url: account2LoginUrl,
        username: account2Username,
        password: account2Password,
        token_path: account2TokenPath,
        bearer_token: account2Bearer,
        cookie: account2Cookie,
      },
    };

    try {
      const token = getAccessToken();
      const res = await fetch(`${API_BASE}/attack-suite/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
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
          const eventMatch = part.match(/^event: (\S+)/m);
          const dataMatch = part.match(/^data: ([\s\S]+)/m);
          if (!eventMatch || !dataMatch) continue;

          const event = eventMatch[1];
          let data: Record<string, unknown>;
          try { data = JSON.parse(dataMatch[1]); } catch { continue; }

          if (event === "start") {
            setScanId(data.scan_id as string);
            toast.success(`Scan started against ${data.target}`);
          } else if (event === "crawl_complete") {
            setCrawlStats({
              pages: data.pages as number,
              forms: data.forms as number,
              endpoints: data.endpoints as number,
              tech_stack: (data.tech_stack as string[]) ?? [],
            });
            setProgressMessages((p) => [...p, {
              module: "crawl",
              message: `Crawl complete — ${data.pages} pages, ${data.forms} forms, ${data.endpoints} endpoints`,
            }]);
          } else if (event === "waf_detected") {
            setWafInfo(data as unknown as WafInfo);
          } else if (event === "ai_plan") {
            setAiPlan(data.plan as string);
            setProgressMessages((p) => [...p, { module: "ai", message: "AI strategy plan generated" }]);
          } else if (event === "progress") {
            setProgressMessages((prev) => {
              const next = [...prev, { module: (data.module as string) ?? "", message: data.message as string }];
              window.setTimeout(() => progressEndRef.current?.scrollIntoView({ behavior: "smooth" }), 0);
              return next;
            });
          } else if (event === "finding") {
            const f = data as unknown as AttackFinding;
            setFindings((prev) => [...prev, f]);
            if (f.is_vulnerable) {
              setCounts((prev) => ({ ...prev, [f.severity]: (prev[f.severity] ?? 0) + 1 }));
            }
          } else if (event === "complete") {
            const completeCounts = data.counts as ScanCounts;
            if (completeCounts) setCounts(completeCounts);
            if (data.waf_info) setWafInfo(data.waf_info as unknown as WafInfo);
            setScanStatus("completed");
            setIsScanning(false);
            toast.success(`Scan complete — ${data.total_findings ?? 0} finding(s)`);
            fetchWithAuth(`${API_BASE}/attack-suite/scans`)
              .then((r) => r.ok ? r.json() : [])
              .then((d) => { if (Array.isArray(d)) setHistory(d); })
              .catch(() => {});
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
  }, [
    target, selectedModules, authHeaders, followRedirects, timeout, aiAnalysis,
    crawlerEnabled, crawlerDepth, crawlerPages, crawlerRobots,
    loginEnabled, loginUrl, loginType, loginUsername, loginPassword,
    loginUsernameField, loginPasswordField, loginBearerToken, loginCookie, loginTokenPath,
    account2Enabled, account2LoginType, account2LoginUrl, account2Username, account2Password,
    account2TokenPath, account2Bearer, account2Cookie,
  ]);

  const stopScan = () => {
    abortRef.current?.abort();
    setIsScanning(false);
    setScanStatus("idle");
    toast.info("Scan stopped");
  };

  const testAuth = useCallback(async () => {
    if (!target.trim()) { toast.error("Enter a target URL first"); return; }
    setTestingAuth(true);
    setTestAuthResult(null);
    const body = {
      target: target.trim(),
      modules: [],
      auth_headers: Object.fromEntries(authHeaders.filter(h => h.key).map(h => [h.key, h.value])),
      follow_redirects: followRedirects,
      timeout,
      login: {
        enabled: loginEnabled, login_url: loginUrl, login_type: loginType,
        username: loginUsername, password: loginPassword,
        username_field: loginUsernameField, password_field: loginPasswordField,
        bearer_token: loginBearerToken, cookie: loginCookie, token_path: loginTokenPath,
      },
      account2: { enabled: false },
    };
    try {
      const r = await fetchWithAuth(`${API_BASE}/attack-suite/test-auth`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (r.ok) {
        const data = await r.json();
        setTestAuthResult(data);
        if (data.reachable && (!loginEnabled || data.auth_success)) {
          toast.success(loginEnabled ? `Auth successful (${data.auth_type})` : "Target is reachable");
        } else if (data.error) {
          toast.error(`Test failed: ${data.error}`);
        }
      }
    } catch (e) {
      toast.error("Test connection failed");
    } finally {
      setTestingAuth(false);
    }
  }, [target, authHeaders, followRedirects, timeout, loginEnabled, loginUrl, loginType,
      loginUsername, loginPassword, loginUsernameField, loginPasswordField,
      loginBearerToken, loginCookie, loginTokenPath]);

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify({ scan_id: scanId, target, findings }, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `attack-suite-${target.replace(/[^a-z0-9]/gi, "_")}-${Date.now()}.json`;
    a.click();
  };

  const findingsByModule = findings.reduce<Record<string, AttackFinding[]>>((acc, f) => {
    if (!acc[f.module]) acc[f.module] = [];
    acc[f.module].push(f);
    return acc;
  }, {});

  const totalVulnerable = findings.filter((f) => f.is_vulnerable).length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Suite"
        description="Adaptive web security scanner — crawler + pattern library from 5700+ bug bounty reports + AI planner"
      >
        <div className="flex items-center gap-2">
          {findings.length > 0 && (
            <Button variant="outline" size="sm" onClick={exportJSON} className="gap-1.5">
              <Download className="h-3.5 w-3.5" /> Export JSON
            </Button>
          )}
          <Button
            variant="outline" size="sm"
            onClick={() => setShowHistory(!showHistory)}
            className="gap-1.5"
          >
            <History className="h-3.5 w-3.5" /> History ({history.length})
          </Button>
        </div>
      </PageHeader>

      {/* ── Tab switcher ── */}
      <div className="flex items-center gap-1 rounded-lg bg-zinc-900 border border-zinc-800 p-1 w-fit">
        <button
          onClick={() => setActiveTab("scanner")}
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors",
            activeTab === "scanner"
              ? "bg-zinc-700 text-zinc-100"
              : "text-zinc-500 hover:text-zinc-300"
          )}
        >
          <Swords className="h-3.5 w-3.5" />
          Scanner
        </button>
        <button
          onClick={() => setActiveTab("burp")}
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors",
            activeTab === "burp"
              ? "bg-orange-600 text-white"
              : "text-zinc-500 hover:text-zinc-300"
          )}
        >
          <Network className="h-3.5 w-3.5" />
          Burp Import
        </button>
        <button
          onClick={() => setActiveTab("agent")}
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors",
            activeTab === "agent"
              ? "bg-violet-600 text-white"
              : "text-zinc-500 hover:text-zinc-300"
          )}
        >
          <BrainCircuit className="h-3.5 w-3.5" />
          AI Agent
        </button>
      </div>

      {/* ── Burp Import tab ── */}
      {activeTab === "burp" && (
        <BurpImport />
      )}

      {/* ── AI Agent tab ── */}
      {activeTab === "agent" && (
        <AttackAgentPanel defaultTarget={target} />
      )}

      {/* ── Scanner tab ── */}
      {activeTab === "scanner" && <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">

        {/* ── Config Panel ── */}
        <div className="space-y-4">

          {/* Target + run */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
                <Swords className="h-4 w-4 text-blue-400" />
                Scan Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-5">

              {/* Target URL */}
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400">Target URL</Label>
                <Input
                  placeholder="https://example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={isScanning}
                  className="font-mono text-xs"
                />
              </div>

              {/* Modules grid */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-zinc-400">Modules ({selectedModules.size}/{MODULES.length})</Label>
                  <div className="flex items-center gap-2">
                    <button
                      className="text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
                      onClick={() => setSelectedModules(new Set(MODULES.map((m) => m.id)))}
                      disabled={isScanning}
                    >All</button>
                    <span className="text-zinc-700 text-[10px]">/</span>
                    <button
                      className="text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
                      onClick={() => setSelectedModules(new Set())}
                      disabled={isScanning}
                    >None</button>
                  </div>
                </div>

                {/* Presets */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-zinc-400">Presets</Label>
                  <div className="grid grid-cols-2 gap-1">
                    {Object.entries(PRESETS).map(([key, preset]) => (
                      <button
                        key={key}
                        type="button"
                        disabled={isScanning}
                        onClick={() => setSelectedModules(new Set(preset.modules))}
                        className="rounded border border-zinc-700 px-2 py-1.5 text-left transition-colors hover:border-blue-500/50 hover:bg-blue-600/5 disabled:opacity-50"
                      >
                        <p className="text-[11px] font-medium text-zinc-300">{preset.label}</p>
                        <p className="text-[10px] text-zinc-600">{preset.description}</p>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-1">
                  {MODULES.map((mod) => (
                    <div
                      key={mod.id}
                      className={cn(
                        "flex items-start gap-2 rounded-md border p-2 cursor-pointer transition-colors",
                        selectedModules.has(mod.id)
                          ? "border-blue-600/30 bg-blue-600/5"
                          : "border-zinc-800 hover:border-zinc-700",
                        isScanning && "opacity-50 cursor-not-allowed"
                      )}
                      onClick={() => !isScanning && toggleModule(mod.id)}
                    >
                      <Checkbox
                        checked={selectedModules.has(mod.id)}
                        onCheckedChange={() => !isScanning && toggleModule(mod.id)}
                        aria-label={`Include ${mod.label} module`}
                        className="mt-0.5"
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <p className="text-xs font-medium text-zinc-300">{mod.label}</p>
                          <span className="text-[9px] text-zinc-600 border border-zinc-700 rounded px-1">{mod.category}</span>
                        </div>
                        <p className="text-[10px] text-zinc-500 leading-tight mt-0.5">{mod.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Auth Headers */}
              <div className="space-y-2">
                <button
                  className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors w-full"
                  onClick={() => setShowAuthHeaders(!showAuthHeaders)}
                >
                  {showAuthHeaders
                    ? <ChevronDown className="h-3 w-3" />
                    : <ChevronRight className="h-3 w-3" />}
                  Auth Headers
                  {authHeaders.length > 0 && (
                    <Badge variant="secondary" className="text-[10px] py-0 h-4 ml-auto">{authHeaders.length}</Badge>
                  )}
                </button>
                {showAuthHeaders && (
                  <div className="space-y-2 pl-4 border-l border-zinc-800">
                    {authHeaders.map((h, i) => (
                      <div key={i} className="flex items-center gap-1.5">
                        <Input
                          placeholder="Header-Name"
                          value={h.key}
                          onChange={(e) => updateAuthHeader(i, "key", e.target.value)}
                          disabled={isScanning}
                          className="font-mono text-xs h-7 text-[11px]"
                        />
                        <span className="text-zinc-600 text-xs">:</span>
                        <Input
                          placeholder="value"
                          value={h.value}
                          onChange={(e) => updateAuthHeader(i, "value", e.target.value)}
                          disabled={isScanning}
                          className="font-mono text-xs h-7 text-[11px]"
                        />
                        <button
                          onClick={() => removeAuthHeader(i)}
                          disabled={isScanning}
                          className="text-zinc-600 hover:text-zinc-300 transition-colors shrink-0"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                    <button
                      onClick={addAuthHeader}
                      disabled={isScanning}
                      className="flex items-center gap-1 text-[11px] text-zinc-500 hover:text-zinc-300 transition-colors"
                    >
                      <Plus className="h-3 w-3" /> Add header
                    </button>
                  </div>
                )}
              </div>

              {/* Follow Redirects */}
              <div className="flex items-center justify-between">
                <Label className="text-xs text-zinc-400">Follow Redirects</Label>
                <Switch checked={followRedirects} onCheckedChange={setFollowRedirects} disabled={isScanning} />
              </div>

              {/* Timeout */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-zinc-400">Request Timeout</Label>
                  <span className="text-xs font-mono text-zinc-300">{timeout}s</span>
                </div>
                <Slider
                  min={5} max={60} step={5}
                  value={[timeout]} onValueChange={([v]) => setTimeoutVal(v)}
                  disabled={isScanning} className="w-full"
                />
                <div className="flex justify-between text-[10px] text-zinc-600">
                  <span>5s</span><span>60s</span>
                </div>
              </div>

              {/* Run / Stop */}
              {isScanning ? (
                <Button onClick={stopScan} variant="destructive" className="w-full gap-2">
                  <Square className="h-4 w-4" /> Stop Scan
                </Button>
              ) : (
                <Button
                  onClick={startScan} className="w-full gap-2"
                  disabled={selectedModules.size === 0}
                >
                  <Play className="h-4 w-4" /> Run Attack Suite
                </Button>
              )}
            </CardContent>
          </Card>

          {/* Advanced config sections */}
          <div className="space-y-2">

            {/* Crawler */}
            <SectionToggle
              icon={<Globe className="h-3.5 w-3.5" />}
              label="Web Crawler"
              enabled={crawlerEnabled}
              onToggle={() => setCrawlerEnabled(!crawlerEnabled)}
              badge={crawlerEnabled ? "On" : undefined}
            >
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label className="text-[11px] text-zinc-400">Max Depth</Label>
                    <span className="text-[11px] font-mono text-zinc-300">{crawlerDepth}</span>
                  </div>
                  <Slider
                    min={1} max={8} step={1}
                    value={[crawlerDepth]} onValueChange={([v]) => setCrawlerDepth(v)}
                    disabled={isScanning}
                  />
                  <div className="flex justify-between text-[10px] text-zinc-600"><span>1</span><span>8</span></div>
                </div>
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label className="text-[11px] text-zinc-400">Max Pages</Label>
                    <span className="text-[11px] font-mono text-zinc-300">{crawlerPages}</span>
                  </div>
                  <Slider
                    min={10} max={300} step={10}
                    value={[crawlerPages]} onValueChange={([v]) => setCrawlerPages(v)}
                    disabled={isScanning}
                  />
                  <div className="flex justify-between text-[10px] text-zinc-600"><span>10</span><span>300</span></div>
                </div>
                <div className="flex items-center justify-between">
                  <Label className="text-[11px] text-zinc-400">Respect robots.txt</Label>
                  <Switch
                    checked={crawlerRobots} onCheckedChange={setCrawlerRobots}
                    disabled={isScanning}
                  />
                </div>
              </div>
            </SectionToggle>

            {/* Login */}
            <SectionToggle
              icon={<LogIn className="h-3.5 w-3.5" />}
              label="Login / Auth"
              enabled={loginEnabled}
              onToggle={() => setLoginEnabled(!loginEnabled)}
              badge={loginEnabled ? "On" : undefined}
            >
              <div className="space-y-3">
                {/* Login type selector */}
                <div className="space-y-1.5">
                  <Label className="text-[11px] text-zinc-400">Login Type</Label>
                  <div className="grid grid-cols-3 gap-1">
                    {([
                      { value: "rest_json", label: "REST JSON" },
                      { value: "form", label: "Form" },
                      { value: "bearer", label: "Bearer" },
                      { value: "basic", label: "Basic" },
                      { value: "cookie", label: "Cookie" },
                    ] as const).map(({ value: t, label }) => (
                      <button
                        key={t}
                        type="button"
                        className={cn(
                          "rounded border px-2 py-1 text-[11px] transition-colors",
                          loginType === t
                            ? "border-blue-500/50 bg-blue-600/10 text-blue-300"
                            : "border-zinc-700 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
                        )}
                        onClick={() => setLoginType(t)}
                        disabled={isScanning}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>

                {loginType === "form" && (
                  <>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Login URL</Label>
                      <Input
                        placeholder="https://example.com/login"
                        value={loginUrl}
                        onChange={(e) => setLoginUrl(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs h-7"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="space-y-1">
                        <Label className="text-[10px] text-zinc-400">Username field</Label>
                        <Input
                          placeholder="username"
                          value={loginUsernameField}
                          onChange={(e) => setLoginUsernameField(e.target.value)}
                          disabled={isScanning}
                          className="font-mono text-xs h-7"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-[10px] text-zinc-400">Password field</Label>
                        <Input
                          placeholder="password"
                          value={loginPasswordField}
                          onChange={(e) => setLoginPasswordField(e.target.value)}
                          disabled={isScanning}
                          className="font-mono text-xs h-7"
                        />
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Username</Label>
                      <Input
                        placeholder="admin@example.com"
                        value={loginUsername}
                        onChange={(e) => setLoginUsername(e.target.value)}
                        disabled={isScanning}
                        className="text-xs h-7"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Password</Label>
                      <Input
                        type="password"
                        placeholder="••••••••"
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        disabled={isScanning}
                        className="text-xs h-7"
                      />
                    </div>
                  </>
                )}

                {loginType === "bearer" && (
                  <div className="space-y-1.5">
                    <Label className="text-[11px] text-zinc-400">Bearer Token</Label>
                    <Input
                      placeholder="eyJhbGci..."
                      value={loginBearerToken}
                      onChange={(e) => setLoginBearerToken(e.target.value)}
                      disabled={isScanning}
                      className="font-mono text-xs h-7"
                    />
                  </div>
                )}

                {loginType === "basic" && (
                  <>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Username</Label>
                      <Input
                        value={loginUsername}
                        onChange={(e) => setLoginUsername(e.target.value)}
                        disabled={isScanning}
                        className="text-xs h-7"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Password</Label>
                      <Input
                        type="password"
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        disabled={isScanning}
                        className="text-xs h-7"
                      />
                    </div>
                  </>
                )}

                {loginType === "cookie" && (
                  <div className="space-y-1.5">
                    <Label className="text-[11px] text-zinc-400">Cookie String</Label>
                    <Input
                      placeholder="session=abc; csrf=xyz"
                      value={loginCookie}
                      onChange={(e) => setLoginCookie(e.target.value)}
                      disabled={isScanning}
                      className="font-mono text-xs h-7"
                    />
                  </div>
                )}

                {loginType === "rest_json" && (
                  <>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Login URL</Label>
                      <Input
                        placeholder="https://example.com/rest/user/login"
                        value={loginUrl}
                        onChange={(e) => setLoginUrl(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs h-7"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="space-y-1">
                        <Label className="text-[10px] text-zinc-400">Username field</Label>
                        <Input
                          placeholder="email"
                          value={loginUsernameField}
                          onChange={(e) => setLoginUsernameField(e.target.value)}
                          disabled={isScanning}
                          className="font-mono text-xs h-7"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-[10px] text-zinc-400">Password field</Label>
                        <Input
                          placeholder="password"
                          value={loginPasswordField}
                          onChange={(e) => setLoginPasswordField(e.target.value)}
                          disabled={isScanning}
                          className="font-mono text-xs h-7"
                        />
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Username / Email</Label>
                      <Input
                        placeholder="admin@example.com"
                        value={loginUsername}
                        onChange={(e) => setLoginUsername(e.target.value)}
                        disabled={isScanning}
                        className="text-xs h-7"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Password</Label>
                      <Input
                        type="password"
                        placeholder="••••••••"
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        disabled={isScanning}
                        className="text-xs h-7"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Token path in response</Label>
                      <Input
                        placeholder="authentication.token"
                        value={loginTokenPath}
                        onChange={(e) => setLoginTokenPath(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs h-7"
                      />
                      <p className="text-[10px] text-zinc-600">
                        Dot-notation path to JWT in JSON response. e.g. <span className="font-mono">authentication.token</span> for Juice Shop, <span className="font-mono">access_token</span> for OAuth.
                      </p>
                    </div>
                  </>
                )}

                {/* Test Connection & Auth */}
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="w-full gap-1.5 text-xs"
                  disabled={isScanning || testingAuth || !target}
                  onClick={testAuth}
                >
                  {testingAuth ? <Loader2 className="h-3 w-3 animate-spin" /> : <Globe className="h-3 w-3" />}
                  {testingAuth ? "Testing..." : "Test Connection & Auth"}
                </Button>

                {testAuthResult && (
                  <div className={cn(
                    "rounded-md border p-2 text-xs space-y-1",
                    testAuthResult.reachable ? "border-emerald-600/30 bg-emerald-600/5" : "border-red-600/30 bg-red-600/5"
                  )}>
                    <div className="flex items-center gap-1.5">
                      {testAuthResult.reachable
                        ? <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                        : <XCircle className="h-3 w-3 text-red-400" />}
                      <span className={testAuthResult.reachable ? "text-emerald-400" : "text-red-400"}>
                        {testAuthResult.reachable ? "Target reachable" : "Target unreachable"}
                      </span>
                    </div>
                    {loginEnabled && (
                      <div className="flex items-center gap-1.5">
                        {testAuthResult.auth_success
                          ? <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                          : <XCircle className="h-3 w-3 text-red-400" />}
                        <span className={testAuthResult.auth_success ? "text-emerald-400" : "text-red-400"}>
                          {testAuthResult.auth_success
                            ? `Auth OK (${testAuthResult.auth_type})`
                            : "Auth failed"}
                        </span>
                      </div>
                    )}
                    {testAuthResult.tech_stack && testAuthResult.tech_stack.length > 0 && (
                      <p className="text-zinc-500 text-[10px]">Tech: {testAuthResult.tech_stack.join(", ")}</p>
                    )}
                    {testAuthResult.error && (
                      <p className="text-red-400 text-[10px]">{testAuthResult.error}</p>
                    )}
                  </div>
                )}
              </div>
            </SectionToggle>

            {/* Account 2 (IDOR) */}
            <SectionToggle
              icon={<Users className="h-3.5 w-3.5" />}
              label="Account 2 (IDOR)"
              enabled={account2Enabled}
              onToggle={() => setAccount2Enabled(!account2Enabled)}
              badge={account2Enabled ? "On" : undefined}
            >
              <div className="space-y-3">
                <p className="text-[10px] text-zinc-500 leading-relaxed">
                  Second session for cross-account IDOR testing. Account 2 will attempt to access resources discovered under Account 1.
                </p>
                <div className="space-y-1.5">
                  <Label className="text-[11px] text-zinc-400">Auth Type</Label>
                  <div className="grid grid-cols-3 gap-1">
                    {([
                      { value: "rest_json", label: "REST JSON" },
                      { value: "bearer", label: "Bearer" },
                      { value: "cookie", label: "Cookie" },
                    ] as const).map(({ value: t, label }) => (
                      <button
                        key={t}
                        type="button"
                        className={cn(
                          "rounded border px-2 py-1 text-[11px] transition-colors",
                          account2LoginType === t
                            ? "border-blue-500/50 bg-blue-600/10 text-blue-300"
                            : "border-zinc-700 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
                        )}
                        onClick={() => setAccount2LoginType(t)}
                        disabled={isScanning}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>

                {account2LoginType === "rest_json" && (
                  <>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Login URL</Label>
                      <Input
                        placeholder="https://example.com/rest/user/login"
                        value={account2LoginUrl}
                        onChange={(e) => setAccount2LoginUrl(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs h-7"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Username / Email</Label>
                      <Input
                        placeholder="user@example.com"
                        value={account2Username}
                        onChange={(e) => setAccount2Username(e.target.value)}
                        disabled={isScanning}
                        className="text-xs h-7"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Password</Label>
                      <Input
                        type="password"
                        placeholder="••••••••"
                        value={account2Password}
                        onChange={(e) => setAccount2Password(e.target.value)}
                        disabled={isScanning}
                        className="text-xs h-7"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-[11px] text-zinc-400">Token path in response</Label>
                      <Input
                        placeholder="access_token"
                        value={account2TokenPath}
                        onChange={(e) => setAccount2TokenPath(e.target.value)}
                        disabled={isScanning}
                        className="font-mono text-xs h-7"
                      />
                    </div>
                  </>
                )}

                {account2LoginType === "bearer" && (
                  <div className="space-y-1.5">
                    <Label className="text-[11px] text-zinc-400">Bearer Token</Label>
                    <Input
                      placeholder="eyJhbGci..."
                      value={account2Bearer}
                      onChange={(e) => setAccount2Bearer(e.target.value)}
                      disabled={isScanning}
                      className="font-mono text-xs h-7"
                    />
                  </div>
                )}

                {account2LoginType === "cookie" && (
                  <div className="space-y-1.5">
                    <Label className="text-[11px] text-zinc-400">Cookie String</Label>
                    <Input
                      placeholder="session=xyz"
                      value={account2Cookie}
                      onChange={(e) => setAccount2Cookie(e.target.value)}
                      disabled={isScanning}
                      className="font-mono text-xs h-7"
                    />
                  </div>
                )}
              </div>
            </SectionToggle>

            {/* AI Analysis */}
            <div className="rounded-lg border border-zinc-800 px-3 py-2.5 space-y-2.5">
              <div className="flex items-start gap-3">
                <BrainCircuit className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <p className="text-xs font-medium text-zinc-300">AI Strategy Planner</p>
                      <p className="text-[10px] text-zinc-500 mt-0.5 leading-relaxed">
                        Claude analyzes target using the Hunt Harness methodology, plans attack strategy, and deep-analyzes critical findings.
                      </p>
                    </div>
                    <Switch checked={aiAnalysis} onCheckedChange={(v) => {
                      setAiAnalysis(v);
                    }} disabled={isScanning} />
                  </div>
                </div>
              </div>
              {/* API Key input — always visible so users can configure it */}
              <div className="space-y-1.5">
                <div className="flex items-center gap-1.5">
                  <Key className="h-3 w-3 text-zinc-500" />
                  <span className="text-[10px] text-zinc-500 font-medium">Anthropic API Key</span>
                  {anthropicKey && <span className="text-[10px] text-emerald-500">● configured</span>}
                </div>
                <div className="relative">
                  <input
                    type={showApiKey ? "text" : "password"}
                    placeholder="sk-ant-..."
                    value={anthropicKey}
                    onChange={(e) => {
                      setAnthropicKey(e.target.value);
                      localStorage.setItem("attack_suite_anthropic_key", e.target.value);
                      if (e.target.value) setAiAnalysis(true);
                    }}
                    disabled={isScanning}
                    className="w-full bg-zinc-900 border border-zinc-700 rounded px-2.5 py-1.5 text-xs text-zinc-300 font-mono placeholder:text-zinc-600 focus:outline-none focus:border-purple-500 pr-8"
                  />
                  <button
                    type="button"
                    onClick={() => setShowApiKey((v) => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                  >
                    {showApiKey ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                  </button>
                </div>
                <p className="text-[10px] text-zinc-600">Saved to localStorage. Used for AI strategy + critical finding analysis.</p>
              </div>
            </div>
          </div>
        </div>

        {/* ── Results Panel ── */}
        <div className="lg:col-span-2 space-y-4">

          {/* Status bar */}
          {(scanStatus !== "idle" || findings.length > 0) && (
            <div className="flex items-center gap-2 flex-wrap rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
              {isScanning && <Loader2 className="h-4 w-4 text-blue-400 animate-spin shrink-0" />}
              {!isScanning && scanStatus === "completed" && <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />}
              {!isScanning && scanStatus === "failed" && <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />}
              <span className="text-xs text-zinc-400 mr-2">
                {isScanning ? "Scanning…" : scanStatus === "completed" ? `${totalVulnerable} vulnerable` : "Scan failed"}
              </span>
              {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
                <div key={sev} className={cn("flex items-center gap-1.5 rounded-md border px-2 py-1", SEV_COLORS[sev])}>
                  <div className={cn("h-1.5 w-1.5 rounded-full", SEV_DOT[sev])} />
                  <span className="text-[11px] font-medium capitalize">{sev}</span>
                  <span className={cn("text-[11px] font-bold", SEV_BADGE_TEXT[sev])}>{counts[sev]}</span>
                </div>
              ))}
              {/* WAF detection badge */}
              {wafInfo?.detected && (
                <Badge variant="outline" className="border-amber-500 text-amber-400 ml-2">
                  <Shield className="h-3 w-3 mr-1" />
                  WAF: {wafInfo.vendor || "Unknown"}
                </Badge>
              )}
              {wafInfo && !wafInfo.detected && (
                <Badge variant="outline" className="border-zinc-600 text-zinc-400 ml-2">
                  No WAF
                </Badge>
              )}
            </div>
          )}

          {/* Crawl Stats */}
          {crawlStats && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3">
              <div className="flex items-center gap-2 mb-3">
                <Network className="h-4 w-4 text-blue-400" />
                <span className="text-xs font-semibold text-zinc-300">Crawl Results</span>
              </div>
              <div className="grid grid-cols-3 gap-3 mb-3">
                {[
                  { label: "Pages", value: crawlStats.pages },
                  { label: "Forms", value: crawlStats.forms },
                  { label: "Endpoints", value: crawlStats.endpoints },
                ].map((stat) => (
                  <div key={stat.label} className="text-center rounded-md border border-zinc-800 bg-zinc-900 py-2">
                    <p className="text-lg font-bold text-blue-400">{stat.value}</p>
                    <p className="text-[10px] text-zinc-500">{stat.label}</p>
                  </div>
                ))}
              </div>
              {crawlStats.tech_stack.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap">
                  <Search className="h-3 w-3 text-zinc-500" />
                  <span className="text-[10px] text-zinc-500">Tech:</span>
                  {crawlStats.tech_stack.map((t) => (
                    <Badge key={t} variant="secondary" className="text-[10px] py-0 h-4">{t}</Badge>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* AI Strategy Plan */}
          {aiPlan && (
            <div className="rounded-lg border border-purple-600/30 bg-purple-600/5">
              <div className="flex items-center gap-2 px-4 py-2.5 border-b border-purple-600/20">
                <BrainCircuit className="h-4 w-4 text-purple-400" />
                <span className="text-xs font-semibold text-purple-300">AI Attack Strategy</span>
              </div>
              <div className="px-4 py-3 max-h-[220px] overflow-y-auto">
                <pre className="text-xs text-zinc-300 font-mono whitespace-pre-wrap leading-relaxed">{aiPlan}</pre>
              </div>
            </div>
          )}

          {/* Progress log */}
          {progressMessages.length > 0 && (
            <div className="rounded-lg border border-zinc-800">
              <button
                className="w-full flex items-center justify-between px-3 py-2 border-b border-zinc-800 hover:bg-zinc-800/30 transition-colors"
                onClick={() => setShowProgress(!showProgress)}
              >
                <span className="text-xs text-zinc-500 font-mono">
                  progress log ({progressMessages.length})
                </span>
                {showProgress
                  ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" />
                  : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
              </button>
              {showProgress && (
                <div className="h-[180px] overflow-y-auto bg-zinc-950 rounded-b-lg p-3 space-y-0.5 font-mono">
                  {progressMessages.map((msg, i) => (
                    <div key={i} className="text-xs leading-5 flex items-start gap-2">
                      {msg.module && (
                        <span className={cn(
                          "shrink-0",
                          msg.module === "crawl" ? "text-blue-400" :
                          msg.module === "ai" ? "text-purple-400" :
                          "text-emerald-400"
                        )}>
                          [{msg.module}]
                        </span>
                      )}
                      <span className="text-zinc-400">{msg.message}</span>
                    </div>
                  ))}
                  <div ref={progressEndRef} />
                </div>
              )}
            </div>
          )}

          {/* Findings */}
          {findings.length > 0 ? (
            <div className="space-y-4">
              {Object.entries(findingsByModule).map(([moduleName, moduleFix]) => {
                const moduleDef = MODULES.find((m) => m.id === moduleName);
                return (
                  <div key={moduleName}>
                    <div className="flex items-center gap-2 mb-2">
                      <Shield className="h-4 w-4 text-zinc-500" />
                      <h3 className="text-sm font-semibold text-zinc-300">
                        {moduleDef?.label ?? moduleName}
                      </h3>
                      <Badge variant="secondary" className="text-[10px] py-0 h-4">
                        {moduleFix.length}
                      </Badge>
                      <span className="text-[10px] text-zinc-600 ml-1">
                        {moduleFix.filter((f) => f.is_vulnerable).length} vulnerable
                      </span>
                    </div>
                    <div className="space-y-2">
                      {moduleFix.map((f) => (
                        <FindingCard key={f.id} finding={f} />
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            !isScanning && scanStatus === "idle" && (
              <div className="flex flex-col items-center justify-center py-20 text-zinc-600 space-y-3">
                <Swords className="h-12 w-12" />
                <p className="text-sm">Run a scan to discover vulnerabilities</p>
                <p className="text-xs text-zinc-700">
                  {MODULES.length} modules · patterns from 5700+ bug bounty reports · crawler + login support
                </p>
              </div>
            )
          )}

          {isScanning && findings.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500 space-y-3">
              <Loader2 className="h-8 w-8 animate-spin text-blue-400" />
              <p className="text-sm">
                {crawlStats ? `Attacking ${crawlStats.endpoints} discovered endpoints…` : `Crawling ${target}…`}
              </p>
              <p className="text-xs">{progressMessages.length} events received</p>
            </div>
          )}
        </div>
      </div>}{/* end scanner grid */}

      {/* History */}
      {activeTab === "scanner" && showHistory && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
              <History className="h-4 w-4 text-zinc-400" />
              Scan History
            </CardTitle>
          </CardHeader>
          <CardContent>
            {history.length === 0 ? (
              <p className="text-sm text-zinc-600 py-4 text-center">No past scans</p>
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
                      entry.status === "failed" ? "bg-red-400" : "bg-zinc-500"
                    )} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono text-zinc-200 truncate">{entry.target}</p>
                      <p className="text-[10px] text-zinc-500">{new Date(entry.started_at).toLocaleString()}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <p className="text-xs text-zinc-400">{entry.total_findings} findings</p>
                      <p className={cn("text-[10px] capitalize",
                        entry.status === "completed" ? "text-emerald-400" :
                        entry.status === "failed" ? "text-red-400" : "text-zinc-500"
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
