"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  XCircle,
  Eye,
  EyeOff,
  Loader2,
  Save,
  ExternalLink,
  GitBranch,
  Copy,
  Check,
  Wifi,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/page-header";
import { orgApi } from "@/lib/api";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface Integration {
  id: string;
  name: string;
  description: string;
  category: string;
  docsUrl: string;
  fields: {
    key: string;
    label: string;
    placeholder: string;
    hint?: string;
  }[];
}

const INTEGRATIONS: Integration[] = [
  {
    id: "shodan",
    name: "Shodan",
    description: "Internet-wide scan data for IP enrichment, open ports, vulnerabilities, and banner grabbing.",
    category: "Enrichment",
    docsUrl: "https://account.shodan.io/",
    fields: [
      { key: "shodan_key", label: "API Key", placeholder: "your-shodan-api-key", hint: "Found in your Shodan account settings" },
    ],
  },
  {
    id: "censys",
    name: "Censys",
    description: "Internet scan data for certificate transparency, IP enrichment, and host discovery.",
    category: "Enrichment",
    docsUrl: "https://search.censys.io/account/api",
    fields: [
      { key: "censys_id", label: "API ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
      { key: "censys_secret", label: "API Secret", placeholder: "your-censys-api-secret" },
    ],
  },
  {
    id: "securitytrails",
    name: "SecurityTrails",
    description: "Historical DNS data, subdomain enumeration, and domain intelligence.",
    category: "Intelligence",
    docsUrl: "https://securitytrails.com/app/account/credentials",
    fields: [
      { key: "securitytrails_key", label: "API Key", placeholder: "your-securitytrails-key" },
    ],
  },
  {
    id: "github",
    name: "GitHub",
    description: "Source code reconnaissance, secret scanning, and employee/org discovery.",
    category: "OSINT",
    docsUrl: "https://github.com/settings/tokens",
    fields: [
      { key: "github_token", label: "Personal Access Token", placeholder: "ghp_xxxxxxxxxxxxxxxxxxxx", hint: "Requires repo and read:org scopes" },
    ],
  },
  {
    id: "alienvault",
    name: "AlienVault OTX",
    description: "Threat intelligence indicators, malware data, and attack pattern analysis.",
    category: "Threat Intel",
    docsUrl: "https://otx.alienvault.com/settings",
    fields: [
      { key: "alienvault_key", label: "OTX API Key", placeholder: "your-alienvault-otx-key" },
    ],
  },
  {
    id: "passivetotal",
    name: "PassiveTotal / RiskIQ",
    description: "Passive DNS, WHOIS history, and attack surface visibility from RiskIQ.",
    category: "Intelligence",
    docsUrl: "https://api.riskiq.net/api/",
    fields: [
      { key: "passivetotal_user", label: "Username / Email", placeholder: "user@example.com" },
      { key: "passivetotal_key", label: "API Key", placeholder: "your-passivetotal-key" },
    ],
  },
];

const CATEGORY_COLORS: Record<string, string> = {
  AI: "bg-violet-500/10 text-violet-400 border-violet-500/20",
  Enrichment: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  Intelligence: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  OSINT: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  "Threat Intel": "bg-red-500/10 text-red-400 border-red-500/20",
};

type AIProvider = "anthropic" | "qwen";

const AI_FIELDS: Record<AIProvider, { key: string; label: string; placeholder: string; hint?: string; secret: boolean }[]> = {
  anthropic: [
    { key: "anthropic_key", label: "API Key", placeholder: "sk-ant-api03-...", hint: "Required for AI-assisted triage, executive summaries, Attack Suite planning, and the AI Agent.", secret: true },
    { key: "ai_base_url", label: "API Gateway URL (optional)", placeholder: "https://your-bedrock-proxy.example.com", hint: "Custom Anthropic-compatible endpoint (AWS Bedrock proxy, etc.). Leave blank for the default Anthropic API.", secret: false },
    { key: "ai_model_override", label: "Model Override (optional)", placeholder: "claude-sonnet-4-6", hint: "Leave blank to use claude-sonnet-4-6.", secret: false },
  ],
  qwen: [
    { key: "qwen_base_url", label: "Base URL", placeholder: "http://localhost:8000/v1", hint: "Your self-hosted Qwen (or any OpenAI-compatible) server's chat completions endpoint.", secret: false },
    { key: "qwen_api_key", label: "API Key (optional)", placeholder: "leave blank if your server needs none", hint: "Most self-hosted servers don't require one.", secret: true },
    { key: "qwen_model", label: "Model", placeholder: "Qwen2.5-72B-Instruct", hint: "Must match the model name your server serves.", secret: false },
  ],
};

function AIProviderCard({
  credentials,
  onSave,
  isSaving,
}: {
  credentials: Record<string, boolean | string>;
  onSave: (values: Record<string, string | null>) => void;
  isSaving: boolean;
}) {
  const savedProvider = ((credentials.ai_provider as AIProvider) || "anthropic");
  const [provider, setProvider] = useState<AIProvider>(savedProvider);
  const [values, setValues] = useState<Record<string, string>>({});
  const [showFields, setShowFields] = useState<Record<string, boolean>>({});
  const [isDirty, setIsDirty] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; error?: string | null; reply?: string | null } | null>(null);
  const [testing, setTesting] = useState(false);

  const fields = AI_FIELDS[provider];
  const isConfigured = provider === "anthropic"
    ? Boolean(credentials.anthropic_key)
    : Boolean(credentials.qwen_base_url) && Boolean(credentials.qwen_model);

  const handleChange = (key: string, value: string) => {
    setValues((prev) => ({ ...prev, [key]: value }));
    setIsDirty(true);
    setTestResult(null);
  };

  const handleProviderChange = (next: AIProvider) => {
    if (next === provider) return;
    setProvider(next);
    setValues({});
    setTestResult(null);
    setIsDirty(next !== savedProvider);
  };

  const handleSave = () => {
    const payload: Record<string, string | null> = {};
    fields.forEach((f) => {
      if (values[f.key] !== undefined) payload[f.key] = values[f.key] || null;
    });
    if (provider !== savedProvider) payload.ai_provider = provider;
    if (Object.keys(payload).length > 0) {
      onSave(payload);
      setValues({});
      setIsDirty(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const payload: { provider: string; base_url?: string; api_key?: string; model?: string } = { provider };
      if (provider === "anthropic") {
        if (values.anthropic_key) payload.api_key = values.anthropic_key;
        if (values.ai_base_url) payload.base_url = values.ai_base_url;
        if (values.ai_model_override) payload.model = values.ai_model_override;
      } else {
        if (values.qwen_base_url) payload.base_url = values.qwen_base_url;
        if (values.qwen_api_key) payload.api_key = values.qwen_api_key;
        if (values.qwen_model) payload.model = values.qwen_model;
      }
      const result = await orgApi.testAIConnection(payload);
      setTestResult(result);
      if (result.ok) toast.success("Connection successful");
      else toast.error(result.error || "Connection failed");
    } catch (e) {
      setTestResult({ ok: false, error: (e as Error).message });
      toast.error((e as Error).message || "Connection test failed");
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card className={cn("border transition-colors", isConfigured ? "border-emerald-800/40" : "border-zinc-800")}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1">
            <div className="flex items-center gap-2.5">
              <CardTitle className="text-sm font-semibold text-zinc-100">AI Provider</CardTitle>
              <Badge variant="outline" className={cn("text-[10px] px-1.5 py-0 h-4", CATEGORY_COLORS.AI)}>AI</Badge>
              {isConfigured && (
                <span className="flex items-center gap-1 text-[11px] text-emerald-400">
                  <CheckCircle2 className="h-3 w-3" /> Configured
                </span>
              )}
            </div>
            <CardDescription className="mt-1 text-xs leading-relaxed">
              Powers AI-assisted triage, executive summaries, Attack Suite planning/analysis, the Security
              Test Case Generator, and the autonomous Attack Suite AI Agent.
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-0 space-y-3">
        <div className="flex items-center gap-1 rounded-lg bg-zinc-900 border border-zinc-800 p-1 w-fit">
          <button
            type="button"
            onClick={() => handleProviderChange("anthropic")}
            className={cn(
              "px-3 py-1.5 rounded text-xs font-medium transition-colors",
              provider === "anthropic" ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            Claude API
          </button>
          <button
            type="button"
            onClick={() => handleProviderChange("qwen")}
            className={cn(
              "px-3 py-1.5 rounded text-xs font-medium transition-colors",
              provider === "qwen" ? "bg-violet-600 text-white" : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            Self-hosted Qwen
          </button>
        </div>

        {fields.map((field) => {
          const isSet = Boolean(credentials[field.key]);
          const currentValue = values[field.key] ?? "";
          return (
            <div key={field.key} className="space-y-1">
              <div className="flex items-center justify-between">
                <Label className="text-xs text-zinc-400">{field.label}</Label>
                {isSet && !currentValue && (
                  <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="h-2.5 w-2.5" /> Set
                  </span>
                )}
              </div>
              <div className="relative">
                <Input
                  type={field.secret && !showFields[field.key] ? "password" : "text"}
                  placeholder={isSet ? "••••••••••••••••" : field.placeholder}
                  value={currentValue}
                  onChange={(e) => handleChange(field.key, e.target.value)}
                  className="pr-9 text-xs font-mono"
                />
                {field.secret && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 text-zinc-500 hover:text-zinc-300"
                    onClick={() => setShowFields((prev) => ({ ...prev, [field.key]: !prev[field.key] }))}
                    aria-label={showFields[field.key] ? `Hide ${field.label ?? field.key}` : `Show ${field.label ?? field.key}`}
                  >
                    {showFields[field.key] ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                  </Button>
                )}
              </div>
              {field.hint && <p className="text-[10px] text-zinc-600">{field.hint}</p>}
            </div>
          );
        })}

        {testResult && (
          <div className={cn(
            "rounded-lg border px-3 py-2 text-xs flex items-start gap-2",
            testResult.ok ? "border-emerald-600/30 bg-emerald-600/5 text-emerald-300" : "border-red-600/30 bg-red-600/5 text-red-300"
          )}>
            {testResult.ok ? <CheckCircle2 className="h-3.5 w-3.5 mt-0.5 shrink-0" /> : <XCircle className="h-3.5 w-3.5 mt-0.5 shrink-0" />}
            <span>{testResult.ok ? `Connected — model replied: "${testResult.reply}"` : testResult.error}</span>
          </div>
        )}

        <div className="flex items-center justify-between pt-1">
          <Button size="sm" variant="outline" onClick={handleTest} disabled={testing} className="h-7 text-xs gap-1.5">
            {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wifi className="h-3 w-3" />}
            {testing ? "Testing..." : "Test Connection"}
          </Button>
          <Button size="sm" onClick={handleSave} disabled={!isDirty || isSaving} className="h-7 text-xs gap-1.5">
            {isSaving ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
            {isSaving ? "Saving..." : "Save"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function IntegrationCard({
  integration,
  configuredFields,
  onSave,
  isSaving,
}: {
  integration: Integration;
  configuredFields: Record<string, boolean | string>;
  onSave: (values: Record<string, string | null>) => void;
  isSaving: boolean;
}) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [showFields, setShowFields] = useState<Record<string, boolean>>({});
  const [isDirty, setIsDirty] = useState(false);

  const isConfigured = integration.fields.every((f) => configuredFields[f.key]);
  const isPartial = !isConfigured && integration.fields.some((f) => configuredFields[f.key]);

  const handleChange = (key: string, value: string) => {
    setValues((prev) => ({ ...prev, [key]: value }));
    setIsDirty(true);
  };

  const handleSave = () => {
    const payload: Record<string, string | null> = {};
    integration.fields.forEach((f) => {
      payload[f.key] = values[f.key] !== undefined ? values[f.key] || null : undefined as unknown as null;
    });
    // Only include fields that were actually changed
    const changedPayload: Record<string, string | null> = {};
    integration.fields.forEach((f) => {
      if (values[f.key] !== undefined) {
        changedPayload[f.key] = values[f.key] || null;
      }
    });
    if (Object.keys(changedPayload).length > 0) {
      onSave(changedPayload);
      setValues({});
      setIsDirty(false);
    }
  };

  return (
    <Card className={cn(
      "border transition-colors",
      isConfigured ? "border-emerald-800/40" : "border-zinc-800"
    )}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1">
            <div className="flex items-center gap-2.5">
              <CardTitle className="text-sm font-semibold text-zinc-100">
                {integration.name}
              </CardTitle>
              <Badge
                variant="outline"
                className={cn("text-[10px] px-1.5 py-0 h-4", CATEGORY_COLORS[integration.category])}
              >
                {integration.category}
              </Badge>
              {isConfigured ? (
                <span className="flex items-center gap-1 text-[11px] text-emerald-400">
                  <CheckCircle2 className="h-3 w-3" />
                  Configured
                </span>
              ) : isPartial ? (
                <span className="flex items-center gap-1 text-[11px] text-amber-400">
                  <XCircle className="h-3 w-3" />
                  Partial
                </span>
              ) : null}
            </div>
            <CardDescription className="mt-1 text-xs leading-relaxed">
              {integration.description}
            </CardDescription>
          </div>
          <a
            href={integration.docsUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="shrink-0 text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="space-y-3">
          {integration.fields.map((field) => {
            const isSet = configuredFields[field.key];
            const currentValue = values[field.key] ?? "";

            return (
              <div key={field.key} className="space-y-1">
                <div className="flex items-center justify-between">
                  <Label htmlFor={`${integration.id}-${field.key}`} className="text-xs text-zinc-400">
                    {field.label}
                  </Label>
                  {isSet && !currentValue && (
                    <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="h-2.5 w-2.5" />
                      Set
                    </span>
                  )}
                </div>
                <div className="relative">
                  <Input
                    id={`${integration.id}-${field.key}`}
                    type={showFields[field.key] ? "text" : "password"}
                    placeholder={isSet ? "••••••••••••••••" : field.placeholder}
                    value={currentValue}
                    onChange={(e) => handleChange(field.key, e.target.value)}
                    className="pr-9 text-xs font-mono"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 text-zinc-500 hover:text-zinc-300"
                    onClick={() => setShowFields((prev) => ({ ...prev, [field.key]: !prev[field.key] }))}
                    aria-label={showFields[field.key] ? `Hide ${field.label ?? field.key}` : `Show ${field.label ?? field.key}`}
                  >
                    {showFields[field.key] ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                  </Button>
                </div>
                {field.hint && (
                  <p className="text-[10px] text-zinc-600">{field.hint}</p>
                )}
              </div>
            );
          })}
          <div className="flex items-center justify-between pt-1">
            {isConfigured && (
              <button
                type="button"
                className="text-[11px] text-red-400/70 hover:text-red-400 transition-colors"
                onClick={() => {
                  const payload: Record<string, null> = {};
                  integration.fields.forEach((f) => { payload[f.key] = null; });
                  onSave(payload);
                }}
              >
                Remove credentials
              </button>
            )}
            <div className="ml-auto">
              <Button
                size="sm"
                onClick={handleSave}
                disabled={!isDirty || isSaving}
                className="h-7 text-xs gap-1.5"
              >
                {isSaving ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Save className="h-3 w-3" />
                )}
                Save
              </Button>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function IntegrationsPage() {
  const queryClient = useQueryClient();
  const [savingId, setSavingId] = useState<string | null>(null);

  const { data: credentials, isLoading } = useQuery({
    queryKey: ["org", "credentials"],
    queryFn: () => orgApi.getCredentials(),
    staleTime: 30_000,
  });

  const updateMutation = useMutation({
    mutationFn: (data: Record<string, string | null>) => orgApi.updateCredentials(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org", "credentials"] });
      toast.success("Credentials saved");
      setSavingId(null);
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to save credentials");
      setSavingId(null);
    },
  });

  const handleSave = (integrationId: string, values: Record<string, string | null>) => {
    setSavingId(integrationId);
    updateMutation.mutate(values);
  };

  const configuredFields: Record<string, boolean | string> = credentials ?? {};

  const configuredCount = INTEGRATIONS.filter((i) =>
    i.fields.every((f) => configuredFields[f.key])
  ).length;

  return (
    <div className="space-y-6 max-w-4xl">
      <PageHeader
        title="Integrations"
        description="Configure third-party API keys used during security scans"
      >
        <div className="flex items-center gap-2 text-sm text-zinc-400">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          <span>{configuredCount} of {INTEGRATIONS.length} configured</span>
        </div>
      </PageHeader>

      {/* Info banner */}
      <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
        <p className="text-sm text-blue-300">
          <strong>Security:</strong> All credentials are encrypted with AES-256-GCM before storage.
          Values are write-only — once saved, they cannot be read back.
          Leave a field blank to keep the existing value.
        </p>
      </div>

      {isLoading ? (
        <div className="h-56 rounded-lg border border-zinc-800 bg-zinc-900 animate-pulse" />
      ) : (
        <AIProviderCard
          credentials={configuredFields}
          onSave={(values) => handleSave("ai-provider", values)}
          isSaving={savingId === "ai-provider" && updateMutation.isPending}
        />
      )}

      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-48 rounded-lg border border-zinc-800 bg-zinc-900 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {INTEGRATIONS.map((integration) => (
            <IntegrationCard
              key={integration.id}
              integration={integration}
              configuredFields={configuredFields}
              onSave={(values) => handleSave(integration.id, values)}
              isSaving={savingId === integration.id && updateMutation.isPending}
            />
          ))}
        </div>
      )}

      {/* CI/CD Integration */}
      <CICDIntegration />
    </div>
  );
}

function CICDIntegration() {
  const [copied, setCopied] = useState<string | null>(null);

  const copy = (key: string, text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied(null), 2000);
    });
  };

  const ghActionsSnippet = `- name: AttackTrace Security Scan
  uses: actions/github-script@v7
  env:
    ATTACKTRACE_API_URL: \${{ secrets.ATTACKTRACE_API_URL }}
    ATTACKTRACE_TOKEN: \${{ secrets.ATTACKTRACE_TOKEN }}
  with:
    script: |
      const res = await fetch(\`\${process.env.ATTACKTRACE_API_URL}/api/v1/scans\`, {
        method: 'POST',
        headers: {
          'Authorization': \`Bearer \${process.env.ATTACKTRACE_TOKEN}\`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_domains: ['\${{ vars.TARGET_DOMAIN }}'],
          intensity: 'quick',
        }),
      });
      if (!res.ok) core.setFailed('AttackTrace scan failed: ' + res.status);
      const scan = await res.json();
      core.info(\`Scan started: \${scan.id}\`);`;

  const curlSnippet = `# Trigger a scan via REST API
curl -X POST https://your-attacktrace.com/api/v1/scans \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"target_domains": ["example.com"], "intensity": "quick"}'`;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <GitBranch className="h-4 w-4 text-zinc-400" />
        <h2 className="text-sm font-semibold text-zinc-300">CI/CD Integration</h2>
        <Badge variant="outline" className="text-[10px] border-zinc-700 text-zinc-500">REST API</Badge>
      </div>
      <p className="text-xs text-zinc-500">
        Trigger scans from your pipeline on every deployment to catch new vulnerabilities early.
        Use the API directly or embed the snippet below in your GitHub Actions workflow.
      </p>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* GitHub Actions */}
        <Card className="border-zinc-800 bg-zinc-900">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm text-zinc-200">GitHub Actions</CardTitle>
              <Button
                size="sm"
                variant="ghost"
                className="h-6 px-2 text-xs gap-1 text-zinc-500 hover:text-zinc-200"
                onClick={() => copy("gh", ghActionsSnippet)}
              >
                {copied === "gh" ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                {copied === "gh" ? "Copied" : "Copy"}
              </Button>
            </div>
            <CardDescription className="text-xs">Add to .github/workflows/security.yml</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="text-[10px] font-mono text-zinc-400 bg-zinc-950 rounded-md p-3 overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {ghActionsSnippet}
            </pre>
          </CardContent>
        </Card>

        {/* REST API / curl */}
        <Card className="border-zinc-800 bg-zinc-900">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm text-zinc-200">REST API (curl)</CardTitle>
              <Button
                size="sm"
                variant="ghost"
                className="h-6 px-2 text-xs gap-1 text-zinc-500 hover:text-zinc-200"
                onClick={() => copy("curl", curlSnippet)}
              >
                {copied === "curl" ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                {copied === "curl" ? "Copied" : "Copy"}
              </Button>
            </div>
            <CardDescription className="text-xs">Call from any script or CI runner</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="text-[10px] font-mono text-zinc-400 bg-zinc-950 rounded-md p-3 overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {curlSnippet}
            </pre>
          </CardContent>
        </Card>
      </div>

      <p className="text-xs text-zinc-600">
        Store your API token in GitHub Secrets as <code className="text-zinc-400">ATTACKTRACE_TOKEN</code>.
        Generate tokens from Settings → Team Members → API Keys.
      </p>
    </div>
  );
}
