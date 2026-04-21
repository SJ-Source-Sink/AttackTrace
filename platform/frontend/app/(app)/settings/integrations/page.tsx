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
    id: "anthropic",
    name: "Anthropic Claude",
    description: "Powers AI-assisted triage, executive summaries, and the AI mode in the Security Test Case Generator.",
    category: "AI",
    docsUrl: "https://console.anthropic.com/settings/keys",
    fields: [
      { key: "anthropic_key", label: "API Key", placeholder: "sk-ant-api03-...", hint: "Required for AI Test Case Generator and AI triage features" },
    ],
  },
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

function IntegrationCard({
  integration,
  configuredFields,
  onSave,
  isSaving,
}: {
  integration: Integration;
  configuredFields: Record<string, boolean>;
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

  const configuredFields: Record<string, boolean> = credentials ?? {};

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
    </div>
  );
}
