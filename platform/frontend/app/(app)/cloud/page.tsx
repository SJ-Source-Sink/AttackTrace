"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Cloud,
  Loader2,
  RefreshCw,
  Server,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { EmptyState } from "@/components/shared/empty-state";
import { cloudApi } from "@/lib/api";
import { toast } from "sonner";
import type { CloudDiscoverResult, CloudAsset, CloudAssetListResponse } from "@/types";

type Provider = "aws" | "gcp" | "azure";

interface DiscoveredSession {
  provider: Provider;
  result: CloudDiscoverResult;
}

// ─── AWS Credentials Form ────────────────────────────────────────────────────

function AwsForm({
  onDiscover,
  loading,
}: {
  onDiscover: (creds: Record<string, string>) => void;
  loading: boolean;
}) {
  const [keyId, setKeyId] = useState("");
  const [secret, setSecret] = useState("");
  const [token, setToken] = useState("");

  return (
    <div className="space-y-3">
      <div>
        <label className="text-xs text-zinc-500 mb-1 block">Access Key ID</label>
        <Input
          placeholder="AKIA..."
          value={keyId}
          onChange={(e) => setKeyId(e.target.value)}
          autoComplete="off"
        />
      </div>
      <div>
        <label className="text-xs text-zinc-500 mb-1 block">Secret Access Key</label>
        <Input
          type="password"
          placeholder="Secret..."
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          autoComplete="off"
        />
      </div>
      <div>
        <label className="text-xs text-zinc-500 mb-1 block">Session Token (optional)</label>
        <Input
          placeholder="Token (for temporary credentials)"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          autoComplete="off"
        />
      </div>
      <Button
        className="w-full gap-2"
        disabled={loading || !keyId || !secret}
        onClick={() => onDiscover({ access_key_id: keyId, secret_access_key: secret, session_token: token })}
      >
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Cloud className="h-4 w-4" />}
        Discover AWS Assets
      </Button>
    </div>
  );
}

// ─── GCP Credentials Form ────────────────────────────────────────────────────

function GcpForm({
  onDiscover,
  loading,
}: {
  onDiscover: (creds: Record<string, string>) => void;
  loading: boolean;
}) {
  const [json, setJson] = useState("");

  return (
    <div className="space-y-3">
      <div>
        <label className="text-xs text-zinc-500 mb-1 block">Service Account JSON</label>
        <textarea
          className="w-full h-32 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 placeholder-zinc-600 focus:outline-none focus:ring-2 focus:ring-blue-600 font-mono resize-y"
          placeholder='{"type": "service_account", ...}'
          value={json}
          onChange={(e) => setJson(e.target.value)}
        />
      </div>
      <Button
        className="w-full gap-2"
        disabled={loading || !json}
        onClick={() => onDiscover({ service_account_json: json })}
      >
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Cloud className="h-4 w-4" />}
        Discover GCP Assets
      </Button>
    </div>
  );
}

// ─── Azure Credentials Form ───────────────────────────────────────────────────

function AzureForm({
  onDiscover,
  loading,
}: {
  onDiscover: (creds: Record<string, string>) => void;
  loading: boolean;
}) {
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-zinc-500 mb-1 block">Client ID</label>
          <Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="UUID" autoComplete="off" />
        </div>
        <div>
          <label className="text-xs text-zinc-500 mb-1 block">Client Secret</label>
          <Input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder="Secret" autoComplete="off" />
        </div>
        <div>
          <label className="text-xs text-zinc-500 mb-1 block">Tenant ID</label>
          <Input value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="UUID" autoComplete="off" />
        </div>
        <div>
          <label className="text-xs text-zinc-500 mb-1 block">Subscription ID</label>
          <Input value={subscriptionId} onChange={(e) => setSubscriptionId(e.target.value)} placeholder="UUID" autoComplete="off" />
        </div>
      </div>
      <Button
        className="w-full gap-2"
        disabled={loading || !clientId || !clientSecret || !tenantId || !subscriptionId}
        onClick={() =>
          onDiscover({ client_id: clientId, client_secret: clientSecret, tenant_id: tenantId, subscription_id: subscriptionId })
        }
      >
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Cloud className="h-4 w-4" />}
        Discover Azure Assets
      </Button>
    </div>
  );
}

// ─── Provider Card ────────────────────────────────────────────────────────────

const PROVIDER_META: Record<Provider, { label: string; color: string; logo: string }> = {
  aws: { label: "Amazon Web Services", color: "border-orange-500/30", logo: "AWS" },
  gcp: { label: "Google Cloud Platform", color: "border-blue-500/30", logo: "GCP" },
  azure: { label: "Microsoft Azure", color: "border-sky-500/30", logo: "AZ" },
};

function ProviderCard({
  provider,
  onResult,
}: {
  provider: Provider;
  onResult: (result: DiscoveredSession) => void;
}) {
  const meta = PROVIDER_META[provider];

  const discoverMutation = useMutation({
    mutationFn: (creds: Record<string, string>) =>
      cloudApi.discover(provider, creds) as Promise<CloudDiscoverResult>,
    onSuccess: (data) => {
      if (data.message) {
        toast.info(data.message);
      } else {
        toast.success(`Discovered ${data.discovered} ${provider.toUpperCase()} assets`);
      }
      onResult({ provider, result: data });
    },
    onError: (err: unknown) => {
      toast.error("Discovery failed", {
        description: (err as { message?: string })?.message ?? "Unknown error",
      });
    },
  });

  return (
    <Card className={`border ${meta.color}`}>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold text-zinc-300 flex items-center gap-2">
          <span className="inline-flex h-7 w-10 items-center justify-center rounded bg-zinc-800 text-xs font-bold text-zinc-300">
            {meta.logo}
          </span>
          {meta.label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {provider === "aws" && (
          <AwsForm
            onDiscover={(c) => discoverMutation.mutate(c)}
            loading={discoverMutation.isPending}
          />
        )}
        {provider === "gcp" && (
          <GcpForm
            onDiscover={(c) => discoverMutation.mutate(c)}
            loading={discoverMutation.isPending}
          />
        )}
        {provider === "azure" && (
          <AzureForm
            onDiscover={(c) => discoverMutation.mutate(c)}
            loading={discoverMutation.isPending}
          />
        )}
      </CardContent>
    </Card>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CloudDiscoveryPage() {
  const queryClient = useQueryClient();
  const [sessions, setSessions] = useState<DiscoveredSession[]>([]);

  const { data: savedAssets, isLoading: assetsLoading } = useQuery({
    queryKey: ["cloud", "assets"],
    queryFn: () => cloudApi.listAssets() as Promise<CloudAssetListResponse>,
    staleTime: 60_000,
  });

  const handleResult = (session: DiscoveredSession) => {
    setSessions((prev) => {
      const filtered = prev.filter((s) => s.provider !== session.provider);
      return [...filtered, session];
    });
    queryClient.invalidateQueries({ queryKey: ["cloud", "assets"] });
  };

  const allDiscovered: CloudAsset[] = sessions.flatMap((s) => s.result.assets);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cloud Asset Discovery"
        description="Enumerate cloud resources across AWS, GCP, and Azure using cloudlist"
      >
        <Button
          variant="outline"
          size="sm"
          className="gap-1.5"
          onClick={() => queryClient.invalidateQueries({ queryKey: ["cloud", "assets"] })}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
      </PageHeader>

      {/* Provider discovery cards */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {(["aws", "gcp", "azure"] as Provider[]).map((p) => (
          <ProviderCard key={p} provider={p} onResult={handleResult} />
        ))}
      </div>

      {/* Session results */}
      {allDiscovered.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-zinc-300">
              Discovered Assets ({allDiscovered.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900/50">
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">Value</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">Provider</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">Resource Type</th>
                  </tr>
                </thead>
                <tbody>
                  {allDiscovered.map((asset, i) => (
                    <tr key={i} className="border-b border-zinc-800/60 hover:bg-zinc-800/30">
                      <td className="px-4 py-3 font-mono text-xs text-zinc-300">{asset.value}</td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className="text-[10px] uppercase">
                          {asset.provider}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-zinc-400 text-xs">{asset.resource_type}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Saved org cloud assets */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-300">
            Saved Cloud Assets
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {assetsLoading ? (
            <div className="p-4 space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : (savedAssets?.items ?? []).length === 0 ? (
            <div className="p-6">
              <EmptyState
                icon={<Server className="h-8 w-8" />}
                title="No cloud assets"
                description="Run a cloud discovery to populate this list."
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900/50">
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">Value</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">Tags</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">Risk</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {savedAssets!.items.map((a) => (
                    <tr key={a.id} className="border-b border-zinc-800/60 hover:bg-zinc-800/30">
                      <td className="px-4 py-3 font-mono text-xs text-zinc-300">{a.value}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {a.tags.slice(0, 3).map((tag) => (
                            <span key={tag} className="inline-flex rounded px-1.5 py-0.5 text-[10px] bg-zinc-800 text-zinc-400">
                              {tag}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-zinc-400 text-xs">
                        {a.risk_score != null ? a.risk_score.toFixed(1) : "—"}
                      </td>
                      <td className="px-4 py-3 text-zinc-400 text-xs">
                        {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
