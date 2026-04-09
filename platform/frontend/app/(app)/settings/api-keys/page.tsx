"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Key, Plus, Trash2, Copy, Eye, EyeOff, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { PageHeader } from "@/components/shared/page-header";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { orgApi } from "@/lib/api";
import { formatDate, formatRelativeTime } from "@/lib/utils";
import { toast } from "sonner";
import type { ApiKey } from "@/types";

interface CreatedKey {
  id: string;
  key: string;
  name: string;
}

export default function ApiKeysPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [createdKey, setCreatedKey] = useState<CreatedKey | null>(null);
  const [showKey, setShowKey] = useState(false);

  const { data: apiKeysData, isLoading } = useQuery({
    queryKey: ["org", "api-keys"],
    queryFn: () => orgApi.apiKeys() as Promise<{ items: ApiKey[] } | ApiKey[]>,
    staleTime: 60_000,
  });
  const apiKeys = Array.isArray(apiKeysData) ? apiKeysData : (apiKeysData as { items: ApiKey[] })?.items ?? [];

  const createMutation = useMutation({
    mutationFn: () => orgApi.createApiKey({ name: keyName }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["org", "api-keys"] });
      setCreatedKey(data as CreatedKey);
      setShowCreate(false);
      setKeyName("");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => orgApi.deleteApiKey(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org", "api-keys"] });
      toast.success("API key deleted");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const copyKey = () => {
    if (createdKey) {
      navigator.clipboard.writeText(createdKey.key);
      toast.success("API key copied to clipboard");
    }
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <PageHeader
        title="API Keys"
        description="Manage API keys for programmatic access"
      >
        <Button onClick={() => setShowCreate(true)} className="gap-1.5">
          <Plus className="h-4 w-4" />
          Create API Key
        </Button>
      </PageHeader>

      {/* Info banner */}
      <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
        <p className="text-sm text-blue-300">
          <strong>Security notice:</strong> API keys provide full access to the AttackTrace API.
          Store them securely and never expose them in client-side code.
        </p>
      </div>

      {/* Keys list */}
      <div className="space-y-2">
        {isLoading
          ? Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-20 w-full rounded-lg" />
            ))
          : !apiKeys || apiKeys.length === 0
            ? (
              <Card>
                <CardContent className="flex flex-col items-center py-12">
                  <Key className="h-8 w-8 text-zinc-600 mb-3" />
                  <p className="text-zinc-500 text-sm">No API keys created yet.</p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-4"
                    onClick={() => setShowCreate(true)}
                  >
                    Create your first API key
                  </Button>
                </CardContent>
              </Card>
            )
            : apiKeys.map((key) => (
                <div
                  key={key.id}
                  className="flex items-center gap-4 rounded-lg border border-zinc-800 bg-zinc-900 p-4 hover:border-zinc-700 transition-colors"
                >
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-zinc-800">
                    <Key className="h-4 w-4 text-zinc-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-zinc-200">{key.name}</p>
                    <div className="flex items-center gap-3 mt-1">
                      <code className="text-xs text-zinc-500 font-mono">
                        {key.key_prefix}••••••••••••
                      </code>
                      <span className="text-xs text-zinc-600">
                        Created {formatDate(key.created_at)}
                      </span>
                      {key.last_used && (
                        <span className="text-xs text-zinc-600">
                          Last used {formatRelativeTime(key.last_used)}
                        </span>
                      )}
                    </div>
                  </div>
                  {key.expires_at && (
                    <Badge variant="outline" className="text-xs shrink-0">
                      Expires {formatDate(key.expires_at)}
                    </Badge>
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-zinc-500 hover:text-red-400"
                    onClick={() => deleteMutation.mutate(key.id)}
                    disabled={deleteMutation.isPending}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
      </div>

      {/* Create Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create API Key</DialogTitle>
            <DialogDescription>
              Give your API key a descriptive name to identify its purpose.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5 py-2">
            <Label htmlFor="key-name">Key Name</Label>
            <Input
              id="key-name"
              placeholder="e.g., CI/CD Pipeline, Monitoring"
              value={keyName}
              onChange={(e) => setKeyName(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate()}
              disabled={!keyName || createMutation.isPending}
              className="gap-1.5"
            >
              {createMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Key className="h-4 w-4" />
              )}
              Create Key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Show Created Key Dialog */}
      <Dialog open={!!createdKey} onOpenChange={() => setCreatedKey(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>API Key Created</DialogTitle>
            <DialogDescription>
              Copy this key now — it will not be shown again.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3">
              <p className="text-xs text-yellow-400 font-medium mb-1">
                Save this key securely
              </p>
              <p className="text-xs text-yellow-400/70">
                This is the only time you will see this key. Store it in a password manager or secrets manager.
              </p>
            </div>

            <div className="relative">
              <div className="rounded-md border border-zinc-700 bg-zinc-950 p-3 pr-20 font-mono text-sm text-zinc-300 break-all">
                {showKey ? createdKey?.key : "••••••••••••••••••••••••••••••••"}
              </div>
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  onClick={() => setShowKey(!showKey)}
                >
                  {showKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  onClick={copyKey}
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => setCreatedKey(null)} className="w-full">
              I&apos;ve saved my key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
