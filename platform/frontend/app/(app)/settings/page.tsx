"use client";

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Loader2, Building2, Save, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { useAuth } from "@/lib/auth";
import { orgApi } from "@/lib/api";
import { toast } from "sonner";

const settingsSchema = z.object({
  full_name: z.string().min(2),
  email: z.string().email(),
  organization_name: z.string().min(2),
});

type SettingsFormData = z.infer<typeof settingsSchema>;

const DEFAULT_SLA: Record<string, number> = {
  critical: 1,
  high: 7,
  medium: 30,
  low: 90,
  info: 180,
};

const SEVERITY_LABELS: { key: string; label: string; color: string }[] = [
  { key: "critical", label: "Critical", color: "text-red-400" },
  { key: "high", label: "High", color: "text-orange-400" },
  { key: "medium", label: "Medium", color: "text-yellow-400" },
  { key: "low", label: "Low", color: "text-blue-400" },
  { key: "info", label: "Info", color: "text-zinc-400" },
];

function SlaConfigCard({ orgId }: { orgId: string }) {
  const [sla, setSla] = useState<Record<string, number>>(DEFAULT_SLA);
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await orgApi.updateSlaConfig(orgId, sla);
      toast.success("SLA configuration saved");
    } catch {
      toast.error("Failed to save SLA configuration");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Clock className="h-4 w-4 text-orange-400" />
          SLA Configuration
        </CardTitle>
        <CardDescription>
          Set the number of days to resolve findings by severity. These deadlines are applied
          automatically when new findings are created.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {SEVERITY_LABELS.map(({ key, label, color }) => (
            <div key={key} className="flex items-center gap-4">
              <Label className={`w-20 text-sm font-medium ${color}`}>{label}</Label>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min={1}
                  max={365}
                  value={sla[key] ?? DEFAULT_SLA[key]}
                  onChange={(e) =>
                    setSla((prev) => ({
                      ...prev,
                      [key]: Math.max(1, parseInt(e.target.value) || 1),
                    }))
                  }
                  className="w-24 h-8 text-sm"
                />
                <span className="text-xs text-zinc-500">days</span>
              </div>
            </div>
          ))}
          <div className="pt-2">
            <Button
              onClick={handleSave}
              disabled={saving}
              size="sm"
              className="gap-1.5 bg-orange-600 hover:bg-orange-500 text-white"
            >
              {saving ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Save className="h-3.5 w-3.5" />
              )}
              Save SLA Settings
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function SettingsPage() {
  const { user } = useAuth();
  const [isSaving, setIsSaving] = useState(false);

  const { register, handleSubmit, formState: { errors, isDirty } } = useForm<SettingsFormData>({
    resolver: zodResolver(settingsSchema),
    defaultValues: {
      full_name: user?.full_name ?? "",
      email: user?.email ?? "",
      organization_name: "",
    },
  });

  const onSubmit = async (data: SettingsFormData) => {
    setIsSaving(true);
    try {
      // API call would go here
      await new Promise((resolve) => setTimeout(resolve, 800));
      toast.success("Settings saved");
    } catch {
      toast.error("Failed to save settings");
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-2xl">
      <PageHeader
        title="Settings"
        description="Manage your organization and profile settings"
      />

      {/* Profile */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Profile</CardTitle>
          <CardDescription>Update your personal information</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="full_name">Full Name</Label>
              <Input id="full_name" {...register("full_name")} />
              {errors.full_name && (
                <p className="text-xs text-red-400">{errors.full_name.message}</p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="email">Email Address</Label>
              <Input id="email" type="email" {...register("email")} />
              {errors.email && (
                <p className="text-xs text-red-400">{errors.email.message}</p>
              )}
            </div>
            <Button type="submit" disabled={isSaving || !isDirty} className="gap-1.5">
              {isSaving ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              Save Changes
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Organization */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Building2 className="h-4 w-4" />
            Organization
          </CardTitle>
          <CardDescription>Manage your organization settings</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="org_name">Organization Name</Label>
              <Input
                id="org_name"
                {...register("organization_name")}
                placeholder="Acme Corporation"
              />
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="rounded-lg border border-zinc-800 p-3">
                <p className="text-zinc-500 text-xs uppercase mb-1">Plan</p>
                <p className="font-semibold text-zinc-200">Enterprise</p>
              </div>
              <div className="rounded-lg border border-zinc-800 p-3">
                <p className="text-zinc-500 text-xs uppercase mb-1">Your Role</p>
                <p className="font-semibold text-zinc-200 capitalize">{user?.role}</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* SLA Configuration */}
      {user?.org_id && <SlaConfigCard orgId={user.org_id} />}

      {/* Danger Zone */}
      <Card className="border-red-900/30">
        <CardHeader>
          <CardTitle className="text-base text-red-400">Danger Zone</CardTitle>
          <CardDescription>Irreversible and destructive actions</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between py-3 border-b border-zinc-800">
            <div>
              <p className="text-sm font-medium text-zinc-200">Delete all scan data</p>
              <p className="text-xs text-zinc-500">Permanently delete all scans, assets, and findings</p>
            </div>
            <Button variant="destructive" size="sm">Delete Data</Button>
          </div>
          <div className="flex items-center justify-between pt-3">
            <div>
              <p className="text-sm font-medium text-zinc-200">Delete organization</p>
              <p className="text-xs text-zinc-500">Permanently delete your organization and all data</p>
            </div>
            <Button variant="destructive" size="sm">Delete Organization</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
