"use client";

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Loader2, Save, Clock, ShieldCheck, ShieldOff, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { useAuth } from "@/lib/auth";
import { orgApi, apiFetch } from "@/lib/api";
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

function MfaCard() {
  const { user, refreshUser } = useAuth();
  const [step, setStep] = useState<"idle" | "enrolling" | "backup-codes">("idle");
  const [secret, setSecret] = useState("");
  const [otpauthUrl, setOtpauthUrl] = useState("");
  const [code, setCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const startEnroll = async () => {
    setBusy(true);
    try {
      const data = await apiFetch<{ secret: string; otpauth_url: string }>("/auth/mfa/enroll", {
        method: "POST",
      });
      setSecret(data.secret);
      setOtpauthUrl(data.otpauth_url);
      setStep("enrolling");
    } catch {
      toast.error("Failed to start MFA enrollment");
    } finally {
      setBusy(false);
    }
  };

  const confirmEnroll = async () => {
    setBusy(true);
    try {
      const data = await apiFetch<{ mfa_enabled: boolean; backup_codes: string[] }>(
        "/auth/mfa/verify",
        { method: "POST", body: JSON.stringify({ code }) },
      );
      setBackupCodes(data.backup_codes);
      setStep("backup-codes");
      setCode("");
      await refreshUser();
      toast.success("Two-factor authentication enabled");
    } catch {
      toast.error("Invalid code — please try again");
    } finally {
      setBusy(false);
    }
  };

  const disable = async () => {
    setBusy(true);
    try {
      await apiFetch("/auth/mfa/disable", {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      setPassword("");
      setStep("idle");
      await refreshUser();
      toast.success("Two-factor authentication disabled");
    } catch {
      toast.error("Incorrect password");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          {user?.mfa_enabled ? (
            <ShieldCheck className="h-4 w-4 text-green-400" />
          ) : (
            <ShieldOff className="h-4 w-4 text-zinc-500" />
          )}
          Two-Factor Authentication
        </CardTitle>
        <CardDescription>
          Require a code from an authenticator app (Google Authenticator, 1Password, Authy) in
          addition to your password.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {step === "enrolling" ? (
          <div className="space-y-4">
            <div>
              <p className="text-sm text-zinc-400 mb-2">
                Scan can&apos;t happen here — add this key manually in your authenticator app:
              </p>
              <div className="flex items-center gap-2">
                <code className="text-xs bg-zinc-900 border border-zinc-800 rounded px-2 py-1.5 text-zinc-300 break-all">
                  {secret}
                </code>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => { navigator.clipboard.writeText(secret); toast.success("Copied"); }}
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              </div>
              <p className="text-[10px] text-zinc-600 mt-1 break-all">{otpauthUrl}</p>
            </div>
            <div className="space-y-1.5 max-w-xs">
              <Label htmlFor="mfa-code">Enter the 6-digit code to confirm</Label>
              <Input
                id="mfa-code"
                inputMode="numeric"
                placeholder="123456"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </div>
            <Button size="sm" disabled={busy || code.length === 0} onClick={confirmEnroll}>
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Verify & Enable"}
            </Button>
          </div>
        ) : step === "backup-codes" ? (
          <div className="space-y-3">
            <p className="text-sm text-zinc-300">
              Save these one-time backup codes somewhere safe — each can be used once if you lose
              access to your authenticator app.
            </p>
            <div className="grid grid-cols-2 gap-2">
              {backupCodes.map((c) => (
                <code
                  key={c}
                  className="text-xs bg-zinc-900 border border-zinc-800 rounded px-2 py-1.5 text-zinc-300"
                >
                  {c}
                </code>
              ))}
            </div>
            <Button size="sm" variant="outline" onClick={() => setStep("idle")}>
              Done
            </Button>
          </div>
        ) : user?.mfa_enabled ? (
          <div className="space-y-3">
            <p className="text-sm text-zinc-400">Two-factor authentication is currently enabled.</p>
            <div className="space-y-1.5 max-w-xs">
              <Label htmlFor="mfa-disable-password">Confirm password to disable</Label>
              <Input
                id="mfa-disable-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <Button variant="destructive" size="sm" disabled={busy || !password} onClick={disable}>
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Disable 2FA"}
            </Button>
          </div>
        ) : (
          <Button size="sm" onClick={startEnroll} disabled={busy} className="gap-1.5">
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
            Enable 2FA
          </Button>
        )}
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

      {/* Security */}
      <MfaCard />

      {/* SLA Configuration */}
      {user?.org_id && <SlaConfigCard orgId={user.org_id} />}

    </div>
  );
}
