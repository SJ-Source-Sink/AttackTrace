"use client";

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Loader2, Building2, Save } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { useAuth } from "@/lib/auth";
import { toast } from "sonner";

const settingsSchema = z.object({
  full_name: z.string().min(2),
  email: z.string().email(),
  organization_name: z.string().min(2),
});

type SettingsFormData = z.infer<typeof settingsSchema>;

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
