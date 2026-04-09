"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  UserPlus, Trash2, MoreVertical, Loader2, Shield, Eye, Edit, Crown,
  KeyRound, Copy, Check, Link2, Clock, XCircle, RefreshCw, Plus,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { orgApi, type InviteCodeItem } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { toast } from "sonner";
import type { OrgMember, UserRole } from "@/types";

const ROLE_CONFIG: Record<UserRole, { label: string; icon: React.ElementType; color: string }> = {
  owner: { label: "Owner", icon: Crown, color: "text-yellow-400" },
  admin: { label: "Admin", icon: Shield, color: "text-blue-400" },
  analyst: { label: "Analyst", icon: Edit, color: "text-emerald-400" },
  viewer: { label: "Viewer", icon: Eye, color: "text-zinc-400" },
};

function getInitials(name: string): string {
  return name.split(" ").map((n) => n[0]).join("").toUpperCase().slice(0, 2);
}

function getInviteUrl(code: string): string {
  const base = typeof window !== "undefined" ? window.location.origin : "";
  return `${base}/register?code=${code}`;
}

function InviteCodeRow({ item, onRevoke }: { item: InviteCodeItem; onRevoke: (id: string) => void }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(getInviteUrl(item.code)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const status = item.is_revoked
    ? { label: "Revoked", color: "bg-zinc-800 text-zinc-500", icon: XCircle }
    : item.used_at
    ? { label: "Used", color: "bg-emerald-500/10 text-emerald-400", icon: Check }
    : !item.is_valid
    ? { label: "Expired", color: "bg-amber-500/10 text-amber-400", icon: Clock }
    : { label: "Active", color: "bg-blue-500/10 text-blue-400", icon: RefreshCw };

  const StatusIcon = status.icon;
  const roleConfig = ROLE_CONFIG[item.role as UserRole] ?? ROLE_CONFIG.analyst;
  const RoleIcon = roleConfig.icon;

  return (
    <div className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 hover:border-zinc-700 transition-colors">
      <div className="flex-shrink-0">
        <KeyRound className="h-4 w-4 text-zinc-500" />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-medium text-zinc-200 tracking-wider">
            {item.code}
          </span>
          <span className={`inline-flex items-center gap-1 text-xs px-1.5 py-0.5 rounded ${status.color}`}>
            <StatusIcon className="h-3 w-3" />
            {status.label}
          </span>
        </div>
        <div className="flex items-center gap-3 mt-0.5">
          <span className={`flex items-center gap-1 text-xs ${roleConfig.color}`}>
            <RoleIcon className="h-3 w-3" />
            {roleConfig.label}
          </span>
          {item.email && (
            <span className="text-xs text-zinc-600">for {item.email}</span>
          )}
          {item.expires_at && !item.used_at && (
            <span className="text-xs text-zinc-600">
              expires {formatDate(item.expires_at)}
            </span>
          )}
          {item.used_at && (
            <span className="text-xs text-zinc-600">
              used {formatDate(item.used_at)}
            </span>
          )}
          {!item.used_at && !item.is_revoked && (
            <span className="text-xs text-zinc-600">
              created {formatDate(item.created_at)}
            </span>
          )}
        </div>
      </div>

      {item.is_valid && !item.is_revoked && !item.used_at && (
        <div className="flex items-center gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 gap-1.5 text-xs text-zinc-400 hover:text-zinc-200"
            onClick={handleCopy}
          >
            {copied ? (
              <Check className="h-3.5 w-3.5 text-emerald-400" />
            ) : (
              <Copy className="h-3.5 w-3.5" />
            )}
            {copied ? "Copied!" : "Copy link"}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-zinc-600 hover:text-red-400"
            onClick={() => onRevoke(item.id)}
          >
            <XCircle className="h-4 w-4" />
          </Button>
        </div>
      )}
    </div>
  );
}

export default function MembersPage() {
  const queryClient = useQueryClient();
  const [showGenerate, setShowGenerate] = useState(false);
  const [codeRole, setCodeRole] = useState<UserRole>("analyst");
  const [codeEmail, setCodeEmail] = useState("");
  const [codeExpiry, setCodeExpiry] = useState("7");

  const { data: membersData, isLoading: membersLoading } = useQuery({
    queryKey: ["org", "members"],
    queryFn: () => orgApi.members() as Promise<{ items: OrgMember[] } | OrgMember[]>,
    staleTime: 60_000,
  });
  const members = Array.isArray(membersData) ? membersData : (membersData as { items: OrgMember[] })?.items ?? [];

  const { data: inviteCodes, isLoading: codesLoading } = useQuery({
    queryKey: ["org", "invite-codes"],
    queryFn: () => orgApi.inviteCodes(),
    staleTime: 30_000,
  });

  const generateMutation = useMutation({
    mutationFn: () =>
      orgApi.createInviteCode({
        role: codeRole,
        email: codeEmail.trim() || undefined,
        expires_in_days: parseInt(codeExpiry, 10),
      }),
    onSuccess: (newCode) => {
      queryClient.invalidateQueries({ queryKey: ["org", "invite-codes"] });
      setShowGenerate(false);
      setCodeEmail("");
      // Auto-copy the link
      const url = getInviteUrl(newCode.code);
      navigator.clipboard.writeText(url).catch(() => {});
      toast.success(`Invite code ${newCode.code} generated — link copied!`);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => orgApi.revokeInviteCode(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org", "invite-codes"] });
      toast.success("Invite code revoked");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const removeMutation = useMutation({
    mutationFn: (userId: string) => orgApi.removeMember(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org", "members"] });
      toast.success("Member removed");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const updateRoleMutation = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: UserRole }) =>
      orgApi.updateMemberRole(userId, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org", "members"] });
      toast.success("Role updated");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const activeCodes = inviteCodes?.items?.filter((c) => c.is_valid && !c.is_revoked && !c.used_at) ?? [];
  const pastCodes = inviteCodes?.items?.filter((c) => !c.is_valid || c.is_revoked || c.used_at) ?? [];

  return (
    <div className="space-y-8 max-w-3xl">
      <PageHeader
        title="Team Members"
        description="Manage team access and permissions"
      >
        <Button onClick={() => setShowGenerate(true)} className="gap-1.5">
          <KeyRound className="h-4 w-4" />
          Generate Invite Code
        </Button>
      </PageHeader>

      {/* Role descriptions */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(Object.entries(ROLE_CONFIG) as [UserRole, typeof ROLE_CONFIG[UserRole]][]).map(([role, config]) => {
          const Icon = config.icon;
          return (
            <div key={role} className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
              <Icon className={`h-4 w-4 ${config.color} mb-2`} />
              <p className={`text-sm font-semibold ${config.color}`}>{config.label}</p>
              <p className="text-xs text-zinc-600 mt-0.5">
                {role === "owner" && "Full access"}
                {role === "admin" && "Manage team & settings"}
                {role === "analyst" && "Run scans, manage findings"}
                {role === "viewer" && "Read-only access"}
              </p>
            </div>
          );
        })}
      </div>

      {/* Members list */}
      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">
          Members ({members?.length ?? 0})
        </h2>
        {membersLoading
          ? Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 p-4 rounded-lg border border-zinc-800">
                <Skeleton className="h-10 w-10 rounded-full" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-3 w-48" />
                </div>
              </div>
            ))
          : members?.map((member) => {
              const roleConfig = ROLE_CONFIG[member.role];
              const RoleIcon = roleConfig.icon;

              return (
                <div
                  key={member.id}
                  className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 p-4 hover:border-zinc-700 transition-colors"
                >
                  <Avatar className="h-10 w-10">
                    <AvatarFallback>{getInitials(member.user.full_name)}</AvatarFallback>
                  </Avatar>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-zinc-200">{member.user.full_name}</p>
                    <p className="text-xs text-zinc-500">{member.user.email}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className={`flex items-center gap-1 text-xs font-medium ${roleConfig.color}`}>
                      <RoleIcon className="h-3.5 w-3.5" />
                      {roleConfig.label}
                    </div>
                    <span className="text-xs text-zinc-600">
                      Joined {formatDate(member.joined_at)}
                    </span>
                  </div>

                  {member.role !== "owner" && (
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          onClick={() => updateRoleMutation.mutate({ userId: member.user.id, role: "admin" })}
                        >
                          Make Admin
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => updateRoleMutation.mutate({ userId: member.user.id, role: "analyst" })}
                        >
                          Make Analyst
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => updateRoleMutation.mutate({ userId: member.user.id, role: "viewer" })}
                        >
                          Make Viewer
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-red-400 focus:text-red-400 focus:bg-red-400/10"
                          onClick={() => removeMutation.mutate(member.user.id)}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Remove from team
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  )}
                </div>
              );
            })}
      </div>

      {/* Invite Codes section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">
              Invite Codes
            </h2>
            <p className="text-xs text-zinc-600 mt-0.5">
              Generate a code and share the link — anyone with it can join your org
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() => setShowGenerate(true)}
          >
            <Plus className="h-3.5 w-3.5" />
            New Code
          </Button>
        </div>

        {codesLoading ? (
          Array.from({ length: 2 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 p-4 rounded-lg border border-zinc-800">
              <Skeleton className="h-4 w-40" />
              <Skeleton className="h-4 w-20 ml-auto" />
            </div>
          ))
        ) : activeCodes.length === 0 && pastCodes.length === 0 ? (
          <div className="rounded-lg border border-dashed border-zinc-800 p-8 text-center">
            <KeyRound className="h-8 w-8 text-zinc-700 mx-auto mb-3" />
            <p className="text-sm text-zinc-500">No invite codes yet</p>
            <p className="text-xs text-zinc-600 mt-1">
              Generate a code to invite team members
            </p>
            <Button
              size="sm"
              className="mt-4 gap-1.5"
              onClick={() => setShowGenerate(true)}
            >
              <KeyRound className="h-3.5 w-3.5" />
              Generate first code
            </Button>
          </div>
        ) : (
          <div className="space-y-2">
            {activeCodes.length > 0 && (
              <>
                <p className="text-xs text-zinc-600 font-medium uppercase tracking-wide pl-1">Active</p>
                {activeCodes.map((item) => (
                  <InviteCodeRow
                    key={item.id}
                    item={item}
                    onRevoke={(id) => revokeMutation.mutate(id)}
                  />
                ))}
              </>
            )}
            {pastCodes.length > 0 && (
              <>
                <p className="text-xs text-zinc-600 font-medium uppercase tracking-wide pl-1 mt-3">
                  Past codes
                </p>
                {pastCodes.map((item) => (
                  <InviteCodeRow
                    key={item.id}
                    item={item}
                    onRevoke={(id) => revokeMutation.mutate(id)}
                  />
                ))}
              </>
            )}
          </div>
        )}
      </div>

      {/* Generate Code Dialog */}
      <Dialog open={showGenerate} onOpenChange={setShowGenerate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-blue-400" />
              Generate Invite Code
            </DialogTitle>
            <DialogDescription>
              Create a shareable invite link. The recipient uses it to register their account.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label>Role</Label>
              <Select value={codeRole} onValueChange={(v) => setCodeRole(v as UserRole)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">Admin — Manage team & settings</SelectItem>
                  <SelectItem value="analyst">Analyst — Run scans, manage findings</SelectItem>
                  <SelectItem value="viewer">Viewer — Read-only access</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="code-email">
                Restrict to email{" "}
                <span className="text-zinc-600 font-normal">(optional)</span>
              </Label>
              <Input
                id="code-email"
                type="email"
                placeholder="colleague@company.com"
                value={codeEmail}
                onChange={(e) => setCodeEmail(e.target.value)}
              />
              <p className="text-xs text-zinc-600">
                Leave blank to allow any email
              </p>
            </div>

            <div className="space-y-1.5">
              <Label>Expires in</Label>
              <Select value={codeExpiry} onValueChange={setCodeExpiry}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 day</SelectItem>
                  <SelectItem value="3">3 days</SelectItem>
                  <SelectItem value="7">7 days</SelectItem>
                  <SelectItem value="14">14 days</SelectItem>
                  <SelectItem value="30">30 days</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2.5 flex items-center gap-2">
              <Link2 className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
              <span className="text-xs text-zinc-500 font-mono truncate">
                {typeof window !== "undefined" ? window.location.origin : ""}/register?code=AttackTrace-XXXX-XXXX
              </span>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowGenerate(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => generateMutation.mutate()}
              disabled={generateMutation.isPending}
              className="gap-1.5"
            >
              {generateMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <KeyRound className="h-4 w-4" />
              )}
              Generate & Copy Link
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
