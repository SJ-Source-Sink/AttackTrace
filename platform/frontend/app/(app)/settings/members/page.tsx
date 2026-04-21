"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  UserPlus, Trash2, MoreVertical, Loader2, Shield, Eye, Edit, Crown,
  Copy, Check, Link2, RefreshCw, ChevronDown,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from "@/components/ui/dialog";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { orgApi } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { toast } from "sonner";
import type { OrgMember, UserRole } from "@/types";

const ROLE_CONFIG: Record<UserRole, { label: string; icon: React.ElementType; color: string; desc: string }> = {
  owner:   { label: "Owner",   icon: Crown,  color: "text-yellow-400", desc: "Full access" },
  admin:   { label: "Admin",   icon: Shield, color: "text-blue-400",   desc: "Manage team & settings" },
  analyst: { label: "Analyst", icon: Edit,   color: "text-emerald-400",desc: "Run scans, manage findings" },
  viewer:  { label: "Viewer",  icon: Eye,    color: "text-zinc-400",   desc: "Read-only access" },
};

function getInitials(name: string) {
  return name.split(" ").map((n) => n[0]).join("").toUpperCase().slice(0, 2);
}

function getInviteUrl(code: string) {
  const base = typeof window !== "undefined" ? window.location.origin : "";
  return `${base}/register?code=${code}`;
}

export default function MembersPage() {
  const queryClient = useQueryClient();

  // Add member dialog state
  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName]       = useState("");
  const [newEmail, setNewEmail]     = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole]       = useState<UserRole>("analyst");

  // Invite link copy state
  const [linkCopied, setLinkCopied] = useState(false);

  // Members
  const { data: membersData, isLoading: membersLoading } = useQuery({
    queryKey: ["org", "members"],
    queryFn: () => orgApi.members() as Promise<{ items: OrgMember[] } | OrgMember[]>,
    staleTime: 60_000,
  });
  const members = Array.isArray(membersData)
    ? membersData
    : (membersData as { items: OrgMember[] })?.items ?? [];

  // Invite link
  const { data: inviteLink, isLoading: linkLoading } = useQuery({
    queryKey: ["org", "invite-link"],
    queryFn: () => orgApi.getInviteLink(),
    staleTime: Infinity,
  });

  // Create member directly
  const createMutation = useMutation({
    mutationFn: () => orgApi.createMember({ full_name: newName, email: newEmail, password: newPassword, role: newRole }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org", "members"] });
      setShowAdd(false);
      setNewName(""); setNewEmail(""); setNewPassword(""); setNewRole("analyst");
      toast.success("Member added successfully");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  // Regenerate invite link
  const regenMutation = useMutation({
    mutationFn: () => orgApi.regenerateInviteLink(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org", "invite-link"] });
      toast.success("Invite link regenerated");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  // Remove member
  const removeMutation = useMutation({
    mutationFn: (userId: string) => orgApi.removeMember(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org", "members"] });
      toast.success("Member removed");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  // Update role
  const updateRoleMutation = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: UserRole }) =>
      orgApi.updateMemberRole(userId, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org", "members"] });
      toast.success("Role updated");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const copyInviteLink = () => {
    if (!inviteLink?.code) return;
    navigator.clipboard.writeText(getInviteUrl(inviteLink.code)).then(() => {
      setLinkCopied(true);
      setTimeout(() => setLinkCopied(false), 2000);
    });
  };

  const canSubmit = newName.trim() && newEmail.trim() && newPassword.trim();

  return (
    <div className="space-y-8 max-w-3xl">
      <PageHeader title="Team Members" description="Manage team access and permissions">
        <Button onClick={() => setShowAdd(true)} className="gap-1.5">
          <UserPlus className="h-4 w-4" />
          Add Member
        </Button>
      </PageHeader>

      {/* Invite Link */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <Link2 className="h-4 w-4 text-blue-400" />
              <p className="text-sm font-semibold text-zinc-200">Invite Link</p>
            </div>
            <p className="text-xs text-zinc-500">
              Share this link so teammates can create their own account.
            </p>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="text-xs text-zinc-500 hover:text-zinc-300 gap-1.5 shrink-0"
            onClick={() => regenMutation.mutate()}
            disabled={regenMutation.isPending}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${regenMutation.isPending ? "animate-spin" : ""}`} />
            Regenerate
          </Button>
        </div>

        <div className="mt-3 flex items-center gap-2">
          <div className="flex-1 rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 min-w-0">
            {linkLoading ? (
              <Skeleton className="h-4 w-64" />
            ) : (
              <span className="text-xs font-mono text-zinc-400 truncate block">
                {inviteLink ? getInviteUrl(inviteLink.code) : "—"}
              </span>
            )}
          </div>
          <Button
            size="sm"
            variant="outline"
            className="gap-1.5 shrink-0 border-zinc-700"
            onClick={copyInviteLink}
            disabled={!inviteLink}
          >
            {linkCopied ? (
              <><Check className="h-3.5 w-3.5 text-emerald-400" /> Copied</>
            ) : (
              <><Copy className="h-3.5 w-3.5" /> Copy</>
            )}
          </Button>
        </div>
      </div>

      {/* Members list */}
      <div className="space-y-2">
        <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider px-1">
          Members ({members.length})
        </h2>

        {membersLoading
          ? Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 p-4 rounded-xl border border-zinc-800">
                <Skeleton className="h-10 w-10 rounded-full" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-3 w-48" />
                </div>
              </div>
            ))
          : members.map((member) => {
              const cfg = ROLE_CONFIG[member.role] ?? ROLE_CONFIG.analyst;
              const RoleIcon = cfg.icon;
              return (
                <div
                  key={member.user_id}
                  className="flex items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3 hover:border-zinc-700 transition-colors"
                >
                  <Avatar className="h-9 w-9 shrink-0">
                    <AvatarFallback className="text-xs">{getInitials(member.full_name)}</AvatarFallback>
                  </Avatar>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-zinc-200 leading-none">{member.full_name}</p>
                    <p className="text-xs text-zinc-500 mt-0.5">{member.email}</p>
                  </div>
                  <div className={`flex items-center gap-1 text-xs font-medium ${cfg.color}`}>
                    <RoleIcon className="h-3.5 w-3.5" />
                    {cfg.label}
                  </div>
                  <span className="text-xs text-zinc-600 hidden sm:block">
                    {formatDate(member.joined_at)}
                  </span>

                  {member.role !== "owner" && (
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0">
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-44">
                        <DropdownMenuItem onClick={() => updateRoleMutation.mutate({ userId: member.user_id, role: "admin" })}>
                          Make Admin
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => updateRoleMutation.mutate({ userId: member.user_id, role: "analyst" })}>
                          Make Analyst
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => updateRoleMutation.mutate({ userId: member.user_id, role: "viewer" })}>
                          Make Viewer
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-red-400 focus:text-red-400 focus:bg-red-400/10"
                          onClick={() => removeMutation.mutate(member.user_id)}
                        >
                          <Trash2 className="h-3.5 w-3.5 mr-2" />
                          Remove
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  )}
                </div>
              );
            })}
      </div>

      {/* Add Member Dialog */}
      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserPlus className="h-4 w-4 text-blue-400" />
              Add Team Member
            </DialogTitle>
            <DialogDescription>
              Create an account for your teammate. Share the credentials with them directly.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-1">
            <div className="space-y-1.5">
              <Label>Full name</Label>
              <Input
                placeholder="Jane Smith"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Email</Label>
              <Input
                type="email"
                placeholder="jane@company.com"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Temporary password</Label>
              <Input
                type="text"
                placeholder="They can change this after login"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Role</Label>
              <Select value={newRole} onValueChange={(v) => setNewRole(v as UserRole)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(["admin", "analyst", "viewer"] as UserRole[]).map((r) => {
                    const c = ROLE_CONFIG[r];
                    const Icon = c.icon;
                    return (
                      <SelectItem key={r} value={r}>
                        <span className="flex items-center gap-2">
                          <Icon className={`h-3.5 w-3.5 ${c.color}`} />
                          <span>{c.label}</span>
                          <span className="text-zinc-500 text-xs">— {c.desc}</span>
                        </span>
                      </SelectItem>
                    );
                  })}
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAdd(false)}>Cancel</Button>
            <Button
              onClick={() => createMutation.mutate()}
              disabled={createMutation.isPending || !canSubmit}
              className="gap-1.5"
            >
              {createMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <UserPlus className="h-4 w-4" />
              )}
              Create Account
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
