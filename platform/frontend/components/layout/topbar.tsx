"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Bell, ChevronDown, LogOut, Settings, User, Plus, Search, CheckCircle2, XCircle, Loader2, Clock } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { cn } from "@/lib/utils";
import { scansApi } from "@/lib/api";
import type { Scan } from "@/types";

const NOTIF_LS_KEY = "attacktrace:notif:last_seen";
const POLL_INTERVAL_MS = 30_000;

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function NotificationIcon({ status }: { status: Scan["status"] }) {
  if (status === "completed") return <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />;
  if (status === "failed") return <XCircle className="h-4 w-4 text-red-400 shrink-0" />;
  if (status === "running") return <Loader2 className="h-4 w-4 text-blue-400 shrink-0 animate-spin" />;
  return <Clock className="h-4 w-4 text-zinc-400 shrink-0" />;
}

function NotificationPanel({ onOpen }: { onOpen: () => void }) {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const hasFetched = useRef(false);

  const fetchScans = useCallback(async () => {
    try {
      const res = await scansApi.list({ per_page: 15, page: 1 }) as { items?: Scan[] } | Scan[];
      const items: Scan[] = (res as { items?: Scan[] }).items ?? (res as Scan[]) ?? [];
      setScans(items.slice(0, 12));
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!hasFetched.current) {
      hasFetched.current = true;
      fetchScans();
      onOpen();
    }
  }, [fetchScans, onOpen]);

  const handleClick = (scanId: string) => {
    router.push(`/scans/${scanId}`);
  };

  return (
    <div className="w-80">
      <div className="px-3 py-2 border-b border-zinc-800 flex items-center justify-between">
        <span className="text-sm font-semibold text-zinc-100">Notifications</span>
        <span className="text-xs text-zinc-500">Recent scans</span>
      </div>
      <div className="max-h-[420px] overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 text-zinc-500 animate-spin" />
          </div>
        ) : scans.length === 0 ? (
          <div className="py-8 text-center text-sm text-zinc-500">No scans yet</div>
        ) : (
          scans.map((scan) => (
            <button
              key={scan.id}
              type="button"
              onClick={() => handleClick(scan.id)}
              className="w-full text-left px-3 py-2.5 hover:bg-zinc-800/60 transition-colors border-b border-zinc-800/50 last:border-0"
            >
              <div className="flex items-start gap-2.5">
                <div className="mt-0.5">
                  <NotificationIcon status={scan.status} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-zinc-200 font-medium truncate">
                    {scan.company_name || scan.target_domains?.[0] || "Scan"}
                  </p>
                  <p className="text-xs text-zinc-500 truncate">
                    {scan.target_domains?.[0]}
                  </p>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <span className={cn(
                      "text-xs capitalize",
                      scan.status === "completed" && "text-emerald-400",
                      scan.status === "failed" && "text-red-400",
                      scan.status === "running" && "text-blue-400",
                      scan.status === "pending" && "text-zinc-400",
                      scan.status === "cancelled" && "text-zinc-500",
                    )}>
                      {scan.status}
                    </span>
                    <span className="text-zinc-600">·</span>
                    <span className="text-xs text-zinc-500">{relativeTime(scan.updated_at)}</span>
                  </div>
                </div>
              </div>
            </button>
          ))
        )}
      </div>
      <div className="px-3 py-2 border-t border-zinc-800">
        <button
          type="button"
          onClick={() => router.push("/scans")}
          className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          View all scans →
        </button>
      </div>
    </div>
  );
}

interface TopbarProps {
  className?: string;
}

function getInitials(name: string): string {
  return name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

export function Topbar({ className }: TopbarProps) {
  const { user, logout } = useAuth();
  const router = useRouter();
  const [notifOpen, setNotifOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  // Poll for unread count (scans completed/failed since last opened)
  useEffect(() => {
    const computeUnread = async () => {
      try {
        const lastSeen = parseInt(localStorage.getItem(NOTIF_LS_KEY) ?? "0", 10);
        const res = await scansApi.list({ per_page: 15, page: 1 }) as { items?: Scan[] } | Scan[];
        const items: Scan[] = (res as { items?: Scan[] }).items ?? (res as Scan[]) ?? [];
        const count = items.filter((s) => {
          const t = new Date(s.updated_at).getTime();
          return t > lastSeen && (s.status === "completed" || s.status === "failed");
        }).length;
        setUnreadCount(count);
      } catch {
        // ignore
      }
    };
    computeUnread();
    const id = setInterval(computeUnread, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  const handleNotifOpen = useCallback(() => {
    localStorage.setItem(NOTIF_LS_KEY, Date.now().toString());
    setUnreadCount(0);
  }, []);

  const handleLogout = async () => {
    await logout();
    router.push("/login");
  };

  return (
    <header
      className={cn(
        "flex h-14 items-center justify-between border-b border-zinc-800 bg-zinc-950 px-6",
        className,
      )}
    >
      {/* Left: breadcrumb / search */}
      <div className="flex items-center gap-3">
        <div className="relative hidden md:flex items-center">
          <Search className="absolute left-3 h-4 w-4 text-zinc-500" />
          <input
            type="search"
            placeholder="Search assets, findings..."
            className="h-8 w-64 rounded-md border border-zinc-800 bg-zinc-900 pl-9 pr-3 text-sm text-zinc-300 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
      </div>

      {/* Right: actions + user */}
      <div className="flex items-center gap-2">
        {/* New Scan CTA */}
        <Button
          size="sm"
          className="hidden md:flex gap-1.5"
          onClick={() => router.push("/scans/new")}
        >
          <Plus className="h-3.5 w-3.5" />
          New Scan
        </Button>

        {/* Notifications */}
        <DropdownMenu open={notifOpen} onOpenChange={setNotifOpen}>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="relative h-8 w-8">
              <Bell className="h-4 w-4 text-zinc-400" />
              {unreadCount > 0 && (
                <span className="absolute top-1 right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white leading-none">
                  {unreadCount > 9 ? "9+" : unreadCount}
                </span>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="p-0 w-80" sideOffset={8}>
            {notifOpen && <NotificationPanel onOpen={handleNotifOpen} />}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* User menu */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              className="flex items-center gap-2 px-2 h-8 hover:bg-zinc-800"
            >
              <Avatar className="h-6 w-6">
                <AvatarImage src={user?.avatar_url} />
                <AvatarFallback className="text-xs">
                  {user?.full_name ? getInitials(user.full_name) : "?"}
                </AvatarFallback>
              </Avatar>
              <span className="hidden md:inline text-sm text-zinc-300 max-w-[120px] truncate">
                {user?.full_name ?? user?.email ?? "User"}
              </span>
              <ChevronDown className="h-3 w-3 text-zinc-500" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="font-normal">
              <div className="flex flex-col space-y-1">
                <p className="text-sm font-medium text-zinc-100">
                  {user?.full_name ?? "User"}
                </p>
                <p className="text-xs text-zinc-400 truncate">{user?.email}</p>
                <p className="text-xs text-zinc-500 capitalize">{user?.role}</p>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link href="/settings" className="flex items-center gap-2 cursor-pointer">
                <User className="h-4 w-4" />
                Profile
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link href="/settings" className="flex items-center gap-2 cursor-pointer">
                <Settings className="h-4 w-4" />
                Settings
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={handleLogout}
              className="text-red-400 focus:text-red-400 focus:bg-red-400/10 cursor-pointer"
            >
              <LogOut className="h-4 w-4 mr-2" />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
