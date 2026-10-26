"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Bell, ChevronDown, LogOut, Settings, User, Plus, Search, CheckCircle2, XCircle, Loader2, AlertTriangle, MessageSquare, UserPlus, Radar, Clock3 } from "lucide-react";
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
import { notificationsApi } from "@/lib/api";
import type { NotificationFeedItem } from "@/types";

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

const EVENT_ICONS: Record<string, React.ElementType> = {
  "scan.completed": CheckCircle2,
  "scan.failed": XCircle,
  "finding.created": AlertTriangle,
  "finding.critical": AlertTriangle,
  "finding.assigned": UserPlus,
  "finding.commented": MessageSquare,
  "sla.breached": Clock3,
  "member.added": UserPlus,
};

function NotificationIcon({ eventType, severity }: { eventType: string; severity: string }) {
  const Icon = EVENT_ICONS[eventType] ?? Radar;
  const color =
    severity === "critical" || eventType === "scan.failed" ? "text-red-400"
    : severity === "high" ? "text-orange-400"
    : eventType === "scan.completed" ? "text-emerald-400"
    : "text-blue-400";
  return <Icon className={cn("h-4 w-4 shrink-0", color)} />;
}

function notificationHref(item: NotificationFeedItem): string | null {
  if (!item.resource_id) return null;
  if (item.resource_type === "finding") return `/findings/${item.resource_id}`;
  if (item.resource_type === "scan_job") return `/scans/${item.resource_id}`;
  return null;
}

function NotificationPanel({ onOpen }: { onOpen: (lastId: string) => void }) {
  const router = useRouter();
  const [items, setItems] = useState<NotificationFeedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const hasFetched = useRef(false);

  const fetchFeed = useCallback(async () => {
    try {
      const res = await notificationsApi.feed(20);
      setItems(res.items);
      onOpen(res.items[0]?.id ?? "0");
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  }, [onOpen]);

  useEffect(() => {
    if (!hasFetched.current) {
      hasFetched.current = true;
      fetchFeed();
    }
  }, [fetchFeed]);

  const handleClick = (item: NotificationFeedItem) => {
    const href = notificationHref(item);
    if (href) router.push(href);
  };

  return (
    <div className="w-96">
      <div className="px-3 py-2 border-b border-zinc-800 flex items-center justify-between">
        <span className="text-sm font-semibold text-zinc-100">Notifications</span>
        <span className="text-xs text-zinc-500">Scans, findings &amp; alerts</span>
      </div>
      <div className="max-h-[420px] overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 text-zinc-500 animate-spin" />
          </div>
        ) : items.length === 0 ? (
          <div className="py-8 text-center text-sm text-zinc-500">No activity yet</div>
        ) : (
          items.map((item) => {
            const href = notificationHref(item);
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleClick(item)}
                disabled={!href}
                className={cn(
                  "w-full text-left px-3 py-2.5 border-b border-zinc-800/50 last:border-0 transition-colors",
                  href ? "hover:bg-zinc-800/60 cursor-pointer" : "cursor-default",
                )}
              >
                <div className="flex items-start gap-2.5">
                  <div className="mt-0.5">
                    <NotificationIcon eventType={item.event_type} severity={item.severity} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-zinc-200 font-medium truncate">{item.title}</p>
                    {item.body && (
                      <p className="text-xs text-zinc-500 truncate">{item.body}</p>
                    )}
                    <span className="text-xs text-zinc-600">{relativeTime(item.timestamp)}</span>
                  </div>
                </div>
              </button>
            );
          })
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

  // Poll the real notification feed for the unread count (scan completions/
  // failures, critical findings, SLA breaches, assignments, comments).
  useEffect(() => {
    const computeUnread = async () => {
      try {
        const res = await notificationsApi.feed(1);
        setUnreadCount(res.unread_count);
      } catch {
        // ignore
      }
    };
    computeUnread();
    const id = setInterval(computeUnread, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  const handleNotifOpen = useCallback((lastId: string) => {
    notificationsApi.markRead(lastId).catch(() => {});
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
            <Button variant="ghost" size="icon" className="relative h-8 w-8" aria-label={unreadCount > 0 ? `Notifications (${unreadCount} unread)` : "Notifications"}>
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
