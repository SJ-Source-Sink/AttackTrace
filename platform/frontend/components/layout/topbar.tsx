"use client";

import React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Bell, ChevronDown, LogOut, Settings, User, Plus, Search } from "lucide-react";
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

  const handleLogout = () => {
    logout();
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
        <Button variant="ghost" size="icon" className="relative h-8 w-8">
          <Bell className="h-4 w-4 text-zinc-400" />
          <span className="absolute top-1 right-1 h-2 w-2 rounded-full bg-red-500" />
        </Button>

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
