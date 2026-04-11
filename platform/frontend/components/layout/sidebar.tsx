"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Radar,
  Globe,
  ShieldAlert,
  FileText,
  Settings,
  Users,
  Key,
  ChevronRight,
  Zap,
  Plug,
  Network,
  Crosshair,
  Wind,
  Swords,
  BrainCircuit,
  GitFork,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
  children?: NavItem[];
}

const navItems: NavItem[] = [
  {
    label: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    label: "Scans",
    href: "/scans",
    icon: Radar,
  },
  {
    label: "Assets",
    href: "/assets",
    icon: Globe,
  },
  {
    label: "Findings",
    href: "/findings",
    icon: ShieldAlert,
  },
  {
    label: "Reports",
    href: "/reports",
    icon: FileText,
  },
  {
    label: "Nmap Scanner",
    href: "/nmap",
    icon: Network,
    badge: "Tool",
  },
  {
    label: "Nuclei Scanner",
    href: "/nuclei",
    icon: Crosshair,
    badge: "Tool",
  },
  {
    label: "ffuf Fuzzer",
    href: "/ffuf",
    icon: Wind,
    badge: "Tool",
  },
];

const attackSuiteItems: NavItem[] = [
  {
    label: "Attack Suite",
    href: "/attack-suite",
    icon: Swords,
    badge: "New",
  },
  {
    label: "AI Attack Suite",
    href: "/ai-attack-suite",
    icon: BrainCircuit,
    badge: "AI",
  },
  {
    label: "Takeover Checker",
    href: "/takeover",
    icon: GitFork,
    badge: "New",
  },
];

const settingsItems: NavItem[] = [
  {
    label: "Settings",
    href: "/settings",
    icon: Settings,
  },
  {
    label: "Integrations",
    href: "/settings/integrations",
    icon: Plug,
  },
  {
    label: "Team Members",
    href: "/settings/members",
    icon: Users,
  },
  {
    label: "API Keys",
    href: "/settings/api-keys",
    icon: Key,
  },
];

interface SidebarProps {
  className?: string;
}

function NavLink({ item, isActive }: { item: NavItem; isActive: boolean }) {
  const Icon = item.icon;

  return (
    <Link
      href={item.href}
      className={cn(
        "group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-all",
        isActive
          ? "bg-blue-600/10 text-blue-400 border border-blue-600/20"
          : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100",
      )}
    >
      <Icon
        className={cn(
          "h-4 w-4 shrink-0 transition-colors",
          isActive ? "text-blue-400" : "text-zinc-500 group-hover:text-zinc-300",
        )}
      />
      <span className="flex-1">{item.label}</span>
      {item.badge && (
        <Badge variant="secondary" className="text-xs py-0 px-1.5 h-5">
          {item.badge}
        </Badge>
      )}
      {isActive && <ChevronRight className="h-3 w-3 text-blue-400 shrink-0" />}
    </Link>
  );
}

export function Sidebar({ className }: SidebarProps) {
  const pathname = usePathname();

  const isActive = (href: string) => {
    if (href === "/dashboard") return pathname === "/dashboard";
    return pathname.startsWith(href);
  };

  return (
    <aside
      className={cn(
        "flex h-full w-60 flex-col border-r border-zinc-800 bg-zinc-950",
        className,
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 border-b border-zinc-800 px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-blue-600">
          <Zap className="h-4 w-4 text-white" />
        </div>
        <div>
          <div className="text-sm font-bold text-zinc-100 leading-none">AttackTrace</div>
          <div className="text-xs text-zinc-500 leading-none mt-0.5">Attack Surface</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-3 space-y-0.5">
        <div className="mb-4">
          <div className="px-3 pb-2">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
              Platform
            </p>
          </div>
          <div className="space-y-0.5">
            {navItems.map((item) => (
              <NavLink key={item.href} item={item} isActive={isActive(item.href)} />
            ))}
          </div>
        </div>

        <div className="mb-4">
          <div className="px-3 pb-2">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
              Attack Suites
            </p>
          </div>
          <div className="space-y-0.5">
            {attackSuiteItems.map((item) => (
              <NavLink key={item.href} item={item} isActive={isActive(item.href)} />
            ))}
          </div>
        </div>

        <div className="mb-4">
          <div className="px-3 pb-2">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
              Configuration
            </p>
          </div>
          <div className="space-y-0.5">
            {settingsItems.map((item) => (
              <NavLink key={item.href} item={item} isActive={isActive(item.href)} />
            ))}
          </div>
        </div>
      </nav>

      {/* Footer */}
      <div className="border-t border-zinc-800 p-3">
        <div className="rounded-md bg-zinc-900 p-3">
          <p className="text-xs font-medium text-zinc-300">AttackTrace Enterprise</p>
          <p className="text-xs text-zinc-500 mt-0.5">Attack Surface Management</p>
          <div className="mt-2 flex items-center gap-1.5">
            <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs text-emerald-400">All systems operational</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
