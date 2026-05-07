"use client";

import React, { useCallback } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";
import {
  LayoutDashboard,
  Radar,
  Globe,
  ShieldAlert,
  FileText,
  Settings,
  Users,
  ChevronRight,
  Zap,
  Plug,
  Network,
  Crosshair,
  Wind,
  Swords,
  BrainCircuit,
  GitFork,
  Map,
  ScrollText,
  FlaskConical,
  Smartphone,
  BookOpen,
  Shield,
  Share2,
  Clock,
  Bell,
  BarChart3,
  FileCode2,
  Cloud,
  Bot,
  Link2,
  Target,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
  toolKey?: string;
  children?: NavItem[];
}

const navItems: NavItem[] = [
  {
    label: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    label: "Executive Dashboard",
    href: "/dashboard/executive",
    icon: BarChart3,
  },
  {
    label: "Scans",
    href: "/scans",
    icon: Radar,
    toolKey: "scans",
  },
  {
    label: "Assets",
    href: "/assets",
    icon: Globe,
    toolKey: "assets",
  },
  {
    label: "Findings",
    href: "/findings",
    icon: ShieldAlert,
    toolKey: "findings",
  },
  {
    label: "Network Map",
    href: "/network",
    icon: Share2,
    toolKey: "network_graph",
  },
  {
    label: "Reports",
    href: "/reports",
    icon: FileText,
    toolKey: "reports",
  },
];

const toolItems: NavItem[] = [
  {
    label: "Nmap Scanner",
    href: "/nmap",
    icon: Network,
    toolKey: "nmap",
  },
  {
    label: "Nuclei Scanner",
    href: "/nuclei",
    icon: Crosshair,
    toolKey: "nuclei",
  },
  {
    label: "ffuf Fuzzer",
    href: "/ffuf",
    icon: Wind,
    toolKey: "ffuf",
  },
  {
    label: "Firewall Scanner",
    href: "/firewall",
    icon: Shield,
    toolKey: "firewall",
  },
  {
    label: "Test Case Generator",
    href: "/test-generator",
    icon: FlaskConical,
    toolKey: "test_generator",
  },
  {
    label: "AI/LLM Scanner",
    href: "/ai-scanner",
    icon: Bot,
  },
  {
    label: "MCP Scanner",
    href: "/mcp-scanner",
    icon: Link2,
  },
];

const mobileItems: NavItem[] = [
  {
    label: "Mobile Scanner",
    href: "/mobile",
    icon: Smartphone,
    toolKey: "mobile",
  },
  {
    label: "Pattern Library",
    href: "/mobile/patterns",
    icon: BookOpen,
    toolKey: "mobile",
  },
];

const attackSuiteItems: NavItem[] = [
  {
    label: "Attack Suite",
    href: "/attack-suite",
    icon: Swords,
    toolKey: "attack_suite",
  },
  {
    label: "AI Attack Suite",
    href: "/ai-attack-suite",
    icon: BrainCircuit,
    badge: "AI",
    toolKey: "attack_suite",
  },
  {
    label: "Takeover Checker",
    href: "/takeover",
    icon: GitFork,
    toolKey: "takeover",
  },
  {
    label: "Attack Path Mapper",
    href: "/attackmapper",
    icon: Map,
    toolKey: "attackmapper",
  },
];

const cloudItems: NavItem[] = [
  {
    label: "Cloud Discovery",
    href: "/cloud",
    icon: Cloud,
  },
];

const intelligenceItems: NavItem[] = [
  {
    label: "MITRE ATT&CK",
    href: "/mitre",
    icon: Target,
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
    label: "Audit Log",
    href: "/settings/audit-log",
    icon: ScrollText,
  },
  {
    label: "Schedules",
    href: "/settings/schedules",
    icon: Clock,
  },
  {
    label: "Notifications",
    href: "/settings/notifications",
    icon: Bell,
  },
  {
    label: "Templates",
    href: "/settings/templates",
    icon: FileCode2,
  },
];

interface SidebarProps {
  className?: string;
}

const NavLink = React.memo(function NavLink({ item, isActive }: { item: NavItem; isActive: boolean }) {
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
});

export function Sidebar({ className }: SidebarProps) {
  const pathname = usePathname();
  const { hasToolAccess } = useAuth();

  const isActive = useCallback(
    (href: string) => {
      if (href === "/dashboard") return pathname === "/dashboard";
      if (href === "/dashboard/executive") return pathname === "/dashboard/executive";
      return pathname.startsWith(href);
    },
    [pathname],
  );

  const filterItems = useCallback(
    (items: NavItem[]) => items.filter((item) => item.toolKey ? hasToolAccess(item.toolKey) : true),
    [hasToolAccess],
  );

  const visibleNavItems = filterItems(navItems);
  const visibleToolItems = filterItems(toolItems);
  const visibleMobileItems = filterItems(mobileItems);
  const visibleAttackSuiteItems = filterItems(attackSuiteItems);
  const visibleCloudItems = filterItems(cloudItems);
  const visibleIntelligenceItems = filterItems(intelligenceItems);

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
          <div className="text-xs text-zinc-500 leading-none mt-0.5">Recon & Security Toolkit</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-3 space-y-0.5">
        {visibleNavItems.length > 0 && (
          <div className="mb-4">
            <div className="px-3 pb-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                Platform
              </p>
            </div>
            <div className="space-y-0.5">
              {visibleNavItems.map((item) => (
                <NavLink key={item.href} item={item} isActive={isActive(item.href)} />
              ))}
            </div>
          </div>
        )}

        {visibleToolItems.length > 0 && (
          <div className="mb-4">
            <div className="px-3 pb-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                Tools
              </p>
            </div>
            <div className="space-y-0.5">
              {visibleToolItems.map((item) => (
                <NavLink key={item.href} item={item} isActive={isActive(item.href)} />
              ))}
            </div>
          </div>
        )}

        {visibleMobileItems.length > 0 && (
          <div className="mb-4">
            <div className="px-3 pb-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                Mobile Security
              </p>
            </div>
            <div className="space-y-0.5">
              {visibleMobileItems.map((item) => (
                <NavLink key={item.href} item={item} isActive={isActive(item.href)} />
              ))}
            </div>
          </div>
        )}

        {visibleAttackSuiteItems.length > 0 && (
          <div className="mb-4">
            <div className="px-3 pb-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                Attack Suites
              </p>
            </div>
            <div className="space-y-0.5">
              {visibleAttackSuiteItems.map((item) => (
                <NavLink key={item.href} item={item} isActive={isActive(item.href)} />
              ))}
            </div>
          </div>
        )}

        {visibleCloudItems.length > 0 && (
          <div className="mb-4">
            <div className="px-3 pb-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                Cloud
              </p>
            </div>
            <div className="space-y-0.5">
              {visibleCloudItems.map((item) => (
                <NavLink key={item.href} item={item} isActive={isActive(item.href)} />
              ))}
            </div>
          </div>
        )}

        {visibleIntelligenceItems.length > 0 && (
          <div className="mb-4">
            <div className="px-3 pb-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                Intelligence
              </p>
            </div>
            <div className="space-y-0.5">
              {visibleIntelligenceItems.map((item) => (
                <NavLink key={item.href} item={item} isActive={isActive(item.href)} />
              ))}
            </div>
          </div>
        )}

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
          <p className="text-xs font-medium text-zinc-300">AttackTrace</p>
          <p className="text-xs text-zinc-500 mt-0.5">Recon & Security Toolkit</p>
          <div className="mt-2 flex items-center gap-1.5">
            <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs text-emerald-400">All systems operational</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
