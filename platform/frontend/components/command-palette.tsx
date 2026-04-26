"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";

interface CommandItem {
  id: string;
  label: string;
  description?: string;
  href?: string;
  action?: () => void;
  icon?: string;
  category: string;
  keywords?: string[];
}

const COMMANDS: CommandItem[] = [
  // Navigation
  { id: "nav-dashboard", label: "Dashboard", description: "View attack surface overview", href: "/dashboard", icon: "📊", category: "Navigation", keywords: ["home", "overview"] },
  { id: "nav-scans", label: "Scans", description: "View and manage scans", href: "/scans", icon: "🔍", category: "Navigation" },
  { id: "nav-findings", label: "Findings", description: "View security findings", href: "/findings", icon: "⚠️", category: "Navigation" },
  { id: "nav-assets", label: "Assets", description: "View discovered assets", href: "/assets", icon: "🖥️", category: "Navigation" },
  { id: "nav-reports", label: "Reports", description: "Generate and view reports", href: "/reports", icon: "📋", category: "Navigation" },
  { id: "nav-nmap", label: "Nmap Scanner", description: "Port and service scanner", href: "/nmap", icon: "🔌", category: "Tools" },
  { id: "nav-nuclei", label: "Nuclei Scanner", description: "Vulnerability scanner", href: "/nuclei", icon: "🧬", category: "Tools" },
  { id: "nav-ffuf", label: "ffuf Fuzzer", description: "Web content fuzzer", href: "/ffuf", icon: "🎯", category: "Tools" },
  { id: "nav-firewall", label: "Firewall Scanner", description: "WAF detection and bypass", href: "/firewall", icon: "🛡️", category: "Tools" },
  { id: "nav-attack", label: "Attack Suite", description: "Automated attack chains", href: "/attack-suite", icon: "⚔️", category: "Tools" },
  { id: "nav-network", label: "Network Map", description: "Attack surface visualization", href: "/network-map", icon: "🕸️", category: "Tools" },
  { id: "nav-ai-scanner", label: "AI/LLM Scanner", description: "Discover exposed AI endpoints", href: "/ai-scanner", icon: "🤖", category: "Tools" },
  { id: "nav-mcp-scanner", label: "MCP Scanner", description: "Detect unauthenticated MCP servers", href: "/mcp-scanner", icon: "🔗", category: "Tools" },
  { id: "nav-settings", label: "Settings", description: "Configure your workspace", href: "/settings", icon: "⚙️", category: "Settings" },
  { id: "nav-integrations", label: "Integrations", description: "Connect external tools", href: "/settings/integrations", icon: "🔧", category: "Settings" },
  // Quick actions
  { id: "action-new-scan", label: "Start New Scan", description: "Launch a new security scan", href: "/scans?new=true", icon: "▶️", category: "Actions" },
];

export function CommandPalette() {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const router = useRouter();

  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const filtered = React.useMemo(() => {
    if (!query.trim()) return COMMANDS;
    const q = query.toLowerCase();
    return COMMANDS.filter(
      (cmd) =>
        cmd.label.toLowerCase().includes(q) ||
        (cmd.description?.toLowerCase().includes(q) ?? false) ||
        (cmd.keywords?.some((k) => k.includes(q)) ?? false) ||
        cmd.category.toLowerCase().includes(q)
    );
  }, [query]);

  const grouped = React.useMemo(() => {
    const groups: Record<string, CommandItem[]> = {};
    for (const cmd of filtered) {
      if (!groups[cmd.category]) groups[cmd.category] = [];
      groups[cmd.category].push(cmd);
    }
    return groups;
  }, [filtered]);

  const handleSelect = (cmd: CommandItem) => {
    setOpen(false);
    setQuery("");
    if (cmd.action) {
      cmd.action();
    } else if (cmd.href) {
      router.push(cmd.href);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { setOpen(v); if (!v) setQuery(""); }}>
      <DialogContent className="overflow-hidden p-0 shadow-2xl max-w-2xl">
        <div className="flex items-center border-b border-zinc-700 px-4">
          <span className="text-zinc-400 mr-3 text-lg">⌘</span>
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search commands, pages, tools..."
            className="flex-1 bg-transparent py-4 text-sm text-zinc-100 placeholder-zinc-500 outline-none"
            onKeyDown={(e) => {
              if (e.key === "Escape") { setOpen(false); setQuery(""); }
            }}
          />
          <kbd className="hidden sm:inline-block px-2 py-1 text-xs text-zinc-500 border border-zinc-700 rounded">ESC</kbd>
        </div>
        <div className="max-h-96 overflow-y-auto py-2">
          {Object.keys(grouped).length === 0 ? (
            <p className="py-8 text-center text-sm text-zinc-500">No results for &quot;{query}&quot;</p>
          ) : (
            Object.entries(grouped).map(([category, items]) => (
              <div key={category} className="px-2 py-1">
                <div className="px-2 py-1 text-xs font-semibold text-zinc-500 uppercase tracking-wider">
                  {category}
                </div>
                {items.map((cmd) => (
                  <button
                    key={cmd.id}
                    onClick={() => handleSelect(cmd)}
                    className="w-full flex items-center gap-3 rounded-md px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-700 transition-colors text-left"
                  >
                    {cmd.icon && <span className="text-base w-6 text-center">{cmd.icon}</span>}
                    <div className="flex-1 min-w-0">
                      <div className="font-medium">{cmd.label}</div>
                      {cmd.description && (
                        <div className="text-xs text-zinc-500 truncate">{cmd.description}</div>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            ))
          )}
        </div>
        <div className="border-t border-zinc-700 px-4 py-2 flex items-center gap-4 text-xs text-zinc-500">
          <span><kbd className="px-1.5 py-0.5 border border-zinc-700 rounded">↑↓</kbd> navigate</span>
          <span><kbd className="px-1.5 py-0.5 border border-zinc-700 rounded">↵</kbd> select</span>
          <span><kbd className="px-1.5 py-0.5 border border-zinc-700 rounded">ESC</kbd> close</span>
          <span className="ml-auto">⌘K to open</span>
        </div>
      </DialogContent>
    </Dialog>
  );
}
