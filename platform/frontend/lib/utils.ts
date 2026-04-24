import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { format, formatDistanceToNow, parseISO } from "date-fns";
import type { FindingSeverity, ScanStatus, AssetType } from "@/types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateString: string, formatStr = "MMM d, yyyy"): string {
  try {
    return format(parseISO(dateString), formatStr);
  } catch {
    return dateString;
  }
}

export function formatRelativeTime(dateString: string): string {
  try {
    return formatDistanceToNow(parseISO(dateString), { addSuffix: true });
  } catch {
    return dateString;
  }
}

export function formatDateTime(dateString: string): string {
  return formatDate(dateString, "MMM d, yyyy HH:mm");
}

export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(isFinite(seconds) ? seconds : 0));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  const hours = Math.floor(s / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

export function severityColor(severity: FindingSeverity): string {
  const colors: Record<FindingSeverity, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-blue-400",
    info: "text-gray-400",
  };
  return colors[severity] ?? "text-gray-400";
}

export function severityBgColor(severity: FindingSeverity): string {
  const colors: Record<FindingSeverity, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    low: "bg-blue-400/10 text-blue-400 border-blue-400/20",
    info: "bg-gray-400/10 text-gray-400 border-gray-400/20",
  };
  return colors[severity] ?? "bg-gray-400/10 text-gray-400 border-gray-400/20";
}

export function severityHex(severity: FindingSeverity): string {
  const colors: Record<FindingSeverity, string> = {
    critical: "#dc2626",
    high: "#f97316",
    medium: "#eab308",
    low: "#60a5fa",
    info: "#9ca3af",
  };
  return colors[severity] ?? "#9ca3af";
}

export function scanStatusColor(status: ScanStatus): string {
  const colors: Record<ScanStatus, string> = {
    pending: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    running: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    completed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    failed: "bg-red-500/10 text-red-400 border-red-500/20",
    cancelled: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  };
  return colors[status] ?? "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
}

export function assetTypeIcon(type: AssetType): string {
  const icons: Record<AssetType, string> = {
    subdomain: "Globe",
    ip: "Network",
    domain: "Globe2",
    webapp: "Link",
    cloud: "Cloud",
  };
  return icons[type] ?? "Circle";
}

export function riskScoreColor(score: number): string {
  if (score >= 80) return "text-red-500";
  if (score >= 60) return "text-orange-500";
  if (score >= 40) return "text-yellow-500";
  if (score >= 20) return "text-blue-400";
  return "text-emerald-500";
}

export function riskScoreBarColor(score: number): string {
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-yellow-500";
  if (score >= 20) return "bg-blue-400";
  return "bg-emerald-500";
}

export function truncate(str: string, maxLength = 50): string {
  if (str.length <= maxLength) return str;
  return `${str.slice(0, maxLength)}...`;
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1).replace(/_/g, " ");
}

export function generateMockRiskHistory(days = 30): Array<{ date: string; score: number; critical: number; high: number }> {
  const history = [];
  const now = new Date();
  let score = 45 + Math.random() * 20;

  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    score = Math.max(10, Math.min(95, score + (Math.random() - 0.48) * 5));
    history.push({
      date: format(date, "MMM d"),
      score: Math.round(score),
      critical: Math.round(score * 0.15),
      high: Math.round(score * 0.3),
    });
  }
  return history;
}
