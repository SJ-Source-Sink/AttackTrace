"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface SlaBadgeProps {
  sla_deadline?: string | null;
}

export function SlaBadge({ sla_deadline }: SlaBadgeProps) {
  if (!sla_deadline) return null;

  const deadline = new Date(sla_deadline);
  const now = new Date();
  const diffMs = deadline.getTime() - now.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  const isOverdue = diffMs < 0;
  const isWarning = !isOverdue && diffDays < 7;

  const label = isOverdue
    ? `Overdue ${Math.abs(diffDays)}d`
    : `Due in ${diffDays}d`;

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold border",
        isOverdue
          ? "bg-red-950/60 border-red-700/50 text-red-300"
          : isWarning
          ? "bg-yellow-950/60 border-yellow-700/50 text-yellow-300"
          : "bg-emerald-950/60 border-emerald-700/50 text-emerald-300"
      )}
      title={`SLA deadline: ${deadline.toLocaleDateString()}`}
    >
      {label}
    </span>
  );
}
