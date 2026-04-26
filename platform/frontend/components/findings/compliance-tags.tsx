"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface ComplianceTagsProps {
  tags?: string[] | null;
}

function tagColor(tag: string): string {
  if (tag.startsWith("OWASP")) {
    return "bg-orange-950/60 border-orange-700/50 text-orange-300";
  }
  if (tag.startsWith("PCI")) {
    return "bg-blue-950/60 border-blue-700/50 text-blue-300";
  }
  if (tag.startsWith("SOC2")) {
    return "bg-purple-950/60 border-purple-700/50 text-purple-300";
  }
  return "bg-zinc-800/60 border-zinc-600/50 text-zinc-400";
}

export function ComplianceTags({ tags }: ComplianceTagsProps) {
  if (!tags || tags.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1">
      {tags.map((tag) => (
        <span
          key={tag}
          className={cn(
            "inline-flex items-center rounded px-1.5 py-0.5 text-[9px] font-semibold border",
            tagColor(tag)
          )}
        >
          {tag}
        </span>
      ))}
    </div>
  );
}
