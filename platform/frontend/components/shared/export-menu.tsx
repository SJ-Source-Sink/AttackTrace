"use client";

import React, { useState } from "react";
import { Download, Loader2, FileSpreadsheet, FileText, FileCode2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export type ExportFormat = "csv" | "html" | "pdf";

const FORMAT_META: Record<ExportFormat, { label: string; icon: React.ElementType }> = {
  csv: { label: "CSV", icon: FileSpreadsheet },
  html: { label: "HTML", icon: FileCode2 },
  pdf: { label: "PDF", icon: FileText },
};

interface ExportMenuProps {
  label: string;
  onExport: (format: ExportFormat) => Promise<void>;
  formats?: ExportFormat[];
  disabled?: boolean;
  size?: "sm" | "default";
  variant?: "outline" | "ghost" | "default";
}

/** Shared export dropdown for list pages (Findings, Assets) — one button,
 * one menu of formats, consistent loading/disabled state everywhere it's used
 * instead of each page re-implementing its own export button. */
export function ExportMenu({
  label,
  onExport,
  formats = ["csv", "html", "pdf"],
  disabled,
  size = "sm",
  variant = "outline",
}: ExportMenuProps) {
  const [pending, setPending] = useState<ExportFormat | null>(null);

  const handleExport = async (format: ExportFormat) => {
    setPending(format);
    try {
      await onExport(format);
    } finally {
      setPending(null);
    }
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant={variant} size={size} disabled={disabled || pending !== null} className="gap-1.5">
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
          {label}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-40">
        {formats.map((fmt) => {
          const { label: fmtLabel, icon: Icon } = FORMAT_META[fmt];
          return (
            <DropdownMenuItem
              key={fmt}
              onClick={() => handleExport(fmt)}
              className="gap-2 cursor-pointer"
            >
              <Icon className="h-3.5 w-3.5 text-zinc-500" />
              {fmtLabel}
            </DropdownMenuItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
