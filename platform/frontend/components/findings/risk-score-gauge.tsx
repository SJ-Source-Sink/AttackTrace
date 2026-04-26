"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface RiskScoreGaugeProps {
  score?: number | null;
  explanation?: string | null;
  size?: "sm" | "md";
}

export function RiskScoreGauge({ score, explanation, size = "sm" }: RiskScoreGaugeProps) {
  if (score == null) return null;

  const rounded = Math.round(score);

  const colorClass =
    rounded >= 70
      ? "bg-red-600 text-white border-red-700/60"
      : rounded >= 40
      ? "bg-amber-600 text-white border-amber-700/60"
      : "bg-emerald-700 text-white border-emerald-800/60";

  const sizeClass = size === "md" ? "h-8 w-8 text-xs" : "h-6 w-6 text-[10px]";

  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded-full font-bold border shrink-0",
        colorClass,
        sizeClass
      )}
      title={explanation ?? `Risk score: ${rounded}/100`}
    >
      {rounded}
    </span>
  );
}
