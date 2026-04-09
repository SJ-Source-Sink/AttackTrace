import React from "react";
import { Badge } from "@/components/ui/badge";
import { severityBgColor } from "@/lib/utils";
import type { FindingSeverity } from "@/types";

interface SeverityBadgeProps {
  severity: FindingSeverity;
  showLabel?: boolean;
}

export function SeverityBadge({ severity, showLabel = true }: SeverityBadgeProps) {
  return (
    <Badge
      className={`capitalize border ${severityBgColor(severity)} font-semibold`}
    >
      {showLabel ? severity : null}
    </Badge>
  );
}
