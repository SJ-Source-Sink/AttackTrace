import React from "react";
import { cn } from "@/lib/utils";

interface PageHeaderProps {
  title: string;
  description?: string;
  children?: React.ReactNode;
  className?: string;
}

export function PageHeader({ title, description, children, className }: PageHeaderProps) {
  return (
    <div className={cn("flex items-start justify-between gap-4 pb-6", className)}>
      <div className="space-y-1">
        <h1 className="text-2xl font-bold tracking-tight text-zinc-100">{title}</h1>
        {description && (
          <p className="text-sm text-zinc-400">{description}</p>
        )}
      </div>
      {children && (
        <div className="flex items-center gap-2 shrink-0">{children}</div>
      )}
    </div>
  );
}
