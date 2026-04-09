import React from "react";
import { cn } from "@/lib/utils";

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export function EmptyState({ icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center py-16 px-4 text-center", className)}>
      {icon && (
        <div className="mb-4 rounded-full bg-zinc-800/50 p-4 text-zinc-500">
          {icon}
        </div>
      )}
      <h3 className="mb-2 text-base font-semibold text-zinc-300">{title}</h3>
      {description && (
        <p className="mb-6 max-w-sm text-sm text-zinc-500">{description}</p>
      )}
      {action}
    </div>
  );
}
