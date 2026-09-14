import React from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
  /**
   * When true, renders the error variant instead of the empty-state variant:
   * a distinct icon/copy signaling a failed fetch rather than genuinely-empty
   * data, plus a Retry button (wired to `onRetry`). Keeps the same layout so
   * it's a drop-in swap wherever `EmptyState` is already used.
   */
  isError?: boolean;
  /** Overrides the default error title ("Something went wrong loading this data"). */
  errorTitle?: string;
  /** Message shown under the error title — usually the caught error's `.message`. */
  errorMessage?: string;
  /** Called when the Retry button is clicked — typically a react-query `refetch`. */
  onRetry?: () => void;
  /** True while a retry is in flight — disables the button and shows a spinner. */
  isRetrying?: boolean;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
  isError,
  errorTitle,
  errorMessage,
  onRetry,
  isRetrying,
}: EmptyStateProps) {
  if (isError) {
    return (
      <div
        className={cn("flex flex-col items-center justify-center py-16 px-4 text-center", className)}
      >
        <div className="mb-4 rounded-full bg-red-500/10 p-4 text-red-400">
          <AlertTriangle className="h-8 w-8" />
        </div>
        <h3 className="mb-2 text-base font-semibold text-zinc-300">
          {errorTitle ?? title}
        </h3>
        <p className="mb-6 max-w-sm text-sm text-zinc-500">
          {errorMessage ?? description ?? "An error occurred while loading this data."}
        </p>
        {onRetry && (
          <Button variant="outline" size="sm" onClick={onRetry} disabled={isRetrying} className="gap-1.5">
            <RefreshCw className={cn("h-3.5 w-3.5", isRetrying && "animate-spin")} />
            Retry
          </Button>
        )}
      </div>
    );
  }

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
