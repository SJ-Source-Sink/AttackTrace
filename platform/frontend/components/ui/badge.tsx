import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-blue-600 text-white shadow hover:bg-blue-700",
        secondary: "border-transparent bg-zinc-700 text-zinc-100 hover:bg-zinc-600",
        destructive: "border-transparent bg-red-600 text-white shadow hover:bg-red-700",
        outline: "border-zinc-700 text-zinc-300",
        success: "border-transparent bg-emerald-600/20 text-emerald-400 border-emerald-600/30",
        warning: "border-transparent bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
        critical: "border-red-600/30 bg-red-600/10 text-red-500",
        high: "border-orange-500/30 bg-orange-500/10 text-orange-500",
        medium: "border-yellow-500/30 bg-yellow-500/10 text-yellow-500",
        low: "border-blue-400/30 bg-blue-400/10 text-blue-400",
        info: "border-gray-400/30 bg-gray-400/10 text-gray-400",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
