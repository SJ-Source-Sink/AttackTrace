"use client";

import React, { useState } from "react";
import { QueryClient, QueryClientProvider, MutationCache, QueryCache } from "@tanstack/react-query";
import { Toaster, toast } from "sonner";
import { AuthProvider } from "@/lib/auth";

export function Providers({ children }: { children: React.ReactNode }) {
  // Use useState so each SSR request (Next.js App Router) gets its own
  // QueryClient instance rather than sharing a module-level singleton.
  const [queryClient] = useState(
    () =>
      new QueryClient({
        queryCache: new QueryCache({
          onError: (error, query) => {
            // Only show global toast for background refetches (query already has data),
            // not the initial load (components handle their own empty/error states).
            if (query.state.data !== undefined) {
              const msg = (error as Error).message || "Failed to refresh data";
              // Don't toast on auth errors — those redirect to login
              if ("status" in error && (error as { status: number }).status === 401) return;
              toast.error("Data refresh failed", { description: msg, id: msg });
            }
          },
        }),
        mutationCache: new MutationCache({
          onError: (error) => {
            // Swallow 401 (handled by api.ts redirect) and errors mutations already handle
            if ("status" in error && (error as { status: number }).status === 401) return;
          },
        }),
        defaultOptions: {
          queries: {
            retry: (failureCount, error) => {
              // Don't retry on 401/403/404
              if (error instanceof Error && "status" in error) {
                const status = (error as { status: number }).status;
                if ([401, 403, 404].includes(status)) return false;
              }
              return failureCount < 2;
            },
            staleTime: 60_000,
            refetchOnWindowFocus: false,
          },
        },
      }),
  );

  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        {children}
        <Toaster
          position="top-right"
          theme="dark"
          toastOptions={{
            style: {
              background: "#18181b",
              border: "1px solid #3f3f46",
              color: "#f4f4f5",
            },
          }}
        />
      </AuthProvider>
    </QueryClientProvider>
  );
}
