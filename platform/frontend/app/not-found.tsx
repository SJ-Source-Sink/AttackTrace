"use client";

import Link from "next/link";
import { ShieldAlert, Home, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-zinc-950 flex flex-col items-center justify-center gap-6 text-center px-4">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-orange-500/10 border border-orange-500/20">
        <ShieldAlert className="h-8 w-8 text-orange-400" />
      </div>

      <div className="space-y-2">
        <p className="text-6xl font-bold text-zinc-700">404</p>
        <h1 className="text-xl font-semibold text-zinc-100">Page not found</h1>
        <p className="text-sm text-zinc-400 max-w-sm">
          The page you&apos;re looking for doesn&apos;t exist or has been moved.
        </p>
      </div>

      <div className="flex items-center gap-3">
        <Button variant="outline" size="sm" onClick={() => window.history.back()} className="gap-1.5">
          <ArrowLeft className="h-4 w-4" />
          Go Back
        </Button>
        <Button size="sm" asChild className="gap-1.5 bg-orange-600 hover:bg-orange-500 text-white">
          <Link href="/dashboard">
            <Home className="h-4 w-4" />
            Dashboard
          </Link>
        </Button>
      </div>
    </div>
  );
}
