"use client";

import React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ChevronLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { FindingDetail } from "@/components/findings/finding-detail";
import { Skeleton } from "@/components/shared/loading-skeleton";
import { useFinding } from "@/hooks/use-findings";
import { useRouter } from "next/navigation";

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: finding, isLoading } = useFinding(id);
  const router = useRouter();

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-48" />
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <p className="text-zinc-400 mb-4">Finding not found.</p>
        <Button asChild variant="outline">
          <Link href="/findings">Back to findings</Link>
        </Button>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="mb-6">
        <Button variant="ghost" size="sm" asChild className="gap-1.5 text-zinc-400 hover:text-zinc-100">
          <Link href="/findings">
            <ChevronLeft className="h-4 w-4" />
            Back to Findings
          </Link>
        </Button>
      </div>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900 overflow-hidden min-h-[600px]">
        <FindingDetail finding={finding} onClose={() => router.push("/findings")} />
      </div>
    </div>
  );
}
