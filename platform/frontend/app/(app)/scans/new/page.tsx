import React from "react";
import Link from "next/link";
import { ChevronLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { ScanForm } from "@/components/scans/scan-form";

export default function NewScanPage() {
  return (
    <div className="space-y-6">
      <PageHeader title="New Scan" description="Configure and launch an attack surface scan">
        <Button variant="outline" size="sm" asChild>
          <Link href="/scans" className="gap-1.5">
            <ChevronLeft className="h-4 w-4" />
            Back to Scans
          </Link>
        </Button>
      </PageHeader>

      <ScanForm />
    </div>
  );
}
