"use client";

import React, { useState, useCallback, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Smartphone, Upload, Trash2, Eye, RefreshCw,
  CheckCircle2, Clock, XCircle, Shield,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { fetchWithAuth } from "@/lib/auth";
import { toast } from "sonner";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

const PLATFORM_COLORS: Record<string, string> = {
  android: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  ios:     "bg-blue-500/10 text-blue-400 border-blue-500/30",
  jar:     "bg-amber-500/10 text-amber-400 border-amber-500/30",
  exe:     "bg-violet-500/10 text-violet-400 border-violet-500/30",
  windows: "bg-violet-500/10 text-violet-400 border-violet-500/30",
};

const SEV_DOT: Record<string, string> = {
  Critical: "bg-red-500",
  High:     "bg-orange-500",
  Medium:   "bg-yellow-500",
  Low:      "bg-blue-400",
  Info:     "bg-zinc-500",
};

// MSRA scan object from /api/dashboard/stats → recent_scans
interface MobileScan {
  scan_id: string;
  apk: string;
  platform: string;
  status: string;
  risk_score: number;
  created_at: number; // unix timestamp
  severity_counts?: Record<string, number>;
  total_findings?: number;
}

interface StatsResponse {
  total_scans: number;
  total_findings: number;
  recent_scans: MobileScan[];
}

function StatusBadge({ status }: { status: string }) {
  if (status === "completed" || status === "done")
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400">
        <CheckCircle2 className="h-3.5 w-3.5" /> Completed
      </span>
    );
  if (status === "scanning" || status === "processing" || status === "pending")
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-blue-400">
        <Clock className="h-3.5 w-3.5 animate-pulse" /> Scanning
      </span>
    );
  if (status === "failed" || status === "error")
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-red-400">
        <XCircle className="h-3.5 w-3.5" /> Failed
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-zinc-400">
      <Clock className="h-3.5 w-3.5" /> {status}
    </span>
  );
}

function RiskBar({ score }: { score: number }) {
  const color =
    score >= 75 ? "bg-red-500" :
    score >= 50 ? "bg-orange-500" :
    score >= 25 ? "bg-yellow-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full bg-zinc-800">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${Math.min(score ?? 0, 100)}%` }} />
      </div>
      <span className="text-xs text-zinc-400">{Math.round(score ?? 0)}</span>
    </div>
  );
}

function UploadZone({ onUpload }: { onUpload: (file: File) => void }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) onUpload(file);
    },
    [onUpload],
  );

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      className={cn(
        "border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors",
        dragging
          ? "border-blue-500 bg-blue-500/5"
          : "border-zinc-700 hover:border-zinc-600 hover:bg-zinc-900",
      )}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".apk,.apkm,.xapk,.ipa,.jar,.exe,.dll"
        className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) onUpload(f); }}
      />
      <Upload className="h-8 w-8 text-zinc-500 mx-auto mb-3" />
      <p className="text-sm font-medium text-zinc-300">
        Drop your app file here or click to browse
      </p>
      <p className="text-xs text-zinc-500 mt-1">
        Supports APK, APKM, XAPK, IPA, JAR, EXE, DLL
      </p>
    </div>
  );
}

export default function MobileScannerPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [uploading, setUploading] = useState(false);

  // Sync MSRA findings into central DB on page load
  useEffect(() => {
    fetchWithAuth(`${API_BASE}/mobile/sync`, { method: "POST" }).catch(() => {});
  }, []);

  const { data: statsData, isLoading, refetch } = useQuery<StatsResponse>({
    queryKey: ["mobile", "stats"],
    queryFn: async () => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/stats`);
      if (!res.ok) throw new Error("Failed to fetch mobile stats");
      return res.json();
    },
    staleTime: 0,
    refetchInterval: 5000, // poll so in-progress scans update
  });

  const deleteMutation = useMutation({
    mutationFn: async (scanId: string) => {
      const res = await fetchWithAuth(`${API_BASE}/mobile/scans/${scanId}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Delete failed");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mobile", "stats"] });
      toast.success("Scan deleted");
    },
    onError: () => toast.error("Failed to delete scan"),
  });

  const handleUpload = useCallback(
    async (file: File) => {
      setUploading(true);
      try {
        const formData = new FormData();
        formData.append("file", file);
        const res = await fetchWithAuth(`${API_BASE}/mobile/upload`, {
          method: "POST",
          body: formData,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error?.message ?? "Upload failed");
        toast.success(`Scan started for ${file.name}`);
        queryClient.invalidateQueries({ queryKey: ["mobile", "stats"] });
        // Background sync once scan will eventually complete — also triggered by ScanProgressBanner
        const scanId = data.scan_id ?? data.id;
        if (scanId) router.push(`/mobile/${scanId}`);
      } catch (err: unknown) {
        toast.error(err instanceof Error ? err.message : "Upload failed");
      } finally {
        setUploading(false);
      }
    },
    [queryClient, router],
  );

  const scans: MobileScan[] = statsData?.recent_scans ?? [];
  const totalScans = statsData?.total_scans ?? 0;
  const totalFindings = statsData?.total_findings ?? 0;
  const completedScans = scans.filter((s) => s.status === "completed" || s.status === "done").length;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Mobile Scanner"
        description="Static and dynamic security analysis for Android, iOS, JAR, and Windows executables"
      >
        <Button
          variant="ghost"
          size="sm"
          onClick={() => refetch()}
          className="text-zinc-400 hover:text-zinc-100"
        >
          <RefreshCw className="h-4 w-4" />
        </Button>
      </PageHeader>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4">
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-zinc-500 mb-1">Total Scans</p>
            <p className="text-2xl font-bold text-zinc-100">{totalScans}</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-zinc-500 mb-1">Completed</p>
            <p className="text-2xl font-bold text-emerald-400">{completedScans}</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-zinc-500 mb-1">Total Findings</p>
            <p className="text-2xl font-bold text-orange-400">{totalFindings}</p>
          </CardContent>
        </Card>
      </div>

      {/* Upload zone */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
            <Upload className="h-4 w-4 text-zinc-400" />
            Upload App for Scanning
          </CardTitle>
        </CardHeader>
        <CardContent>
          {uploading ? (
            <div className="border-2 border-dashed border-zinc-700 rounded-lg p-8 text-center">
              <RefreshCw className="h-6 w-6 text-blue-400 animate-spin mx-auto mb-2" />
              <p className="text-sm text-zinc-400">Uploading and starting scan…</p>
            </div>
          ) : (
            <UploadZone onUpload={handleUpload} />
          )}
        </CardContent>
      </Card>

      {/* Scan history */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
            <Shield className="h-4 w-4 text-zinc-400" />
            Scan History
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-6 text-center text-sm text-zinc-500">Loading scans…</div>
          ) : scans.length === 0 ? (
            <div className="p-12 text-center">
              <Smartphone className="h-10 w-10 text-zinc-700 mx-auto mb-3" />
              <p className="text-sm text-zinc-500">No scans yet. Upload an app file to get started.</p>
            </div>
          ) : (
            <div className="divide-y divide-zinc-800">
              {scans.map((scan) => {
                const counts = scan.severity_counts ?? {};
                const platform = scan.platform?.toLowerCase() ?? "android";
                // Display just the short app name before the first underscore or full apk name
                const displayName = scan.apk?.split("_")[0] ?? scan.apk ?? scan.scan_id;
                return (
                  <div
                    key={scan.scan_id}
                    className="flex items-center gap-4 px-4 py-3 hover:bg-zinc-800/50 transition-colors"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-sm font-medium text-zinc-200 truncate max-w-sm" title={scan.apk}>
                          {displayName}
                        </span>
                        <Badge
                          variant="outline"
                          className={cn("text-xs capitalize", PLATFORM_COLORS[platform] ?? PLATFORM_COLORS.android)}
                        >
                          {platform}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-3 flex-wrap">
                        <StatusBadge status={scan.status} />
                        {scan.created_at && (
                          <span className="text-xs text-zinc-600">
                            {new Date(scan.created_at * 1000).toLocaleDateString()}
                          </span>
                        )}
                        {Object.entries(counts)
                          .filter(([, v]) => v && v > 0)
                          .map(([sev, count]) => (
                            <span key={sev} className="flex items-center gap-1">
                              <span className={cn("h-1.5 w-1.5 rounded-full", SEV_DOT[sev] ?? "bg-zinc-500")} />
                              <span className="text-xs text-zinc-500">
                                {count} {sev}
                              </span>
                            </span>
                          ))}
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <RiskBar score={scan.risk_score ?? 0} />
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-500 hover:text-zinc-100"
                          onClick={() => router.push(`/mobile/${scan.scan_id}`)}
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-500 hover:text-red-400"
                          onClick={() => {
                            if (confirm("Delete this scan?")) deleteMutation.mutate(scan.scan_id);
                          }}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
