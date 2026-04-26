"use client";

import React, { useState, KeyboardEvent } from "react";
import { useRouter } from "next/navigation";
import { useForm, Controller } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  X,
  Plus,
  ChevronRight,
  ChevronLeft,
  Loader2,
  Zap,
  Target,
  Layers,
  Calendar,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent } from "@/components/ui/card";
import { useCreateScan } from "@/hooks/use-scans";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";
import type { ScanModule, ScanIntensity } from "@/types";

const scanSchema = z.object({
  company_name: z.string().min(2, "Engagement name is required"),
  domains: z.array(z.string().min(1)).min(1, "At least one domain is required"),
  intensity: z.enum(["passive", "normal", "aggressive", "passive_due_diligence"]),
  skip_modules: z.array(z.string()),
  schedule_type: z.enum(["now", "scheduled"]),
  run_at: z.string().optional(),
  cron: z.string().optional(),
});

type ScanFormData = z.infer<typeof scanSchema>;

const MODULES: { id: ScanModule; label: string; description: string }[] = [
  { id: "infrastructure", label: "Infrastructure", description: "Port scanning, service enumeration, ASN lookup" },
  { id: "cloud", label: "Cloud", description: "AWS, Azure, GCP resource discovery" },
  { id: "osint", label: "OSINT", description: "DNS enumeration, certificate transparency, breach data" },
  { id: "web", label: "Web", description: "Web application scanning, tech fingerprinting" },
  { id: "enrichment", label: "Enrichment", description: "Shodan, VirusTotal, threat intelligence enrichment" },
];

const INTENSITIES: { value: ScanIntensity; label: string; description: string; color: string }[] = [
  {
    value: "passive",
    label: "Passive",
    description: "OSINT only, no active probing. Safest, undetectable.",
    color: "border-emerald-500/30 bg-emerald-500/5 text-emerald-400",
  },
  {
    value: "normal",
    label: "Normal",
    description: "Balanced scan with standard enumeration.",
    color: "border-blue-500/30 bg-blue-500/5 text-blue-400",
  },
  {
    value: "aggressive",
    label: "Aggressive",
    description: "Deep scan with full port scanning. Noisy.",
    color: "border-red-500/30 bg-red-500/5 text-red-400",
  },
  {
    value: "passive_due_diligence",
    label: "Due Diligence",
    description: "Passive OSINT only — no active scanning. Ideal for M&A target assessment without triggering alerts.",
    color: "border-purple-500/30 bg-purple-500/5 text-purple-400",
  },
];

const CRON_PRESETS = [
  { label: "Daily at midnight", value: "0 0 * * *" },
  { label: "Weekly on Monday", value: "0 0 * * 1" },
  { label: "Monthly (1st)", value: "0 0 1 * *" },
  { label: "Every 6 hours", value: "0 */6 * * *" },
];

const STEPS = [
  { id: 1, label: "Target", icon: Target },
  { id: 2, label: "Modules", icon: Layers },
  { id: 3, label: "Schedule", icon: Calendar },
];

export function ScanForm() {
  const router = useRouter();
  const { isLoading: authLoading, isAuthenticated } = useAuth();
  const { mutateAsync: createScan, isPending } = useCreateScan();
  const [currentStep, setCurrentStep] = useState(1);
  const [domainInput, setDomainInput] = useState("");

  const {
    control,
    register,
    handleSubmit,
    watch,
    setValue,
    getValues,
    trigger,
    formState: { errors },
  } = useForm<ScanFormData>({
    resolver: zodResolver(scanSchema),
    defaultValues: {
      company_name: "",
      domains: [],
      intensity: "normal",
      skip_modules: [],
      schedule_type: "now",
      run_at: "",
      cron: "",
    },
  });

  const domains = watch("domains");
  const scheduleType = watch("schedule_type");
  const skipModules = watch("skip_modules");

  const [domainError, setDomainError] = useState<string | null>(null);

  const isValidDomain = (d: string): boolean => {
    if (/^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(d)) return true;
    const ipCidr = d.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/);
    if (ipCidr) {
      const octets = [ipCidr[1], ipCidr[2], ipCidr[3], ipCidr[4]].map(Number);
      const prefix = ipCidr[6] !== undefined ? Number(ipCidr[6]) : null;
      return octets.every((o) => o >= 0 && o <= 255) && (prefix === null || (prefix >= 0 && prefix <= 32));
    }
    return false;
  };

  const addDomain = () => {
    const domain = domainInput.trim().toLowerCase();
    if (!domain) return;
    if (!isValidDomain(domain)) {
      setDomainError(`"${domain}" is not a valid domain or IP`);
      return;
    }
    setDomainError(null);
    if (!domains.includes(domain)) {
      setValue("domains", [...domains, domain]);
    }
    setDomainInput("");
  };

  const removeDomain = (d: string) => {
    setValue("domains", domains.filter((x) => x !== d));
  };

  const handleDomainKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      addDomain();
    }
  };

  const toggleModule = (moduleId: string) => {
    const current = getValues("skip_modules");
    if (current.includes(moduleId)) {
      setValue("skip_modules", current.filter((m) => m !== moduleId));
    } else {
      setValue("skip_modules", [...current, moduleId]);
    }
  };

  const onSubmit = async (data: ScanFormData) => {
    if (!isAuthenticated) {
      router.push("/login");
      return;
    }
    const payload: Record<string, unknown> = {
      target_domains: data.domains,
      company_name: data.company_name,
      intensity: data.intensity,
      modules_to_skip: data.skip_modules,
    };
    if (data.schedule_type === "scheduled") {
      if (data.run_at) payload.scheduled_at = new Date(data.run_at).toISOString();
      if (data.cron) payload.schedule_cron = data.cron;
    }
    try {
      await createScan(payload as never);
      router.push("/scans");
    } catch {
      // error is shown via toast in useCreateScan onError
    }
  };

  // Step fields to validate before advancing
  const STEP_FIELDS: Record<number, (keyof ScanFormData)[]> = {
    1: ["company_name", "domains", "intensity"],
    2: ["skip_modules"],
  };

  const nextStep = async () => {
    const fields = STEP_FIELDS[currentStep];
    const valid = fields ? await trigger(fields) : true;
    if (valid) setCurrentStep((s) => Math.min(3, s + 1));
  };

  const prevStep = () => setCurrentStep((s) => Math.max(1, s - 1));

  return (
    <div className="max-w-2xl mx-auto">
      {/* Step indicator */}
      <div className="flex items-center gap-2 mb-8">
        {STEPS.map((step, idx) => {
          const Icon = step.icon;
          const isCompleted = currentStep > step.id;
          const isActive = currentStep === step.id;

          return (
            <React.Fragment key={step.id}>
              <div
                className={cn(
                  "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-all",
                  isActive && "bg-blue-600/10 text-blue-400 border border-blue-600/20",
                  isCompleted && "text-emerald-400",
                  !isActive && !isCompleted && "text-zinc-500",
                )}
              >
                <Icon className="h-4 w-4" />
                <span className="font-medium">{step.label}</span>
                {isCompleted && (
                  <div className="h-4 w-4 rounded-full bg-emerald-500 flex items-center justify-center">
                    <svg className="h-2.5 w-2.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                )}
              </div>
              {idx < STEPS.length - 1 && (
                <ChevronRight className="h-4 w-4 text-zinc-700" />
              )}
            </React.Fragment>
          );
        })}
      </div>

      <form onSubmit={handleSubmit(onSubmit)}>
        {/* Step 1: Target */}
        {currentStep === 1 && (
          <div className="space-y-6">
            <div>
              <h2 className="text-xl font-bold text-zinc-100">Define Engagement</h2>
              <p className="text-sm text-zinc-400 mt-1">
                Enter the engagement name and domains to scan
              </p>
            </div>

            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="company_name">Engagement Name</Label>
                <Input
                  id="company_name"
                  placeholder="Q2 2026 Pentest"
                  {...register("company_name")}
                  className={cn(errors.company_name && "border-red-500")}
                />
                {errors.company_name && (
                  <p className="text-xs text-red-400">{errors.company_name.message}</p>
                )}
              </div>

              <div className="space-y-1.5">
                <Label>Root Domains</Label>
                <div className="flex gap-2">
                  <Input
                    value={domainInput}
                    onChange={(e) => { setDomainInput(e.target.value); setDomainError(null); }}
                    onKeyDown={handleDomainKeyDown}
                    placeholder="acme.com (press Enter to add)"
                    className={cn("flex-1", domainError && "border-red-500")}
                  />
                  <Button type="button" variant="outline" size="sm" onClick={addDomain}>
                    <Plus className="h-4 w-4" />
                  </Button>
                </div>

                {domains.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {domains.map((domain) => (
                      <span
                        key={domain}
                        className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-800 px-2.5 py-1 text-sm text-zinc-200"
                      >
                        {domain}
                        <button
                          type="button"
                          onClick={() => removeDomain(domain)}
                          className="text-zinc-500 hover:text-zinc-300 transition-colors ml-0.5"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                )}

                {domainError && (
                  <p className="text-xs text-red-400">{domainError}</p>
                )}
                {errors.domains && !domainError && (
                  <p className="text-xs text-red-400">At least one domain is required</p>
                )}
              </div>

              <div className="space-y-2">
                <Label>Scan Intensity</Label>
                <div className="grid grid-cols-2 gap-3">
                  {INTENSITIES.map((intensity) => (
                    <Controller
                      key={intensity.value}
                      name="intensity"
                      control={control}
                      render={({ field }) => (
                        <button
                          type="button"
                          onClick={() => field.onChange(intensity.value)}
                          className={cn(
                            "rounded-lg border p-3 text-left transition-all",
                            field.value === intensity.value
                              ? `${intensity.color} border-opacity-100`
                              : "border-zinc-700 bg-zinc-900 text-zinc-400 hover:border-zinc-600",
                          )}
                        >
                          <div className="font-medium text-sm mb-1">{intensity.label}</div>
                          <div className="text-xs opacity-75 leading-relaxed">
                            {intensity.description}
                          </div>
                        </button>
                      )}
                    />
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Step 2: Modules */}
        {currentStep === 2 && (
          <div className="space-y-6">
            <div>
              <h2 className="text-xl font-bold text-zinc-100">Select Modules</h2>
              <p className="text-sm text-zinc-400 mt-1">
                Choose which modules to skip (all enabled by default)
              </p>
            </div>

            <div className="space-y-3">
              {MODULES.map((module) => {
                const isSkipped = skipModules.includes(module.id);
                return (
                  <Card
                    key={module.id}
                    className={cn(
                      "cursor-pointer transition-all",
                      isSkipped
                        ? "border-zinc-700 opacity-50"
                        : "border-zinc-700 hover:border-zinc-600",
                    )}
                    onClick={() => toggleModule(module.id)}
                  >
                    <CardContent className="flex items-center gap-4 p-4">
                      <Checkbox
                        checked={!isSkipped}
                        onCheckedChange={() => toggleModule(module.id)}
                        onClick={(e) => e.stopPropagation()}
                      />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-zinc-200">
                            {module.label}
                          </span>
                          {isSkipped && (
                            <span className="text-xs text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded">
                              skipped
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-zinc-500 mt-0.5">{module.description}</p>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>
        )}

        {/* Step 3: Schedule */}
        {currentStep === 3 && (
          <div className="space-y-6">
            <div>
              <h2 className="text-xl font-bold text-zinc-100">Schedule</h2>
              <p className="text-sm text-zinc-400 mt-1">
                Run the scan now or schedule it for later
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <Controller
                name="schedule_type"
                control={control}
                render={({ field }) => (
                  <>
                    <button
                      type="button"
                      onClick={() => field.onChange("now")}
                      className={cn(
                        "rounded-lg border p-4 text-left transition-all",
                        field.value === "now"
                          ? "border-blue-500/40 bg-blue-500/10 text-blue-400"
                          : "border-zinc-700 bg-zinc-900 text-zinc-400 hover:border-zinc-600",
                      )}
                    >
                      <Zap className="h-5 w-5 mb-2" />
                      <div className="font-medium text-sm">Run Now</div>
                      <div className="text-xs opacity-70 mt-1">Start immediately</div>
                    </button>
                    <button
                      type="button"
                      onClick={() => field.onChange("scheduled")}
                      className={cn(
                        "rounded-lg border p-4 text-left transition-all",
                        field.value === "scheduled"
                          ? "border-blue-500/40 bg-blue-500/10 text-blue-400"
                          : "border-zinc-700 bg-zinc-900 text-zinc-400 hover:border-zinc-600",
                      )}
                    >
                      <Calendar className="h-5 w-5 mb-2" />
                      <div className="font-medium text-sm">Schedule</div>
                      <div className="text-xs opacity-70 mt-1">Set date or recurring</div>
                    </button>
                  </>
                )}
              />
            </div>

            {scheduleType === "scheduled" && (
              <div className="space-y-4 p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
                <div className="space-y-1.5">
                  <Label htmlFor="run_at">One-time: Run at</Label>
                  <Input
                    id="run_at"
                    type="datetime-local"
                    {...register("run_at")}
                    className="[color-scheme:dark]"
                  />
                </div>

                <div className="space-y-1.5">
                  <Label>Recurring: Cron preset</Label>
                  <div className="grid grid-cols-2 gap-2">
                    {CRON_PRESETS.map((preset) => (
                      <button
                        key={preset.value}
                        type="button"
                        onClick={() => setValue("cron", preset.value)}
                        className={cn(
                          "rounded-md border px-3 py-2 text-xs text-left transition-all",
                          watch("cron") === preset.value
                            ? "border-blue-500/40 bg-blue-500/10 text-blue-400"
                            : "border-zinc-700 text-zinc-400 hover:border-zinc-600",
                        )}
                      >
                        <div className="font-medium">{preset.label}</div>
                        <div className="font-mono text-zinc-600 mt-0.5">{preset.value}</div>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="cron">Custom cron expression</Label>
                  <Input
                    id="cron"
                    placeholder="0 0 * * *"
                    {...register("cron")}
                    className="font-mono"
                  />
                </div>
              </div>
            )}

            {/* Summary */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 space-y-2">
              <h3 className="text-sm font-medium text-zinc-300">Scan Summary</h3>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-zinc-500">Engagement</span>
                  <span className="text-zinc-300">{watch("company_name") || "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Domains</span>
                  <span className="text-zinc-300">{domains.length} domain(s)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Intensity</span>
                  <span className="text-zinc-300 capitalize">{watch("intensity")}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Modules</span>
                  <span className="text-zinc-300">
                    {MODULES.length - skipModules.length}/{MODULES.length} enabled
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Navigation */}
        <div className="flex items-center justify-between mt-8 pt-6 border-t border-zinc-800">
          <Button
            type="button"
            variant="outline"
            onClick={prevStep}
            disabled={currentStep === 1}
            className="gap-1.5"
          >
            <ChevronLeft className="h-4 w-4" />
            Back
          </Button>

          {currentStep < 3 ? (
            <Button type="button" onClick={() => void nextStep()} className="gap-1.5">
              Continue
              <ChevronRight className="h-4 w-4" />
            </Button>
          ) : (
            <Button type="submit" disabled={isPending || authLoading} className="gap-1.5 min-w-[140px]">
              {isPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Launching...
                </>
              ) : (
                <>
                  <Zap className="h-4 w-4" />
                  Launch Scan
                </>
              )}
            </Button>
          )}
        </div>
      </form>
    </div>
  );
}
