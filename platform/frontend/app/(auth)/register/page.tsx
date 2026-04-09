"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Eye, EyeOff, Loader2, Zap, KeyRound } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

const registerSchema = z.object({
  full_name: z.string().min(2, "Full name must be at least 2 characters"),
  email: z.string().email("Please enter a valid email address"),
  invite_code: z.string().min(1, "Invite code is required"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Must contain at least one uppercase letter")
    .regex(/[0-9]/, "Must contain at least one number"),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"],
});

type RegisterFormData = z.infer<typeof registerSchema>;

export default function RegisterPage() {
  const { register: registerUser } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors },
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
  });

  // Pre-fill invite code from URL param (?code=AttackTrace-XXXX-XXXX)
  useEffect(() => {
    const code = searchParams.get("code");
    if (code) setValue("invite_code", code.toUpperCase());
  }, [searchParams, setValue]);

  const onSubmit = async (data: RegisterFormData) => {
    setIsLoading(true);
    setError(null);
    try {
      await registerUser({
        full_name: data.full_name,
        email: data.email,
        password: data.password,
        invite_code: data.invite_code.toUpperCase().trim(),
      });
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-zinc-950">
      {/* Left panel */}
      <div className="hidden lg:flex lg:w-1/2 flex-col justify-between p-12 bg-zinc-900 border-r border-zinc-800">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600">
            <Zap className="h-4 w-4 text-white" />
          </div>
          <span className="text-lg font-bold text-white">AttackTrace</span>
        </div>
        <div>
          <h2 className="text-3xl font-bold text-white leading-tight">
            You&apos;re invited to<br />
            <span className="text-blue-400">AttackTrace Enterprise</span>
          </h2>
          <p className="text-zinc-400 mt-3 text-sm leading-relaxed max-w-sm">
            Complete your account setup to start monitoring your organization&apos;s external attack surface.
          </p>
          <div className="mt-8 space-y-3">
            {["Automated subdomain & asset discovery", "AI-powered vulnerability triage", "Real-time scan progress & alerts"].map((f) => (
              <div key={f} className="flex items-center gap-2.5 text-sm text-zinc-400">
                <div className="h-1.5 w-1.5 rounded-full bg-blue-400 shrink-0" />
                {f}
              </div>
            ))}
          </div>
        </div>
        <p className="text-xs text-zinc-600">Enterprise AttackTrace Platform</p>
      </div>

      {/* Right panel */}
      <div className="flex flex-1 items-center justify-center p-8">
        <div className="w-full max-w-sm">
          <div className="lg:hidden flex items-center gap-2 mb-8">
            <div className="flex h-7 w-7 items-center justify-center rounded-md bg-blue-600">
              <Zap className="h-3.5 w-3.5 text-white" />
            </div>
            <span className="text-base font-bold text-white">AttackTrace</span>
          </div>

          <div className="mb-7">
            <h1 className="text-2xl font-bold text-white">Create your account</h1>
            <p className="text-zinc-400 mt-1 text-sm">
              Use your invite code to get started
            </p>
          </div>

          {error && (
            <div className="mb-5 rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            {/* Invite code — prominent at top */}
            <div className="space-y-1.5">
              <Label htmlFor="invite_code" className="flex items-center gap-1.5">
                <KeyRound className="h-3.5 w-3.5 text-blue-400" />
                Invite Code
              </Label>
              <Input
                id="invite_code"
                type="text"
                placeholder="AttackTrace-XXXX-XXXX"
                autoComplete="off"
                {...register("invite_code")}
                onChange={(e) => {
                  setValue("invite_code", e.target.value.toUpperCase(), { shouldValidate: true });
                }}
                className={cn(
                  "font-mono tracking-wider",
                  errors.invite_code && "border-red-500"
                )}
              />
              {errors.invite_code && (
                <p className="text-xs text-red-400">{errors.invite_code.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="full_name">Full name</Label>
              <Input
                id="full_name"
                type="text"
                placeholder="John Smith"
                {...register("full_name")}
                className={cn(errors.full_name && "border-red-500")}
              />
              {errors.full_name && (
                <p className="text-xs text-red-400">{errors.full_name.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="email">Work email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@company.com"
                {...register("email")}
                className={cn(errors.email && "border-red-500")}
              />
              {errors.email && (
                <p className="text-xs text-red-400">{errors.email.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="Min. 8 chars, 1 uppercase, 1 number"
                  {...register("password")}
                  className={cn("pr-10", errors.password && "border-red-500")}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-300"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {errors.password && (
                <p className="text-xs text-red-400">{errors.password.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="confirmPassword">Confirm password</Label>
              <Input
                id="confirmPassword"
                type="password"
                placeholder="Repeat your password"
                {...register("confirmPassword")}
                className={cn(errors.confirmPassword && "border-red-500")}
              />
              {errors.confirmPassword && (
                <p className="text-xs text-red-400">{errors.confirmPassword.message}</p>
              )}
            </div>

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Creating account...
                </>
              ) : (
                "Create account"
              )}
            </Button>
          </form>

          <p className="mt-5 text-center text-sm text-zinc-500">
            Already have an account?{" "}
            <Link href="/login" className="text-blue-400 hover:text-blue-300 font-medium">
              Sign in
            </Link>
          </p>

          <p className="mt-3 text-center text-xs text-zinc-700">
            Don&apos;t have an invite code? Contact your administrator.
          </p>
        </div>
      </div>
    </div>
  );
}
