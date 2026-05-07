"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Eye, EyeOff, Loader2, Zap, ShieldCheck } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

const loginSchema = z.object({
  email: z.string().min(1, "Please enter your email or username"),
  password: z.string().min(1, "Please enter your password"),
});

type LoginFormData = z.infer<typeof loginSchema>;

export default function LoginPage() {
  const { login } = useAuth();
  const router = useRouter();
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  });

  const onSubmit = async (data: LoginFormData) => {
    setIsLoading(true);
    setError(null);
    try {
      await login(data);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-zinc-950">
      {/* Left: brand panel */}
      <div className="hidden lg:flex lg:w-1/2 flex-col bg-zinc-900 border-r border-zinc-800 p-12 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-blue-950/20 via-zinc-900 to-zinc-950" />

        {/* Grid pattern overlay */}
        <div
          className="absolute inset-0 opacity-5"
          style={{
            backgroundImage: "radial-gradient(circle at 1px 1px, zinc-400 1px, transparent 0)",
            backgroundSize: "40px 40px",
          }}
        />

        <div className="relative z-10 flex items-center gap-3 mb-auto">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600">
            <Zap className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="text-lg font-bold text-white">AttackTrace</div>
            <div className="text-xs text-zinc-400">Security Toolkit & Recon Platform</div>
          </div>
        </div>

        <div className="relative z-10 flex-1 flex flex-col justify-center">
          <h2 className="text-4xl font-bold text-white mb-4 leading-tight">
            Your all-in-one
            <br />
            <span className="text-blue-400">security recon toolkit.</span>
          </h2>
          <p className="text-zinc-400 text-base mb-8 leading-relaxed max-w-md">
            Integrated recon, scanning, and threat intelligence tools for red teams,
            pentesters, and security researchers — all in one place.
          </p>

          <div className="space-y-3">
            {[
              "Subdomain, port & web application recon",
              "AI-powered vulnerability triage & analysis",
              "MITRE ATT&CK attack path mapping",
              "Threat intel, breach data & OSINT",
            ].map((feature) => (
              <div key={feature} className="flex items-center gap-3">
                <ShieldCheck className="h-4 w-4 text-blue-400 shrink-0" />
                <span className="text-zinc-300 text-sm">{feature}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 mt-auto pt-8 border-t border-zinc-800">
          <p className="text-xs text-zinc-600">
            AttackTrace
          </p>
        </div>
      </div>

      {/* Right: login form */}
      <div className="flex flex-1 flex-col items-center justify-center p-8">
        <div className="w-full max-w-md">
          {/* Mobile logo */}
          <div className="flex lg:hidden items-center gap-2 mb-8">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600">
              <Zap className="h-4 w-4 text-white" />
            </div>
            <span className="text-lg font-bold text-white">AttackTrace</span>
          </div>

          <div className="mb-8">
            <h1 className="text-2xl font-bold text-white">Welcome back</h1>
            <p className="text-zinc-400 mt-1 text-sm">
              Sign in to your account to continue
            </p>
          </div>

          {error && (
            <div className="mb-6 rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="email">Email or username</Label>
              <Input
                id="email"
                type="text"
                placeholder="admin or you@company.com"
                autoComplete="username"
                {...register("email")}
                className={cn(errors.email && "border-red-500 focus-visible:ring-red-500")}
              />
              {errors.email && (
                <p className="text-xs text-red-400">{errors.email.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <Label htmlFor="password">Password</Label>
                <button
                  type="button"
                  className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  {...register("password")}
                  className={cn(
                    "pr-10",
                    errors.password && "border-red-500 focus-visible:ring-red-500",
                  )}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-300"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
              {errors.password && (
                <p className="text-xs text-red-400">{errors.password.message}</p>
              )}
            </div>

            <Button
              type="submit"
              className="w-full"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Signing in...
                </>
              ) : (
                "Sign in"
              )}
            </Button>
          </form>

          <p className="mt-6 text-center text-xs text-zinc-600">
            Need access?{" "}
            <Link href="/register" className="text-zinc-500 hover:text-zinc-400">
              Use your invite code
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
