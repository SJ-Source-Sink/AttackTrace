import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  // Derive backend origin from env so CSP works in both dev and production.
  // NEXT_PUBLIC_API_URL is set at build time (e.g. https://api.attacktrace.io/api/v1).
  // Strip the path suffix to get just the origin.
  const rawApiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";
  const apiOrigin = rawApiUrl.replace(/\/api\/v1\/?$/, "").replace(/\/$/, "") || "http://localhost:8000";
  const wsOrigin = apiOrigin.replace(/^https?/, (p) => (p === "https" ? "wss" : "ws"));

  // Security headers for all responses
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-XSS-Protection", "1; mode=block");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  response.headers.set(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // unsafe-eval required by Next.js dev
      "style-src 'self' 'unsafe-inline'",
      `img-src 'self' data: blob: ${apiOrigin}`,
      "font-src 'self'",
      `connect-src 'self' ${apiOrigin} ${wsOrigin}`,
      "frame-ancestors 'none'",
    ].join("; ")
  );

  return response;
}

export const config = {
  // Apply to all routes except static assets and Next.js internals
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
