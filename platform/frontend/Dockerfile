# ─── AttackTrace Frontend Dockerfile (Next.js 15) ────────────────────────────────────
#
# Three-stage build following the official Next.js Docker example:
#   deps     — install node_modules
#   builder  — compile the Next.js app (standalone output mode)
#   runner   — minimal image with only the standalone output
#
# Requires next.config.ts to have:
#   output: 'standalone'
#
# This produces a self-contained server bundle under .next/standalone/
# that does NOT need node_modules at runtime, keeping the final image ~120 MB.

# ═══════════════════════════════════════════════════════════════
# Stage 1 — deps: install production + dev dependencies
# ═══════════════════════════════════════════════════════════════
FROM node:20-alpine AS deps

# libc6-compat is required by some native npm packages on Alpine
RUN apk add --no-cache libc6-compat

WORKDIR /app

# Copy only the lockfile and package manifest first so Docker can cache
# the npm ci layer independently of source code changes.
COPY package.json package-lock.json* ./

# Install all deps (including devDependencies needed for the build)
RUN npm ci

# ═══════════════════════════════════════════════════════════════
# Stage 2 — builder: compile the Next.js application
# ═══════════════════════════════════════════════════════════════
FROM node:20-alpine AS builder

WORKDIR /app

# Copy installed node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy all source files
COPY . .

# Build-time environment variables (public, non-secret)
# These are baked into the JS bundle by Next.js at build time.
# Pass the real API URL via --build-arg when building for different environments.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

# Disable Next.js telemetry during CI builds
ENV NEXT_TELEMETRY_DISABLED=1

# Build the application
RUN npm run build

# ═══════════════════════════════════════════════════════════════
# Stage 3 — runner: minimal production image
# ═══════════════════════════════════════════════════════════════
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Create a non-root user for security
RUN addgroup --system --gid 1001 nodejs && \
    adduser  --system --uid 1001 nextjs

# Copy only the artefacts needed to run the standalone server:
#   - public/ assets (served as static files)
#   - .next/standalone/ (the self-contained Node.js server)
#   - .next/static/ (hashed JS/CSS chunks referenced by the server)
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD wget -qO- http://localhost:3000/api/health 2>/dev/null || \
        wget -qO- http://localhost:3000/ 2>/dev/null | grep -q "html" || exit 1

# Next.js standalone server entry point
CMD ["node", "server.js"]
