"use client"

const CONFIDENCE_CONFIG = {
  certain: {
    label: "Certain",
    className: "bg-emerald-900/40 border-emerald-500/40 text-emerald-300",
    dot: "bg-emerald-400",
    title: "Proof-based — OOB callback, credentials verified, data confirmed",
  },
  high: {
    label: "High",
    className: "bg-blue-900/40 border-blue-500/40 text-blue-300",
    dot: "bg-blue-400",
    title: "Strong signal — two independent confirmations (e.g. dead CNAME + fingerprint match)",
  },
  medium: {
    label: "Medium",
    className: "bg-yellow-900/30 border-yellow-500/30 text-yellow-300",
    dot: "bg-yellow-400",
    title: "Needs a control/differential to be sure — status-flip, differential response, repeated timing",
  },
  low: {
    label: "Low",
    className: "bg-zinc-800/60 border-zinc-600/40 text-zinc-400",
    dot: "bg-zinc-500",
    title: "Weak or unconfirmed — single heuristic, reflected value, bare signal",
  },
}

interface ConfidenceBadgeProps {
  confidence?: string | null
  className?: string
}

export function ConfidenceBadge({ confidence, className }: ConfidenceBadgeProps) {
  if (!confidence) return null
  const cfg = CONFIDENCE_CONFIG[confidence as keyof typeof CONFIDENCE_CONFIG]
  if (!cfg) return null

  return (
    <span
      title={cfg.title}
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${cfg.className} ${className ?? ""}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}
