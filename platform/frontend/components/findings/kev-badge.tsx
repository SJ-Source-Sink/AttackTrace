"use client"

interface KevBadgeProps {
  kev_status?: boolean
  epss_score?: number | null
  className?: string
}

export function KevBadge({ kev_status, epss_score, className }: KevBadgeProps) {
  if (!kev_status && !epss_score) return null

  return (
    <div className={`flex items-center gap-1.5 flex-wrap ${className ?? ""}`}>
      {kev_status && (
        <span className="inline-flex items-center gap-1 rounded-full bg-red-900/50 border border-red-500/50 px-2 py-0.5 text-[10px] font-bold text-red-300 uppercase tracking-wide">
          <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
          Exploited in Wild
        </span>
      )}
      {epss_score != null && (
        <span className="inline-flex items-center gap-1 rounded-full bg-orange-900/30 border border-orange-500/30 px-2 py-0.5 text-[10px] font-medium text-orange-300">
          EPSS {(epss_score * 100).toFixed(1)}%
        </span>
      )}
    </div>
  )
}
