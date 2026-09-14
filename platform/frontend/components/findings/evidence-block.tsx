"use client";

import { ExternalLink } from "lucide-react";

/**
 * Renders a finding's `evidence` field, which is genuinely a dict (or null)
 * at the API level (see backend FindingResponse.evidence: Optional[dict]) —
 * NOT an array, despite an earlier frontend type claiming `FindingEvidence[]`.
 * That mismatch meant finding-detail.tsx's evidence section silently never
 * rendered anything for any real finding (dict.length is undefined, so the
 * `.length > 0` guard was always false). Handles every shape actually
 * produced across scanners: a flat dict (rendered as a key/value table), a
 * single {"raw": "..."} string wrapper, the MSRA {file,line,snippet} shape,
 * a legacy array of {title,content,url} objects, or a plain string.
 */
export function EvidenceBlock({ evidence }: { evidence: unknown }) {
  if (!evidence) return null;

  // Array of legacy FindingEvidence objects from AttackTrace
  if (Array.isArray(evidence)) {
    if (evidence.length === 0) return null;
    return (
      <div className="space-y-2">
        {(evidence as Array<{ title?: string; content?: string; url?: string }>).map((e, i) => (
          <div key={i} className="bg-zinc-950 rounded-md border border-zinc-800 overflow-hidden">
            {e.title && (
              <p className="text-xs text-zinc-500 px-3 pt-2 pb-1 border-b border-zinc-800 font-medium">{e.title}</p>
            )}
            {e.url && (
              <a href={e.url} target="_blank" rel="noopener noreferrer"
                className="text-xs text-blue-400 hover:underline px-3 py-1 flex items-center gap-1">
                {e.url} <ExternalLink className="h-2.5 w-2.5" />
              </a>
            )}
            {e.content && (
              <pre className="p-3 text-xs text-zinc-300 font-mono overflow-x-auto whitespace-pre-wrap">{e.content}</pre>
            )}
          </div>
        ))}
      </div>
    );
  }

  // MSRA-style: {file, line, snippet}
  if (typeof evidence === "object" && evidence !== null && "file" in evidence) {
    const ev = evidence as { file?: string; line?: number; snippet?: string };
    return (
      <div className="bg-zinc-950 rounded-md border border-zinc-800 overflow-hidden">
        {ev.file && (
          <p className="text-xs text-zinc-500 font-mono px-3 pt-2 pb-1 border-b border-zinc-800 truncate">
            {ev.file}
            {ev.line != null && <span className="text-zinc-600">:{ev.line}</span>}
          </p>
        )}
        <pre className="p-3 text-xs text-zinc-300 font-mono overflow-x-auto whitespace-pre-wrap">
          {ev.snippet ?? ""}
        </pre>
      </div>
    );
  }

  // Generic dict evidence (e.g. {"raw": "..."} or arbitrary key/value pairs
  // recorded by a scanner) — render as a clean key/value table rather than
  // silently showing nothing just because it isn't the {file,line,snippet} shape.
  if (typeof evidence === "object" && evidence !== null) {
    const entries = Object.entries(evidence as Record<string, unknown>).filter(
      ([, v]) => v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && v.length === 0),
    );
    if (entries.length === 0) return null;
    // A single "raw" string is common (legacy scanners) — render it plainly.
    if (entries.length === 1 && entries[0][0] === "raw" && typeof entries[0][1] === "string") {
      return (
        <pre className="bg-zinc-950 rounded-md p-3 text-xs text-zinc-300 font-mono overflow-x-auto border border-zinc-800 whitespace-pre-wrap">
          {entries[0][1] as string}
        </pre>
      );
    }
    return (
      <div className="bg-zinc-950 rounded-md border border-zinc-800 overflow-hidden divide-y divide-zinc-800">
        {entries.map(([key, value]) => (
          <div key={key} className="px-3 py-2 flex gap-3 text-xs">
            <span className="text-zinc-500 font-mono shrink-0 w-28 truncate">{key.replace(/_/g, " ")}</span>
            <span className="text-zinc-300 break-words">
              {Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value)}
            </span>
          </div>
        ))}
      </div>
    );
  }

  // Plain string
  return (
    <pre className="bg-zinc-950 rounded-md p-3 text-xs text-zinc-300 font-mono overflow-x-auto border border-zinc-800 whitespace-pre-wrap">
      {String(evidence)}
    </pre>
  );
}
