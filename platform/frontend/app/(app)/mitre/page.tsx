"use client";
import { useState, useEffect } from "react";
import { API_BASE } from "@/lib/api";

interface MitreMapping {
  finding_id: string;
  finding_title: string;
  severity: string;
  affected_asset: string;
  cwe: string;
  attack_technique: {
    id: string;
    name: string;
    tactic: string;
    description: string;
    url: string;
    mitigations: string[];
  };
  apt_groups: Array<{id: string; name: string; country: string; also_known_as: string[]}>;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  info: "bg-zinc-500/20 text-zinc-300 border-zinc-500/40",
};

export default function MitrePage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<MitreMapping | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("access_token") || "";
    fetch(`${API_BASE}/mitre/map`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="p-6 text-zinc-400">Loading MITRE ATT&CK mappings...</div>;
  if (!data) return <div className="p-6 text-red-400">Failed to load mappings</div>;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">MITRE ATT&CK Mapper</h1>
        <p className="text-zinc-400 text-sm mt-1">Maps your findings to ATT&CK techniques and identifies APT groups that use these techniques.</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total Findings", value: data.total_findings, color: "text-zinc-200" },
          { label: "Mapped to ATT&CK", value: data.mapped_count, color: "text-blue-300" },
          { label: "Tactics Covered", value: Object.keys(data.tactic_summary || {}).length, color: "text-purple-300" },
          { label: "APT Groups Exposed", value: Object.keys(data.apt_exposure || {}).length, color: "text-red-300" },
        ].map((s) => (
          <div key={s.label} className="bg-zinc-900 border border-zinc-700 rounded-lg p-4">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-zinc-500 text-sm">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2">
          <h2 className="text-lg font-semibold text-zinc-200 mb-3">Technique Mappings</h2>
          <div className="space-y-2">
            {(data.mappings || []).map((m: MitreMapping) => (
              <button
                key={m.finding_id}
                onClick={() => setSelected(selected?.finding_id === m.finding_id ? null : m)}
                className={`w-full text-left bg-zinc-900 border rounded-lg p-4 hover:border-zinc-500 transition-colors ${selected?.finding_id === m.finding_id ? "border-blue-500" : "border-zinc-700"}`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`inline-block px-2 py-0.5 rounded text-xs border ${SEVERITY_COLORS[m.severity] || SEVERITY_COLORS.info}`}>
                        {m.severity.toUpperCase()}
                      </span>
                      <span className="text-xs text-zinc-500">{m.cwe}</span>
                    </div>
                    <div className="text-sm font-medium text-zinc-200 truncate">{m.finding_title}</div>
                    <div className="text-xs text-zinc-500 mt-0.5 truncate">{m.affected_asset || "—"}</div>
                  </div>
                  <div className="flex-shrink-0 text-right">
                    <div className="text-xs font-mono text-blue-400">{m.attack_technique.id}</div>
                    <div className="text-xs text-zinc-400 mt-0.5">{m.attack_technique.tactic}</div>
                    {m.apt_groups.length > 0 && (
                      <div className="text-xs text-red-400 mt-0.5">{m.apt_groups.length} APT group{m.apt_groups.length > 1 ? "s" : ""}</div>
                    )}
                  </div>
                </div>
                {selected?.finding_id === m.finding_id && (
                  <div className="mt-3 pt-3 border-t border-zinc-700 space-y-2">
                    <div>
                      <span className="text-xs text-zinc-500">Technique: </span>
                      <a href={m.attack_technique.url} target="_blank" rel="noopener noreferrer"
                        className="text-xs text-blue-400 hover:underline" onClick={e => e.stopPropagation()}>
                        {m.attack_technique.id} — {m.attack_technique.name}
                      </a>
                    </div>
                    <div className="text-xs text-zinc-400">{m.attack_technique.description}</div>
                    {m.attack_technique.mitigations.length > 0 && (
                      <div>
                        <span className="text-xs text-zinc-500">Mitigations: </span>
                        <span className="text-xs text-green-400">{m.attack_technique.mitigations.join(", ")}</span>
                      </div>
                    )}
                    {m.apt_groups.length > 0 && (
                      <div>
                        <span className="text-xs text-zinc-500">Known APTs: </span>
                        {m.apt_groups.map(apt => (
                          <span key={apt.id} className="inline-block mr-2 text-xs text-red-300">
                            {apt.name} ({apt.country})
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </button>
            ))}
            {(!data.mappings || data.mappings.length === 0) && (
              <div className="text-zinc-500 text-sm py-8 text-center">No mapped findings found.</div>
            )}
          </div>
        </div>

        <div className="space-y-4">
          <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-zinc-300 mb-3">Tactics Breakdown</h3>
            <div className="space-y-2">
              {Object.entries(data.tactic_summary || {}).map(([tactic, count]) => (
                <div key={tactic} className="flex justify-between items-center">
                  <span className="text-xs text-zinc-400 truncate">{tactic}</span>
                  <span className="text-xs font-medium text-zinc-200 ml-2">{count as number}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-zinc-300 mb-3">APT Exposure</h3>
            <div className="space-y-2">
              {Object.entries(data.apt_exposure || {}).slice(0, 8).map(([apt, count]) => (
                <div key={apt} className="flex justify-between items-center">
                  <span className="text-xs text-red-400 truncate">{apt}</span>
                  <span className="text-xs text-zinc-400">{count as number} findings</span>
                </div>
              ))}
              {Object.keys(data.apt_exposure || {}).length === 0 && (
                <p className="text-xs text-zinc-500">No APT exposure detected</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
