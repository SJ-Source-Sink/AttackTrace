"use client";
import { useState } from "react";
import { API_BASE } from "@/lib/api";

export default function CICDPage() {
  const [target, setTarget] = useState("");
  const [intensity, setIntensity] = useState("passive");
  const [failOn, setFailOn] = useState("high");
  const [timeout, setTimeout_] = useState(120);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");

  const runScan = async () => {
    if (!target) return;
    setRunning(true);
    setResult(null);
    setError("");
    try {
      const token = localStorage.getItem("access_token") || "";
      const resp = await fetch(`${API_BASE}/cicd/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          target_domains: [target],
          intensity,
          fail_on_severity: failOn,
          timeout_seconds: timeout,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data?.detail?.error?.message || "Scan failed");
      setResult(data);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">CI/CD Integration</h1>
        <p className="text-zinc-400 text-sm mt-1">Trigger scans from your pipeline and get SARIF 2.1 output for GitHub Security tab.</p>
      </div>

      <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-6 space-y-4">
        <h2 className="text-lg font-semibold text-zinc-200">Scan Configuration</h2>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Target Domain</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              className="w-full bg-zinc-800 border border-zinc-600 rounded px-3 py-2 text-zinc-200 text-sm"
            />
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Intensity</label>
            <select value={intensity} onChange={(e) => setIntensity(e.target.value)}
              className="w-full bg-zinc-800 border border-zinc-600 rounded px-3 py-2 text-zinc-200 text-sm">
              <option value="passive">Passive</option>
              <option value="normal">Normal</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Fail CI on Severity</label>
            <select value={failOn} onChange={(e) => setFailOn(e.target.value)}
              className="w-full bg-zinc-800 border border-zinc-600 rounded px-3 py-2 text-zinc-200 text-sm">
              <option value="critical">Critical only</option>
              <option value="high">High and above</option>
              <option value="medium">Medium and above</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Timeout (seconds)</label>
            <input
              type="number" value={timeout} onChange={(e) => setTimeout_(Number(e.target.value))}
              min={30} max={600}
              className="w-full bg-zinc-800 border border-zinc-600 rounded px-3 py-2 text-zinc-200 text-sm"
            />
          </div>
        </div>
        <button
          onClick={runScan}
          disabled={running || !target}
          className="px-5 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded transition-colors"
        >
          {running ? "Running Scan..." : "Run CI Scan"}
        </button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-300 text-sm">{error}</div>
      )}

      {result && (
        <div className="space-y-4">
          <div className={`rounded-lg p-4 border ${result.ci_failed ? "bg-red-900/30 border-red-700" : "bg-green-900/30 border-green-700"}`}>
            <div className="flex items-center justify-between">
              <span className={`text-lg font-semibold ${result.ci_failed ? "text-red-300" : "text-green-300"}`}>
                {result.ci_failed ? "CI FAILED — Security findings detected" : "CI PASSED — No blocking findings"}
              </span>
              <span className="text-zinc-400 text-sm">Scan: {result.scan_id?.slice(0, 8)}...</span>
            </div>
            {result.fail_reason && <p className="text-sm text-zinc-400 mt-1">{result.fail_reason}</p>}
            <div className="flex gap-6 mt-3 text-sm">
              <span className="text-zinc-300">Status: <span className="font-medium">{result.status}</span></span>
              <span className="text-zinc-300">Findings: <span className="font-medium">{result.findings_count}</span></span>
              <span className="text-zinc-300">SARIF rules: <span className="font-medium">{result.sarif?.runs?.[0]?.tool?.driver?.rules?.length ?? 0}</span></span>
            </div>
          </div>

          <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-zinc-300 mb-3">GitHub Actions Snippet</h3>
            <pre className="text-xs text-zinc-400 bg-zinc-800 p-3 rounded overflow-x-auto whitespace-pre-wrap">{result.github_action_snippet}</pre>
          </div>

          <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-zinc-300">SARIF 2.1 Output</h3>
              <button
                onClick={() => {
                  const blob = new Blob([JSON.stringify(result.sarif, null, 2)], {type: "application/json"});
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a"); a.href = url; a.download = "results.sarif.json"; a.click();
                }}
                className="text-xs text-blue-400 hover:text-blue-300"
              >Download SARIF</button>
            </div>
            <pre className="text-xs text-zinc-500 bg-zinc-800 p-3 rounded overflow-auto max-h-64">
              {JSON.stringify(result.sarif, null, 2).slice(0, 2000)}{result.sarif ? "..." : ""}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
