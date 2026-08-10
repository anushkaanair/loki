import { useEffect, useRef, useState } from "react";
import { AttemptMsg, CampaignData, Finding, GenerationMsg } from "./types";
import { FitnessPlot } from "./FitnessPlot";

const SEV: Record<string, string> = {
  Critical: "text-[#ff3b57] border-[#ff3b57]",
  High: "text-[#ffb300] border-[#ffb300]",
  Medium: "text-[#ffe066] border-[#ffe066]",
  Low: "text-[#7a8a7a] border-[#1f291f]",
};
const heat = (r: number) =>
  r <= 0.001 ? "#0d120d" : r < 0.2 ? "#14361c" : r < 0.5 ? "#3a4d12" : r < 0.8 ? "#6b4a0e" : "#5c1420";

export default function App() {
  const [connected, setConnected] = useState(false);
  const [running, setRunning] = useState(false);
  const [feed, setFeed] = useState<AttemptMsg[]>([]);
  const [gens, setGens] = useState<GenerationMsg[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [data, setData] = useState<CampaignData | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [counts, setCounts] = useState({ total: 0, success: 0 });
  const ws = useRef<WebSocket | null>(null);
  const feedRef = useRef<HTMLDivElement | null>(null);

  // Load the most recent completed campaign on mount, so the board is populated
  // from stored evidence instead of sitting empty until someone runs a new one.
  useEffect(() => {
    fetch("/api/latest")
      .then((r) => r.json())
      .then((d) => {
        if (!d.campaign_id) return;
        fetch(`/api/campaign/${d.campaign_id}`).then((r) => r.json()).then(setData);
        fetch(`/api/campaign/${d.campaign_id}/findings`)
          .then((r) => r.json())
          .then((f) => setFindings(f || []));
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const host = location.port === "5175" ? location.hostname + ":8008" : location.host;
    const socket = new WebSocket(`${proto}://${host}/ws`);
    ws.current = socket;
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.type === "attempt") {
        setFeed((f) => [m, ...f].slice(0, 200));
        setCounts((c) => ({ total: c.total + 1, success: c.success + (m.success ? 1 : 0) }));
      } else if (m.type === "generation") {
        setGens((g) => [...g, m]);
      } else if (m.type === "start") {
        setFeed([]); setGens([]); setFindings([]); setData(null);
        setCounts({ total: 0, success: 0 }); setRunning(true);
      } else if (m.type === "done") {
        setFindings(m.findings || []); setRunning(false);
        fetch(`/api/campaign/${m.campaign_id}`).then((r) => r.json()).then(setData);
      }
    };
    return () => socket.close();
  }, []);

  const start = () =>
    ws.current?.send(JSON.stringify({ action: "start", generations: 5, population_size: 20,
      matrix_trials: 10, seed: 42 }));

  return (
    <div className="h-full flex flex-col">
      <header className="flex items-center gap-4 px-5 py-3 border-b border-[#1f291f]">
        <span className="text-[#39ff5b] font-bold text-lg tracking-widest">▲ LOKI</span>
        <span className="text-[#7a8a7a] text-xs">adaptive AI red-teaming console</span>
        <span className={`text-xs px-2 py-0.5 rounded border ${connected ? "text-[#39ff5b] border-[#39ff5b]" : "text-[#ff3b57] border-[#ff3b57]"}`}>
          {connected ? "● engine online" : "○ disconnected"}
        </span>
        {data && (
          // Never let a reader mistake simulator numbers for real-model numbers.
          <span
            className={`text-xs px-2 py-0.5 rounded border ${
              data.is_simulator
                ? "text-[#ffb300] border-[#ffb300]"
                : "text-[#39d0ff] border-[#39d0ff]"
            }`}
            title={data.backend}
          >
            {data.is_simulator ? "SIMULATOR HARNESS" : "REAL MODEL"} · {data.backend.split("@")[0]}
          </span>
        )}
        <div className="ml-auto flex items-center gap-4 text-xs text-[#7a8a7a]">
          <span>probes <b className="text-[#c8d6c8]">{counts.total}</b></span>
          <span>hits <b className="text-[#39ff5b]">{counts.success}</b></span>
          <button onClick={start} disabled={!connected || running}
            className="px-4 py-1.5 rounded bg-[#14361c] border border-[#39ff5b] text-[#39ff5b] disabled:opacity-40 hover:bg-[#1c4a26]">
            {running ? "running…" : "▶ launch campaign"}
          </button>
        </div>
      </header>

      <div className="flex-1 grid grid-cols-[1fr_1.1fr_1.2fr] gap-px bg-[#1f291f] overflow-hidden">
        {/* LEFT — live attack feed */}
        <section className="bg-[#0a0d0a] flex flex-col overflow-hidden">
          <h2 className="px-4 py-2 text-[#9fe6a8] text-xs uppercase tracking-wider border-b border-[#1f291f]">live attack feed</h2>
          <div ref={feedRef} className="flex-1 overflow-y-auto text-[11px] leading-relaxed p-2 font-mono">
            {feed.length === 0 && <div className="text-[#7a8a7a] p-3">Launch a campaign to stream attempts…</div>}
            {feed.map((a, i) => (
              <div key={i} className={`px-2 py-0.5 flex gap-2 ${i === 0 ? "flash" : ""}`}>
                <span className={a.success ? "text-[#39ff5b]" : a.partial ? "text-[#ffb300]" : "text-[#3a4d3a]"}>
                  {a.success ? "✔" : a.partial ? "◐" : "·"}
                </span>
                <span className="text-[#7a8a7a] w-8">{a.phase === "matrix" ? "MTX" : `g${a.generation}`}</span>
                <span className="text-[#c8d6c8] w-24 truncate">{a.target}</span>
                <span className="text-[#39d0ff] w-32 truncate">{a.technique}</span>
                {a.success && <span className="text-[#ffb300]">{a.owasp}</span>}
                <span className="ml-auto text-[#3a4d3a]">{a.latency}ms</span>
              </div>
            ))}
          </div>
        </section>

        {/* CENTER — findings board */}
        <section className="bg-[#0a0d0a] flex flex-col overflow-hidden">
          <h2 className="px-4 py-2 text-[#9fe6a8] text-xs uppercase tracking-wider border-b border-[#1f291f]">
            findings board {findings.length > 0 && <span className="text-[#7a8a7a]">· {findings.length} distinct</span>}
          </h2>
          <div className="flex-1 overflow-y-auto p-3 grid gap-2 content-start">
            {findings.length === 0 && <div className="text-[#7a8a7a]">Confirmed findings appear here after the evidence pipeline runs.</div>}
            {findings.map((f) => (
              <button key={f.finding_id} onClick={() => setSelected(f)}
                className={`text-left bg-[#111611] border rounded-md p-3 hover:border-[#39ff5b] ${SEV[f.severity]}`}>
                <div className="flex items-center gap-2 text-xs">
                  <b>{f.finding_id}</b>
                  <span className={`px-1.5 rounded border text-[10px] ${SEV[f.severity]}`}>{f.severity}</span>
                  <span className="text-[#c8d6c8]">{f.owasp_category}</span>
                  <span className="ml-auto text-[10px] px-1.5 rounded border border-[#1f291f]"
                        style={{ color: f.reproduction.status === "CONFIRMED" ? "#39ff5b" : "#ffb300" }}>
                    {f.reproduction.status} {f.reproduction.successes}/{f.reproduction.trials}
                  </span>
                </div>
                <div className="text-[11px] text-[#7a8a7a] mt-1">{f.target.name} · {f.technique_family}</div>
                <div className="text-[10px] text-[#3a4d3a] mt-1">proof: {f.proof.type} — {f.proof.detail}</div>
              </button>
            ))}
          </div>
        </section>

        {/* RIGHT — live benchmark + fitness */}
        <section className="bg-[#0a0d0a] flex flex-col overflow-y-auto">
          <h2 className="px-4 py-2 text-[#9fe6a8] text-xs uppercase tracking-wider border-b border-[#1f291f]">genetic fitness / generation</h2>
          <div className="p-3"><FitnessPlot gens={gens} /></div>
          <h2 className="px-4 py-2 text-[#9fe6a8] text-xs uppercase tracking-wider border-y border-[#1f291f]">benchmark report</h2>
          {!data && <div className="p-3 text-[#7a8a7a] text-xs">Runs after the campaign completes.</div>}
          {data && <Benchmark data={data} />}
        </section>
      </div>

      {selected && <TranscriptModal f={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function Benchmark({ data }: { data: CampaignData }) {
  const m = data.matrix;
  return (
    <div className="p-3 text-[11px]">
      <div className="mb-3">
        <div className="text-[#9fe6a8] mb-1">guardrail tier vs. attack success rate</div>
        <table className="w-full border-collapse">
          <tbody>
            {Object.entries(data.headline).map(([t, r]) => (
              <tr key={t} className="border-b border-[#1f291f]">
                <td className="py-1 text-[#c8d6c8]">{t}</td>
                <td className="text-right" style={{ color: r.rate < 0.15 ? "#39ff5b" : "#ff3b57" }}>
                  {(r.rate * 100).toFixed(0)}%
                </td>
                <td className="text-right text-[#7a8a7a]">{r.successes}/{r.trials}</td>
                <td className="text-right text-[#3a4d3a]">[{r.ci_95[0].toFixed(2)},{r.ci_95[1].toFixed(2)}]</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="text-[#9fe6a8] mb-1">technique × defense effectiveness</div>
      <div className="overflow-x-auto">
        <table className="border-collapse text-[10px]">
          <thead><tr><th className="text-left pr-2 text-[#7a8a7a]">family</th>
            {m.targets.map((t) => <th key={t} className="px-1 text-[#7a8a7a] rotate-0 whitespace-nowrap">{t.replace("chat-", "").replace("-target", "")}</th>)}</tr></thead>
          <tbody>
            {m.families.map((fam) => (
              <tr key={fam}><td className="pr-2 text-[#c8d6c8] whitespace-nowrap">{fam}</td>
                {m.targets.map((t) => {
                  const c = m.cells[fam][t];
                  return <td key={t} className="text-center px-1 py-0.5"
                    style={{ background: c ? heat(c.rate) : "#0d120d", color: "#c8d6c8" }}>
                    {c ? `${(c.rate * 100).toFixed(0)}` : "–"}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 text-[10px] text-[#7a8a7a]">
        judge: classifier F1 {data.judge.classifier.f1?.toFixed(3) ?? "n/a"} · κ(clf,llm)={data.judge.inter_signal_kappa ?? "n/a"} (n={data.judge.n_agreement_pairs})
      </div>
    </div>
  );
}

function TranscriptModal({ f, onClose }: { f: Finding; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-8 z-50" onClick={onClose}>
      <div className="bg-[#0d120d] border border-[#39ff5b] rounded-lg max-w-3xl w-full max-h-[80vh] overflow-y-auto p-5"
           onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2">
          <b className="text-[#39ff5b]">{f.finding_id}</b>
          <span className={`px-1.5 rounded border text-xs ${SEV[f.severity]}`}>{f.severity}</span>
          <span className="text-[#c8d6c8] text-xs">{f.owasp_category} · {f.target.name} · {f.technique_family}</span>
          <button onClick={onClose} className="ml-auto text-[#7a8a7a] hover:text-[#ff3b57]">✕</button>
        </div>
        <div className="text-xs text-[#7a8a7a] mt-2">
          reproduction {f.reproduction.successes}/{f.reproduction.trials} ({f.reproduction.status}),
          95% CI [{f.reproduction.ci_95[0].toFixed(2)}, {f.reproduction.ci_95[1].toFixed(2)}] · {f.variant_count} variant(s)
        </div>
        <div className="text-xs text-[#9fe6a8] mt-1">proof ({f.proof.type}): {f.proof.detail}</div>
        <div className="mt-3 text-xs text-[#9fe6a8]">transcript</div>
        <div className="mt-1 space-y-1">
          {f.transcript.map((t, i) => (
            <div key={i} className="text-[11px]">
              <span className="text-[#39d0ff]">[{t.role}]</span>{" "}
              <span className="text-[#c8d6c8] whitespace-pre-wrap">{t.content.slice(0, 800)}</span>
            </div>
          ))}
        </div>
        <div className="mt-3 text-[11px]">
          replay: <code className="bg-[#111611] px-2 py-1 rounded text-[#9fe6a8]">{f.replay}</code>
        </div>
      </div>
    </div>
  );
}
