import { GenerationMsg } from "./types";

// Live fitness-over-generations plot (best + mean per target). Pure SVG — makes
// the "adaptive" claim visible at a glance.
const COLORS = ["#39ff5b", "#39d0ff", "#ffb300", "#ff3b57", "#c86bff"];

export function FitnessPlot({ gens }: { gens: GenerationMsg[] }) {
  const W = 520, H = 220, pad = 34;
  const targets = Array.from(new Set(gens.map((g) => g.target)));
  const maxGen = Math.max(1, ...gens.map((g) => g.generation));
  const maxFit = Math.max(1, ...gens.map((g) => g.best));
  const x = (g: number) => pad + (g / maxGen) * (W - pad * 2);
  const y = (f: number) => H - pad - (f / maxFit) * (H - pad * 2);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full">
      <rect x={0} y={0} width={W} height={H} fill="#0d120d" />
      {[0, 0.25, 0.5, 0.75, 1].map((t) => (
        <line key={t} x1={pad} x2={W - pad} y1={y(t * maxFit)} y2={y(t * maxFit)}
              stroke="#1f291f" />
      ))}
      <text x={4} y={y(maxFit) + 4} fill="#7a8a7a" fontSize="9">{maxFit.toFixed(1)}</text>
      <text x={10} y={H - pad + 12} fill="#7a8a7a" fontSize="9">gen 0</text>
      <text x={W - pad - 24} y={H - pad + 12} fill="#7a8a7a" fontSize="9">gen {maxGen}</text>
      {targets.map((tgt, i) => {
        const series = gens.filter((g) => g.target === tgt).sort((a, b) => a.generation - b.generation);
        const best = series.map((g) => `${x(g.generation)},${y(g.best)}`).join(" ");
        const mean = series.map((g) => `${x(g.generation)},${y(g.mean)}`).join(" ");
        const c = COLORS[i % COLORS.length];
        return (
          <g key={tgt}>
            <polyline points={best} fill="none" stroke={c} strokeWidth={2} />
            <polyline points={mean} fill="none" stroke={c} strokeWidth={1}
                      strokeDasharray="3 3" opacity={0.6} />
            <text x={pad + 4} y={16 + i * 12} fill={c} fontSize="9">■ {tgt}</text>
          </g>
        );
      })}
    </svg>
  );
}
