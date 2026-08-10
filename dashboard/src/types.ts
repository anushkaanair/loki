export interface AttemptMsg {
  type: "attempt";
  target: string;
  technique: string;
  generation: number;
  phase: string;
  success: boolean;
  partial: boolean;
  owasp: string;
  severity: string;
  latency: number;
}

export interface GenerationMsg {
  type: "generation";
  target: string;
  generation: number;
  best: number;
  mean: number;
  n_success: number;
  n_partial: number;
  refusal_modes: Record<string, string>;
}

export interface Finding {
  finding_id: string;
  owasp_category: string;
  severity: string;
  target: { name: string; model?: string };
  technique_family: string;
  reproduction: { trials: number; successes: number; rate: number; ci_95: number[]; status: string };
  transcript: { role: string; content: string }[];
  proof: { type: string; detail: string };
  judge_signals: Record<string, unknown>;
  replay: string;
  variant_count: number;
}

export interface Rate { successes: number; trials: number; rate: number; ci_95: number[]; }
export interface CampaignData {
  backend: string;
  is_simulator: boolean;
  campaign_id: string;
  summary: { n_findings: number; n_confirmed: number; by_severity: Record<string, number>;
             by_owasp: Record<string, number>; total_successful_attempts: number };
  headline: Record<string, Rate>;
  matrix: { families: string[]; targets: string[]; cells: Record<string, Record<string, Rate | null>> };
  judge: { inter_signal_kappa: number | null; n_agreement_pairs: number;
           classifier: { precision?: number; recall?: number; f1?: number } };
  budget: Record<string, number>;
}
