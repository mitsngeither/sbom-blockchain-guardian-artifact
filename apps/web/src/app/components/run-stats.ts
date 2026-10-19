import type { PipelineRun } from "./api-data";
import { isUnscored } from "./utils";

export type RunStats = {
  totalRuns: number;
  passedRuns: number;
  blockedRuns: number;
  /** null when no real run exists, so the UI can show "—" instead of 0%. */
  passRate: number | null;
  avgRisk: number | null;
};

export function summarizeRuns(runs: PipelineRun[]): RunStats {
  const totalRuns = runs.length;
  const passedRuns = runs.filter((run) => run.policy === "PASS").length;
  const blockedRuns = runs.filter((run) => run.policy === "BLOCK" || run.status === "blocked").length;

  if (totalRuns === 0) {
    return { totalRuns: 0, passedRuns: 0, blockedRuns: 0, passRate: null, avgRisk: null };
  }

  // FAILED runs carry the 0 sentinel, not a score; keep them out of avgRisk.
  const scored = runs.filter((run) => !isUnscored(run.risk));

  return {
    totalRuns,
    passedRuns,
    blockedRuns,
    passRate: Math.round((passedRuns / totalRuns) * 1000) / 10,
    avgRisk: scored.length === 0
      ? null
      : Math.round((scored.reduce((sum, run) => sum + run.risk, 0) / scored.length) * 10) / 10,
  };
}

export function chartLabel(timestamp: string, fallbackIndex: number): string {
  if (!timestamp) return "Run " + (fallbackIndex + 1);

  const match = /^\d{4}-(\d{2}-\d{2})T(\d{2}:\d{2})/.exec(timestamp);

  return match ? match[1] + " " + match[2] : "Run " + (fallbackIndex + 1);
}
