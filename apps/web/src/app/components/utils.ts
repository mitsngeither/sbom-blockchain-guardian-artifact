import type { IntegrityStatus, LifecycleStatus, OnchainStatus, PipelineStatus, PolicyDecision } from "./types";

export function cx(...classes: (string | false | undefined | null)[]) {
  return classes.filter(Boolean).join(" ");
}

// Same bands as getRiskRatingFromScore in src/detector/risk-scorer.ts (24/49/74).
// 0 means nothing was analyzed; a real analysis scores at least 1.
export function isUnscored(score: number) {
  return score <= 0;
}

export function riskColor(score: number) {
  if (isUnscored(score)) return "#5a6a85";
  if (score <= 24) return "#00ff9d";
  if (score <= 49) return "#ffb300";
  if (score <= 74) return "#ff8a3d";
  return "#ff3d5a";
}

export function riskLabel(score: number) {
  if (isUnscored(score)) return "N/A";
  if (score <= 24) return "LOW";
  if (score <= 49) return "MEDIUM";
  if (score <= 74) return "HIGH";
  return "CRITICAL";
}

/** Shows the 0 sentinel as an em dash. */
export function riskScoreText(score: number) {
  return isUnscored(score) ? "—" : String(score);
}

export function lifecycleColor(s: LifecycleStatus): string {
  if (s === "REGISTERED") return "#00e5ff";
  if (s === "APPROVED") return "#00ff9d";
  if (s === "REJECTED") return "#ff3d5a";
  if (s === "NOT ON CHAIN") return "#5a6a85";
  return "#ffb300";
}

export function onchainColor(s: OnchainStatus): string {
  if (s === "REGISTERED") return "#00e5ff";
  if (s === "REJECTED") return "#ff3d5a";
  if (s === "NOT SUBMITTED") return "#5a6a85";
  return "#ffb300";
}

export function policyColor(p: PolicyDecision): string {
  if (p === "PASS") return "#00ff9d";
  if (p === "BLOCK" || p === "FAILED") return "#ff3d5a";
  if (p === "REVIEW") return "#ffb300";
  return "#ffb300";
}

export function integrityColor(s: IntegrityStatus): string {
  if (s === "VERIFIED") return "#00ff9d";
  if (s === "UNVERIFIED") return "#ff3d5a";
  if (s === "NOT ON CHAIN") return "#5a6a85";
  return "#ffb300";
}

export function pipelineStatusColor(s: PipelineStatus): string {
  if (s === "passed") return "#00ff9d";
  if (s === "blocked") return "#ffb300";
  if (s === "failed") return "#ff3d5a";
  if (s === "review") return "#ffb300";
  return "#00e5ff";
}
