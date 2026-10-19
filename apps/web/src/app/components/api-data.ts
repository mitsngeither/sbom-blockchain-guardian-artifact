import type {
  IntegrityStatus,
  LifecycleStatus,
  OnchainStatus,
  PipelineStatus,
  PolicyDecision,
} from "./types";
import { riskScoreText } from "./utils";
import { chartLabel } from "./run-stats";

export type SbomTxn = {
  project: string;
  version: string;
  /** SBOM content digest, not a transaction hash. */
  sbomHash: string;
  risk: number;
  status: LifecycleStatus;
  timestamp: string;
};

export type SbomRegistrationPoint = {
  date: string;
  count: number;
};

export type NetworkStatus = {
  chainName: string;
  contractAddress: string;
  configured: boolean;
};

export type AttestationRecord = {
  projectId: string;
  projectIdHash: string;
  version: string;
  sbomHash: string;
  merkleRoot: string;
  submitter: string;
  timestamp: string;
  riskScore: number;
  status: "None" | "Active" | "Revoked";
};

export type SbomHistoryEntry = AttestationRecord & {
  id: string;
  commit: string;
  date: string;
  /** Where this record came from: on-chain, artifact registry, or demo. */
  origin: string;
  risk: "none" | "low" | "medium" | "high";
  lifecycle: LifecycleStatus;
  integrityCheck: IntegrityStatus;
};

export type DiffEntry = {
  type: "added" | "removed" | "updated";
  pkg: string;
  version: string;
  prev: string;
  source?: string;
  meaning?: string;
};

export type PipelineRun = {
  id: string;
  repo: string;
  /** Analysis mode ("full" | "incremental"), not a git branch. */
  mode: string;
  commit: string;
  status: PipelineStatus;
  /** Number of packages the detector analyzed. */
  analyzedPackages: number;
  risk: number;
  policy: PolicyDecision;
  onchain: OnchainStatus;
  timestamp: string;
  /** GitHub Actions run link; absent for runs not from CI. */
  runUrl?: string;
  reasons?: string[];
};

export type RiskPoint = {
  date: string;
  risk: number;
};

export type DashboardData = {
  txns: SbomTxn[];
  registrations: SbomRegistrationPoint[];
  network: NetworkStatus;
  totalRecords: number;
  activeRecords: number;
  verifiedRecords: number;
};

export type RunsData = {
  pipelines: PipelineRun[];
  riskChart: RiskPoint[];
};

export type SbomHistoryData = {
  source: "contract" | "demo" | "registry";
  network: NetworkStatus;
  history: SbomHistoryEntry[];
  diffEntries: DiffEntry[];
};

export type VerifyUploadResult = {
  status: "STRUCTURE_VALID" | "STRUCTURE_INVALID" | "ATTESTED_VALID" | "MISMATCH" | "NOT_FOUND" | "REVOKED";
  structureValid: boolean;
  projectId: string;
  version: string;
  computedHash?: string;
  onChainHash?: string;
  record?: AttestationRecord;
  message: string;
};

type ApiEvidence = {
  runId: string;
  projectId: string;
  mode: string;
  analyzedPackages: number;
  skippedPackages: number;
  highestRiskScore: number;
  overallRating: string;
  decision: PolicyDecision;
  onChainStatus: string;
  commit?: string;
  timestamp?: string;
  runUrl?: string;
  reasons?: string[];
};

type SbomHistoryApiResponse = {
  source: "contract" | "demo" | "registry";
  network: NetworkStatus;
  records: AttestationRecord[];
};

export type SbomProjectSummary = {
  projectId: string;
  versions: number;
  latestVersion: string;
  latestHash: string;
  latestCreatedAt: string;
  activeAttestations: number;
  storedArtifacts: number;
};

type SbomProjectsApiResponse = {
  projects: SbomProjectSummary[];
};

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...init } as RequestInit);
  if (!response.ok) {
    throw new Error(path + " returned " + response.status);
  }
  return response.json() as Promise<T>;
}

function evidenceArray(value: unknown): ApiEvidence[] {
  return Array.isArray(value) ? value as ApiEvidence[] : [];
}

function lifecycleFromEvidence(item: ApiEvidence): LifecycleStatus {
  if (item.onChainStatus === "REGISTERED" || item.onChainStatus === "REJECTED" || item.onChainStatus === "PENDING") {
    return item.onChainStatus;
  }
  return item.decision === "BLOCK" ? "REJECTED" : "PENDING";
}

export function lifecycleFromRecord(record: AttestationRecord, source?: SbomHistoryApiResponse["source"]): LifecycleStatus {
  if (record.status === "Active") return "REGISTERED";
  if (record.status === "Revoked") return "REJECTED";
  // The contract was read and does not hold this version (e.g. it went to an earlier deployment):
  // nothing is waiting, so "PENDING" would be wrong.
  return source === "contract" ? "NOT ON CHAIN" : "PENDING";
}

function pipelineStatusFromDecision(decision: PolicyDecision): PipelineStatus {
  if (decision === "PASS") return "passed";
  if (decision === "BLOCK") return "blocked";
  if (decision === "REVIEW") return "review";
  if (decision === "FAILED") return "failed";
  return "running";
}

function onchainStatus(value: string): OnchainStatus {
  if (value === "REGISTERED" || value === "REJECTED" || value === "PENDING" || value === "NOT SUBMITTED") {
    return value;
  }
  return "PENDING";
}

// Same bands as getRiskRatingFromScore in src/detector/risk-scorer.ts.
// `none` is score 0, i.e. nothing analyzed.
export function riskBand(score: number): "none" | "low" | "medium" | "high" {
  if (score <= 0) return "none";
  if (score <= 24) return "low";
  if (score <= 49) return "medium";
  return "high";
}

function commitFromRunId(runId: string): string {
  return runId.replace(/[^a-zA-Z0-9]/g, "").slice(0, 7) || "unknown";
}

const TIMESTAMP_FORMATTER = new Intl.DateTimeFormat("sv-SE", {
  timeZone: "Asia/Bangkok",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

/** Renders in Asia/Bangkok (GMT+7) to match the header clock in AppShell.tsx. */
function formatTimestamp(timestamp: string): string {
  const seconds = Number(timestamp);
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  return TIMESTAMP_FORMATTER.format(new Date(seconds * 1000));
}

const DAY_KEY_FORMATTER = new Intl.DateTimeFormat("sv-SE", {
  timeZone: "Asia/Bangkok",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
});

function dayKey(date: Date): string {
  return DAY_KEY_FORMATTER.format(date);
}

/** Groups records by GMT+7 day over the last 7 days. */
function last7DaysRegistrations(records: AttestationRecord[]): SbomRegistrationPoint[] {
  const dayMs = 24 * 60 * 60 * 1000;

  const counts = new Map<string, number>();
  for (const record of records) {
    const seconds = Number(record.timestamp);
    if (!Number.isFinite(seconds) || seconds <= 0) continue;
    const key = dayKey(new Date(seconds * 1000));
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const points: SbomRegistrationPoint[] = [];
  for (let i = 6; i >= 0; i--) {
    const key = dayKey(new Date(Date.now() - i * dayMs));
    points.push({ date: key.slice(5), count: counts.get(key) ?? 0 });
  }
  return points;
}

export async function fetchDashboardData(): Promise<DashboardData> {
  const [registry, history] = await Promise.all([
    fetchJson<SbomProjectsApiResponse>("/api/sbom/projects"),
    fetchJson<SbomHistoryApiResponse>("/api/sbom/history"),
  ]);

  if (registry.projects.length > 0 || history.records.length > 0) {
    const totalRecords = history.records.length || registry.projects.reduce((sum, project) => sum + project.storedArtifacts, 0);
    const activeRecords = history.records.filter((record) => record.status === "Active").length;

    return {
      txns: history.records.map((record) => ({
        project: record.projectId,
        version: record.version,
        sbomHash: record.sbomHash,
        risk: record.riskScore,
        status: lifecycleFromRecord(record, history.source),
        timestamp: formatTimestamp(record.timestamp),
      })),
      registrations: last7DaysRegistrations(history.records),
      network: history.network,
      totalRecords,
      activeRecords,
      verifiedRecords: activeRecords,
    };
  }

  const records = evidenceArray(await fetchJson<unknown>("/api/dashboard"));
  const activeRecords = history.records.filter((record) => record.status === "Active").length;

  return {
    txns: records.map((item) => ({
      project: item.projectId,
      version: item.mode,
      sbomHash: item.onChainStatus === "REGISTERED" ? item.runId : "-",
      risk: item.highestRiskScore,
      status: lifecycleFromEvidence(item),
      timestamp: "2026-07-09 00:00:00",
    })),
    registrations: records.map((item, index) => ({
      date: "Run " + (index + 1),
      count: item.analyzedPackages,
    })),
    network: history.network,
    totalRecords: history.records.length,
    activeRecords,
    verifiedRecords: activeRecords,
  };
}

export async function fetchRunsData(): Promise<RunsData> {
  const records = evidenceArray(await fetchJson<unknown>("/api/runs"));

  const pipelines: PipelineRun[] = records.map((item) => ({
    id: item.runId,
    repo: item.projectId,
    mode: item.mode,
    commit: item.commit && item.commit !== "unknown" ? item.commit : commitFromRunId(item.runId),
    status: pipelineStatusFromDecision(item.decision),
    analyzedPackages: item.analyzedPackages,
    risk: item.highestRiskScore,
    policy: item.decision,
    onchain: onchainStatus(item.onChainStatus),
    timestamp: item.timestamp ?? "",
    runUrl: item.runUrl,
    reasons: item.reasons,
  }));

  return {
    pipelines,
    riskChart: pipelines.map((run, index) => ({
      date: chartLabel(run.timestamp, index),
      risk: run.risk,
    })),
  };
}

export function buildSbomEvidenceEntries(record: AttestationRecord, source: SbomHistoryApiResponse["source"]): DiffEntry[] {
  const isContract = source === "contract";
  const state = lifecycleFromRecord(record, source);
  const stateSource = isContract
    ? record.status === "Active"
      ? "SBOMRegistry contract — on-chain Active attestation"
      : record.status === "Revoked"
        ? "SBOMRegistry contract — on-chain Revoked attestation"
        : "SBOMRegistry contract — no Active attestation found"
    : source === "registry"
      ? "Local Registry — waiting for on-chain Active record"
      : "Demo Fixture — simulated attestation state";

  return [
    {
      type: "updated",
      pkg: "SBOM hash",
      version: record.sbomHash,
      prev: isContract ? "SBOMRegistry contract — committed content digest" : "Artifact Store — immutable content digest",
      source: isContract ? "SBOMRegistry contract" : "Artifact Store",
      meaning: isContract ? "committed content digest" : "immutable content digest",
    },
    {
      type: "updated",
      pkg: "Merkle root",
      version: record.merkleRoot,
      prev: isContract ? "SBOMRegistry contract — committed component root" : "SBOM Merkle tree — component-level integrity",
      source: isContract ? "SBOMRegistry contract" : "SBOM Merkle tree",
      meaning: isContract ? "committed component root" : "component-level integrity",
    },
    {
      type: "updated",
      pkg: "Risk score",
      version: riskScoreText(record.riskScore),
      // Only contract records carry a score computed by the pipeline;
      // ingested artifacts store whatever the caller sent.
      prev: isContract
        ? record.riskScore <= 0
          ? "SBOMRegistry contract — no packages were analyzed (sentinel 0)"
          : "Risk Detector — dependency diff + policy scoring"
        : "Artifact Store — caller-supplied at ingest, not computed",
      source: isContract ? "Risk Detector" : "Artifact Store",
      meaning: isContract
        ? record.riskScore <= 0
          ? "no packages were analyzed (sentinel 0)"
          : "dependency diff + policy scoring"
        : "caller-supplied at ingest, not computed",
    },
    {
      type: "updated",
      pkg: "Attestation state",
      version: state,
      prev: stateSource,
      source: isContract ? "SBOMRegistry contract" : source === "registry" ? "Local Registry" : "Demo Fixture",
      meaning: isContract ? record.status === "Active" ? "on-chain Active attestation" : record.status === "Revoked" ? "on-chain Revoked attestation" : "no Active attestation found" : source === "registry" ? "waiting for on-chain Active record" : "simulated attestation state",
    },
  ];
}

export async function fetchSbomHistoryData(): Promise<SbomHistoryData> {
  const response = await fetchJson<SbomHistoryApiResponse>("/api/sbom/history");
  const recordSource = response.source === "contract" ? "on-chain" : response.source === "registry" ? "artifact registry" : "demo";

  return {
    source: response.source,
    network: response.network,
    history: response.records.map((record) => ({
      ...record,
      id: record.version,
      commit: commitFromRunId(record.version),
      date: formatTimestamp(record.timestamp),
      origin: recordSource,
      risk: riskBand(record.riskScore),
      lifecycle: lifecycleFromRecord(record, response.source),
      integrityCheck: record.status === "Active" ? "VERIFIED" : record.status === "Revoked" ? "UNVERIFIED" : response.source === "contract" ? "NOT ON CHAIN" : "PENDING",
    })),
    diffEntries: response.records.flatMap((record) => buildSbomEvidenceEntries(record, response.source)),
  };
}

export async function verifyUploadedSbom(
  record: AttestationRecord,
  sbomContent: string,
): Promise<VerifyUploadResult> {
  return fetchJson<VerifyUploadResult>("/api/sbom/verify-upload", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      projectId: record.projectId,
      version: record.version,
      sbomContent,
    }),
  });
}

/**
 * Reference copy of an on-chain record's SBOM, stored via POST /sbom/ingest.
 * Null if none was stored (older records).
 */
export async function fetchStoredArtifactContent(
  record: AttestationRecord,
): Promise<string | null> {
  const path = "/api/sbom/artifacts/" + encodeURIComponent(record.projectId) + "/" + encodeURIComponent(record.version);
  const response = await fetch(path, { cache: "no-store" } as RequestInit);

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    throw new Error(path + " returned " + response.status);
  }

  return response.text();
}
