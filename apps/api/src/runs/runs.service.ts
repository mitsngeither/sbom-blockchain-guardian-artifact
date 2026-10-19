import { Injectable } from '@nestjs/common';
import { existsSync, readFileSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { BlockchainService } from '../blockchain/blockchain.service';

/**
 * How the on-chain status of a run was established:
 * `chain-verified` (receipt matches an Active record on chain),
 * `receipt-file-only` (receipt is well-formed, chain not checked) or `none`.
 */
export type OnChainEvidence = 'chain-verified' | 'receipt-file-only' | 'none';

type ChainReceipt = {
  transactionHash: string;
  projectId: string;
  version: string;
  merkleRoot: string;
  /** Run id the receipt was written for; optional for older receipts. */
  runId?: string;
};

type PipelineRunEvidence = {
  runId: string;
  projectId: string;
  mode: string;
  analyzedPackages: number;
  skippedPackages: number;
  highestRiskScore: number;
  overallRating: string;
  decision: 'PASS' | 'BLOCK' | 'REVIEW' | 'PENDING' | 'FAILED';
  onChainStatus: string;
  onChainEvidence: OnChainEvidence;
  source: 'pipeline-artifact';
  commit: string;
  timestamp: string;
  version?: string;
  reasons?: string[];
  artifactPath?: string;
  txHash?: string;
  runUrl?: string;
};

type RiskReport = {
  projectId?: string;
  currentVersion?: string;
  mode?: string;
  runId?: string;
  commit?: string;
  timestamp?: string;
  packageReports?: Array<{ risk?: { riskScore?: number } }>;
  summary?: {
    overallRating?: string;
    decision?: string;
    analyzedPackages?: number;
    skippedPackages?: number;
    reasons?: string[];
  };
};

function firstExistingPath(...candidates: string[]): string {
  return candidates.find((candidate) => existsSync(candidate)) ?? candidates[0];
}

function defaultArtifactsRoot(): string {
  return firstExistingPath(
    resolve(process.cwd(), 'pipeline-artifacts'),
    resolve(process.cwd(), '../../pipeline-artifacts'),
  );
}

function runIdFromFile(fileName: string): string {
  return fileName.replace(/\.json$/, '') || 'unknown';
}

function normalizeDecision(value: string): PipelineRunEvidence["decision"] {
  if (value === "PASS" || value === "BLOCK" || value === "REVIEW" || value === "FAILED") return value;
  return "PENDING";
}

const HEX32 = /^0x[0-9a-fA-F]{64}$/;

/** Reads the submission receipt; null if it is not a well-formed transaction record. */
export function readChainReceipt(path: string): ChainReceipt | null {
  if (!existsSync(path)) return null;

  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<ChainReceipt>;

    if (!HEX32.test(parsed.transactionHash ?? '')) return null;
    if (!HEX32.test(parsed.projectId ?? '')) return null;
    if (!HEX32.test(parsed.merkleRoot ?? '')) return null;
    if (typeof parsed.version !== 'string' || !parsed.version.trim()) return null;

    return parsed as ChainReceipt;
  } catch {
    return null;
  }
}

function receiptFileFor(runId: string): string {
  return 'pipeline-artifacts/chain/receipt-' + runId + '.json';
}

/**
 * Actions link for CI run ids (`<GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>`).
 * Local runs (`local-<timestamp>`) get undefined.
 */
const CI_RUN_ID = /^(\d+)-\d+$/;

export function runUrlFor(runId: string): string | undefined {
  const match = CI_RUN_ID.exec(runId);
  if (!match) return undefined;

  return 'https://github.com/mitsngeither/sbom-blockchain-guardian/actions/runs/' + match[1];
}

// A PASS run without its own receipt is NOT SUBMITTED. REVIEW runs are never submitted.
function onChainStatusFor(
  decision: PipelineRunEvidence['decision'],
  evidence: OnChainEvidence,
): string {
  if (decision === 'BLOCK') return 'REJECTED';
  if (decision === 'REVIEW' || decision === 'FAILED') return 'NOT SUBMITTED';
  if (decision !== 'PASS') return 'PENDING';
  return evidence === 'none' ? 'NOT SUBMITTED' : 'REGISTERED';
}

export function mapRiskReportToRun(
  fileName: string,
  report: RiskReport,
  onChainEvidence: OnChainEvidence,
): PipelineRunEvidence {
  const decision = normalizeDecision(report.summary?.decision ?? 'PENDING');
  // FAILED: the detector never ran. 0 is the "unscored" sentinel (utils.ts isUnscored).
  const rating = decision === 'FAILED' ? 'UNKNOWN' : report.summary?.overallRating ?? 'LOW';
  // Real packages score at least 1, so 0 here means nothing was analyzed
  // (no dependency changed this run), not a clean result.
  const highestRiskScore = decision === 'FAILED'
    ? 0
    : report.packageReports?.reduce(
      (highest, item) => Math.max(highest, item.risk?.riskScore ?? 0),
      0,
    ) ?? 0;
  const runId = report.runId ?? runIdFromFile(fileName);

  return {
    runId,
    projectId: report.projectId ?? 'unknown-project',
    mode: report.mode ?? 'unknown',
    analyzedPackages: report.summary?.analyzedPackages ?? report.packageReports?.length ?? 0,
    skippedPackages: report.summary?.skippedPackages ?? 0,
    highestRiskScore,
    overallRating: rating,
    decision,
    onChainStatus: onChainStatusFor(decision, onChainEvidence),
    onChainEvidence,
    source: 'pipeline-artifact',
    commit: report.commit ?? 'unknown',
    timestamp: report.timestamp ?? '',
    version: report.currentVersion,
    reasons: report.summary?.reasons ?? [],
    artifactPath: 'pipeline-artifacts/risk/history/' + fileName,
    txHash: onChainEvidence !== 'none' ? receiptFileFor(runId) : undefined,
    runUrl: runUrlFor(runId),
  };
}

/** Characters allowed in a run id that is used to build a file path. */
const SAFE_RUN_ID = /^[A-Za-z0-9._-]+$/;

@Injectable()
export class RunsService {
  // Overridable for tests.
  artifactsRoot: string = defaultArtifactsRoot();

  constructor(private readonly blockchainService: BlockchainService) {}

  private get historyDir(): string {
    return resolve(this.artifactsRoot, 'risk/history');
  }

  private get chainDir(): string {
    return resolve(this.artifactsRoot, 'chain');
  }

  private async resolveOnChainEvidence(runId: string): Promise<OnChainEvidence> {
    // runId comes from file content; reject anything that could escape chainDir.
    if (!SAFE_RUN_ID.test(runId)) return 'none';

    const receipt = readChainReceipt(resolve(this.chainDir, 'receipt-' + runId + '.json'));

    if (!receipt) return 'none';
    // A copied or renamed receipt must not pair with the wrong run.
    if (receipt.runId && receipt.runId !== runId) return 'none';
    if (!this.blockchainService.isConfigured()) return 'receipt-file-only';

    try {
      const record = await this.blockchainService.getVersion(
        receipt.projectId,
        receipt.version,
      );

      return record.status === 'Active'
        && record.merkleRoot.toLowerCase() === receipt.merkleRoot.toLowerCase()
        ? 'chain-verified'
        : 'none';
    } catch {
      // RPC unreachable: fall back to what the file alone can support.
      return 'receipt-file-only';
    }
  }

  private async readDirectory(directory: string): Promise<PipelineRunEvidence[]> {
    if (!existsSync(directory)) return [];

    const files = (await readdir(directory)).filter((file) => file.endsWith('.json')).sort();
    const runs: PipelineRunEvidence[] = [];

    for (const file of files) {
      try {
        const report = JSON.parse(await readFile(resolve(directory, file), 'utf8')) as RiskReport;
        const runId = report.runId ?? runIdFromFile(file);
        const evidence = await this.resolveOnChainEvidence(runId);

        runs.push(mapRiskReportToRun(file, report, evidence));
      } catch {
        // Ignore partial/corrupt artifacts, e.g. an interrupted report write.
      }
    }

    return runs;
  }

  async getRunStatus(): Promise<PipelineRunEvidence[]> {
    const real = await this.readDirectory(this.historyDir);

    real.sort((left, right) => right.timestamp.localeCompare(left.timestamp));

    return real;
  }
}
