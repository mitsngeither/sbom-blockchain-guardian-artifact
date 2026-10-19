import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Test, TestingModule } from '@nestjs/testing';
import { BlockchainService } from '../blockchain/blockchain.service';
import { mapRiskReportToRun, readChainReceipt, runUrlFor, RunsService } from './runs.service';

const VALID_RECEIPT = {
  status: 'CONFIRMED',
  onChainStatus: 'ATTESTED',
  transactionHash: '0x' + 'a'.repeat(64),
  projectId: '0x' + 'b'.repeat(64),
  version: '1.0.0',
  merkleRoot: '0x' + 'c'.repeat(64),
  riskScore: 7,
};

describe('RunsService', () => {
  let service: RunsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RunsService,
        {
          provide: BlockchainService,
          useValue: { isConfigured: jest.fn().mockReturnValue(false) },
        },
      ],
    }).compile();

    service = module.get<RunsService>(RunsService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('maps a stamped PASS history entry with its own receipt to a registered run', () => {
    const run = mapRiskReportToRun('1234567890-1.json', {
      runId: '1234567890-1',
      commit: '702fa42',
      timestamp: '2026-08-26T09:42:18.000Z',
      projectId: 'sbom-blockchain-guardian',
      currentVersion: '1.0.0',
      mode: 'full',
      packageReports: [{ risk: { riskScore: 7 } }],
      summary: {
        overallRating: 'LOW',
        decision: 'PASS',
        analyzedPackages: 1214,
        skippedPackages: 0,
        reasons: ['full scan'],
      },
    }, 'receipt-file-only');

    expect(run).toEqual(expect.objectContaining({
      runId: '1234567890-1',
      commit: '702fa42',
      timestamp: '2026-08-26T09:42:18.000Z',
      projectId: 'sbom-blockchain-guardian',
      decision: 'PASS',
      onChainStatus: 'REGISTERED',
      onChainEvidence: 'receipt-file-only',
      source: 'pipeline-artifact',
    }));
  });

  // Each PASS run must be judged by its own receipt, not a shared one.
  it('reports NOT SUBMITTED for a PASS run that has no receipt of its own', () => {
    const run = mapRiskReportToRun('99-1.json', {
      runId: '99-1',
      summary: { overallRating: 'LOW', decision: 'PASS' },
    }, 'none');

    expect(run.onChainStatus).toBe('NOT SUBMITTED');
    expect(run.onChainEvidence).toBe('none');
  });

  it('records a BLOCK run as rejected with no on-chain evidence', () => {
    const run = mapRiskReportToRun('98-1.json', {
      runId: '98-1',
      summary: { overallRating: 'LOW', decision: 'BLOCK' },
    }, 'none');

    expect(run.onChainStatus).toBe('REJECTED');
    expect(run.onChainEvidence).toBe('none');
  });

  // FAILED entries have no packageReports or rating and must not get defaults.
  it('reports a FAILED run with no on-chain status and the unscored risk sentinel', () => {
    const run = mapRiskReportToRun('97-1.json', {
      runId: '97-1',
      summary: { decision: 'FAILED' },
    }, 'none');

    expect(run.decision).toBe('FAILED');
    expect(run.highestRiskScore).toBe(0);
    expect(run.onChainStatus).toBe('NOT SUBMITTED');
  });

  // Empty packageReports (nothing changed) gives 0, meaning "not scored".
  it('reports the unscored sentinel for a PASS run where nothing was analyzed, not a fabricated score', () => {
    const run = mapRiskReportToRun('96-1.json', {
      runId: '96-1',
      summary: { overallRating: 'LOW', decision: 'PASS', analyzedPackages: 0 },
      packageReports: [],
    }, 'none');

    expect(run.decision).toBe('PASS');
    expect(run.highestRiskScore).toBe(0);
  });

  it('derives a run id from the file name when the report carries none', () => {
    const run = mapRiskReportToRun('99-1.json', {
      summary: { overallRating: 'LOW', decision: 'PASS', analyzedPackages: 1214 },
    }, 'none');

    expect(run.runId).toBe('99-1');
    expect(run.source).toBe('pipeline-artifact');
    expect(run.commit).toBe('unknown');
  });
});

// Only CI run ids (`<GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>`) get an Actions link.
describe('runUrlFor', () => {
  it('builds an Actions run URL from a GITHUB_RUN_ID-GITHUB_RUN_ATTEMPT runId', () => {
    expect(runUrlFor('32942433248-1')).toBe(
      'https://github.com/mitsngeither/sbom-blockchain-guardian/actions/runs/32942433248',
    );
  });

  it('returns undefined for a local runId', () => {
    expect(runUrlFor('local-20260826T075817Z-block-test')).toBeUndefined();
  });

  it('returns undefined for a malformed or empty runId', () => {
    expect(runUrlFor('')).toBeUndefined();
    expect(runUrlFor('not-a-run-id')).toBeUndefined();
    expect(runUrlFor('99')).toBeUndefined();
  });
});

describe('getRunStatus', () => {
  let service: RunsService;
  let root: string;

  function receiptBody(overrides: Record<string, unknown> = {}) {
    return {
      transactionHash: '0x' + 'a'.repeat(64),
      projectId: '0x' + 'b'.repeat(64),
      version: '1.0.0',
      merkleRoot: '0x' + 'c'.repeat(64),
      ...overrides,
    };
  }

  function writeArtifact(subdir: string, fileName: string, body: unknown): void {
    const dir = join(root, subdir);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, fileName), JSON.stringify(body));
  }

  beforeEach(async () => {
    root = mkdtempSync(join(tmpdir(), 'guardian-run-status-'));

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RunsService,
        {
          provide: BlockchainService,
          useValue: { isConfigured: jest.fn().mockReturnValue(false) },
        },
      ],
    }).compile();

    service = module.get<RunsService>(RunsService);
    service.artifactsRoot = root;
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('tags every real run with source pipeline-artifact and ignores a leftover risk/fixtures directory', async () => {
    writeArtifact('risk/history', 'real.json', {
      runId: 'real-1',
      timestamp: '2026-08-01T00:00:00.000Z',
      summary: { overallRating: 'LOW', decision: 'PASS' },
    });
    writeArtifact('risk/fixtures', 'fixture.json', {
      summary: { overallRating: 'LOW', decision: 'PASS' },
    });

    const runs = await service.getRunStatus();

    expect(runs.map((r) => r.runId)).toEqual(['real-1']);
    expect(runs[0].source).toBe('pipeline-artifact');
  });

  it('sorts real runs newest-first by timestamp', async () => {
    writeArtifact('risk/history', 'a.json', {
      runId: 'older',
      timestamp: '2026-01-01T00:00:00.000Z',
      summary: { overallRating: 'LOW', decision: 'PASS' },
    });
    writeArtifact('risk/history', 'b.json', {
      runId: 'newer',
      timestamp: '2026-06-01T00:00:00.000Z',
      summary: { overallRating: 'LOW', decision: 'PASS' },
    });

    const runs = await service.getRunStatus();

    expect(runs.map((r) => r.runId)).toEqual(['newer', 'older']);
  });

  it('reports REGISTERED for a PASS run with a matching chain/receipt-<runId>.json, and NOT SUBMITTED for one without', async () => {
    writeArtifact('risk/history', 'with-receipt.json', {
      runId: 'has-receipt',
      timestamp: '2026-08-01T00:00:00.000Z',
      summary: { overallRating: 'LOW', decision: 'PASS' },
    });
    writeArtifact('risk/history', 'without-receipt.json', {
      runId: 'no-receipt',
      timestamp: '2026-08-02T00:00:00.000Z',
      summary: { overallRating: 'LOW', decision: 'PASS' },
    });
    writeArtifact('chain', 'receipt-has-receipt.json', receiptBody());

    const runs = await service.getRunStatus();

    expect(runs.find((r) => r.runId === 'has-receipt')?.onChainStatus).toBe('REGISTERED');
    expect(runs.find((r) => r.runId === 'no-receipt')?.onChainStatus).toBe('NOT SUBMITTED');
  });

  it('returns an empty list when risk/history is absent', async () => {
    const runs = await service.getRunStatus();

    expect(runs).toEqual([]);
  });

  // A receipt whose runId disagrees with the run it is filed under is ignored.
  it('treats a receipt whose own runId does not match the run as no evidence', async () => {
    writeArtifact('risk/history', 'mismatched.json', {
      runId: 'run-a',
      timestamp: '2026-08-01T00:00:00.000Z',
      summary: { overallRating: 'LOW', decision: 'PASS' },
    });
    // Filed under run-a's name, stamped for another run.
    writeArtifact('chain', 'receipt-run-a.json', receiptBody({ runId: 'run-b' }));

    const runs = await service.getRunStatus();

    expect(runs.find((r) => r.runId === 'run-a')?.onChainStatus).toBe('NOT SUBMITTED');
  });

  it('still accepts a receipt that carries no runId field at all', async () => {
    writeArtifact('risk/history', 'legacy.json', {
      runId: 'run-legacy',
      timestamp: '2026-08-01T00:00:00.000Z',
      summary: { overallRating: 'LOW', decision: 'PASS' },
    });
    writeArtifact('chain', 'receipt-run-legacy.json', receiptBody());

    const runs = await service.getRunStatus();

    expect(runs.find((r) => r.runId === 'run-legacy')?.onChainStatus).toBe('REGISTERED');
  });

  // A runId with path-traversal characters must not escape chainDir.
  it('rejects a runId containing path-traversal characters instead of following it outside chainDir', async () => {
    const maliciousRunId = '/../../leaked';

    // Plant a valid receipt where the unsanitised path would land.
    const naivePath = resolve(join(root, 'chain'), 'receipt-' + maliciousRunId + '.json');
    expect(naivePath.startsWith(join(root, 'chain'))).toBe(false);
    mkdirSync(join(root), { recursive: true });
    writeFileSync(naivePath, JSON.stringify(receiptBody()));

    writeArtifact('risk/history', 'traversal.json', {
      runId: maliciousRunId,
      timestamp: '2026-08-01T00:00:00.000Z',
      summary: { overallRating: 'LOW', decision: 'PASS' },
    });

    const runs = await service.getRunStatus();

    expect(runs.find((r) => r.runId === maliciousRunId)?.onChainStatus).toBe('NOT SUBMITTED');
  });
});

// Receipt validation.
describe('readChainReceipt', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'guardian-receipt-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function write(name: string, body: unknown): string {
    const path = join(dir, name);
    writeFileSync(path, typeof body === 'string' ? body : JSON.stringify(body));
    return path;
  }

  it('accepts a well-formed receipt', () => {
    expect(readChainReceipt(write('ok.json', VALID_RECEIPT))).toEqual(
      expect.objectContaining({ version: '1.0.0', projectId: VALID_RECEIPT.projectId }),
    );
  });

  it('rejects a missing file', () => {
    expect(readChainReceipt(join(dir, 'absent.json'))).toBeNull();
  });

  it('rejects malformed JSON instead of throwing', () => {
    expect(readChainReceipt(write('bad.json', '{"status":"CONFIRMED"'))).toBeNull();
  });

  it('rejects a receipt whose transaction hash is not a 32-byte hex string', () => {
    expect(readChainReceipt(write('tx.json', { ...VALID_RECEIPT, transactionHash: '0xdeadbeef' }))).toBeNull();
  });

  it('rejects a receipt missing its version', () => {
    expect(readChainReceipt(write('ver.json', { ...VALID_RECEIPT, version: '  ' }))).toBeNull();
  });

  it('rejects a receipt whose merkleRoot is not a 32-byte hex string', () => {
    expect(readChainReceipt(write('root.json', { ...VALID_RECEIPT, merkleRoot: 'not-a-root' }))).toBeNull();
  });
});
