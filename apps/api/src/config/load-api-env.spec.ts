import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadApiEnv } from './load-api-env';

describe('loadApiEnv', () => {
  const previousRpcUrl = process.env.RPC_URL;
  const previousContractAddress = process.env.CONTRACT_ADDRESS;

  afterEach(() => {
    if (previousRpcUrl === undefined) {
      delete process.env.RPC_URL;
    } else {
      process.env.RPC_URL = previousRpcUrl;
    }

    if (previousContractAddress === undefined) {
      delete process.env.CONTRACT_ADDRESS;
    } else {
      process.env.CONTRACT_ADDRESS = previousContractAddress;
    }
  });

  it('loads a repo root .env when the API process starts from apps/api', () => {
    delete process.env.RPC_URL;
    delete process.env.CONTRACT_ADDRESS;

    const workspace = mkdtempSync(join(tmpdir(), 'guardian-api-env-'));
    const apiDir = join(workspace, 'apps', 'api');
    mkdirSync(apiDir, { recursive: true });
    writeFileSync(
      join(workspace, '.env'),
      [
        'RPC_URL=http://127.0.0.1:8545',
        'CONTRACT_ADDRESS=0x839e30B5F75f50cCF48f3562a6cAe0E54b699D36',
      ].join('\n'),
    );

    try {
      const loaded = loadApiEnv(apiDir);

      expect(loaded).toContain(join(workspace, '.env'));
      expect(process.env.RPC_URL).toBe('http://127.0.0.1:8545');
      expect(process.env.CONTRACT_ADDRESS).toBe(
        '0x839e30B5F75f50cCF48f3562a6cAe0E54b699D36',
      );
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });
});
