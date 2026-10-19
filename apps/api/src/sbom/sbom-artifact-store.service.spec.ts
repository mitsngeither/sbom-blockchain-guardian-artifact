import { mkdtempSync, rmSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SbomArtifactStoreService } from './sbom-artifact-store.service';

describe('SbomArtifactStoreService', () => {
  let root: string;
  let previousStorageDir: string | undefined;

  beforeEach(() => {
    previousStorageDir = process.env.SBOM_STORAGE_DIR;
    root = mkdtempSync(join(tmpdir(), 'guardian-sbom-store-'));
    process.env.SBOM_STORAGE_DIR = root;
  });

  afterEach(() => {
    if (previousStorageDir === undefined) {
      delete process.env.SBOM_STORAGE_DIR;
    } else {
      process.env.SBOM_STORAGE_DIR = previousStorageDir;
    }
    rmSync(root, { recursive: true, force: true });
  });

  it('stores SBOM content and indexes it by project/version', async () => {
    const store = new SbomArtifactStoreService();
    const sbomContent = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}';

    const record = await store.saveArtifact({
      projectId: 'org/payment-api',
      version: '1.2.3+abc1234',
      sbomContent,
      sbomHash: '0xabc',
      merkleRoot: '0xdef',
      componentCount: 0,
      riskScore: 12,
      repo: 'org/payment-api',
      branch: 'main',
      commit: 'abc1234',
      txHash: '0xtx',
      onChainStatus: 'Active',
    });

    await expect(readFile(record.artifactPath, 'utf8')).resolves.toBe(sbomContent);
    expect(record.merkleRoot).toBe('0xdef');
    await expect(store.getArtifact('org/payment-api', '1.2.3+abc1234')).resolves.toEqual(record);
    await expect(store.listProjects()).resolves.toEqual([
      expect.objectContaining({ projectId: 'org/payment-api', versions: 1, latestVersion: '1.2.3+abc1234' }),
    ]);
  });

  it("reads artifact content from the current storage root when index paths are stale", async () => {
    const store = new SbomArtifactStoreService();
    const projectDir = join(root, "org%2Fpayment-api");
    const sbomContent = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[]}";

    await mkdir(projectDir, { recursive: true });
    await writeFile(join(projectDir, "1.2.3.json"), sbomContent);
    await writeFile(join(root, "index.json"), JSON.stringify({
      records: [{
        projectId: "org/payment-api",
        version: "1.2.3",
        sbomHash: "0xabc",
        artifactPath: "/old/host/path/1.2.3.json",
        artifactUri: "local://org%2Fpayment-api/1.2.3.json",
        componentCount: 0,
        riskScore: 0,
        onChainStatus: "None",
        createdAt: "2026-07-09T00:00:00.000Z",
      }],
    }));

    await expect(store.readArtifactContent("org/payment-api", "1.2.3")).resolves.toBe(sbomContent);
  });
});
