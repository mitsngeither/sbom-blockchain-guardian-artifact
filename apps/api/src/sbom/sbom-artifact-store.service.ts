import { Injectable } from '@nestjs/common';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

// Origin of a stored riskScore. Ingest takes it from the caller as is, so it
// is not an assessed result.
export type RiskScoreSource = 'caller-supplied' | 'not-provided';

export type StoredSbomArtifact = {
  merkleRoot?: string;
  projectId: string;
  version: string;
  sbomHash: string;
  artifactHash?: string;
  artifactPath: string;
  artifactUri: string;
  componentCount: number;
  riskScore: number;
  riskScoreSource?: RiskScoreSource;
  createdAt: string;
  repo?: string;
  branch?: string;
  commit?: string;
  txHash?: string;
  onChainStatus: 'Active' | 'Revoked' | 'None' | 'NotConfigured' | 'Unknown';
  onChainMatch?: boolean;
};

export type StoredSbomProject = {
  projectId: string;
  versions: number;
  latestVersion: string;
  latestHash: string;
  latestCreatedAt: string;
  activeAttestations: number;
  storedArtifacts: number;
};

export type SaveSbomArtifactInput = Omit<StoredSbomArtifact, 'artifactPath' | 'artifactUri' | 'createdAt'> & {
  sbomContent: string;
};

type IndexFile = {
  records: StoredSbomArtifact[];
};

function safeSegment(value: string): string {
  return encodeURIComponent(value.trim());
}

@Injectable()
export class SbomArtifactStoreService {
  private readonly rootDir = process.env.SBOM_STORAGE_DIR ?? resolve(process.cwd(), 'storage/sboms');
  private readonly indexPath = resolve(this.rootDir, 'index.json');

  async saveArtifact(input: SaveSbomArtifactInput): Promise<StoredSbomArtifact> {
    const projectDir = resolve(this.rootDir, safeSegment(input.projectId));
    const artifactPath = resolve(projectDir, `${safeSegment(input.version)}.json`);
    const artifactUri = `local://${safeSegment(input.projectId)}/${safeSegment(input.version)}.json`;
    const record: StoredSbomArtifact = {
      projectId: input.projectId,
      version: input.version,
      sbomHash: input.sbomHash,
      artifactHash: input.artifactHash,
      merkleRoot: input.merkleRoot,
      artifactPath,
      artifactUri,
      componentCount: input.componentCount,
      riskScore: input.riskScore,
      riskScoreSource: input.riskScoreSource,
      repo: input.repo,
      branch: input.branch,
      commit: input.commit,
      txHash: input.txHash,
      onChainStatus: input.onChainStatus,
      onChainMatch: input.onChainMatch,
      createdAt: new Date().toISOString(),
    };

    await mkdir(projectDir, { recursive: true });
    await writeFile(artifactPath, input.sbomContent);

    const index = await this.readIndex();
    const records = index.records.filter(
      (item) => item.projectId !== input.projectId || item.version !== input.version,
    );
    records.unshift(record);
    await this.writeIndex({ records });

    return record;
  }

  async listArtifacts(projectId?: string): Promise<StoredSbomArtifact[]> {
    const index = await this.readIndex();
    const records = projectId
      ? index.records.filter((item) => item.projectId === projectId)
      : index.records;

    return records.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async listProjects(): Promise<StoredSbomProject[]> {
    const records = await this.listArtifacts();
    const grouped = new Map<string, StoredSbomArtifact[]>();

    for (const record of records) {
      const items = grouped.get(record.projectId) ?? [];
      items.push(record);
      grouped.set(record.projectId, items);
    }

    return [...grouped.entries()].map(([projectId, items]) => {
      const sorted = items.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const latest = sorted[0];
      return {
        projectId,
        versions: new Set(items.map((item) => item.version)).size,
        latestVersion: latest.version,
        latestHash: latest.sbomHash,
        latestCreatedAt: latest.createdAt,
        activeAttestations: items.filter((item) => item.onChainStatus === 'Active').length,
        storedArtifacts: items.length,
      };
    });
  }

  async getArtifact(projectId: string, version: string): Promise<StoredSbomArtifact | null> {
    const records = await this.listArtifacts(projectId);
    return records.find((item) => item.version === version) ?? null;
  }

  async readArtifactContent(projectId: string, version: string): Promise<string | null> {
    const artifact = await this.getArtifact(projectId, version);
    if (!artifact) return null;
    const artifactPath = resolve(this.rootDir, safeSegment(projectId), safeSegment(version) + '.json');
    return readFile(artifactPath, 'utf8');
  }

  private async readIndex(): Promise<IndexFile> {
    if (!existsSync(this.indexPath)) {
      return { records: [] };
    }

    const content = await readFile(this.indexPath, 'utf8');
    const parsed = JSON.parse(content) as Partial<IndexFile>;
    return { records: Array.isArray(parsed.records) ? parsed.records : [] };
  }

  private async writeIndex(index: IndexFile): Promise<void> {
    await mkdir(this.rootDir, { recursive: true });
    await writeFile(this.indexPath, JSON.stringify(index, null, 2));
  }
}
