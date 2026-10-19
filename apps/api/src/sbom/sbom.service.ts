import { Injectable } from '@nestjs/common';
import { buildSBOMMerkleTree, computeArtifactHash, parseSBOMContent } from '@guardian/sbom-core';
import {
  BlockchainService,
  type SbomRegistryRecord,
} from '../blockchain/blockchain.service';
import { demoData } from '../data/demo-data';
import { IngestSbomDto } from './dto/ingest-sbom.dto';
import { VerifySbomDto } from './dto/verify-sbom.dto';
import {
  SbomArtifactStoreService,
  type StoredSbomArtifact,
} from './sbom-artifact-store.service';

const ZERO_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000";

export function artifactMerkleRoot(sbomContent: string): string {
  const flattened = parseSBOMContent(sbomContent);
  if (flattened.components.length === 0) return ZERO_HASH;
  return buildSBOMMerkleTree(flattened).root;
}

function isCycloneDxSbom(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const sbom = value as { bomFormat?: unknown; specVersion?: unknown; components?: unknown; };
  return sbom.bomFormat === "CycloneDX"
    && typeof sbom.specVersion === "string"
    && Array.isArray(sbom.components);
}

function componentCount(value: unknown): number {
  if (!value || typeof value !== "object") return 0;
  const sbom = value as { metadata?: { component?: unknown; }; components?: unknown[]; };
  return (sbom.metadata?.component ? 1 : 0) + (Array.isArray(sbom.components) ? sbom.components.length : 0);
}

function artifactToRegistryRecord(item: StoredSbomArtifact, merkleRoot = item.merkleRoot ?? ZERO_HASH): SbomRegistryRecord {
  const status = item.onChainStatus === 'Active' || item.onChainStatus === 'Revoked'
    ? item.onChainStatus
    : 'None';

  return {
    projectId: item.projectId,
    projectIdHash: item.projectId,
    version: item.version,
    sbomHash: item.sbomHash,
    artifactHash: item.artifactHash ?? ZERO_HASH,
    merkleRoot,
    submitter: item.repo ?? 'artifact-registry',
    timestamp: String(Math.floor(new Date(item.createdAt).getTime() / 1000)),
    riskScore: item.riskScore,
    status,
  };
}

function demoHistoryRecords(): SbomRegistryRecord[] {
  return demoData.map((item) => ({
    projectId: item.projectId,
    projectIdHash: item.projectId,
    version: item.runId,
    sbomHash: item.onChainStatus === 'REGISTERED' ? item.runId : ZERO_HASH,
    artifactHash: ZERO_HASH,
    merkleRoot: ZERO_HASH,
    submitter: 'demo',
    timestamp: '0',
    riskScore: item.highestRiskScore,
    status: item.onChainStatus === 'REGISTERED' ? 'Active' : 'None',
  }));
}

type IngestResult = {
  status: "INGESTED" | "STRUCTURE_INVALID";
  structureValid: boolean;
  projectId: string;
  version: string;
  message: string;
  sbomHash?: string;
  artifactHash?: string;
  artifact?: StoredSbomArtifact;
  onChainRecord?: SbomRegistryRecord;
  onChainMatch?: boolean;
};

type VerifyResult = {
  status: "STRUCTURE_VALID" | "STRUCTURE_INVALID" | "ATTESTED_VALID" | "MISMATCH" | "NOT_FOUND" | "REVOKED";
  structureValid: boolean;
  projectId: string;
  version: string;
  message: string;
  computedHash?: string;
  onChainHash?: string;
  record?: SbomRegistryRecord;
};

type VerifyArtifactResult = {
  status: "NOT_FOUND" | "REVOKED" | "ARTIFACT_UNAVAILABLE" | "ATTESTED_VALID" | "MISMATCH";
  projectId: string;
  version: string;
  message: string;
  onChainHash?: string;
  recomputedHash?: string;
  record?: SbomRegistryRecord;
};

@Injectable()
export class SbomService {
  constructor(
    private readonly blockchainService: BlockchainService,
    private readonly artifactStore: SbomArtifactStoreService,
  ) { }

  private async resolveArtifactRecord(artifact: StoredSbomArtifact): Promise<SbomRegistryRecord> {
    if (artifact.merkleRoot) return artifactToRegistryRecord(artifact);
    try {
      const content = await this.artifactStore.readArtifactContent(artifact.projectId, artifact.version);
      const merkleRoot = content ? artifactMerkleRoot(content) : ZERO_HASH;
      return artifactToRegistryRecord(artifact, merkleRoot);
    } catch {
      return artifactToRegistryRecord(artifact);
    }
  }

  async getHistory(projectId?: string) {
    const resolvedProjectId = projectId ?? this.blockchainService.getDefaultProjectId();
    const localArtifacts = await this.artifactStore.listArtifacts(resolvedProjectId);

    let chainRecords: SbomRegistryRecord[] = [];
    let chainError: string | undefined;

    if (this.blockchainService.isConfigured()) {
      try {
        chainRecords = await this.blockchainService.getHistory(resolvedProjectId);
      } catch (error) {
        chainError = error instanceof Error ? error.message : String(error);
      }
    }

    const merged = new Map<string, SbomRegistryRecord>();
    for (const record of chainRecords) {
      merged.set(record.version, record);
    }

    // A readable contract is authoritative: a local copy it does not hold was never recorded there
    // (or went to an earlier deployment), so its cached ingest-time status must not show as Active.
    const contractRead = this.blockchainService.isConfigured() && !chainError;
    for (const artifact of localArtifacts) {
      if (merged.has(artifact.version)) continue;
      const record = await this.resolveArtifactRecord(artifact);
      merged.set(artifact.version, contractRead ? { ...record, status: 'None' } : record);
    }

    if (merged.size > 0) {
      return {
        source: chainRecords.length > 0 ? 'contract' : 'registry',
        network: this.blockchainService.getNetworkStatus(),
        projectId: resolvedProjectId,
        records: [...merged.values()],
        ...(chainError ? { error: chainError } : {}),
      };
    }

    return {
      source: 'demo',
      network: this.blockchainService.getNetworkStatus(),
      projectId: resolvedProjectId,
      records: demoHistoryRecords(),
      ...(chainError ? { error: chainError } : {}),
    };
  }

  async getRecord(projectId: string, version: string) {
    return this.blockchainService.getVersion(projectId, version);
  }

  getProjects() {
    return this.artifactStore.listProjects();
  }

  async getArtifact(projectId: string, version: string) {
    return this.artifactStore.getArtifact(projectId, version);
  }

  async getArtifactContent(projectId: string, version: string) {
    return this.artifactStore.readArtifactContent(projectId, version);
  }

  async ingestSbom(input: IngestSbomDto): Promise<IngestResult> {
    if (!input.projectId?.trim() || !input.version?.trim()) {
      return {
        status: 'STRUCTURE_INVALID',
        structureValid: false,
        projectId: input.projectId ?? '',
        version: input.version ?? '',
        message: 'Project ID and version are required to ingest an SBOM artifact.',
      };
    }

    let parsedSbom: unknown;

    try {
      parsedSbom = JSON.parse(input.sbomContent);
    } catch {
      return {
        status: 'STRUCTURE_INVALID',
        structureValid: false,
        projectId: input.projectId,
        version: input.version,
        message: 'Uploaded SBOM is not valid JSON.',
      };
    }

    if (!isCycloneDxSbom(parsedSbom)) {
      return {
        status: 'STRUCTURE_INVALID',
        structureValid: false,
        projectId: input.projectId,
        version: input.version,
        message: 'Uploaded JSON is missing CycloneDX bomFormat, specVersion, or components.',
      };
    }

    const sbomHash = this.blockchainService.computeSbomHash(input.sbomContent);
    const merkleRoot = artifactMerkleRoot(input.sbomContent);

    let artifactHash: string | undefined;
    try {
      const result = await computeArtifactHash(input.projectId, input.version);
      artifactHash = result.artifactHash;
    } catch {
      artifactHash = undefined;
    }

    let onChainRecord: SbomRegistryRecord | undefined;
    let onChainMatch: boolean | undefined;
    let onChainStatus: StoredSbomArtifact['onChainStatus'] = this.blockchainService.isConfigured()
      ? 'Unknown'
      : 'NotConfigured';

    if (this.blockchainService.isConfigured()) {
      try {
        onChainRecord = await this.blockchainService.getVersion(input.projectId, input.version);
        onChainStatus = onChainRecord.status;
        onChainMatch = onChainRecord.status === 'Active' && onChainRecord.sbomHash.toLowerCase() === sbomHash.toLowerCase();
      } catch {
        onChainStatus = 'Unknown';
      }
    }

    const hasCallerRiskScore = Number.isSafeInteger(input.riskScore);

    const artifact = await this.artifactStore.saveArtifact({
      projectId: input.projectId.trim(),
      version: input.version.trim(),
      sbomContent: input.sbomContent,
      sbomHash,
      artifactHash,
      merkleRoot,
      componentCount: componentCount(parsedSbom),
      riskScore: hasCallerRiskScore ? input.riskScore as number : 0,
      riskScoreSource: hasCallerRiskScore ? 'caller-supplied' : 'not-provided',
      repo: input.repo,
      branch: input.branch,
      commit: input.commit,
      txHash: input.txHash,
      onChainStatus,
      onChainMatch,
    });

    return {
      status: 'INGESTED',
      structureValid: true,
      projectId: artifact.projectId,
      version: artifact.version,
      sbomHash,
      artifactHash,
      artifact,
      onChainRecord,
      onChainMatch,
      message: onChainMatch === true
        ? 'SBOM artifact stored and matched to an active on-chain attestation.'
        : 'SBOM artifact stored. On-chain attestation can be matched when the contract record exists.',
    };
  }

  async verifyUpload(input: VerifySbomDto): Promise<VerifyResult> {
    if (!input.projectId?.trim() || !input.version?.trim()) {
      return {
        status: 'NOT_FOUND',
        structureValid: false,
        projectId: input.projectId ?? '',
        version: input.version ?? '',
        message: 'No selected on-chain attestation was provided.',
      };
    }

    let parsedSbom: unknown;

    try {
      parsedSbom = JSON.parse(input.sbomContent);
    } catch {
      return {
        status: 'STRUCTURE_INVALID',
        structureValid: false,
        projectId: input.projectId,
        version: input.version,
        message: 'Uploaded file is not valid JSON.',
      };
    }

    if (!isCycloneDxSbom(parsedSbom)) {
      return {
        status: 'STRUCTURE_INVALID',
        structureValid: false,
        projectId: input.projectId,
        version: input.version,
        message: 'Uploaded JSON is missing CycloneDX bomFormat, specVersion, or components.',
      };
    }

    const computedHash = this.blockchainService.computeSbomHash(input.sbomContent);

    if (!this.blockchainService.isConfigured()) {
      return {
        status: 'STRUCTURE_VALID',
        structureValid: true,
        projectId: input.projectId,
        version: input.version,
        computedHash,
        message: 'SBOM structure is valid. Configure RPC_URL and CONTRACT_ADDRESS to verify attestation.',
      };
    }

    const record = await this.blockchainService.getVersion(input.projectId, input.version);

    if (record.status === 'None') {
      return {
        status: 'NOT_FOUND',
        structureValid: true,
        projectId: input.projectId,
        version: input.version,
        computedHash,
        record,
        message: 'No on-chain record exists for the selected project and version.',
      };
    }

    if (record.status === 'Revoked') {
      return {
        status: 'REVOKED',
        structureValid: true,
        projectId: input.projectId,
        version: input.version,
        computedHash,
        onChainHash: record.sbomHash,
        record,
        message: 'The selected on-chain attestation has been revoked.',
      };
    }

    const isVerified = await this.blockchainService.verifyHash(input.projectId, input.version, computedHash);

    return {
      status: isVerified ? 'ATTESTED_VALID' : 'MISMATCH',
      structureValid: true,
      projectId: input.projectId,
      version: input.version,
      computedHash,
      onChainHash: record.sbomHash,
      record,
      message: isVerified
        ? 'Uploaded SBOM hash matches the active on-chain attestation.'
        : 'Uploaded SBOM hash does not match the selected on-chain attestation.',
    };
  }

  async verifyArtifact(projectId: string, version: string): Promise<VerifyArtifactResult> {
    const record = await this.blockchainService.getVersion(projectId, version);

    if (record.status === 'None') {
      return {
        status: 'NOT_FOUND',
        projectId,
        version,
        message: 'No on-chain record exists for the selected project and version.',
      };
    }

    if (record.status === 'Revoked') {
      return {
        status: 'REVOKED',
        projectId,
        version,
        onChainHash: record.artifactHash,
        record,
        message: 'The selected on-chain attestation has been revoked.',
      };
    }

    let recomputedHash: string;
    try {
      const result = await computeArtifactHash(projectId, version);
      recomputedHash = result.artifactHash;
    } catch {
      return {
        status: 'ARTIFACT_UNAVAILABLE',
        projectId,
        version,
        onChainHash: record.artifactHash,
        record,
        message: 'Could not fetch the artifact from npm to recompute its hash (package not published, or version removed).',
      };
    }

    const matches = record.artifactHash.toLowerCase() === recomputedHash.toLowerCase();

    return {
      status: matches ? 'ATTESTED_VALID' : 'MISMATCH',
      projectId,
      version,
      onChainHash: record.artifactHash,
      recomputedHash,
      record,
      message: matches
        ? 'The artifact currently on npm matches the on-chain attestation.'
        : 'The artifact currently on npm does NOT match the on-chain attestation -- possible tampering or republish.',
    };
  }

  getRiskReports() {
    return demoData;
  }

  getRiskReportsByRunId(runId: string) {
    return demoData.filter((item) => item.runId === runId);
  }
}