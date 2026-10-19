import { Injectable } from '@nestjs/common';
import { ethers } from 'ethers';
import { loadApiEnv } from '../config/load-api-env';
import { canonicalSbomDocument } from '@guardian/sbom-core';

loadApiEnv();

type RegistryStatus = 'None' | 'Active' | 'Revoked';

export type SbomRegistryRecord = {
  projectId: string;
  projectIdHash: string;
  version: string;
  sbomHash: string;
  artifactHash: string;
  merkleRoot: string;
  submitter: string;
  timestamp: string;
  riskScore: number;
  status: RegistryStatus;
};

const SBOM_REGISTRY_ABI = [
  'function getHistory(bytes32 projectId) view returns (string[])',
  'function getLatest(bytes32 projectId) view returns (tuple(bytes32 sbomHash, bytes32 artifactHash, bytes32 merkleRoot, address submitter, uint48 timestamp, uint32 riskScore, uint8 status))',
  'function getVersion(bytes32 projectId, string version) view returns (tuple(bytes32 sbomHash,bytes32 artifactHash, bytes32 merkleRoot, address submitter, uint48 timestamp, uint32 riskScore, uint8 status))',
  'function verifySBOM(bytes32 projectId, string version, bytes32 sbomHash) view returns (bool)',
] as const;

const STATUS_NAMES: RegistryStatus[] = ['None', 'Active', 'Revoked'];
const ZERO_HASH = ethers.ZeroHash;

function normalizeBytes32(value: string): string {
  const trimmed = value.trim();

  if (ethers.isHexString(trimmed, 32)) {
    return trimmed;
  }

  return ethers.keccak256(ethers.toUtf8Bytes(trimmed));
}

@Injectable()
export class BlockchainService {
  private readonly rpcUrl = process.env.SEPOLIA_RPC_URL ?? process.env.RPC_URL;
  private readonly contractAddress = process.env.CONTRACT_ADDRESS;
  // SEPOLIA_RPC_URL takes precedence above, so the default label follows it.
  // `||` rather than `??`: Compose sets CHAIN_NAME to "" when it is unset.
  private readonly chainName = process.env.CHAIN_NAME?.trim()
    || (process.env.SEPOLIA_RPC_URL ? 'Sepolia' : 'Guardian Devnet');
  private readonly defaultProjectId =
    process.env.PROJECT_ID ??
    process.env.GUARDIAN_PROJECT_ID ??
    'sbom-blockchain-guardian';

  isConfigured(): boolean {
    return Boolean(
      this.rpcUrl &&
      this.contractAddress &&
      ethers.isAddress(this.contractAddress),
    );
  }

  getDefaultProjectId(): string {
    return this.defaultProjectId;
  }

  getNetworkStatus() {
    return {
      chainName: this.chainName,
      contractAddress: this.contractAddress ?? '',
      configured: this.isConfigured(),
    };
  }

  computeSbomHash(sbomContent: string): string {
    const canonical = canonicalSbomDocument(sbomContent);
    return ethers.keccak256(ethers.toUtf8Bytes(canonical));
  }

  async getLatest(projectId = this.defaultProjectId): Promise<SbomRegistryRecord> {
    const contract = this.getContract();
    const projectIdHash = normalizeBytes32(projectId);
    const record = await contract.getLatest(projectIdHash);

    return this.formatRecord(projectId, projectIdHash, 'latest', record);
  }

  async getHistory(projectId = this.defaultProjectId): Promise<SbomRegistryRecord[]> {
    const contract = this.getContract();
    const projectIdHash = normalizeBytes32(projectId);
    const versions = await contract.getHistory(projectIdHash) as string[];

    const records = await Promise.all(
      versions.map(async (version) => {
        const record = await contract.getVersion(projectIdHash, version);
        return this.formatRecord(projectId, projectIdHash, version, record);
      }),
    );

    return records.reverse();
  }

  async getVersion(
    projectId: string,
    version: string,
  ): Promise<SbomRegistryRecord> {
    const contract = this.getContract();
    const projectIdHash = normalizeBytes32(projectId);
    const record = await contract.getVersion(projectIdHash, version);

    return this.formatRecord(projectId, projectIdHash, version, record);
  }

  async verifyHash(
    projectId: string,
    version: string,
    sbomHash: string,
  ): Promise<boolean> {
    const contract = this.getContract();

    return contract.verifySBOM(
      normalizeBytes32(projectId),
      version,
      normalizeBytes32(sbomHash),
    );
  }

  private getContract() {
    if (!this.isConfigured()) {
      throw new Error(
        'Blockchain RPC is not configured. Set RPC_URL and CONTRACT_ADDRESS.',
      );
    }

    const provider = new ethers.JsonRpcProvider(this.rpcUrl);
    return new ethers.Contract(
      this.contractAddress as string,
      SBOM_REGISTRY_ABI,
      provider,
    );
  }

  private formatRecord(
    projectId: string,
    projectIdHash: string,
    version: string,
    record: {
      sbomHash: string;
      artifactHash: string;
      merkleRoot: string;
      submitter: string;
      timestamp: bigint;
      riskScore: bigint;
      status: bigint;
    },
  ): SbomRegistryRecord {
    const statusIndex = Number(record.status);

    return {
      projectId,
      projectIdHash,
      version,
      sbomHash: record.sbomHash,
      artifactHash: record.artifactHash,
      merkleRoot: record.merkleRoot,
      submitter: record.submitter,
      timestamp: record.timestamp.toString(),
      riskScore: Number(record.riskScore),
      status:
        record.sbomHash === ZERO_HASH
          ? 'None'
          : STATUS_NAMES[statusIndex] ?? 'None',
    };
  }
}
