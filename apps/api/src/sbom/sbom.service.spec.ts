import { Test, TestingModule } from '@nestjs/testing';
import { BlockchainService, type SbomRegistryRecord } from '../blockchain/blockchain.service';
import { SbomArtifactStoreService, type StoredSbomArtifact } from './sbom-artifact-store.service';
import { SbomService } from './sbom.service';

function chainRecord(overrides: Partial<SbomRegistryRecord> = {}): SbomRegistryRecord {
  return {
    projectId: 'sbom-blockchain-guardian',
    projectIdHash: '0x283b542a6659354867be82cc78de553bab5cf494a5cffa401f45dbbaff2852f3',
    version: '1.0.0',
    sbomHash: '0xbf35648e796920d429be61c4ea144fc1e75ac32c31f41545665a273099c9312d',
    artifactHash: '0x' + '00'.repeat(32),
    merkleRoot: '0x0f34e072c7469e0a814f589d4cee7f257b6c712da4bb93fa4175f9d5016ae6f5',
    submitter: '0x9a8F3ec8C8E921B21150e3d9f159966fC01f4972',
    timestamp: '1783566820',
    riskScore: 7,
    status: 'Active',
    ...overrides,
  };
}

function localArtifact(overrides: Partial<StoredSbomArtifact> = {}): StoredSbomArtifact {
  return {
    projectId: 'sbom-blockchain-guardian',
    version: '2.0.0-local-only',
    sbomHash: '0xaaaa',
    merkleRoot: '0xbbbb',
    artifactPath: '/tmp/irrelevant.json',
    artifactUri: 'local://irrelevant.json',
    componentCount: 1,
    riskScore: 1,
    createdAt: new Date().toISOString(),
    onChainStatus: 'None',
    ...overrides,
  };
}

async function buildService(
  blockchainOverrides: Partial<BlockchainService>,
  artifactStoreOverrides: Partial<SbomArtifactStoreService>,
): Promise<SbomService> {
  const module: TestingModule = await Test.createTestingModule({
    providers: [BlockchainService, SbomArtifactStoreService, SbomService],
  })
    .overrideProvider(BlockchainService)
    .useValue({
      isConfigured: () => false,
      getDefaultProjectId: () => 'sbom-blockchain-guardian',
      getNetworkStatus: () => ({ chainName: 'test', contractAddress: '', configured: false }),
      getHistory: async () => [],
      ...blockchainOverrides,
    })
    .overrideProvider(SbomArtifactStoreService)
    .useValue({
      listArtifacts: async () => [],
      readArtifactContent: async () => null,
      ...artifactStoreOverrides,
    })
    .compile();

  return module.get<SbomService>(SbomService);
}

describe('SbomService', () => {
  it('should be defined', async () => {
    const service = await buildService({}, {});
    expect(service).toBeDefined();
  });

  describe('getHistory', () => {
    it('returns only real chain records when the project has no local uploads', async () => {
      const service = await buildService(
        {
          isConfigured: () => true,
          getHistory: async () => [chainRecord()],
        },
        { listArtifacts: async () => [] },
      );

      const result = await service.getHistory('sbom-blockchain-guardian');

      expect(result.source).toBe('contract');
      expect(result.records).toEqual([chainRecord()]);
    });

    it('merges local-only uploads alongside real chain records instead of one shadowing the other', async () => {
      const local = localArtifact();
      const onChain = chainRecord();

      const service = await buildService(
        {
          isConfigured: () => true,
          getHistory: async () => [onChain],
        },
        { listArtifacts: async () => [local] },
      );

      const result = await service.getHistory('sbom-blockchain-guardian');

      expect(result.source).toBe('contract');
      expect(result.records).toHaveLength(2);
      expect(result.records.find((r) => r.version === onChain.version)).toEqual(onChain);
      expect(result.records.find((r) => r.version === local.version)).toEqual(
        expect.objectContaining({ version: local.version, status: 'None' }),
      );
    });

    it('prefers the on-chain record over a local copy of the same version', async () => {
      const onChain = chainRecord({ version: '1.0.0', status: 'Active' });
      const staleLocal = localArtifact({ version: '1.0.0', onChainStatus: 'None' });

      const service = await buildService(
        {
          isConfigured: () => true,
          getHistory: async () => [onChain],
        },
        { listArtifacts: async () => [staleLocal] },
      );

      const result = await service.getHistory('sbom-blockchain-guardian');

      expect(result.records).toHaveLength(1);
      expect(result.records[0]).toEqual(onChain);
    });

    it('does not report a cached Active status for a local artifact the current contract does not hold', async () => {
      // e.g. records written to a previous contract deployment, cached as Active at ingest time
      const staleActive = localArtifact({ version: '1.0.0-old-contract', onChainStatus: 'Active' });

      const service = await buildService(
        {
          isConfigured: () => true,
          getHistory: async () => [chainRecord()],
        },
        { listArtifacts: async () => [staleActive] },
      );

      const result = await service.getHistory('sbom-blockchain-guardian');

      expect(result.records.find((r) => r.version === staleActive.version)).toEqual(
        expect.objectContaining({ status: 'None' }),
      );
    });

    it('keeps the cached status when the contract could not be read', async () => {
      const cached = localArtifact({ version: '1.0.0-cached', onChainStatus: 'Active' });

      const service = await buildService(
        {
          isConfigured: () => true,
          getHistory: async () => {
            throw new Error('rpc down');
          },
        },
        { listArtifacts: async () => [cached] },
      );

      const result = await service.getHistory('sbom-blockchain-guardian');

      expect(result.records[0]).toEqual(expect.objectContaining({ status: 'Active' }));
      expect(result).toEqual(expect.objectContaining({ error: 'rpc down' }));
    });

    it('falls back to the local artifact store when the chain is not configured', async () => {
      const local = localArtifact({ projectId: 'demo-clean-app', version: '1.0.0' });

      const service = await buildService(
        { isConfigured: () => false },
        { listArtifacts: async () => [local] },
      );

      const result = await service.getHistory('demo-clean-app');

      expect(result.source).toBe('registry');
      expect(result.records).toHaveLength(1);
    });

    it('falls back to demo data when neither the chain nor local storage has anything', async () => {
      const service = await buildService(
        { isConfigured: () => false },
        { listArtifacts: async () => [] },
      );

      const result = await service.getHistory('unknown-project');

      expect(result.source).toBe('demo');
      expect(result.records.length).toBeGreaterThan(0);
    });
  });
});
