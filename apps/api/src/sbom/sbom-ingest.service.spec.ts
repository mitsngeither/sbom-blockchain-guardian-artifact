import { Test, TestingModule } from '@nestjs/testing';
import { BlockchainService } from '../blockchain/blockchain.service';
import { SbomArtifactStoreService } from './sbom-artifact-store.service';
import { SbomService } from './sbom.service';

describe('SbomService ingestion', () => {
  it('ingests a CycloneDX SBOM into the artifact store', async () => {
    const blockchain = {
      computeSbomHash: jest.fn().mockReturnValue('0xhash'),
      isConfigured: jest.fn().mockReturnValue(false),
      getNetworkStatus: jest.fn().mockReturnValue({ chainName: 'Guardian Devnet', contractAddress: '', configured: false }),
      getDefaultProjectId: jest.fn().mockReturnValue('sbom-blockchain-guardian'),
    };
    const store = {
      saveArtifact: jest.fn().mockResolvedValue({
        projectId: 'org/payment-api',
        version: '1.0.0',
        sbomHash: '0xhash',
        merkleRoot: '0xmerkle',
        artifactPath: '/tmp/sbom.json',
        artifactUri: 'local://org%2Fpayment-api/1.0.0.json',
        componentCount: 1,
        riskScore: 0,
        createdAt: '2026-07-09T00:00:00.000Z',
        onChainStatus: 'NotConfigured',
      }),
      listArtifacts: jest.fn().mockResolvedValue([]),
    };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SbomService,
        { provide: BlockchainService, useValue: blockchain },
        { provide: SbomArtifactStoreService, useValue: store },
      ],
    }).compile();
    const service = module.get(SbomService);
    const sbomContent = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [{ name: 'axios', version: '1.14.1' }],
    });

    await expect(service.ingestSbom({
      projectId: 'org/payment-api',
      version: '1.0.0',
      sbomContent,
      repo: 'org/payment-api',
      branch: 'main',
      commit: 'abc1234',
    })).resolves.toEqual(expect.objectContaining({
      status: 'INGESTED',
      projectId: 'org/payment-api',
      version: '1.0.0',
      sbomHash: '0xhash',
      artifact: expect.objectContaining({ artifactUri: 'local://org%2Fpayment-api/1.0.0.json' }),
    }));

    expect(store.saveArtifact).toHaveBeenCalledWith(expect.objectContaining({
      projectId: 'org/payment-api',
      version: '1.0.0',
      sbomHash: '0xhash',
      componentCount: 1,
      onChainStatus: 'NotConfigured',
    }));

    const merkleRoot = store.saveArtifact.mock.calls[0][0].merkleRoot;
    expect(typeof merkleRoot).toBe("string");
    expect(merkleRoot).toHaveLength(66);
    expect(merkleRoot.startsWith("0x")).toBe(true);
    expect(merkleRoot).not.toBe(
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    );
  });
});
