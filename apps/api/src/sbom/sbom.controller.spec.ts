import { Test, TestingModule } from '@nestjs/testing';
import { BlockchainService } from '../blockchain/blockchain.service';
import { SbomArtifactStoreService } from './sbom-artifact-store.service';
import { SbomController } from './sbom.controller';
import { SbomService } from './sbom.service';

describe('SbomController', () => {
  let controller: SbomController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SbomController],
      providers: [BlockchainService, SbomArtifactStoreService, SbomService],
    }).compile();

    controller = module.get<SbomController>(SbomController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
