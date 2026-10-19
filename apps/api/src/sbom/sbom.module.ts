import { Module } from '@nestjs/common';
import { BlockchainService } from '../blockchain/blockchain.service';
import { SbomController } from './sbom.controller';
import { SbomArtifactStoreService } from './sbom-artifact-store.service';
import { SbomService } from './sbom.service';

@Module({
  controllers: [SbomController],
  providers: [BlockchainService, SbomArtifactStoreService, SbomService],
})
export class SbomModule {}
