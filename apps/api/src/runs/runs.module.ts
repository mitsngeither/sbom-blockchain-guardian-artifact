import { Module } from '@nestjs/common';
import { BlockchainService } from '../blockchain/blockchain.service';
import { RunsService } from './runs.service';
import { RunsController } from './runs.controller';

@Module({
  controllers: [RunsController],
  providers: [RunsService, BlockchainService],
})
export class RunsModule {}
