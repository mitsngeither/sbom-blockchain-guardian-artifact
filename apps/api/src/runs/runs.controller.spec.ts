import { Test, TestingModule } from '@nestjs/testing';
import { BlockchainService } from '../blockchain/blockchain.service';
import { RunsController } from './runs.controller';
import { RunsService } from './runs.service';

describe('RunsController', () => {
  let controller: RunsController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [RunsController],
      providers: [
        RunsService,
        {
          provide: BlockchainService,
          useValue: { isConfigured: jest.fn().mockReturnValue(false) },
        },
      ],
    }).compile();

    controller = module.get<RunsController>(RunsController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
