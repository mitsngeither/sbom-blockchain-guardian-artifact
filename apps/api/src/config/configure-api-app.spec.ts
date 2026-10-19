import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { SbomController } from '../sbom/sbom.controller';
import { SbomService } from '../sbom/sbom.service';
import { configureApiApp } from './configure-api-app';

describe('configureApiApp', () => {
  let app: INestApplication;
  const verifyUpload = jest.fn();

  beforeEach(async () => {
    verifyUpload.mockResolvedValue({ status: 'STRUCTURE_VALID' });

    const moduleRef = await Test.createTestingModule({
      controllers: [SbomController],
      providers: [
        {
          provide: SbomService,
          useValue: {
            getHistory: jest.fn(),
            getRecord: jest.fn(),
            verifyUpload,
            getRiskReports: jest.fn(),
            getRiskReportsByRunId: jest.fn(),
          },
        },
      ],
    }).compile();

    app = moduleRef.createNestApplication({ bodyParser: false });
    configureApiApp(app);
    await app.init();
  });

  afterEach(async () => {
    await app.close();
    verifyUpload.mockReset();
  });

  it('accepts uploaded SBOM JSON bodies larger than the Express default limit', async () => {
    const largeSbomContent = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: Array.from({ length: 5000 }, (_, index) => ({
        name: `pkg-${index}`,
        version: '1.0.0',
      })),
    });

    expect(Buffer.byteLength(largeSbomContent, 'utf8')).toBeGreaterThan(100_000);

    await request(app.getHttpServer())
      .post('/api/sbom/verify-upload')
      .send({
        projectId: 'sbom-blockchain-guardian',
        version: '1.0.0',
        sbomContent: largeSbomContent,
      })
      .expect(201);

    expect(verifyUpload).toHaveBeenCalledWith(
      expect.objectContaining({ sbomContent: largeSbomContent }),
    );
  });
});
