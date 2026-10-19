import { Body, Controller, Get, NotFoundException, Param, Post } from '@nestjs/common';
import { IngestSbomDto } from './dto/ingest-sbom.dto';
import { VerifySbomDto } from './dto/verify-sbom.dto';
import { SbomService } from './sbom.service';

@Controller('sbom')
export class SbomController {
  constructor(private readonly sbomService: SbomService) { }

  @Get('projects')
  async getProjects() {
    return { projects: await this.sbomService.getProjects() };
  }

  @Post('ingest')
  ingestSbom(@Body() body: IngestSbomDto) {
    return this.sbomService.ingestSbom(body);
  }

  @Get('artifacts/:projectId/:version')
  async getArtifactContent(
    @Param('projectId') projectId: string,
    @Param('version') version: string,
  ) {
    const content = await this.sbomService.getArtifactContent(decodeURIComponent(projectId), decodeURIComponent(version));
    if (!content) throw new NotFoundException('SBOM artifact not found');
    return JSON.parse(content) as unknown;
  }

  @Get('history')
  getHistory() {
    return this.sbomService.getHistory();
  }

  @Get('history/:projectId')
  getHistoryByProject(@Param('projectId') projectId: string) {
    return this.sbomService.getHistory(projectId);
  }

  @Get('records/:projectId/:version')
  getRecord(
    @Param('projectId') projectId: string,
    @Param('version') version: string,
  ) {
    return this.sbomService.getRecord(projectId, version);
  }

  @Get('verify-artifact/:projectId/:version')
  verifyArtifact(
    @Param('projectId') projectId: string,
    @Param('version') version: string,
  ) {
    return this.sbomService.verifyArtifact(
      decodeURIComponent(projectId),
      decodeURIComponent(version),
    );
  }


  @Post('verify-upload')
  verifyUpload(@Body() body: VerifySbomDto) {
    return this.sbomService.verifyUpload(body);
  }

  @Get('risk-reports')
  getRiskReports() {
    return this.sbomService.getRiskReports();
  }

  @Get('risk-reports/:runId')
  getRiskReportsByRunId(@Param('runId') runId: string) {
    return this.sbomService.getRiskReportsByRunId(runId);
  }
}
