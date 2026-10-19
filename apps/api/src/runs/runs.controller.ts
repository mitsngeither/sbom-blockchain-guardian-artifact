import { Controller, Get } from '@nestjs/common';
import { RunsService } from './runs.service';
``;
@Controller('runs')
export class RunsController {
  constructor(private readonly runsService: RunsService) { }

  @Get()
  getRunStatus() {
    return this.runsService.getRunStatus();
  }
}
