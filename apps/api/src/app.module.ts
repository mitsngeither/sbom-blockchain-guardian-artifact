import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DashboardModule } from './dashboard/dashboard.module';
import { RunsModule } from './runs/runs.module';
import { SbomModule } from './sbom/sbom.module';

@Module({
  imports: [DashboardModule, RunsModule, SbomModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
