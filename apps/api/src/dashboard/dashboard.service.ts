import { Injectable } from '@nestjs/common';
import { demoData } from '../data/demo-data';

@Injectable()
export class DashboardService {
  // Demo data only. The web app calls this only when there are no real SBOMs yet.
  getDashboard() {
    return demoData;
  }
}
