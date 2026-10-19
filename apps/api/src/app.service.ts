import { Injectable } from "@nestjs/common";
import { demoData } from "./data/demo-data";

@Injectable()
export class AppService {
  getHealth(): { status: string; } {
    return {
      status: "ok",
    };
  }

  getSbomHistory() {
    return demoData;
  }
}
