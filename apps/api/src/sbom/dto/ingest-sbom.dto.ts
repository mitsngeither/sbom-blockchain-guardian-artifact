export class IngestSbomDto {
  projectId!: string;
  version!: string;
  sbomContent!: string;
  repo?: string;
  branch?: string;
  commit?: string;
  txHash?: string;
  riskScore?: number;
}
