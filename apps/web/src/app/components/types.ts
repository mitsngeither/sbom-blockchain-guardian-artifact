export type LifecycleStatus = "PENDING" | "APPROVED" | "REGISTERED" | "REJECTED" | "NOT ON CHAIN";
export type IntegrityStatus = "VERIFIED" | "UNVERIFIED" | "PENDING" | "NOT ON CHAIN";
export type PipelineStatus = "passed" | "blocked" | "failed" | "running" | "review";
export type PolicyDecision = "PASS" | "BLOCK" | "REVIEW" | "PENDING" | "FAILED";
export type OnchainStatus = "REGISTERED" | "REJECTED" | "PENDING" | "NOT SUBMITTED";
export type VerifyState =
  | "idle"
  | "processing"
  | "STRUCTURE_VALID"
  | "STRUCTURE_INVALID"
  | "ATTESTED_VALID"
  | "MISMATCH"
  | "NOT_FOUND"
  | "REVOKED";
export type FilterKey = "all" | PipelineStatus;
