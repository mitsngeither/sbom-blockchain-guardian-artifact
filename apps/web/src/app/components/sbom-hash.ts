import { keccak256, toUtf8Bytes } from "ethers";

// Copy of the canonicalization in packages/sbom-core/src/sbom-merkle.ts.
// Importing it pulls node:crypto into the client bundle. Keep the two in sync.
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(object[key])}`)
    .join(",")}}`;
}

// Generators write a new serialNumber and metadata.timestamp on every run;
// drop them so a regenerated SBOM hashes the same.
function canonicalSbomDocument(sbomJson: string): string {
  const parsed = JSON.parse(sbomJson) as Record<string, unknown>;
  delete parsed.serialNumber;

  const metadata = parsed.metadata;
  if (metadata && typeof metadata === "object" && !Array.isArray(metadata)) {
    delete (metadata as Record<string, unknown>).timestamp;
  }

  return stableStringify(parsed);
}

/**
 * keccak256 of the canonical SBOM, same as BlockchainService#computeSbomHash.
 * Computed in the browser so verification does not depend on the server.
 */
export function computeSbomHashClientSide(sbomContent: string): string {
  return keccak256(toUtf8Bytes(canonicalSbomDocument(sbomContent)));
}
