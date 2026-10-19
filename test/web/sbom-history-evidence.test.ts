import assert from "node:assert/strict";
import test from "node:test";

import {
  buildSbomEvidenceEntries,
  type AttestationRecord,
} from "../../apps/web/src/app/components/api-data.ts";

const record: AttestationRecord = {
  projectId: "demo-added-axios",
  projectIdHash: "demo-added-axios",
  version: "1.1.0-added-axios",
  sbomHash: "0xdcccfae15070598e0dc84c136f86a265602c248a92ba939564791cd2b3837ede",
  merkleRoot: "0x9139028f92ecf51a115c3c2052fcc95606168d6464955a0db8032f81fa04bbb4",
  submitter: "demo-added-axios",
  timestamp: "1783595016",
  riskScore: 42,
  status: "None",
};

test("SBOM history evidence rows show canonical sources for a registry artifact", () => {
  const rows = buildSbomEvidenceEntries(record, "registry");

  assert.deepEqual(rows.map(({ pkg, version, source, meaning }) => ({ pkg, version, source, meaning })), [
    {
      pkg: "SBOM hash",
      version: record.sbomHash,
      source: "Artifact Store",
      meaning: "immutable content digest",
    },
    {
      pkg: "Merkle root",
      version: record.merkleRoot,
      source: "SBOM Merkle tree",
      meaning: "component-level integrity",
    },
    {
      // Ingested artifacts carry a caller-supplied score, not a detector result.
      pkg: "Risk score",
      version: "42",
      source: "Artifact Store",
      meaning: "caller-supplied at ingest, not computed",
    },
    {
      pkg: "Attestation state",
      version: "PENDING",
      source: "Local Registry",
      meaning: "waiting for on-chain Active record",
    },
  ]);
});

test("SBOM history evidence credits the detector only for on-chain scores", () => {
  const rows = buildSbomEvidenceEntries({ ...record, status: "Active" }, "contract");
  const riskRow = rows.find((row) => row.pkg === "Risk score");

  assert.equal(riskRow?.source, "Risk Detector");
  assert.equal(riskRow?.meaning, "dependency diff + policy scoring");
});

test("SBOM history evidence renders a zero risk score as the unscored sentinel", () => {
  // 0 means nothing was analyzed; do not show it as a LOW score.
  const rows = buildSbomEvidenceEntries(
    { ...record, status: "Active", riskScore: 0 },
    "contract",
  );
  const riskRow = rows.find((row) => row.pkg === "Risk score");

  assert.equal(riskRow?.version, "—");
  assert.equal(riskRow?.meaning, "no packages were analyzed (sentinel 0)");
});

test("SBOM history evidence rows identify on-chain state when sourced from contract", () => {
  const rows = buildSbomEvidenceEntries({ ...record, status: "Active" }, "contract");

  assert.equal(rows.at(-1)?.version, "REGISTERED");
  assert.equal(rows.at(-1)?.source, "SBOMRegistry contract");
  assert.equal(rows.at(-1)?.meaning, "on-chain Active attestation");
});
