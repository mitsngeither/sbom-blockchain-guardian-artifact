import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  parseRawSBOM,
  buildSBOMMerkleTree,
  createComponentProof,
  verifyComponentProof,
} from "@guardian/sbom-core";

// Merkle timings on synthetic SBOMs of N components (same shape as
// test/sboms/sbom-v3-axios-1.14.1.json). Only valid for Merkle scaling: names
// are shorter than real ones and the detector is not involved.
// Real SBOMs: scripts/measure-scale-real.ts.

const sizes = (process.env.SBOM_SCALE_COMPONENTS ?? "100,1000,2500,5000,10000")
  .split(",")
  .map(s => Number(s.trim()))
  .filter(n => Number.isFinite(n) && n > 0);

function genMockSbom(targetCount: number) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    components: Array.from({ length: targetCount }, (_, i) => ({
      "bom-ref": `mock-pkg-${i}@1.0.0`,
      type: "library",
      name: `mock-pkg-${i}`,
      version: "1.0.0",
      purl: `pkg:npm/mock-pkg-${i}@1.0.0`,
      hashes: [
        {
          alg: "SHA-256",
          content: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
      ],
    })),
  };
}

console.log(
  "=== [SYNTHETIC] Merkle scaling benchmark: only N varies, components carry " +
  "no real content. Not valid for detector or gas numbers. ===\n"
);
console.log("N".padStart(7), "build(ms)".padStart(11), "proof_avg(ms)".padStart(14), "verify(ms)".padStart(12), "log2(N)".padStart(9));

for (const targetCount of sizes) {
  const file = path.join(os.tmpdir(), `mock-sbom-${targetCount}.json`);
  fs.writeFileSync(file, JSON.stringify(genMockSbom(targetCount), null, 2), "utf8");

  const sbom = await parseRawSBOM(file);

  const t0 = performance.now();
  const tree = buildSBOMMerkleTree(sbom);
  const tBuild = performance.now() - t0;

  let min = Infinity, max = 0, sum = 0;
  const t1 = performance.now();
  for (const leaf of tree.leaves) {
    const p = createComponentProof(tree, leaf.key);
    const n = p.proof.length;
    min = Math.min(min, n); max = Math.max(max, n); sum += n;
  }
  const tAllProofs = performance.now() - t1;

  const sample = createComponentProof(tree, tree.leaves[0].key);
  const t2 = performance.now();
  for (let i = 0; i < 100; i++) verifyComponentProof(sample);
  const tVerify = (performance.now() - t2) / 100;

  console.log(
    String(tree.leaves.length).padStart(7),
    tBuild.toFixed(1).padStart(11),
    (tAllProofs / tree.leaves.length).toFixed(3).padStart(14),
    tVerify.toFixed(3).padStart(12),
    Math.log2(tree.leaves.length).toFixed(2).padStart(9),
    `  (proof hashes min/max: ${min}/${max})`
  );

  fs.unlinkSync(file);
}
