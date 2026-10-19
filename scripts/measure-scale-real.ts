// Merkle timings on a real SBOM (the "Real" rows of the scale table).
// Usage: npx tsx scripts/measure-scale-real.ts [path-to-cyclonedx.json]
// Defaults to sbom1.json, this project's own SBOM (1,215 components).
// Synthetic sizes are in measure-scale.ts.

import { parseRawSBOM, buildSBOMMerkleTree, createComponentProof, verifyComponentProof } from "@guardian/sbom-core";

const file = process.argv[2] ?? "sbom1.json";
const sbom = await parseRawSBOM(file);

const t0 = performance.now();
const tree = buildSBOMMerkleTree(sbom);
const tBuild = performance.now() - t0;

// a proof for every leaf, to get proof-size stats
let min = Infinity, max = 0, sum = 0;
const t1 = performance.now();
for (const leaf of tree.leaves) {
  const p = createComponentProof(tree, leaf.key);
  const n = p.proof.length;
  min = Math.min(min, n); max = Math.max(max, n); sum += n;
}
const tAllProofs = performance.now() - t1;

// time to verify one proof (mean of 100)
const sample = createComponentProof(tree, tree.leaves[0].key);
const t2 = performance.now();
for (let i = 0; i < 100; i++) verifyComponentProof(sample);
const tVerify = (performance.now() - t2) / 100;

console.log("file:", file);
console.log("leaves:", tree.leaves.length);
console.log("log2(n):", Math.log2(tree.leaves.length).toFixed(2));
console.log("build tree (ms):", tBuild.toFixed(1));
console.log("proof hashes  min/max/avg:", min, max, (sum / tree.leaves.length).toFixed(2));
console.log("create 1 proof (ms):", (tAllProofs / tree.leaves.length).toFixed(3));
console.log("verify 1 proof (ms):", tVerify.toFixed(3));
