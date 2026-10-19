# Results

Raw output behind the numbers in the paper.

| File | Paper | Produced by | When / where |
|---|---|---|---|
| `gas-sepolia-v2-20261017.log` | gas table, gas figures in the text | `scripts/benchmark-gas-stats.ts` | 2026-10-16/17, Sepolia blocks 11930128–11930861, 100 runs per operation |
| `latency-sepolia-v2-20261017.log` | latency table | `scripts/benchmark-latency.ts` | 2026-10-17, Sepolia |
| `verify-component-sepolia-v2-20261017.log` | `verifyComponent` / `verifySBOM` view-call times | `scripts/benchmark-verify-component.ts` | 2026-10-17, Sepolia, CI record `1.0.0+9028fbd.38974146992-1` |
| `sbom-ci-38974146992.json` | input of the `verifyComponent` run | CI run 38974146992 (`pnpm sbom`) | its Merkle root equals the on-chain `merkleRoot` of that record |
| `rpn-calibration-20261017.log` | detector calibration (Section V) | `scripts/calibrate-rpn-thresholds.ts` | see below |
| `v1/` | not used by the paper | same scripts | August 2026 runs against the first contract version |

The registry used by CI is `0x32010dD1A7393BA546ba2220FCb6126F160E6CB0`. The gas
and latency benchmarks deploy their own copy of `SBOMRegistry` first, so their
logs show other addresses (`0x5C8D…3851`, `0xD83c…5539`). All three run the
same code: their on-chain bytecode, immutables masked, matches
`contracts/SBOMRegistry.sol` as compiled here, metadata hash included.

The gas run uses three keys: the deployer proposes and executes, and two
different reviewer keys approve. This is the N=2 setup CI uses. The `RAW`
section of the gas log lists every per-run `gasUsed` value.

Sepolia changed its gas schedule at block 11,856,337 (2026-10-06). Since then,
writing a new storage slot costs about 110,900 gas instead of about 22,300. That
is why these gas numbers are roughly four times the ones in `v1/`. For example,
the same `registerSBOM` call on the v1 benchmark contract
(`0x23e493FAaB41152a698eF1Cecf3688842cB0b17C`) estimates at 192,275 gas just
before that block and 806,955 gas after it.

The first registry version (`0x79062d55BB1A1B16269a7FC519fC829603F2E385`) is
still on chain. It let a proposer choose the approval threshold and approve its
own proposal, which is why it was replaced.

The calibration log is a re-run made on 2026-10-17, after the script's output
was switched from Vietnamese to English. It used the same dataset as the
original 2026-08-24 run, and every number in it is identical to that run.

Not here: Merkle scaling (`scripts/measure-scale-real.ts`,
`scripts/measure-scale.ts`) and detector precision/recall
(`scripts/evaluate-detector-ablation.ts`) print to stdout; see the main README
for how to run them.
