# sbom-blockchain-guardian

Code for the paper *Design and Evaluation of a Blockchain Architecture for SBOM
Governance in DevSecOps* (Journal of Science and Technology on Information
Security). The tag `isj-2026` marks the version the paper refers to.

The idea in one paragraph: the SBOM itself stays off chain. The pipeline hashes
it, builds a Merkle tree over its components, runs a few risk checks on the
dependencies that changed, and only if the policy gate passes does it record
`sbomHash`, `artifactHash`, `merkleRoot` and `riskScore` in the `SBOMRegistry`
contract, either through an EIP-712 signed submission or through
propose/approve/execute with N reviewers.

The contract used in the paper is on Sepolia at
`0x32010dD1A7393BA546ba2220FCb6126F160E6CB0`. An earlier version without the multisig checks (minimum
threshold, no self-approval, revoke/cancel/expiry, role re-check at execute) is
still at `0x79062d55BB1A1B16269a7FC519fC829603F2E385`; nothing in the paper relies on it.

## What's where

```
contracts/SBOMRegistry.sol   the registry contract
packages/sbom-core/          SBOM parsing, diff, canonicalization, Merkle tree
src/detector/                lifecycle-script, cooldown and typosquat checks, risk scorer
src/pipeline/                the CI pipeline steps (risk gate, submission prep, receipts)
scripts/                     deploy, submit, benchmarks, dataset/evaluation scripts
testJS/                      contract tests (Hardhat + mocha)
test/                        off-chain tests (node:test)
apps/api/                    NestJS API used by the dashboard
apps/web/                    Next.js dashboard
.github/workflows/           the CI workflow the paper describes
```

## Setup

Node 24 and pnpm 11 (the versions CI used).

```bash
pnpm install
cp .env.example .env    # only needed for anything that talks to a network
```

## Running the tests

```bash
pnpm run build          # sbom-core, contract compile, type check
pnpm test               # contract tests
pnpm run test:phase4    # off-chain tests
```

`pnpm run test:all` runs all three. None of them need a network or a key.

## Where the numbers in the paper come from

| Paper | Script | Raw output |
|---|---|---|
| Gas per operation (100 runs) | `scripts/benchmark-gas-stats.ts` | `results/gas-sepolia-v2-20261017.log` |
| End-to-end latency | `scripts/benchmark-latency.ts` | `results/latency-sepolia-v2-20261017.log` |
| Merkle cost vs. SBOM size | `scripts/measure-scale-real.ts` (real rows), `scripts/measure-scale.ts` (synthetic rows) | printed to stdout |
| `verifyComponent` view call time | `scripts/benchmark-verify-component.ts` | `results/verify-component-sepolia-v2-20261017.log` |
| RPN threshold enumeration | `scripts/calibrate-rpn-thresholds.ts` | `results/rpn-calibration-20261017.log` |
| Detector precision / recall | `scripts/evaluate-detector-ablation.ts` | printed to stdout |

The gas and latency scripts deploy a fresh contract each time, so the addresses
in those logs are not the one above. `results/README.md` says where each log
came from. Anything that runs with `--network sepolia`
needs `SEPOLIA_RPC_URL` and `SEPOLIA_PRIVATE_KEY` in `.env` and costs test ETH
(the gas benchmark also needs `REVIEWER_1_KEY` and `REVIEWER_2_KEY` as its two approvers),
except `benchmark-verify-component.ts`, which only does `eth_call`.

```bash
pnpm hardhat run scripts/benchmark-gas-stats.ts --network sepolia
pnpm hardhat run scripts/benchmark-latency.ts --network sepolia
pnpm hardhat run scripts/benchmark-verify-component.ts --network sepolia
npx tsx scripts/measure-scale-real.ts                          # sbom1.json, 1,215 components
npx tsx scripts/measure-scale-real.ts test/sboms/sbom-v2-added-axios.json   # 25 components
npx tsx scripts/measure-scale.ts
DATASET_FILE=test/fixtures/labeled-dataset-primary-eval.json npx tsx scripts/calibrate-rpn-thresholds.ts
```

### Detector dataset

The labeled corpus (400 malicious, 1,581 benign npm packages) is **not** in
this repo, because the malicious half is real malware source.

- Malicious: sampled from DataDog's
  [malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)
  by `scripts/build-frozen-holdout.ts` (set `DATASET_DIR` to the dataset's
  `samples/npm` folder).
- Benign: every package in this project's own `node_modules/.pnpm`, extracted
  by `scripts/build-representative-benign.ts`.

The paper's run used both sets merged into
`test/fixtures/labeled-dataset-primary-eval.json`:

```bash
DATASET_FILE=test/fixtures/labeled-dataset-primary-eval.json npx tsx scripts/evaluate-detector-ablation.ts
```

The paper reports the `Baseline` row (the patterns CI actually runs):
TP=22, FP=0, TN=1581, FN=378. The other rows are offline experiments that were
never wired into the pipeline.

`contracts/SBOMRegistry.sol` is left untouched, comments included, so it
matches the source that was compiled and deployed.

## CI

`.github/workflows/sbom-blockchain-guardian.yaml` is kept as it ran for the
paper, but GitHub Actions is turned off for this repository. The workflow
expects a self-hosted runner, repository secrets and some absolute paths on the
original runner host, so it would not run here as-is anyway. One test
(`test/pipeline/workflow-contract.test.ts`) reads the workflow file to check
that the approval steps are all there, which is why it lives at its usual path.
Runner setup is in `docs/self-hosted-runner-setup.md`.

## Running the dashboard

See `apps/api/README.md` and `apps/web/README.md`, or
`deploy/docker/README.md` for Docker Compose.

## License

MIT, see `LICENSE`.
