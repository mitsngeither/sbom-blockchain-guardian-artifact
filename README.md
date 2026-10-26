# sbom-blockchain-guardian

Code for the paper *Design and Evaluation of a Blockchain Architecture for SBOM Governance in DevSecOps* (Journal of Science and Technology on Information Security, 2026). The tag `isj-2026` marks the exact version the paper refers to.


## Overview

The SBOM itself stays off-chain. On each run, the CI pipeline hashes the components, builds a Merkle tree and runs risk checks on the dependencies that changed. If the policy gate passes, it writes `sbomHash`, `artifactHash`, `merkleRoot` and `riskScore` to the `SBOMRegistry` contract, either as an EIP-712 signed submission or through a propose/approve/execute flow that needs N reviewers.

The contract used in the paper is deployed on Sepolia at [`0x32010dD1A7393BA546ba2220FCb6126F160E6CB0`](https://sepolia.etherscan.io/address/0x32010dD1A7393BA546ba2220FCb6126F160E6CB0). It was compiled with solc 0.8.28 using the default Hardhat profile (optimizer off). Its on-chain bytecode matches `contracts/SBOMRegistry.sol` as compiled in this repository, metadata hash included (see `results/README.md`).

An earlier version without the multisig safeguards (minimum threshold, no self-approval, revoke/cancel/expiry, role re-check at execution) is still deployed at [`0x79062d55BB1A1B16269a7FC519fC829603F2E385`](https://sepolia.etherscan.io/address/0x79062d55BB1A1B16269a7FC519fC829603F2E385). None of the results in the paper come from it.

`contracts/SBOMRegistry.sol` is kept exactly as compiled and deployed, comments included, so it matches the on-chain code.

## Repository structure

```text
contracts/SBOMRegistry.sol   the registry contract
packages/sbom-core/          SBOM parsing, diff, canonicalization, Merkle tree
src/detector/                lifecycle-script, cooldown and typosquat checks, risk scorer
src/pipeline/                the CI pipeline steps (risk gate, submission prep, receipts)
scripts/                     deploy, submit, benchmarks, dataset/evaluation scripts
testJS/                      contract tests (Hardhat + mocha)
test/                        off-chain tests (node:test)
apps/api/                    NestJS API used by the dashboard
apps/web/                    Next.js dashboard
.github/workflows/           the CI workflow described in the paper
```

## Setup

You need Node 24 and pnpm 11 (the versions used in CI).

```bash
pnpm install
cp .env.example .env    # only needed for scripts that talk to Sepolia
```

Scripts run with `--network sepolia` read these variables from `.env` and need some Sepolia test ETH for gas:

- `SEPOLIA_RPC_URL`: Sepolia RPC endpoint
- `SEPOLIA_PRIVATE_KEY`: deployer/submitter key
- `REVIEWER_1_KEY`, `REVIEWER_2_KEY`: the two multisig reviewers (only the gas benchmark uses them)

Use throwaway accounts that hold nothing but test ETH. Never put a key that controls real funds in `.env`.

## Tests

```bash
pnpm run build          # build sbom-core, compile the contract, type-check
pnpm test               # contract tests (testJS/)
pnpm run test:phase4    # off-chain tests (test/): detector, pipeline, sbom-core
```

`pnpm run test:all` runs all three. The tests need no RPC endpoint and no private keys. The first build downloads the Solidity compiler, so it needs internet access once.

## Reproducing the results

Each metric in the paper's evaluation comes from one script:

| Metric in the paper | Script | Raw output |
|---|---|---|
| Gas per operation (100 runs) | `scripts/benchmark-gas-stats.ts` | `results/gas-sepolia-v2-20261017.log` |
| End-to-end latency | `scripts/benchmark-latency.ts` | `results/latency-sepolia-v2-20261017.log` |
| Merkle cost vs. SBOM size | `scripts/measure-scale-real.ts` (real SBOMs), `scripts/measure-scale.ts` (synthetic) | stdout |
| `verifyComponent` call time | `scripts/benchmark-verify-component.ts` | `results/verify-component-sepolia-v2-20261017.log` |
| RPN threshold enumeration | `scripts/calibrate-rpn-thresholds.ts` | `results/rpn-calibration-20261017.log` |
| Detector precision / recall | `scripts/evaluate-detector-ablation.ts` | stdout |

```bash
pnpm hardhat run scripts/benchmark-gas-stats.ts --network sepolia
pnpm hardhat run scripts/benchmark-latency.ts --network sepolia
pnpm hardhat run scripts/benchmark-verify-component.ts --network sepolia

pnpm exec tsx scripts/measure-scale-real.ts                                      # sbom1.json, 1,215 components
pnpm exec tsx scripts/measure-scale-real.ts test/sboms/sbom-v2-added-axios.json  # 25 components
pnpm exec tsx scripts/measure-scale.ts

DATASET_FILE=test/fixtures/labeled-dataset-primary-eval.json pnpm exec tsx scripts/calibrate-rpn-thresholds.ts
```

The gas and latency scripts deploy a fresh contract on every run, so the addresses in their logs differ from the one in the Overview. `benchmark-verify-component.ts` only makes `eth_call` requests and costs no gas. `results/README.md` explains where each log came from.

The `VAR=value command` syntax above works in bash/zsh. On Windows, set the variable separately.

### Detector dataset

The labeled set (400 malicious and 1,581 benign npm packages) is not in this repository, because the malicious part contains live malware.

- Malicious: sampled from DataDog's [malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) with `scripts/build-frozen-holdout.ts`. Point `DATASET_DIR` at the dataset's `samples/npm` directory. The script uses seed 90210 unless `SEED` is set. It also skips any package named in `test/fixtures/labeled-dataset.json` (the earlier development set, not publishh sets were merged into `test/fixtures/labeled-dataset-primary-eval.json` for bash
DATASET_FILE=test/fixtures/labeled-dataset-primary-eval.json pnpm exec tsx scripts/evaluate-detector-ablation.ts
```

The paper reports the `Baseline` row, which is the rule set CI actually runs: TP=22, FP=0, TN=1581, FN=378 (precision 1.00, recall 0.055). The other rows are offline experiments and are not part of the pipeline.

## CI workflow

The workflow in `.github/workflows/sbom-blockchain-guardian.yaml` is kept exactly as it was during the evaluation, but GitHub Actions is turned off for this repository. The workflow needs a self-hosted runner, repository secrets and absolute paths from the original runner host, so it won't run as-is on GitHub-hosted runners.

The file has to stay at that path because `test/pipeline/workflow-contract.test.ts` parses it to check that the approval steps are present. Runner setup is described in `docs/self-hosted-runner-setup.md`.

## Dashboard

See `apps/api/README.md` and `apps/web/README.md`, or `deploy/docker/README.md` to run everything with Docker Compose.

## License

MIT, see `LICENSE
