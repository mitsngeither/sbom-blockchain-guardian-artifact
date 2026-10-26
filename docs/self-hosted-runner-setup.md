# Self-hosted runner setup

> Actions is disabled in this public copy of the repo. This page describes how
> the workflow was set up when it ran for the paper. To run it elsewhere, set
> the `DEPLOY_DIR` variable below to your own deployment path.

The `publish-history` and `submit-chain` jobs in
`.github/workflows/sbom-blockchain-guardian.yaml` run on a self-hosted runner
(label `sbom-guardian`) because they write run history and chain receipts into
the dashboard deployment on that host.

## Register the runner

1. In the repository, go to **Settings > Actions > Runners > New self-hosted runner**.
2. Follow GitHub's generated download/config commands for your OS.
3. When prompted for labels, add: `self-hosted, linux, x64, sbom-guardian`
   (must match `runs-on:` in the workflow exactly).
4. Install as a service so it survives reboots:
   ```bash
   sudo ./svc.sh install
   sudo ./svc.sh start
   ```

## Required repository secrets

Set these under **Settings > Secrets and variables > Actions**. Never commit
any of these values to the repo. A key in git is a key that leaks, even a
throwaway testnet one.

| Secret | Purpose |
| --- | --- |
| `SEPOLIA_RPC_URL` | RPC endpoint for the Sepolia network (Alchemy/Infura) |
| `SEPOLIA_PRIVATE_KEY` | Proposer wallet, funded with Sepolia ETH |
| `CONTRACT_ADDRESS` | Deployed `SBOMRegistry` address on Sepolia |
| `REVIEWER_1_KEY` | First multisig reviewer wallet, granted `TEAM_MEMBER_ROLE` |
| `REVIEWER_2_KEY` | Second multisig reviewer wallet, granted `TEAM_MEMBER_ROLE` |

One repository **variable** (the Variables tab, not a secret):

| Variable | Purpose |
| --- | --- |
| `DEPLOY_DIR` | Absolute path of the app checkout that docker-compose bind-mounts. The self-hosted jobs copy run history and chain receipts into its `pipeline-artifacts/`, and stop early if it is not set. |

## Local development

For local/offline work without spending Sepolia ETH, the `devnet`
network points at a local Geth dev chain instead:

```bash
export DEVNET_RPC_URL=http://127.0.0.1:8545
export DEVNET_PRIVATE_KEY=<local dev key, never committed>
pnpm hardhat run scripts/deploy.ts --network devnet
```

`hardhat.config.ts` reads this key from `process.env.DEVNET_PRIVATE_KEY` at
runtime. Without it the network still resolves but has no signer.
