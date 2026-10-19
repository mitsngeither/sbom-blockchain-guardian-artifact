# api

NestJS backend for the dashboard. It stores SBOM files on disk, reads the
registry contract over RPC and serves pipeline run history.

## Run

From the repo root, after `pnpm install`:

```bash
pnpm --dir apps/api run start:dev
```

It listens on `BE_PORT` (default 5006). Health check: `GET /api/health`.

Settings come from the root `.env` (see `.env.example`). Without
`CONTRACT_ADDRESS` and an RPC URL it still starts, but the on-chain lookups
return nothing.

SBOMs are written under `storage/sboms/` (override with `SBOM_STORAGE_DIR`).
Three small demo projects are checked in there so the dashboard has something
to show.

## Tests

```bash
pnpm --dir apps/api run test
```
