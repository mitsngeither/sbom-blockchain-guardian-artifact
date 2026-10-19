# web

Next.js dashboard: SBOM version history, risk evidence per run, pipeline
history, and a verify page that recomputes the SBOM hash and compares it with
the on-chain record.

## Run

Start the API first (`apps/api`), then from the repo root:

```bash
pnpm --dir apps/web run dev
```

Open http://localhost:5440. Requests to `/api/*` are proxied to
`NEST_API_URL` (default `http://localhost:5006`).
