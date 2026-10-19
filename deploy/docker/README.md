# Docker deployment

Docker Compose setup for the dashboard. It runs two containers:

- `api`: NestJS API on port `5006`
- `web`: Next.js Guardian Console on port `5440`

The blockchain node and the CI runner are not part of it.

## Build and start

```bash
docker compose build
docker compose up -d
# Restart only the web service after changing the web image:
# docker compose up -d --build web
docker compose ps
```

Open:

- Web console: <http://localhost:5440>
- API health: <http://localhost:5006/api/health>

## Blockchain environment

Compose picks up `RPC_URL` / `SEPOLIA_RPC_URL`, `CONTRACT_ADDRESS`, `PROJECT_ID`
and `CHAIN_NAME` from the environment or from a `.env` next to
`docker-compose.yml`. To point it at the Sepolia registry from the paper:

```bash
export SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/<your-key>
export CONTRACT_ADDRESS=0x32010dD1A7393BA546ba2220FCb6126F160E6CB0
export CHAIN_NAME=Sepolia
docker compose up -d
```

For a local Geth chain set `RPC_URL` and leave `SEPOLIA_RPC_URL` unset (it takes precedence).

If the node runs on the same machine, `127.0.0.1` inside the container is the container, not the host. Use `http://host.docker.internal:8545` (Compose already maps it) or the host's LAN IP.

## Persistent artifacts

SBOM artifacts and local registry metadata are mounted at:

```text
./apps/api/storage:/app/apps/api/storage
```

Fine for a demo. A real deployment would want a database and object storage instead.

## Stop

```bash
docker compose down
```
