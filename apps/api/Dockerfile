FROM node:24-bookworm-slim AS base

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"

RUN corepack enable && corepack prepare pnpm@11.1.3 --activate

WORKDIR /app

FROM base AS deps

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/sbom-core/package.json packages/sbom-core/package.json

RUN pnpm install --frozen-lockfile --ignore-scripts --prefer-offline

FROM deps AS build

COPY packages/sbom-core packages/sbom-core
COPY apps/api apps/api

RUN pnpm --filter @guardian/sbom-core build
RUN pnpm --filter api build

FROM base AS runner

ENV NODE_ENV=production
ENV BE_PORT=5006
ENV SBOM_STORAGE_DIR=/app/apps/api/storage/sboms

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/sbom-core/package.json packages/sbom-core/package.json
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/api/node_modules ./apps/api/node_modules
COPY --from=build /app/packages/sbom-core/dist ./packages/sbom-core/dist
COPY --from=build /app/apps/api/dist ./apps/api/dist

EXPOSE 5006

CMD ["pnpm", "--filter", "api", "start:prod"]
