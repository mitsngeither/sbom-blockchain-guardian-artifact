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

ENV NEXT_TELEMETRY_DISABLED=1
ENV NEST_API_URL=http://api:5006

COPY apps/web apps/web

RUN pnpm --dir apps/web build

FROM base AS runner

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=5440
ENV NEST_API_URL=http://api:5006

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/sbom-core/package.json packages/sbom-core/package.json
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/web/node_modules ./apps/web/node_modules
COPY --from=build /app/apps/web/.next ./apps/web/.next
COPY --from=build /app/apps/web/next.config.js ./apps/web/next.config.js

EXPOSE 5440

CMD ["pnpm", "--dir", "apps/web", "exec", "next", "start", "-p", "5440", "-H", "0.0.0.0"]
