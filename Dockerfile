# Clearance multi-stage production image.
# Build: docker build -t clearance:local .
# Runtime expects DATABASE_URL + strong secrets (see deploy/compose).

FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.json tsconfig.base.json ./
COPY packages ./packages
COPY apps ./apps
RUN pnpm install --frozen-lockfile
COPY scripts ./scripts
COPY deploy ./deploy
COPY fixtures ./fixtures
RUN pnpm build

# Backup jobs deliberately use the official PG16 image so pg_dump matches the
# supported production server major. Build/publish this target separately:
# docker build --target backup-runtime -t clearance-backup:<version> .
FROM postgres:16-bookworm AS backup-runtime
WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates curl nodejs openssl \
  && apt-get clean \
  && find /var/lib/apt/lists -type f -delete \
  && groupadd --system --gid 10001 clearance \
  && useradd --system --uid 10001 --gid clearance --home-dir /app --shell /usr/sbin/nologin clearance \
  && mkdir -p /backups \
  && chown clearance:clearance /app /backups
COPY --chown=clearance:clearance --chmod=755 scripts ./scripts
USER clearance
ENTRYPOINT []
CMD ["bash", "scripts/backup-scheduled.sh", "--dir", "/backups"]

# The API performs authenticated backup and restore workflows, so its runtime
# needs the PostgreSQL 16 client matching the supported server. Copy Node 22
# from the build image into the official PG16 base instead of installing the
# older Debian Node/Postgres clients.
FROM postgres:16-bookworm AS runtime
WORKDIR /app
COPY --from=build /usr/local /usr/local
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates tini \
  && apt-get clean \
  && find /var/lib/apt/lists -type f -delete \
  && corepack enable \
  && groupadd --system --gid 10001 clearance \
  && useradd --system --uid 10001 --gid clearance --home-dir /app --shell /usr/sbin/nologin clearance \
  && mkdir -p /backups \
  && chown clearance:clearance /backups

ENV NODE_ENV=production \
    npm_config_update_notifier=false

# Full monorepo runtime layout (services select entrypoints via compose/command).
COPY --from=build --chown=clearance:clearance /app /app

USER clearance

EXPOSE 3000 3100 3200

ENTRYPOINT ["/usr/bin/tini", "--"]

# Generic process liveness: entrypoints override this via compose healthchecks.
# Exits 0 when node can run; service-specific checks live in docker-compose.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "process.exit(0)"]

# Default to management API; compose overrides command per service.
CMD ["node", "packages/clearance-api/dist/server.js"]
