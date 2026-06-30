# Multi-stage build. Keeps final image small: build with full toolchain,
# then ship only the compiled app + production deps.

# ---- Build stage: install everything and compile TS -> JS ----
FROM node:20-slim AS build
WORKDIR /app

# Copy manifests first so Docker can cache the install layer.
# Like: only re-install deps when package files change, not on every code edit.
COPY package*.json ./
RUN npm ci

# Now bring in source and build. Also carry drizzle config + SQL migrations so
# the migrate stage can copy them out (drizzle-kit needs config, schema, SQL).
COPY tsconfig.json nest-cli.json drizzle.config.ts ./
COPY src ./src
COPY drizzle ./drizzle
RUN npm run build

# Keep a full node_modules copy (incl. drizzle-kit) for the migration image.
# Then prune dev deps for the slim runtime image.
RUN cp -r node_modules /tmp/node_modules_full \
 && npm prune --omit=dev

# ---- Migrate stage: runs DB migrations, then exits. Used by the K8s pre-app Job.
# Why a separate stage: the app runtime drops dev deps, but `drizzle-kit migrate`
# is a dev tool. This stage keeps the FULL deps + the SQL migration files so the
# Job can apply them. Like: the plumber's van carries tools the house doesn't keep.
FROM node:20-slim AS migrate
WORKDIR /app
ENV NODE_ENV=production
USER node
# Full deps (drizzle-kit lives here), config, schema, and the SQL files.
COPY --chown=node:node --from=build /tmp/node_modules_full ./node_modules
COPY --chown=node:node --from=build /app/package.json ./package.json
COPY --chown=node:node --from=build /app/drizzle.config.ts ./drizzle.config.ts
COPY --chown=node:node --from=build /app/drizzle ./drizzle
COPY --chown=node:node --from=build /app/src/db ./src/db
# drizzle-kit migrate is idempotent: it tracks applied migrations in a journal
# table and only runs new ones. Safe to re-run on every deploy.
CMD ["npm", "run", "db:migrate"]

# ---- Runtime stage: slim image, just run the compiled app ----
FROM node:20-slim AS runtime
WORKDIR /app

# Run as the built-in non-root user. Safer: app can't mess with the OS.
ENV NODE_ENV=production
USER node

# Bring over only the production deps and compiled output.
COPY --chown=node:node --from=build /app/node_modules ./node_modules
COPY --chown=node:node --from=build /app/dist ./dist

# Document the port the app listens on.
EXPOSE 3000

CMD ["node", "dist/main.js"]
