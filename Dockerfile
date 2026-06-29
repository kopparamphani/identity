# Multi-stage build. Keeps final image small: build with full toolchain,
# then ship only the compiled app + production deps.

# ---- Build stage: install everything and compile TS -> JS ----
FROM node:20-slim AS build
WORKDIR /app

# Copy manifests first so Docker can cache the install layer.
# Like: only re-install deps when package files change, not on every code edit.
COPY package*.json ./
RUN npm ci

# Now bring in source and build.
COPY tsconfig.json nest-cli.json ./
COPY src ./src
RUN npm run build

# Drop dev deps so we only carry what runtime needs into the next stage.
RUN npm prune --omit=dev

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
