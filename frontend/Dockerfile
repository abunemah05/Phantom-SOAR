# syntax=docker/dockerfile:1
# Phantom SOAR frontend: multi-stage production build.
# next.config.js sets output: "standalone", so the runtime stage serves the
# self-contained server produced by `next build` (`node server.js`); `next start`
# is not supported with standalone output.
#
# Build argument NEXT_PUBLIC_API_URL (inlined into the browser bundle at build time):
#   empty (default)  same-origin: the browser calls /api on the page's own origin. This is what
#                    the bundled reverse proxy (deploy/caddy) expects. Recommended.
#   http://host:8000 the browser calls that API origin directly (plain local development without
#                    the proxy; the backend CORS list must then contain the page's origin).
# Never use the internal compose hostname (http://backend:8000): browsers cannot resolve it.
# Changing the value needs a rebuild: docker compose build frontend

FROM node:22.20.0-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22.20.0-alpine AS builder
WORKDIR /app
ARG NEXT_PUBLIC_API_URL=""
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN mkdir -p public && npm run build

FROM node:22.20.0-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
COPY --from=builder --chown=node:node /app/public ./public
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
# Next.js may write its runtime cache here; compose mounts a tmpfs on it so the root filesystem can be read-only.
RUN mkdir -p /app/.next/cache && chown node:node /app/.next/cache
USER node
EXPOSE 3000
CMD ["node", "server.js"]
