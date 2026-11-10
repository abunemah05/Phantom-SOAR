# syntax=docker/dockerfile:1
# Phantom SOAR frontend: multi-stage production build.
# next.config.js sets output: "standalone", so the runtime stage serves the
# self-contained server produced by `next build` (`node server.js`); `next start`
# is not supported with standalone output.

FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:20-alpine AS builder
WORKDIR /app
# NEXT_PUBLIC_* values are inlined into the browser bundle at build time, so this
# must be a URL the *browser* can reach (e.g. http://localhost:8000), not the
# internal compose hostname http://backend:8000.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN mkdir -p public && npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
COPY --from=builder --chown=node:node /app/public ./public
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
USER node
EXPOSE 3000
CMD ["node", "server.js"]
