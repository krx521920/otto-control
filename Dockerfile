FROM node:22.23.1-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22.23.1-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

RUN apk add --no-cache su-exec \
  && mkdir -p /run/otto-runtime-secrets \
  && chown node:node /run/otto-runtime-secrets \
  && chmod 0700 /run/otto-runtime-secrets

COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chmod=0755 deploy/control-entrypoint.sh /usr/local/bin/otto-control-entrypoint

USER root
EXPOSE 7788
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD su-exec node node -e "fetch('http://127.0.0.1:7788/health/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
ENTRYPOINT ["/usr/local/bin/otto-control-entrypoint"]
CMD ["node", "dist/server.js"]
