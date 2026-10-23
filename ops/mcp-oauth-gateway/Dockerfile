# Same pinned base as OpenWA's image (Dockerfile), so the gateway needs no extra base-image upkeep.
FROM docker.io/node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
WORKDIR /app
COPY gateway.mjs ./
# A fresh named volume inherits this ownership, so the non-root gateway can write its state.
RUN mkdir /data && chown node:node /data
USER node
ENV STATE_DIR=/data PORT=2785
EXPOSE 2785
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:2785/.well-known/oauth-protected-resource').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "gateway.mjs"]
