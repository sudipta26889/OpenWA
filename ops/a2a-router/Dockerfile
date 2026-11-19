# Same pinned base as OpenWA's image (Dockerfile) and the MCP OAuth gateway, so there is no extra base-image upkeep.
FROM docker.io/node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
WORKDIR /app
COPY router.mjs ./
COPY evals ./evals
# A fresh named volume inherits this ownership, so the non-root router can write its JSONL files.
RUN mkdir /data && chown node:node /data
USER node
ENV ROUTER_DATA_DIR=/data PORT=8790
EXPOSE 8790
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8790/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "router.mjs"]
