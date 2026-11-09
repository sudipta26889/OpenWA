FROM docker:cli
RUN apk add --no-cache curl jq
COPY watchdog.sh /watchdog.sh
ENTRYPOINT ["sh", "/watchdog.sh"]
