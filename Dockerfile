FROM caddy:2-alpine AS caddy
FROM node:24-alpine
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
WORKDIR /app
COPY --chown=node:node src ./src
COPY --chown=node:node web ./web
COPY --chmod=0755 deploy/entrypoint.sh /usr/local/bin/hop
RUN mkdir /state && chown node:node /state
USER node
ENV PORT=8080 XDG_DATA_HOME=/tmp XDG_CONFIG_HOME=/tmp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hop"]
