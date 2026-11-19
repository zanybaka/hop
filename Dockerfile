FROM caddy:2-alpine AS caddy
FROM node:24-alpine
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
WORKDIR /app
COPY --chown=node:node src ./src
COPY --chown=node:node web ./web
ARG GIT_SHA=unknown
RUN printf '%s' "$GIT_SHA" | grep -Eq '^(unknown|[0-9a-f]{40})$' \
  && printf '{"sha":"%s"}\n' "$GIT_SHA" > web/version.json \
  && chown node:node web/version.json
COPY --chmod=0755 deploy/entrypoint.sh /usr/local/bin/hop
RUN mkdir -m 0700 /state && chown node:node /state
# Kamal сверяет эту метку с именем сервиса у заранее собранного образа.
LABEL service=hop
USER node
ENV PORT=8080 XDG_DATA_HOME=/tmp XDG_CONFIG_HOME=/tmp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hop"]
