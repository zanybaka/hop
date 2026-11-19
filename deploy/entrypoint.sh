#!/bin/sh
set -eu
: "${ACCESS_TRUSTED_PROXY_CIDRS:?Trusted ingress is required}"
: "${HOP_PUBLIC_ORIGIN:?Public origin is required}"
trusted=$(printf '%s' "$ACCESS_TRUSTED_PROXY_CIDRS" | tr ',' ' ')
case "$trusted" in *[!0-9a-fA-F:./\ ]*) exit 1;; esac
cat >/tmp/Caddyfile <<CONFIG
{
    admin off
    auto_https off
    servers {
        trusted_proxies static $trusted
        trusted_proxies_strict
        client_ip_headers X-Forwarded-For
    }
}
:${PORT:-8080} {
    header X-Robots-Tag "noindex, nofollow"
    handle /up {
        rewrite * /
        reverse_proxy 127.0.0.1:49185
    }
    handle {
        reverse_proxy 127.0.0.1:49185 {
            header_up X-Hop-Client-IP {client_ip}
        }
    }
}
CONFIG
caddy validate --config /tmp/Caddyfile
HOP_BASE_PATH= HOP_TRUST_LOOPBACK_PROXY=1 node /app/src/server.mjs /state 49185 &
exec caddy run --config /tmp/Caddyfile
