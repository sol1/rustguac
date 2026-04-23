# Reverse Proxy Configuration

rustguac is designed to run behind a TLS-terminating reverse proxy. The
primary supported path is **HAProxy + Knocknoc** (see
[`haproxy.example.cfg`](../haproxy.example.cfg) and
[`integrations.md`](integrations.md)), which is what sol1 runs in
production. This document covers other reverse proxies and a specific
gotcha that affects nested folder paths across several of them.

## The `%2F` gotcha

rustguac's connections tree uses URL path segments for folder names. When
a folder is nested (e.g. `Clients/Acme/Prod`), the client encodes the
internal `/` as `%2F` so the whole path fits one segment:

```
GET /api/addressbook/folders/shared/Clients%2FAcme%2FProd/subfolders
```

rustguac's router captures `Clients%2FAcme%2FProd` as a single `{folder}`
parameter and percent-decodes it inside the handler. This works correctly
when the reverse proxy passes the request URI through unchanged.

Several reverse proxies **normalise the URI** before forwarding by
default: they decode `%2F` to `/` in the path, which turns the single
segment into three. rustguac's route definition doesn't match, and you get
a 404 on every subfolder click. The top-level folders work fine because
they have no `%2F` in the URL.

If you see HTTP 404 responses from rustguac specifically for nested
subfolder operations (top-level folders work, subfolders don't), check
your reverse proxy's URI handling first. The fix per proxy is below.

## HAProxy (recommended)

Default HAProxy forwards the request URI unchanged. The shipped
`haproxy.example.cfg` doesn't rewrite paths, so it's unaffected by the
`%2F` issue. See [`integrations.md`](integrations.md) for the full
config including Knocknoc.

## nginx

**Affected by default.** nginx normalises the URI when `proxy_pass` has a
URI component (including just a trailing `/`). To preserve `%2F`, use a
`proxy_pass` URL with no path component:

```nginx
server {
    listen 443 ssl http2;
    server_name console.example.com;

    ssl_certificate     /etc/letsencrypt/live/console.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/console.example.com/privkey.pem;

    location / {
        # CRITICAL: no trailing slash or path on the upstream URL.
        # "https://localhost:8089/" would cause nginx to decode %2F to /
        # before forwarding, which breaks nested folder paths.
        proxy_pass https://localhost:8089;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support for session streams.
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Long-lived WebSocket sessions; match rustguac's session_max_duration_secs.
        proxy_read_timeout  8h;
        proxy_send_timeout  8h;
    }
}
```

Trust nginx's IP in `config.toml`:

```toml
trusted_proxies = ["127.0.0.1/32"]
```

## Caddy

Caddy's `reverse_proxy` directive forwards the raw request URI by default,
so nested folders work out of the box.

```caddyfile
console.example.com {
    reverse_proxy https://localhost:8089 {
        transport http {
            tls_insecure_skip_verify  # rustguac's self-signed loopback cert
        }
        header_up X-Real-IP       {remote_host}
        header_up X-Forwarded-For {remote_host}
    }
}
```

rustguac `config.toml`:

```toml
trusted_proxies = ["127.0.0.1/32"]
```

WebSocket support is automatic in Caddy; no extra directives needed.

## Apache (mod_proxy)

**Affected by default.** Apache's `ProxyPass` canonicalises the URI
(decodes `%2F`) unless you add `nocanon`:

```apache
<VirtualHost *:443>
    ServerName console.example.com
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/console.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/console.example.com/privkey.pem

    # The nocanon flag stops Apache from decoding %2F in the path.
    # Without it, nested folder paths 404.
    ProxyPass        / https://localhost:8089/ nocanon
    ProxyPassReverse / https://localhost:8089/

    # rustguac uses a self-signed cert on loopback.
    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off

    # WebSocket support requires mod_proxy_wstunnel and an explicit
    # ws:// upgrade rule; exact syntax depends on Apache version.
    # See https://httpd.apache.org/docs/current/mod/mod_proxy_wstunnel.html

    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

You may also need `AllowEncodedSlashes NoDecode` at the server or vhost
level on some Apache versions to stop the core URI parser rejecting `%2F`
before it reaches mod_proxy.

rustguac `config.toml`:

```toml
trusted_proxies = ["127.0.0.1/32"]
```

## Traefik

Traefik forwards the raw request URI by default, so nested folders work
without special configuration.

```yaml
# traefik dynamic config (file provider)
http:
  routers:
    rustguac:
      rule: "Host(`console.example.com`)"
      entryPoints: [websecure]
      service: rustguac
      tls:
        certResolver: letsencrypt

  services:
    rustguac:
      loadBalancer:
        servers:
          - url: "https://localhost:8089"
        serversTransport: insecure-backend

  serversTransports:
    insecure-backend:
      insecureSkipVerify: true
```

rustguac `config.toml`:

```toml
trusted_proxies = ["127.0.0.1/32"]
```

## Verifying `%2F` passes through

Once your proxy is configured, quickly confirm nested paths survive the
round-trip. From any host that can reach the proxy:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' \
    -H "Authorization: Bearer $YOUR_API_KEY" \
    'https://console.example.com/api/addressbook/folders/shared/nonexistent%2Fsub/subfolders'
```

A correctly configured proxy returns **200** (empty array from rustguac,
since the folder doesn't exist but the route matches). A broken proxy
returns **404** from axum's router (because the URL got decoded to extra
path segments along the way).

## Trusting the proxy's IP

Whichever proxy you use, set `trusted_proxies` in `config.toml` to match
the source IP your proxy connects from (usually `127.0.0.1/32` on
same-host deployments). rustguac then honours `X-Forwarded-For` from that
source, so client IPs appear correctly in audit logs, session history,
and rate-limit decisions.

```toml
trusted_proxies = ["127.0.0.1/32"]
```

Without this setting, all requests from behind the proxy appear to come
from the proxy's own IP.
