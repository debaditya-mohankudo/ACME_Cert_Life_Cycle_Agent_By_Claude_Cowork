# HTTP-01 Challenge Modes

> **This page is a short reference.** For the full guide — mode details, port-80 Linux solutions, scenario examples, and troubleshooting — see [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md).

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Full configuration guide: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)
- Protocol mechanics: [HTTP_01_VALIDATION_EXPLAINED.md](HTTP_01_VALIDATION_EXPLAINED.md)

---

**RFC 8555 § 8.3** — The CA verifies domain ownership by making an unauthenticated HTTP GET to `http://<domain>/.well-known/acme-challenge/<token>` and checking the response body exactly matches the key-authorization string (`{token}.{jwk_thumbprint}`).

Two modes are supported:

| Mode | When to use |
|---|---|
| **Standalone** (default) | No existing web server on port 80. Agent spins up a temporary server. |
| **Webroot** | nginx/Apache already serving port 80. Agent writes the token file into the server's document root. |

Minimal configuration:

```dotenv
# Standalone (default)
HTTP_CHALLENGE_MODE=standalone
HTTP_CHALLENGE_PORT=80

# Webroot
HTTP_CHALLENGE_MODE=webroot
WEBROOT_PATH=/var/www/html
```

For port 80 on Linux (non-root), see the `authbind`, capabilities, and iptables options in [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md#port-80-on-linux).
