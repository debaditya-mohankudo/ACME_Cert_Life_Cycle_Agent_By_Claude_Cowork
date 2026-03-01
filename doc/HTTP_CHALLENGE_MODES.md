# ACME Challenge Modes

> **This page is a short reference.** For the full guide — mode details, port-80 Linux solutions, scenario examples, and troubleshooting — see [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md) and [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md).

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- HTTP-01 configuration guide: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)
- HTTP-01 protocol mechanics: [HTTP_01_VALIDATION_EXPLAINED.md](HTTP_01_VALIDATION_EXPLAINED.md)
- DNS-01 implementation: [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md)

---

## HTTP-01 Challenge

**RFC 8555 § 8.3** — The CA verifies domain ownership by making an unauthenticated HTTP GET to `http://<domain>/.well-known/acme-challenge/<token>` and checking the response body exactly matches the key-authorization string (`{token}.{jwk_thumbprint}`).

### HTTP-01 Modes

| Mode | When to use |
| --- | --- |
| **Standalone** (default) | No existing web server on port 80. Agent spins up a temporary server. |
| **Webroot** | nginx/Apache already serving port 80. Agent writes the token file into the server's document root. |

**Minimal HTTP-01 configuration:**

```dotenv
# Standalone (default)
HTTP_CHALLENGE_MODE=standalone
HTTP_CHALLENGE_PORT=80

# Webroot
HTTP_CHALLENGE_MODE=webroot
WEBROOT_PATH=/var/www/html
```

For port 80 on Linux (non-root), see the `authbind`, capabilities, and iptables options in [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md#port-80-on-linux).

---

## DNS-01 Challenge

**RFC 8555 § 8.4** — The CA verifies domain ownership by checking a TXT record at `_acme-challenge.<domain>` containing the key-authorization string.

### When to use DNS-01

- Wildcard certificates (`*.example.com`)
- Domains behind restrictive firewalls (no port 80 access)
- Automated DNS updates via provider API
- Multi-domain certificates with DNS-based delegation

**Supported DNS providers:**

| Provider | Setup |
| --- | --- |
| **Cloudflare** | API token with `zone.dns_records:edit` permission |
| **Route53** (AWS) | IAM credentials with `route53:ChangeResourceRecordSets` |
| **Google Cloud DNS** | Service account with `dns.changes.create` and `dns.resourceRecordSets.list` |

**Minimal DNS-01 configuration (Cloudflare example):**

```dotenv
HTTP_CHALLENGE_MODE=dns
DNS_PROVIDER=cloudflare
CLOUDFLARE_API_TOKEN=your_token_here
```

See [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md) for provider-specific setup and additional configuration options.
