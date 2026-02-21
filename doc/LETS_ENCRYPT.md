# Let's Encrypt

Let's Encrypt is a free, globally trusted CA that requires no account registration fee and no EAB credentials. Set `CA_PROVIDER` and you are ready to go — the agent selects the correct directory URL and skips EAB automatically.

## Staging (recommended for testing)

Let's Encrypt staging issues certificates that are **not browser-trusted** but exercise the complete ACME flow identically to production. Use this first to validate your setup without consuming production rate-limit quota.

```dotenv
CA_PROVIDER=letsencrypt_staging
MANAGED_DOMAINS=api.example.com,shop.example.com
ANTHROPIC_API_KEY=sk-ant-...
```

```bash
python main.py --once
```

## Production

Once staging works end-to-end, switch to production with a single config change:

```dotenv
CA_PROVIDER=letsencrypt
MANAGED_DOMAINS=api.example.com,shop.example.com
ANTHROPIC_API_KEY=sk-ant-...
```

```bash
python main.py --once
```

Certificates issued in production are browser-trusted and valid for 90 days. With `RENEWAL_THRESHOLD_DAYS=30` (the default), the agent renews approximately 30 days before expiry — well inside Let's Encrypt's recommended renewal window.

## Rate limits

Let's Encrypt enforces rate limits on the production endpoint. The most relevant:

| Limit | Value |
|---|---|
| Certificates per registered domain per week | 50 |
| Duplicate certificates per week | 5 |
| Failed validations per account per domain per hour | 5 |
| New orders per account per 3 hours | 300 |

Staging has much higher (effectively unlimited) limits. Always test with `CA_PROVIDER=letsencrypt_staging` before running against production.

## Switching between staging and production

Both environments share the same account key file. However, staging accounts cannot be reused on production — delete `account.key` (or point `ACCOUNT_KEY_PATH` to a different file) when switching environments so the agent registers a fresh account.

```bash
# Switch from staging to production
rm ./account.key          # or set ACCOUNT_KEY_PATH=./account-prod.key
CA_PROVIDER=letsencrypt python main.py --once
```

## Directory URLs (set automatically)

| `CA_PROVIDER` | Directory URL |
|---|---|
| `letsencrypt` | `https://acme-v02.api.letsencrypt.org/directory` |
| `letsencrypt_staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` |

These are preset inside `LetsEncryptAcmeClient` — no manual URL configuration required.
