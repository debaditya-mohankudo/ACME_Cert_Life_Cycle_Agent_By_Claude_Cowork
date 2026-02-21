# Certificate Storage Layout

Each renewed domain gets its own subdirectory:

```
./certs/api.example.com/
├── cert.pem        # Leaf certificate (end-entity only)
├── chain.pem       # Intermediate CA chain
├── fullchain.pem   # cert.pem + chain.pem — use this in nginx/apache
├── privkey.pem     # RSA-2048 private key (mode 0o600)
└── metadata.json   # {"issued_at", "expires_at", "acme_order_url", "renewed_by"}
```

Point your web server at `fullchain.pem` and `privkey.pem`:

```nginx
ssl_certificate     /path/to/certs/api.example.com/fullchain.pem;
ssl_certificate_key /path/to/certs/api.example.com/privkey.pem;
```
