# HTTP-01 Challenge Configuration Guide

This guide explains how to configure HTTP-01 challenge modes for the ACME Certificate Lifecycle Agent.

## Overview

The HTTP-01 challenge is part of the ACME protocol where the Let's Encrypt (or other CA) server verifies domain ownership by requesting a specific token file from your web server. The agent supports two modes:

1. **Standalone** — Agent creates its own temporary HTTP server
2. **Webroot** — Agent writes token files to an existing web server's directory

---

## Configuration Location

**File:** `.env` (at project root, same level as `main.py`)

```dotenv
HTTP_CHALLENGE_MODE=standalone      # standalone | webroot
HTTP_CHALLENGE_PORT=80               # port for standalone server
WEBROOT_PATH=/var/www/html           # required if HTTP_CHALLENGE_MODE=webroot
```

---

## Setting Reference

| Environment Variable | Used in | Purpose | Default |
|---|---|---|---|
| `HTTP_CHALLENGE_MODE` | `agent/nodes/challenge.py` | Selects challenge mode: **standalone** (spin up server) or **webroot** (write files) | `standalone` |
| `HTTP_CHALLENGE_PORT` | `acme/http_challenge.py` | Port for standalone HTTP server | `80` |
| `WEBROOT_PATH` | `acme/http_challenge.py` | Root directory where agent writes `.well-known/acme-challenge/<token>` files | *(empty)* |

---

## Mode 1: Standalone (Default)

### Configuration

```dotenv
HTTP_CHALLENGE_MODE=standalone
HTTP_CHALLENGE_PORT=80
```

### How it works

1. During ACME authorization, the CA issues a challenge token
2. Agent spins up a lightweight HTTP server on the specified port (e.g., port 80)
3. CA server connects to `http://<your-domain>/.well-known/acme-challenge/<token>` and retrieves the token file
4. Server validates the token and marks the authorization as valid
5. Agent shuts down the temporary HTTP server

### When to use

- **Simple setup:** No existing web server running on port 80
- **Development/testing:** Quick renewal without coordinating with production web server
- **Dedicated renewal server:** Running renewals on an isolated machine with nothing else on port 80

### Limitations

- **Port 80 availability:** The port must be available (nothing else listening) during renewal
- **Port 80 permissions:** On Linux, non-root processes cannot bind port 80 by default (see Port 80 on Linux section below)
- **Timing:** Renewal must complete within the ACME timeout window (usually 5-30 seconds)

---

## Mode 2: Webroot

### Configuration

```dotenv
HTTP_CHALLENGE_MODE=webroot
WEBROOT_PATH=/var/www/html
```

### How it works

1. During ACME authorization, the CA issues a challenge token
2. Agent writes the token to: `<WEBROOT_PATH>/.well-known/acme-challenge/<token>`
3. CA server connects to `http://<your-domain>/.well-known/acme-challenge/<token>` and retrieves the file
4. Existing web server (nginx, Apache, etc.) serves the file from its document root
5. CA validates the token and marks the authorization as valid
6. Agent cleans up the token file

### When to use

- **Production servers:** nginx, Apache, or other web servers already running on port 80
- **Shared infrastructure:** Multiple services on the same machine
- **No permission issues:** Web server already handles port 80

### Prerequisites

1. **Web server running on port 80** (nginx, Apache, etc.)
2. **Correct `WEBROOT_PATH`:** Must point to the web server's document root
   - nginx: Usually `/var/www/html` or `/usr/share/nginx/html`
   - Apache: Usually `/var/www/html` or `/var/www`
3. **Write permissions:** The agent process must be able to write to `<WEBROOT_PATH>/.well-known/acme-challenge/`

### Verify webroot path

```bash
# Check where your web server serves files from
# For nginx
grep root /etc/nginx/nginx.conf          # or /etc/nginx/sites-enabled/*

# For Apache
grep DocumentRoot /etc/apache2/apache2.conf  # or /etc/apache2/sites-enabled/*

# Verify write permissions
touch /var/www/html/.well-known/acme-challenge/test-token
rm /var/www/html/.well-known/acme-challenge/test-token
```

---

## Port 80 on Linux

Non-root processes cannot bind ports below 1024 by default. Here are three solutions:

### Option 1: `authbind` (Recommended for standalone mode)

```bash
# Install authbind
sudo apt install authbind

# Grant permission for port 80
sudo touch /etc/authbind/byport/80
sudo chmod 500 /etc/authbind/byport/80
sudo chown $(whoami) /etc/authbind/byport/80

# Run agent with authbind
authbind --deep python main.py --once
```

### Option 2: Linux capabilities (Permanent)

```bash
# Grant the Python binary permission to bind port 80
sudo setcap 'cap_net_bind_service=+ep' $(which python3)

# Now run normally (no authbind needed)
python main.py --once
```

⚠️ **Warning:** This allows any Python process on the system to bind port 80.

### Option 3: Non-privileged port + iptables redirect

```bash
# Configure agent to use port 8080 instead
# In .env:
HTTP_CHALLENGE_PORT=8080

# Redirect port 80 → 8080 at kernel level
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Make it persistent (survive reboot)
sudo apt install iptables-persistent
sudo iptables-save > /etc/iptables/rules.v4
```

---

## Example Configurations

### Scenario 1: Simple VPS with no existing web server

```dotenv
HTTP_CHALLENGE_MODE=standalone
HTTP_CHALLENGE_PORT=80
```

✓ Agent creates temporary server during renewal
✓ No other services needed
✗ Port 80 must be free during renewal

### Scenario 2: Production server with nginx

```dotenv
HTTP_CHALLENGE_MODE=webroot
WEBROOT_PATH=/var/www/html
```

✓ Works alongside nginx
✓ No port 80 permission issues (nginx already listening)
✗ Must verify `WEBROOT_PATH` matches nginx config

### Scenario 3: Non-root user, standalone mode

```dotenv
HTTP_CHALLENGE_MODE=standalone
HTTP_CHALLENGE_PORT=8080
```

Then setup iptables redirect or use authbind (see Port 80 on Linux section)

---

## Troubleshooting

### "Permission denied" when binding port 80

**Cause:** Non-root process trying to bind port < 1024

**Solutions:**
1. Run as root (not recommended)
2. Use `authbind` (Option 1 above)
3. Use capabilities (Option 2 above)
4. Use non-privileged port + iptables (Option 3 above)

### "Connection refused" during challenge

**Cause 1:** Standalone mode, HTTP server failed to start
- Check `HTTP_CHALLENGE_PORT` is free: `sudo lsof -i :80`
- Check firewall allows port 80

**Cause 2:** Webroot mode, token file not accessible
- Verify `WEBROOT_PATH` is correct: `ls -la <WEBROOT_PATH>`
- Check write permissions: `touch <WEBROOT_PATH>/test && rm <WEBROOT_PATH>/test`
- Verify web server is running: `curl http://localhost/.well-known/acme-challenge/test`

### "Timeout waiting for challenge validation"

**Cause:** CA server cannot reach your domain on port 80

**Solutions:**
- Verify firewall allows inbound port 80: `sudo iptables -L -n | grep 80`
- Check DNS resolution: `nslookup your-domain.com`
- Test manually: `curl http://your-domain.com/.well-known/acme-challenge/test`

---

## Implementation Details

### How the agent implements these modes

**File:** `acme/http_challenge.py`

The agent has two handler classes:

```python
class StandaloneHTTPServer:
    # Spins up a lightweight HTTP server on HTTP_CHALLENGE_PORT
    # Handles /.well-known/acme-challenge/<token> requests
    # Cleans up after verification

class WebrootHTTPChallenge:
    # Writes token to WEBROOT_PATH/.well-known/acme-challenge/<token>
    # Assumes external web server serves the directory
    # Cleans up after verification
```

Selection is made in `agent/nodes/challenge.py` based on `HTTP_CHALLENGE_MODE` setting.

---

## Future Customization Reminders

After deploying this agent to your infrastructure, document these items in this file or a companion deployment guide:

### 1. Deployment Topology
- [ ] Document your specific infrastructure setup
  - Example: "Docker container + nginx reverse proxy on host"
  - Example: "Kubernetes cluster with Ingress controller"
  - Example: "Standalone VPS with Let's Encrypt"
- [ ] Diagram or describe the network layout

### 2. Chosen Solution & Rationale
- [ ] Which HTTP-01 mode did you select? (standalone | webroot)
- [ ] Why was this mode chosen for your environment?
- [ ] What were the rejected alternatives and why?
- [ ] Document any custom port assignments

### 3. Security & Access Control
- [ ] Which Linux port-80 solution was implemented? (authbind | capabilities | iptables)
- [ ] What are the file permissions on `WEBROOT_PATH`?
- [ ] Document the agent process user and its privileges
- [ ] Note any SELinux or AppArmor policies in effect

### 4. Firewall Configuration
- [ ] Document your `ufw` or `iptables` rules for port 80
  - Example: `sudo ufw allow 80/tcp`
  - Example: `sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT`
- [ ] Document any cloud provider security groups (AWS, Azure, GCP)
- [ ] Note any WAF or reverse proxy rules affecting ACME challenges
- [ ] Test inbound connectivity from outside: `curl http://your-domain.com/.well-known/acme-challenge/test`

### 5. Monitoring & Alerts
- [ ] How are HTTP-01 challenge failures detected?
- [ ] What logging/alerting is in place for renewal failures?
- [ ] Document any automated remediation steps

---

## See Also

- [ACME RFC 8555 — HTTP-01 Challenge](https://tools.ietf.org/html/rfc8555#section-8.3)
- [Let's Encrypt Challenge Types](https://letsencrypt.org/docs/challenge-types/)
- Project: `config.py` — Configuration management with Pydantic Settings
