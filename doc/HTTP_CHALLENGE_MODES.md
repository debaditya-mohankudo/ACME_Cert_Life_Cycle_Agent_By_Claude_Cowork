# HTTP-01 Challenge Modes

## Standalone (default)

The agent spins up a minimal HTTP server on port 80 for the duration of each challenge. No existing web server is required. Port 80 must not already be in use during the renewal window.

## Webroot

If nginx or Apache is already serving on port 80, set:

```dotenv
HTTP_CHALLENGE_MODE=webroot
WEBROOT_PATH=/var/www/html
```

The agent writes the token file to `<WEBROOT_PATH>/.well-known/acme-challenge/<token>` and cleans it up after verification.

## Port 80 note

On Linux, non-root processes cannot bind port 80 by default. Options:

```bash
# Option 1: authbind
sudo apt install authbind
sudo touch /etc/authbind/byport/80
sudo chmod 500 /etc/authbind/byport/80
sudo chown $(whoami) /etc/authbind/byport/80
authbind --deep python main.py --once

# Option 2: grant capability to the Python binary
sudo setcap 'cap_net_bind_service=+ep' $(which python3)

# Option 3: non-privileged port + iptables redirect
HTTP_CHALLENGE_PORT=8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```
