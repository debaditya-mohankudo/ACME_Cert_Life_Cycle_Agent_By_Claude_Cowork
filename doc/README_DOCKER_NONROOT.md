# Running the Container as Non-Root

## What changed

The production image runs as **UID 1001** (`acme` system user), not root.
Two files were modified:

| File | Change |
|---|---|
| [`Dockerfile`](../Dockerfile) | `useradd -r -u 1001`; `chown -R 1001 /data`; `USER 1001` |
| [`docker-compose.yml`](../docker-compose.yml) | `cap_add: [NET_BIND_SERVICE]`; `cap_drop: [ALL]`; `security_opt: no-new-privileges:true` |

## Why NET_BIND_SERVICE instead of running as root

Linux prevents unprivileged processes (UID ≠ 0) from binding ports below 1024.
The HTTP-01 standalone challenge server must bind port 80 because the ACME CA
always validates against port 80 on the domain.

`NET_BIND_SERVICE` is the single Linux capability that grants port-80 binding
to a non-root process. Granting it in `docker-compose.yml` (`cap_add`) rather
than embedding `setcap` in the image keeps the binary unmodified and scopes the
privilege to this specific container run.

## Capability surface

```yaml
cap_add:
  - NET_BIND_SERVICE   # bind ports < 1024
cap_drop:
  - ALL                # drops all 37+ default capabilities
security_opt:
  - no-new-privileges:true   # process can never re-elevate via setuid/execve
```

After `cap_drop: ALL` + `cap_add: NET_BIND_SERVICE`, the container retains
exactly one capability. `no-new-privileges` ensures a compromised process cannot
regain dropped capabilities by executing a setuid binary.

## Volume ownership

`/data` is created and `chown`'d to UID 1001 **at image build time** (while still
root, before `USER 1001`). This means the named volume mount point is writable on
first run without a separate `docker-compose` entrypoint script:

```dockerfile
RUN useradd -r -u 1001 -M -s /sbin/nologin acme \
    && mkdir -p /data/certs \
    && chown -R 1001 /data

USER 1001
```

## DNS-01 and webroot modes

When `HTTP_CHALLENGE_MODE=dns` or `HTTP_CHALLENGE_MODE=webroot`, port 80 is
never bound by the agent. `NET_BIND_SERVICE` is harmless in those modes — it
grants a permission that is never exercised.

## Verifying at runtime

```bash
docker compose run --rm acme-agent id
# uid=1001(acme) gid=1001(acme) groups=1001(acme)

docker compose run --rm acme-agent python -c \
  "import socket; s=socket.socket(); s.bind(('',80)); print('port 80 OK')"
# port 80 OK
```
