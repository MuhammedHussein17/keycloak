# Keycloak local research environment

Reproducible setup for Keycloak vulnerability/security research on Windows 10
+ Docker Desktop. The instance runs in Docker; the upstream source tree is
cloned alongside it for code reading and patch comparison.

## Versions pinned in this setup

| Component                       | Value                                                            |
|---------------------------------|------------------------------------------------------------------|
| Host OS                         | Windows 10 Pro 10.0.19045                                        |
| Docker                          | 29.2.0 (Docker Desktop, WSL2 backend)                            |
| Git                             | 2.52.0.windows.1                                                 |
| Keycloak server image           | `quay.io/keycloak/keycloak:26.0` (digest `sha256:09a381c715ab...`) |
| Keycloak server version (kc.sh) | 26.0.8                                                           |
| Quarkus inside image            | 3.15.1                                                           |
| JVM inside image                | OpenJDK 21.0.6 (Red Hat)                                         |
| Source tree commit              | `a9d523b0cdc1e8b75decd2113b851408f3dfde70` (origin/main)         |
| Run mode                        | `start-dev` (development; not production-hardened)               |
| Database                        | Embedded H2 (dev mode default)                                   |

## Layout

```
C:\Users\UPDATE\Desktop\Projects\vulnerabilities\Keycloak\
├── SETUP.md         (this file)
└── keycloak\        (upstream source tree, shallow clone of main)
```

## Prerequisites verified before setup

- `docker info` returned a healthy daemon (Docker Desktop, WSL2 context).
- Ports `8080` and `9000` were not in use.
- Java/Maven are NOT installed on the host. The image ships its own JDK, so
  building from source is not required for running the server. Source is for
  reading only.

## Step 1 — Clone the upstream source

Windows path-length limit causes `git clone` to abort during checkout on this
repo. Enable long-path support, then clone shallow.

```bash
# In the project root
git clone --depth 1 https://github.com/keycloak/keycloak.git
cd keycloak
git config core.longpaths true
git reset --hard HEAD     # complete the checkout that the initial clone aborted
```

Verify:
```bash
git log -1 --format="%H %ci %s"
# a9d523b0cdc1e8b75decd2113b851408f3dfde70 2026-05-07 16:38:41 +0200 ...
```

> If `core.longpaths` is not set, the clone reports
> `error: unable to create file ... Filename too long` and `fatal: unable to
> checkout working tree`. The fetched objects are still valid — `git config
> core.longpaths true && git reset --hard HEAD` recovers without re-cloning.

## Step 2 — Pull the server image

The canonical image is on `quay.io`. During this setup quay.io's manifest
endpoint was returning intermittent **502 Bad Gateway** responses. Google's
public mirror at `mirror.gcr.io` serves the same content and was used as
fallback.

```bash
# Primary (preferred when quay.io is healthy)
docker pull quay.io/keycloak/keycloak:26.0

# Fallback if quay.io returns 502 — same image, mirrored
docker pull mirror.gcr.io/keycloak/keycloak:26.0
docker tag  mirror.gcr.io/keycloak/keycloak:26.0 quay.io/keycloak/keycloak:26.0
```

Resolved digest: `sha256:09a381c715ab0b111835b70f2905955274843a219c6f27efb348e4d9f4086858`

## Step 3 — Run the container

```bash
docker run -d --name keycloak-dev \
  -p 8080:8080 -p 9000:9000 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.0 start-dev
```

- `8080` — HTTP (admin console + realm endpoints).
- `9000` — management interface (health, metrics) when enabled.
- `start-dev` enables the dev profile: HTTP-only, embedded H2, hot config.
  **Do not expose this beyond localhost.**

### Bootstrap admin

Keycloak 26 requires a bootstrap admin via env vars (legacy
`KEYCLOAK_ADMIN`/`KEYCLOAK_ADMIN_PASSWORD` are deprecated). The container
log line `KC-SERVICES0077: Created temporary admin user with username admin`
confirms it.

Credentials for this environment:

| Field    | Value   |
|----------|---------|
| Username | `admin` |
| Password | `admin` |

Rotate before any non-local exposure.

## Step 4 — Verify the running instance

```bash
# Version reported by the binary inside the container
# (MSYS_NO_PATHCONV=1 prevents Git Bash from rewriting the absolute path)
MSYS_NO_PATHCONV=1 docker exec keycloak-dev /opt/keycloak/bin/kc.sh --version
#   Keycloak 26.0.8
#   JVM: 21.0.6 (Red Hat, Inc. OpenJDK 64-Bit Server VM 21.0.6+7-LTS)
#   OS:  Linux 6.6.87.2-microsoft-standard-WSL2 amd64

# Admin console redirect
curl -sI http://localhost:8080/
#   HTTP/1.1 302 Found
#   Location: http://localhost:8080/admin/

# OIDC discovery on the master realm
curl -s http://localhost:8080/realms/master/.well-known/openid-configuration
#   {"issuer":"http://localhost:8080/realms/master", ...}
```

Admin console URL: <http://localhost:8080/admin/>

## Lifecycle commands

```bash
docker logs -f keycloak-dev          # stream logs
docker stop keycloak-dev             # stop
docker start keycloak-dev            # resume
docker rm -f keycloak-dev            # remove (loses H2 data)
```

State is in the container's writable layer — removing the container wipes the
realm/user database. For research that needs persistent state, mount a volume
at `/opt/keycloak/data`.

## Known gotchas captured during setup

1. **Long file paths on Windows** — clone aborts mid-checkout without
   `core.longpaths=true`. Recover with `git reset --hard HEAD`.
2. **quay.io 502s** — manifest endpoint flapped during this setup. The GCR
   mirror (`mirror.gcr.io/keycloak/keycloak`) is the documented fallback.
3. **Git Bash path conversion** — `docker exec keycloak-dev /opt/...` rewrites
   the absolute Linux path to a Windows path. Prefix the command with
   `MSYS_NO_PATHCONV=1` (or use a leading `//opt/...`).
4. **`start-dev` is not production** — HTTP only, ephemeral H2, dev profile
   warnings in the log. Fine for local research, never for any deployment.
