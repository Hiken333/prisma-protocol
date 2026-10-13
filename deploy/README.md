# PRISM test server (Docker on VPS)

Local test deployment — **not** wired into Anarac master/subscription.

## Requirements

- Linux VPS with Docker
- UDP port open (default **4433**)
- `docker compose` v2

## VPS deploy (recommended — no Rust build on server)

Typical layout on VPS: flat directory `/opt/prisma` with:

- `docker-compose.vps.yml`
- `.env`
- `prism-server.tar` (pre-built image)

### 1. Build image on your PC (has Docker)

From repo root (Windows, Git Bash, or Linux):

```powershell
.\installer\scripts\build-prism-server-image.ps1
```

Or manually:

```bash
cd prism/deploy
docker compose -f docker-compose.build.yml build
docker save -o prism-server.tar anarac/prism-server:test
```

### 2. Copy to VPS and start

```bash
scp prism/deploy/prism-server.tar prism/deploy/docker-compose.vps.yml prism/deploy/.env root@YOUR_VPS:/opt/prisma/
ssh root@YOUR_VPS
```

On VPS (one-time — enables internet through tunnel):

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-prism.conf
```

Deploy:

```bash
cd /opt/prisma
docker load -i prism-server.tar
docker compose -f docker-compose.vps.yml up -d
docker compose -f docker-compose.vps.yml logs | grep -E "shadow_pk|NAT MASQUERADE|forwarding disabled"
```

Copy `shadow_pk` from logs into the Windows client: **Settings → Protocol → PRISM**.

### Do NOT use `--build` on VPS unless…

`docker compose up -d --build` only works when the **full** `prism/` Rust tree is on the server and you run from `prism/deploy/` inside the repo. A flat `/opt/prisma` folder has no sources — you will get:

`resolve : lstat /opt/deploy: no such file or directory`

Use `docker-compose.vps.yml` + `prism-server.tar` instead.

## Build from source on a dev machine (inside repo)

```bash
cd prism/deploy
cp .env.example .env
# Edit .env — set PRISM_SHADOW_SK (openssl rand -hex 32)
docker compose -f docker-compose.build.yml up -d --build
docker compose -f docker-compose.build.yml logs 2>&1 | grep shadow_pk
```

## Firewall

```bash
ufw allow 4433/udp
```

For UDP 443, set `PRISM_LISTEN=0.0.0.0:443` and open `443/udp`.

## Client fields

| Field | Source |
|-------|--------|
| Server | VPS public IP |
| Port | 4433 (or your `PRISM_LISTEN` port) |
| Shadow PK | `docker compose logs` → `shadow_pk=` |
| Decoy | same as `PRISM_DECOY` (default `www.cloudflare.com`) |

## Stop

```bash
docker compose -f docker-compose.vps.yml down
```
