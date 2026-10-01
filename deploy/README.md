# Deploying a Sovereign SatsPath Authority

This guide explains how to deploy `satspathd` as a **sovereign single-domain authority** or a **multi-tenant hosted provider**.

SatsPath allows `name@yourdomain.com` to be realistically deployable without hiding the underlying security model.

## Onboarding Workflow

### 1. Initialize Operator and DNS Records

Run the CLI operator tool to generate your operator keys and output the required DNS records:

```bash
satspath server init yourdomain.com
```

Add the printed `TXT` records to your DNS provider (e.g., Cloudflare, Route53, Bind).

### 2. Verify DNS and Trust Quorum

Once DNS records propagate, verify the DNSSEC chain, operator key, and transparency log:

```bash
satspath server check yourdomain.com
```

### 3. Deploy with Docker Compose

We provide a reproducible deployment via Docker Compose. Private user keys **never** reside on the server and are generated locally by users.

Edit `deploy/docker-compose.yml` to set `SATSPATH_AUTHORITY_DOMAIN` and deploy:

```bash
docker compose -f deploy/docker-compose.yml up -d
```

### 4. Reverse Proxy TLS Example (Caddy)

We strongly recommend placing `satspathd` behind a TLS-terminating reverse proxy.

**Caddyfile example**:

```caddyfile
yourdomain.com {
    reverse_proxy localhost:9737
}
```

## Backup & Restore

- **Backup**: Backup the `satspath-data` docker volume. Backups exclude user identity private keys because those keys never reside on the server.
- **Restore**: Restoring a backup preserves the transparency `log_id`, pins, histories, and witness continuity.

## Upgrade Guidance

Upgrading `satspathd` involves updating the pinned image tag in `deploy/docker-compose.yml` to the desired release and restarting:

```bash
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d
```
