# Reverse Proxy Manager

A web application for managing an Nginx reverse proxy: create, edit, enable/disable, and delete proxy configurations with automatic SSL certificate generation, all through a browser UI.

## Features

- Create and manage Nginx reverse proxy configurations
- Automatic self-signed SSL certificate generation per service
- Certificate expiry badges with visual warnings (7 / 30 day thresholds)
- Enable / disable configurations without deleting them
- Clone an existing configuration as a starting point
- Live backend reachability status per service
- Access log viewer (last 50 lines) with in-page search
- Backup and restore all configurations and certificates
- Authentication: username + password, optional per-user TOTP (2FA)
- 30-day persistent sessions
- User management via web UI and CLI
- Dark theme UI

## Quick start

Use the pre-built images from GitHub Container Registry:

```yaml
# compose.yml
services:
  reverse-proxy:
    container_name: reverse-proxy
    image: ghcr.io/clubnix/rpm-rp:latest
    ports:
      - 80:80
      - 443:443
    volumes:
      - logs:/var/log/nginx
      - conf:/etc/nginx/conf.d
      - certs:/etc/nginx/certs
      - scripts:/opt/scripts
    restart: unless-stopped

  web-manager:
    container_name: web-manager
    image: ghcr.io/clubnix/rpm-web:latest
    environment:
      - SSL_COUNTRY=FR
      - SSL_STATE=France
      - SSL_CITY=Noisy-le-Grand
      - SSL_ORGANIZATION_GLOBAL=ESIEE Paris
      - SSL_ORGANIZATION_UNIT=Club*Nix
      - SSL_DAYS=365
    ports:
      - 5000:5000
    volumes:
      - logs:/app/nginx/logs
      - conf:/app/nginx/conf.d
      - certs:/app/nginx/certs
      - scripts:/app/scripts
      - ./logs:/app/logs
      - data:/app/data
    restart: unless-stopped

volumes:
  logs:
  conf:
  certs:
  scripts:
  data:
```

```bash
docker compose up -d
```

The web manager is available at [http://localhost:5000](http://localhost:5000).

On first visit you will be redirected to the setup page to create the admin account.

## Building locally

A `compose-build.yml` file is included to build both images from source:

```bash
docker compose -f compose-build.yml up -d --build
```

## Configuration

Environment variables for the `web-manager` service:

| Variable | Default | Description |
| --- | --- | --- |
| `SSL_COUNTRY` | `FR` | Country code for generated certificates |
| `SSL_STATE` | `France` | State / province |
| `SSL_CITY` | `Noisy-le-Grand` | City |
| `SSL_ORGANIZATION_GLOBAL` | `ESIEE Paris` | Organisation name |
| `SSL_ORGANIZATION_UNIT` | `Club*Nix` | Organisation unit |
| `SSL_DAYS` | `365` | Certificate validity in days |
| `FLASK_SECRET_KEY` | *(auto-generated)* | Override the Flask secret key |
| `AUTH_DB_PATH` | `/app/data/users.db` | Path to the SQLite database |

### Volumes

| Volume | Purpose |
| --- | --- |
| `logs` | Nginx access / error logs (shared with reverse-proxy) |
| `conf` | Nginx `conf.d` directory (shared with reverse-proxy) |
| `certs` | SSL certificates (shared with reverse-proxy) |
| `scripts` | Reload and validation scripts (shared with reverse-proxy) |
| `./logs` | Web manager application logs (host bind-mount) |
| `data` | Persistent data: SQLite database, Flask secret key |

## Authentication

### First run

Navigate to [http://localhost:5000](http://localhost:5000). You will be redirected to `/auth/setup` to create the first (admin) account.

### User management — web UI

The **Users** page (navbar link) lists all accounts. The admin account (first user created) can add and delete other users.

Each user can manage their own password and TOTP settings from the **Settings** dropdown in the top-right of the navbar.

### User management — CLI

Run commands inside the container:

```bash
docker exec -it web-manager python manage_users.py <command>
```

| Command | Description |
| --- | --- |
| `list` | List all users |
| `add <username>` | Create a new user (prompts for password) |
| `passwd <username>` | Change a user's password |
| `delete <username>` | Delete a user |
| `reset-totp <username>` | Disable TOTP for a user |

Example:

```bash
docker exec -it web-manager python manage_users.py add alice
docker exec -it web-manager python manage_users.py list
docker exec -it web-manager python manage_users.py reset-totp alice
```

## Releasing

Docker images are published automatically via GitHub Actions when a tag matching `v*` is pushed:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This builds and pushes `ghcr.io/clubnix/rpm-rp` and `ghcr.io/clubnix/rpm-web` with the tag and `latest`.

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
