#!/usr/bin/env bash
# Prepares the web manager's HTTPS endpoints before nginx starts:
#   - ensures its certificate exists (a self-signed pair is generated on
#     first start; replace manager.crt / manager.key in the manager-ssl
#     volume with your own, e.g. from a local PKI, to use a trusted one);
#   - when MANAGER_DOMAIN is set, writes a server block that serves the
#     manager on that domain over 443 (port 80 redirects to https).
set -euo pipefail

NGINX_DIR="${NGINX_DIR:-/etc/nginx}"
SSL_DIR="${MANAGER_SSL_DIR:-$NGINX_DIR/manager-ssl}"
CONF_DIR="${MANAGER_CONF_DIR:-$NGINX_DIR/manager.d}"
CRT="$SSL_DIR/manager.crt"
KEY="$SSL_DIR/manager.key"
HOSTNAMES="${MANAGER_HOSTNAMES:-localhost}"
DOMAINS="${MANAGER_DOMAIN:-}"

# ── MANAGER_DOMAIN (comma-separated hostnames) ────────────────────────
label='[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?'
server_names=()
IFS=',' read -ra entries <<< "$DOMAINS"
for name in "${entries[@]}"; do
    name="$(echo "$name" | tr -d '[:space:]')"
    [ -z "$name" ] && continue
    if ! [[ "$name" =~ ^$label(\.$label)*$ ]]; then
        echo "manager-ssl: MANAGER_DOMAIN entry '$name' is not a valid hostname" >&2
        exit 1
    fi
    server_names+=("$name")
done

# ── Certificate ───────────────────────────────────────────────────────
mkdir -p "$SSL_DIR"

if [ -f "$CRT" ] && [ -f "$KEY" ]; then
    :
elif [ -f "$CRT" ] || [ -f "$KEY" ]; then
    echo "manager-ssl: only one of $CRT and $KEY exists; restore the missing file or delete both to regenerate" >&2
    exit 1
else
    SAN="IP:127.0.0.1"
    IFS=',' read -ra names <<< "$HOSTNAMES"
    for name in "${names[@]}" "${server_names[@]}"; do
        name="$(echo "$name" | tr -d '[:space:]')"
        [ -z "$name" ] && continue
        if [[ "$name" =~ ^[0-9.]+$ || "$name" == *:* ]]; then
            SAN="$SAN,IP:$name"
        else
            SAN="$SAN,DNS:$name"
        fi
    done
    tmp="$(mktemp -d "$SSL_DIR/.tmp.XXXXXX")"
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
        -keyout "$tmp/manager.key" -out "$tmp/manager.crt" \
        -subj "/CN=reverse-proxy-manager" -addext "subjectAltName=$SAN" > /dev/null 2>&1
    chmod 600 "$tmp/manager.key"
    mv "$tmp/manager.key" "$KEY"
    mv "$tmp/manager.crt" "$CRT"
    rmdir "$tmp"
    echo "manager-ssl: generated a self-signed certificate ($SAN)"
fi

echo "manager-ssl: certificate SHA-256 fingerprint: $(openssl x509 -in "$CRT" -noout -fingerprint -sha256 | cut -d= -f2)"

# ── Server block for MANAGER_DOMAIN ───────────────────────────────────
mkdir -p "$CONF_DIR"
DOMAIN_CONF="$CONF_DIR/manager-domain.conf"

if [ "${#server_names[@]}" -eq 0 ]; then
    rm -f "$DOMAIN_CONF"
    exit 0
fi

cat > "$DOMAIN_CONF" <<EOF
# Generated at container start from MANAGER_DOMAIN; do not edit.
server {
    listen 80;
    server_name ${server_names[*]};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${server_names[*]};

    ssl_certificate $CRT;
    ssl_certificate_key $KEY;

    include $NGINX_DIR/manager_proxy.inc;
}
EOF
echo "manager-ssl: serving the web manager on https://${server_names[0]}/"
