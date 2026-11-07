#!/usr/bin/env bash
# Integration test for the reverse-proxy image: checks that nginx routes
# enabled, disabled and unknown domains correctly.
#
# Usage: reverse-proxy/tests/test_routing.sh [image]   (default: builds rpm-rp-test)
set -uo pipefail

IMAGE="${1:-}"
CONTAINER="rpm-routing-test-$$"
WORK="$(mktemp -d)"
FAILURES=0

cleanup() {
    docker rm -f "$CONTAINER" > /dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ -z "$IMAGE" ]; then
    IMAGE="rpm-rp-test"
    echo "Building $IMAGE..."
    docker build -q -t "$IMAGE" "$(dirname "$0")/.." > /dev/null || exit 1
fi

# ── Fixtures ──────────────────────────────────────────────────────────
# Mimics what the web manager writes: two enabled confs (each with its own
# certificate and the shared $connection_upgrade map) and one disabled conf.
mkdir -p "$WORK/conf.d" "$WORK/certs"
for domain in enabled.test other.test disabled.test; do
    openssl req -x509 -nodes -newkey rsa:2048 -days 1 -subj "/CN=$domain" \
        -keyout "$WORK/certs/$domain.key" -out "$WORK/certs/$domain.crt" 2> /dev/null
done

for domain in enabled.test other.test; do
    cat > "$WORK/conf.d/$domain.conf" <<EOF
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
}
server {
    listen 80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/certs/$domain.crt;
    ssl_certificate_key /etc/nginx/certs/$domain.key;
    server_name $domain;
    location / { return 200 "backend $domain"; }
}
EOF
done
mv "$WORK/conf.d/other.test.conf" "$WORK/conf.d/disabled.test.conf.disabled"
sed -i 's/other\.test/disabled.test/g' "$WORK/conf.d/disabled.test.conf.disabled"

cat > "$WORK/conf.d/disabled.unavailable" <<'EOF'
# disabled.test (disabled)
server {
    listen 80;
    listen 443 ssl;
    ssl_certificate /etc/nginx/certs/disabled.test.crt;
    ssl_certificate_key /etc/nginx/certs/disabled.test.key;
    server_name disabled.test;
    include /etc/nginx/unavailable.inc;
}
EOF
chmod -R a+rX "$WORK"

# ── Start nginx ───────────────────────────────────────────────────────
docker run -d --name "$CONTAINER" \
    -v "$WORK/conf.d:/etc/nginx/conf.d" \
    -v "$WORK/certs:/etc/nginx/certs" \
    "$IMAGE" > /dev/null || exit 1

for _ in $(seq 1 20); do
    docker exec "$CONTAINER" curl -s -o /dev/null http://localhost/health.html && break
    sleep 0.5
done

# ── Checks ────────────────────────────────────────────────────────────
pass() { echo "  ok    $1"; }
fail() { echo "  FAIL  $1"; FAILURES=$((FAILURES + 1)); }

# check <description> <expected> <actual>
check() {
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}

http_code() {   # http_code <host> <scheme> [path]
    docker exec "$CONTAINER" curl -sk -o /dev/null -w '%{http_code}' \
        --resolve "$1:80:127.0.0.1" --resolve "$1:443:127.0.0.1" "$2://$1${3:-/}"
}

body() {        # body <host> <scheme>
    docker exec "$CONTAINER" curl -sk \
        --resolve "$1:80:127.0.0.1" --resolve "$1:443:127.0.0.1" "$2://$1/"
}

cert_cn() {     # cert_cn <sni>
    docker exec "$CONTAINER" sh -c \
        "echo | openssl s_client -connect 127.0.0.1:443 -servername $1 2>/dev/null \
         | openssl x509 -noout -subject 2>/dev/null" | sed -n 's/.*CN *= *//p'
}

echo "nginx config:"
if docker exec "$CONTAINER" nginx -t > /dev/null 2>&1; then
    pass "nginx -t succeeds"
else
    fail "nginx -t succeeds"
    docker exec "$CONTAINER" nginx -t
fi

echo "Healthcheck:"
check "/health.html returns 200" 200 "$(docker exec "$CONTAINER" curl -s -o /dev/null -w '%{http_code}' http://localhost/health.html)"

echo "Enabled domain (enabled.test):"
check "http redirects to https" 301 "$(http_code enabled.test http)"
check "https reaches the backend" "backend enabled.test" "$(body enabled.test https)"
check "https serves its own certificate" enabled.test "$(cert_cn enabled.test)"

echo "Disabled domain (disabled.test):"
check "http returns 503" 503 "$(http_code disabled.test http)"
check "https returns 503" 503 "$(http_code disabled.test https)"
check "https serves its own certificate" disabled.test "$(cert_cn disabled.test)"
if body disabled.test https | grep -q 'Service unavailable'; then
    pass "shows the unavailable page"
else
    fail "shows the unavailable page"
fi

echo "Unknown domain (unknown.test):"
check "http returns 503" 503 "$(http_code unknown.test http)"
check "https returns 503" 503 "$(http_code unknown.test https)"
check "https serves the fallback certificate" unavailable "$(cert_cn unknown.test)"
if body unknown.test http | grep -q 'Service unavailable'; then
    pass "shows the unavailable page"
else
    fail "shows the unavailable page"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "All routing checks passed."
else
    echo "$FAILURES routing check(s) failed."
    exit 1
fi
