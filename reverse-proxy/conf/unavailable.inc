# Shared "service unavailable" response (included inside a server block)

access_log off;
root $NGINX_DIR/unavailable;

error_page 503 /unavailable.html;

location = /unavailable.html {
    internal;
    add_header Cache-Control "no-store" always;
    add_header Retry-After "300" always;
}

location / {
    return 503;
}
