# Proxies a server block to the web manager over the internal compose
# network. Included by every server block that serves the manager.

# Backup archives are uploaded through these listeners.
client_max_body_size 100m;

# Resolve the manager lazily through Docker's DNS, so nginx starts even
# when the web manager is not up yet.
resolver 127.0.0.11 valid=30s ipv6=off;
set $manager_upstream http://web-manager:5000;

location / {
    proxy_pass $manager_upstream;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_read_timeout 120s;
}
