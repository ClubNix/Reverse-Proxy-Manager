#!/bin/bash

while inotifywait -e modify /opt/scripts/reload_nginx; do
    nginx -s reload
done