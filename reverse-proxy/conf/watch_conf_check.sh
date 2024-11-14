#!/bin/bash

while inotifywait -e modify /opt/scripts/check_conf; do
    out=$(nginx -t 2>&1)
    if ! echo "$out" | grep -q "successful"; then
	    echo -e "1\n$out" > /opt/scripts/check_conf_status
    else
	    echo -e "0" > /opt/scripts/check_conf_status
    fi
done
