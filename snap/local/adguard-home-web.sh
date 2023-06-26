#!/bin/sh

yaml_file="${SNAP_DATA}/AdGuardHome.yaml"

# Get the admin interface port from the configuration.
bind_port=$(grep -A 1 "http:" "$yaml_file" | grep "address:" | awk '{print $2}' | awk -F":" '{print $NF}')
readonly bind_port

if [ "$bind_port" = '' ]
then
	xdg-open 'http://localhost:3000'
else
	xdg-open "http://localhost:${bind_port}"
fi
