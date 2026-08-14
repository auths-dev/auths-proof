#!/bin/sh
set -eu
install -d -m 0700 -o postgres -g postgres /var/lib/postgresql/auths-certs
install -m 0600 -o postgres -g postgres /certs/server.key /var/lib/postgresql/auths-certs/server.key
install -m 0644 -o postgres -g postgres /certs/server.crt /var/lib/postgresql/auths-certs/server.crt
exec docker-entrypoint.sh "$@"
