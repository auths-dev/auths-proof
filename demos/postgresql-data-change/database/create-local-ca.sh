#!/bin/sh
set -eu

umask 077
if [ -s /certs/ca.crt ] && [ -s /certs/server.crt ] && [ -s /certs/server.key ]; then
  exit 0
fi

openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes \
  -subj "/CN=Auths PostgreSQL local CA" \
  -keyout /certs/ca.key \
  -out /certs/ca.crt

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj "/CN=postgres" \
  -keyout /certs/server.key \
  -out /certs/server.csr

openssl x509 -req -sha256 -days 30 \
  -in /certs/server.csr \
  -CA /certs/ca.crt \
  -CAkey /certs/ca.key \
  -CAcreateserial \
  -extfile /scripts/local-server.ext \
  -out /certs/server.crt

chown 999:999 /certs/server.crt /certs/server.key
chmod 600 /certs/server.key
chmod 644 /certs/ca.crt /certs/server.crt
rm -f /certs/server.csr /certs/ca.srl
