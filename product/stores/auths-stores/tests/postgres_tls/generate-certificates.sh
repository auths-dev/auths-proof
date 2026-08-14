#!/usr/bin/env bash
set -euo pipefail

output=/fixture/generated
mkdir -p "$output"
rm -f "$output/ca.crt" "$output/ca.key" "$output/server.crt" "$output/server.csr" "$output/server.key" "$output/server.ext"

openssl req -x509 -newkey rsa:3072 -nodes -days 2 \
  -subj "/CN=Auths lifecycle test CA" \
  -keyout "$output/ca.key" \
  -out "$output/ca.crt"
openssl req -newkey rsa:3072 -nodes \
  -subj "/CN=localhost" \
  -keyout "$output/server.key" \
  -out "$output/server.csr"
printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'extendedKeyUsage=serverAuth' > "$output/server.ext"
openssl x509 -req -days 2 \
  -in "$output/server.csr" \
  -CA "$output/ca.crt" \
  -CAkey "$output/ca.key" \
  -CAcreateserial \
  -extfile "$output/server.ext" \
  -out "$output/server.crt"

chown 999:999 "$output/server.crt" "$output/server.key" "$output/ca.crt"
chmod 600 "$output/server.key"
chmod 644 "$output/server.crt" "$output/ca.crt"
