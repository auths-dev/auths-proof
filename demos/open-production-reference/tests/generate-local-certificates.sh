#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../compose" && pwd)
postgres="$root/postgres/certs"
ingress="$root/ingress/certs"
mkdir -p "$postgres" "$ingress"
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj /CN=auths-local-ca -keyout "$postgres/ca.key" -out "$postgres/ca.crt"
openssl req -newkey rsa:3072 -nodes -subj /CN=postgres -keyout "$postgres/server.key" -out "$postgres/server.csr"
printf 'subjectAltName=DNS:postgres\n' >"$postgres/server.ext"
openssl x509 -req -days 1 -in "$postgres/server.csr" -CA "$postgres/ca.crt" -CAkey "$postgres/ca.key" -CAcreateserial -out "$postgres/server.crt" -extfile "$postgres/server.ext"
openssl req -newkey rsa:3072 -nodes -subj /CN=localhost -keyout "$ingress/server.key" -out "$ingress/server.csr"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$ingress/server.ext"
openssl x509 -req -days 1 -in "$ingress/server.csr" -CA "$postgres/ca.crt" -CAkey "$postgres/ca.key" -CAcreateserial -out "$ingress/server.crt" -extfile "$ingress/server.ext"
