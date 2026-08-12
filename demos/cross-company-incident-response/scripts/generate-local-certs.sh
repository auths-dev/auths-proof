#!/usr/bin/env bash
set -euo pipefail

demo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cert_dir="${1:-$demo_dir/infrastructure/certs}"
mkdir -p "$cert_dir"

if [[ ! -f "$cert_dir/ca.key" ]]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$cert_dir/ca.key"
  openssl req -new -x509 -sha256 -key "$cert_dir/ca.key" -out "$cert_dir/ca.crt" -days 2 -subj "/CN=auths-incident-demo-local-ca"
  openssl ecparam -name prime256v1 -genkey -noout -out "$cert_dir/edgeshield-client.key"
  openssl req -new -key "$cert_dir/edgeshield-client.key" -out "$cert_dir/edgeshield-client.csr" -subj "/CN=auths-incident-demo-edgeshield-oncall"
  openssl x509 -req -sha256 -in "$cert_dir/edgeshield-client.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial -out "$cert_dir/edgeshield-client.crt" -days 2
  chmod 600 "$cert_dir"/*.key
fi

openssl x509 -in "$cert_dir/edgeshield-client.crt" -outform DER | openssl dgst -sha256 -r | awk '{print $1}'
