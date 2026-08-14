#!/bin/sh
set -eu
mkdir -p /var/lib/softhsm/tokens
printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\n' >/etc/softhsm2.conf
export SOFTHSM2_CONF=/etc/softhsm2.conf
if ! softhsm2-util --show-slots | grep -q auths-local; then
  softhsm2-util --init-token --free --label auths-local --so-pin "$AUTHS_SOFTHSM_PIN" --pin "$AUTHS_SOFTHSM_PIN"
fi
touch /var/lib/softhsm/ready
exec tail -f /dev/null
