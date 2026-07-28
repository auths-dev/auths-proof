#!/bin/sh
set -eu

chown -R auths:auths /data
exec gosu auths:auths /usr/local/bin/auths-github-demo
