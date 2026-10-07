#!/usr/bin/env python3
"""Actual unprivileged file/egress refusals; no credential or provider request."""

import errno
import ipaddress
import os
from pathlib import Path
import socket
import sys

from common import canonical, require
from resource_io import finish
from production_setup import APPLICATION_UID


def probe(kind, values):
    require(os.getuid() == APPLICATION_UID and kind in ['files', 'egress']
            and 1 <= len(values) <= 8
            and set(os.environ) <= {'PATH', 'LC_CTYPE', 'PYTHONNOUSERSITE'},
            'qualification.application.probe-input')
    for value in values:
        if kind == 'files':
            require(Path(value).is_absolute(), 'qualification.application.probe-input')
            try:
                fd = os.open(value, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as error:
                require(error.errno in [errno.EACCES, errno.EPERM], 'qualification.application.file-refusal-unmeasured')
            else:
                os.close(fd)
                require(False, 'qualification.application.private-file-accessible')
        else:
            address = ipaddress.ip_address(value)
            require(address.is_global, 'qualification.application.probe-input')
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                try:
                    connection.connect((str(address), 443))
                except OSError as error:
                    require(error.errno in [errno.EACCES, errno.EPERM, errno.ECONNREFUSED,
                        errno.ENETUNREACH, errno.EHOSTUNREACH], 'qualification.application.egress-refusal-unmeasured')
                else:
                    require(False, 'qualification.application.provider-reachable')
    return {'schema': 'auths.qualification-application-probe/1', 'kind': kind,
            'attempted': len(values), 'refused': len(values), 'provider_requests': 0}


if __name__ == '__main__':
    def main():
        require(len(sys.argv) >= 3, 'qualification.application.probe-input')
        sys.stdout.buffer.write(canonical(probe(sys.argv[1], sys.argv[2:])))
    finish(main)
