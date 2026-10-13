"""Release-only validation of native process-local boundary measurements."""

from common import closed, identifier, integer, require

FIELDS = ['schema', 'scope', 'credential_lease_calls', 'write_transport_entries',
          'read_transport_entries']
MAXIMUM = (1 << 64) - 1


def snapshot(value):
    closed(value, FIELDS)
    require(value['schema'] == 'auths.gateway-execution-witness/1',
            'qualification.measure.schema')
    identifier(value['scope'], r'[0-9a-f]{32}')
    for field in FIELDS[2:]:
        # Saturation is unusable evidence; do not infer a zero delta from it.
        integer(value[field], 0, MAXIMUM - 1)
    return value


def delta(before, after):
    before, after = snapshot(before), snapshot(after)
    require(before['scope'] == after['scope'], 'qualification.measure.changed-scope')
    result = {}
    for field in FIELDS[2:]:
        require(after[field] >= before[field], 'qualification.measure.decreasing-counter')
        result[field] = after[field] - before[field]
    return result


def aggregate(pairs):
    require(type(pairs) is list and 1 <= len(pairs) <= 2,
            'qualification.measure.host-bound')
    seen, result = set(), dict.fromkeys(FIELDS[2:], 0)
    for pair in pairs:
        require(type(pair) in [tuple, list] and len(pair) == 2, 'qualification.measure.host-bound')
        before, after = pair
        measured = delta(before, after)
        require(before['scope'] not in seen, 'qualification.measure.duplicate-host')
        seen.add(before['scope'])
        for field, count in measured.items():
            result[field] += count
            integer(result[field], 0, (1 << 32) - 1)
    return result
