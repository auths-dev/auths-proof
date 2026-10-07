"""Release-only projection of actual native results and independent read-back.

No passed flag, expected verdict, budget consumption or HTTP success can
substitute for native execution counters or provider evidence. This helper
returns measured facts only; the native corpus runner compares them with the
source-owned case. It grants no authority and never performs provider I/O.
"""

import re

import airtable_record
import stripe_platform
from common import canonical, closed, digest, echo, integer, require, sha256, text
import fresh_evidence
import measure


REFERENCES = {reference.FAMILY: reference for reference in [stripe_platform, airtable_record]}


def result(value):
    """Decode exactly one native result, retaining every meaningful distinction."""
    require(type(value) is dict and type(value.get('outcome')) is str,
            'qualification.observation.result')
    kind = value['outcome']
    if kind in ['denied', 'indeterminate', 'not-entered']:
        closed(value, ['outcome', 'code'])
        code = text(value['code'], maximum=96)
        require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}', code) is not None,
                'qualification.observation.code')
        return 'refused', code, None
    if kind == 'unknown':
        closed(value, ['outcome'])
        return 'unknown', kind, None
    if kind == 'response-recorded':
        closed(value, ['outcome', 'status'])
        integer(value['status'], 100, 599)
        return 'response-recorded', kind, None
    if kind == 'observed':
        # Value equality alone cannot produce the linked evidence required
        # by these two reviewed families. Retain no positive effect claim.
        closed(value, ['outcome', 'status', 'matched'])
        integer(value['status'], 100, 599)
        require(type(value['matched']) is bool, 'qualification.observation.result')
        return 'response-recorded', 'unlinked-observation', None
    require(kind == 'observed-by-provider', 'qualification.observation.result')
    closed(value, ['outcome', 'status', 'evidence'])
    if value['status'] is not None:
        integer(value['status'], 100, 599)
    evidence = value['evidence']
    closed(evidence, ['channel', 'echo', 'evidence_digest', 'observed_at'])
    require(evidence['channel'] == 'read-back', 'qualification.observation.channel')
    digest(evidence['evidence_digest'])
    integer(evidence['observed_at'], 0, 253402300799)
    text(evidence['echo'], maximum=128)
    return 'observed', kind, evidence


class Effects:
    """One journey's measured entries and confirmations, keyed by exact action.

    A read-only recovery can confirm the previously measured entered write.
    Further read-backs cannot count that write again. A fresh engine scope
    still needs its own before/after measurement; native scope validation is
    never replaced by this ledger.
    """

    def __init__(self):
        self.entries = {}
        self.tuple_sha256 = None

    def project(self, tuple_value, reviewed, resources, native_result, before, after, response=None):
        tuple_sha256 = sha256(b'auths.qualification-tuple/1\0' + canonical(tuple_value))
        require(self.tuple_sha256 in [None, tuple_sha256], 'qualification.observation.changed-tuple')
        family = tuple_value['recipe_family']
        reference = REFERENCES.get(family)
        require(reference is not None, 'qualification.observation.family')
        reference.resources(resources, resources['protected_run'])
        closed(reviewed, ['schema', 'actors', 'action_commitment', 'arguments', 'request'])
        require(reviewed['schema'] == 'auths.gateway-submission-review/1'
                and type(reviewed['actors']) is list and len(reviewed['actors']) == 1,
                'qualification.observation.review')
        text(reviewed['actors'][0], maximum=1024)
        commitment = digest(reviewed['action_commitment'])
        recipe_digest = digest(tuple_value['compiled_recipe_sha256'])
        arguments = reviewed['arguments']
        expected_request = reference.request(arguments, resources, commitment, recipe_digest)
        require(reviewed['request'] == expected_request, 'qualification.observation.request')
        counted = measure.delta(before, after)
        leases = integer(counted['credential_lease_calls'], 0, (1 << 32) - 1)
        writes = integer(counted['write_transport_entries'], 0, 1)
        outcome, code, evidence = result(native_result)
        require(outcome != 'refused' or writes == 0, 'qualification.observation.refused-entry')
        key = (family, resources['protected_run'], arguments['operator_namespace'], arguments['operation_id'])
        binding = sha256(canonical({'arguments': arguments, 'action_commitment': commitment,
                                    'resources': resources, 'recipe_digest': recipe_digest}))
        prior = self.entries.get(key)
        require(writes == 0 or prior is None, 'qualification.observation.duplicate-entry')
        require(writes == 0 or len(self.entries) < 64, 'qualification.observation.entry-bound')
        require(writes == 0 or leases > 0, 'qualification.observation.entry-without-lease')
        require(outcome == 'refused' or prior is None or prior['binding'] == binding,
                'qualification.observation.changed-action')
        fresh, confirmed = None, 0
        if evidence is None:
            require(response is None, 'qualification.observation.unexpected-response')
        else:
            require(type(response) is bytes and (writes == 1 or prior is not None),
                    'qualification.observation.unmeasured-effect')
            require(native_result['status'] == 200
                    or (native_result['status'] is None and reference is airtable_record),
                    'qualification.observation.status')
            require(evidence['echo'] == echo(arguments['operator_namespace'], arguments['operation_id'], commitment),
                    'qualification.observation.echo')
            fresh = fresh_evidence.witness(family, arguments, resources, commitment, recipe_digest, response)
            require(fresh['response_sha256'] == evidence['evidence_digest'],
                    'qualification.observation.response-digest')
            confirmed = int(prior is None or not prior['confirmed'])
        # Refusals, malformed results and evidence disagreements leave the
        # ledger untouched. There is no usable projection on those failures.
        if writes == 1:
            self.entries[key] = {'binding': binding, 'confirmed': evidence is not None}
            self.tuple_sha256 = tuple_sha256
        elif evidence is not None:
            prior['confirmed'] = True
        return {'verdict': {'outcome': outcome, 'code': code,
                           'request_sha256': None if outcome == 'refused' else sha256(canonical(reviewed['request'])),
                           'evidence_sha256': None if evidence is None else evidence['evidence_digest']},
                'credential_leases': leases, 'provider_entries': writes,
                'confirmed_by_read_back': confirmed}, fresh

    def commissioning(self, tuple_value, reviewed, resources, execution, response=None):
        """Read the private command's actual final envelope, not a report flag."""
        closed(execution, ['schema', 'result', 'before', 'after'])
        require(execution['schema'] == 'auths.gateway-commissioning-execution/1',
                'qualification.observation.schema')
        return self.project(tuple_value, reviewed, resources, execution['result'],
                            execution['before'], execution['after'], response)
