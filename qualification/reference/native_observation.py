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


def interrupted_state(tuple_value, reviewed, trusted_context_sha256, support):
    """Authenticate a killed owner's durable native Unknown diagnostic.

    The owner did not return a submit result. This is a distinct source of
    evidence: the native store projects its durable Attempting record to
    Unknown, for the exact operation key and installed tuple.
    """
    closed(support, ['schema', 'gateway_package', 'gateway_version', 'semantic_closure_sha256',
        'build_sha256', 'recipe_sha256', 'profile_lock_sha256', 'trusted_context_sha256',
        'deployment', 'credential_store_kind', 'qualification', 'connection', 'attempts', 'codes'])
    target = tuple_value['target']
    require(support['schema'] == 'auths.gateway-support-bundle/1'
            and support['gateway_package'] == target['gateway_package']
            and support['gateway_version'] == target['gateway_version']
            and support['semantic_closure_sha256'] == tuple_value['gateway_semantic_closure_sha256']
            and support['build_sha256'] == target['gateway_build_sha256']
            and support['recipe_sha256'] == tuple_value['compiled_recipe_sha256']
            and support['profile_lock_sha256'] == tuple_value['profile_lock_sha256']
            and support['trusted_context_sha256'] == digest(trusted_context_sha256)
            and support['deployment'] == 'production'
            and support['credential_store_kind'] == target['credential_store_kind']
            and target['store_kind'] == 'postgresql-v1'
            and target['store_schema'] == 'auths.lifecycle.postgresql/6'
            and target['credential_store_kind'] == 'aws-secrets-manager-v1',
            'qualification.observation.interrupted-tuple')
    qualification = support['qualification']
    closed(qualification, ['policy', 'state', 'code'])
    require(qualification['policy'] == 'required'
            and qualification['state'] in ['unqualified', 'candidate', 'qualified', 'stale', 'revoked']
            and (qualification['code'] is None or type(qualification['code']) is str),
            'qualification.observation.interrupted-qualification')
    expected_codes = [] if qualification['code'] is None else [qualification['code']]
    if support['connection'] is None:
        expected_codes += ['gateway.support.connection-unavailable']
    else:
        closed(support['connection'], ['state', 'generation', 'credential_generation', 'credential_held', 'in_flight'])
        require(support['connection']['state'] == 'active'
                and type(support['connection']['credential_held']) is bool,
                'qualification.observation.interrupted-connection')
        for field in ['generation', 'credential_generation', 'in_flight']:
            integer(support['connection'][field], 0, measure.MAXIMUM - 1)
    require(support['codes'] == expected_codes, 'qualification.observation.interrupted-unavailable')
    attempts = support['attempts']
    closed(attempts, ['listed', 'truncated', 'by_stage', 'identifiers'])
    integer(attempts['listed'], 1, 256)
    require(attempts['truncated'] is False and type(attempts['identifiers']) is list
            and len(attempts['identifiers']) == attempts['listed'],
            'qualification.observation.interrupted-attempts')
    stages, keys = {}, set()
    for item in attempts['identifiers']:
        closed(item, ['key_sha256', 'stage'])
        digest(item['key_sha256'])
        require(item['key_sha256'] not in keys and item['stage'] in ['not-entered', 'unknown',
                'response-recorded', 'observed', 'observed-by-provider'],
                'qualification.observation.interrupted-attempts')
        keys.add(item['key_sha256'])
        stages[item['stage']] = stages.get(item['stage'], 0) + 1
    require(type(attempts['by_stage']) is dict and all(type(count) is int for count in attempts['by_stage'].values())
            and attempts['by_stage'] == stages, 'qualification.observation.interrupted-attempts')
    arguments = reviewed['arguments']
    key = sha256(b'auths.gateway-logical-operation/1\0' + arguments['operator_namespace'].encode()
                 + b'\0' + arguments['operation_id'].encode())
    require({'key_sha256': key, 'stage': 'unknown'} in attempts['identifiers'],
            'qualification.observation.interrupted-state')


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
        return self._project(tuple_value, reviewed, resources, result(native_result),
                             measure.delta(before, after), response, status=native_result.get('status'))

    def project_race(self, tuple_value, reviewed, resources, native_results, pairs, response):
        require(type(native_results) is list and len(native_results) == 2 and len(pairs) == 2,
                'qualification.observation.race-hosts')
        decoded = [result(value) for value in native_results]
        linked = [value for value in decoded if value[2] is not None]
        require(linked and all(value[0] in ['observed', 'unknown']
                or (value[0] == 'refused' and value[1] == 'gateway.attempt.replay') for value in decoded)
                and all(all(value[2][field] == linked[0][2][field]
                            for field in ['channel', 'echo', 'evidence_digest']) for value in linked),
                'qualification.observation.race-evidence')
        # Both are actual host results; the survivor's read-only recovery can
        # supply the link. Distinct native scopes are aggregated directly.
        return self._project(tuple_value, reviewed, resources, linked[0], measure.aggregate(pairs), response,
                             status=next(value['status'] for value in native_results
                                         if value['outcome'] == 'observed-by-provider'))

    def project_budget_race(self, tuple_value, reviewed, resources, owner, competitor, pairs, response, code):
        require(code in ['gateway.policy.window-exhausted', 'gateway.policy.sum-exhausted']
                and type(pairs) is list and len(pairs) == 2,
                'qualification.observation.budget-hosts')
        winner, loser = result(owner), result(competitor)
        refusal = measure.delta(*pairs[1])
        require(winner[2] is not None and loser == ('refused', code, None)
                and refusal['credential_lease_calls'] == refusal['write_transport_entries'] == 0,
                'qualification.observation.budget-refusal')
        # The authenticated competitor uses a different operation. Preserve
        # both real process scopes; no synthetic before/after pair is created.
        return self._project(tuple_value, reviewed, resources, winner, measure.aggregate(pairs), response,
                             status=owner.get('status'))

    def project_guard_refusal(self, tuple_value, reviewed, resources, native, before, after):
        require(tuple_value['recipe_family'] == stripe_platform.FAMILY,
                'qualification.observation.guard-family')
        actual = result(native)
        expected = stripe_platform.entry_policy(reviewed['arguments'], resources)
        require(expected in ['gateway.relative-ceiling.above', 'gateway.relative-ceiling.binding-mismatch']
                and actual == ('refused', expected, None), 'qualification.observation.guard-refusal')
        facts, fresh = self.project(tuple_value, reviewed, resources, native, before, after)
        require(facts['credential_leases'] == 1 and facts['provider_entries'] == 0,
                'qualification.observation.guard-entry')
        # This valid original action was independently reauthenticated. The
        # actual native guard code identifies a refusal after that same mapped
        # request, unlike malformed proof/action refusals, which keep no hash.
        facts['verdict']['request_sha256'] = sha256(canonical(reviewed['request']))
        return facts, fresh

    def project_interrupted(self, tuple_value, reviewed, resources, trusted_context_sha256, support, before, after):
        interrupted_state(tuple_value, reviewed, trusted_context_sha256, support)
        counted = measure.delta(before, after)
        require(counted['credential_lease_calls'] >= 1 and counted['write_transport_entries'] == 1,
                'qualification.observation.interrupted-entry')
        return self._project(tuple_value, reviewed, resources, ('unknown', 'unknown', None), counted, None)

    def project_stored_unknown(self, tuple_value, reviewed, resources, trusted_context_sha256, support, before, after):
        interrupted_state(tuple_value, reviewed, trusted_context_sha256, support)
        counted = measure.delta(before, after)
        key = (tuple_value['recipe_family'], resources['protected_run'],
               reviewed['arguments']['operator_namespace'], reviewed['arguments']['operation_id'])
        require(counted['credential_lease_calls'] == counted['write_transport_entries'] == 0
                and key in self.entries and not self.entries[key]['confirmed'],
                'qualification.observation.unmeasured-unknown')
        return self._project(tuple_value, reviewed, resources, ('unknown', 'unknown', None), counted, None)

    def project_admin_refusal(self, tuple_value, reviewed, resources, response, before, after):
        closed(response, ['schema', 'ok', 'code'])
        require(response == {'schema': 'auths.gateway-admin-response/1', 'ok': False,
                             'code': 'gateway.reobserve.not-observable'},
                'qualification.observation.admin-refusal')
        return self._project(tuple_value, reviewed, resources, ('refused', response['code'], None),
                             measure.delta(before, after), None)

    def _project(self, tuple_value, reviewed, resources, decoded_result, counted, response, status=None):
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
        leases = integer(counted['credential_lease_calls'], 0, (1 << 32) - 1)
        writes = integer(counted['write_transport_entries'], 0, 1)
        outcome, code, evidence = decoded_result
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
            require(status == 200 or (status is None and reference is airtable_record),
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
