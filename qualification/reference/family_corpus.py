"""Source-owned corpus expansion; no outcome from a run supplies expectations.

Native review authenticates actors/actions. These provider references derive
requests and fresh-evidence subjects independently. The native stage runner
owns coverage and the comparison of actual observations with this plan.
"""

import airtable_record
import stripe_platform
import fresh_evidence
from common import canonical, closed, digest, require, sha256
from expand import child, decode, read, SOURCES
from packet_plan import public_pool

RESOURCES = 16
REFERENCES = {r.FAMILY: r for r in [stripe_platform, airtable_record]}


def authenticate(family, work, gateway, tuple_value):
    reference = REFERENCES.get(family)
    require(reference is not None and tuple_value['recipe_family'] == family,
            'qualification.corpus.family')
    resources = decode(read(work / 'resources.json', 65536))
    reference.resources(resources, resources['protected_run'])
    values = resources['payments'] if reference is stripe_platform else resources['records']
    require(len(values) == RESOURCES, 'qualification.corpus.resource-count')
    source = SOURCES[family]
    require(decode(read(work / 'recipe.json', 65536)) == reference.recipe(
                decode(read(source / 'recipe.json', 65536)), resources)
            and read(work / 'profile.lock.json', 65536) == read(source / 'profile.lock.json', 65536),
            'qualification.corpus.reviewed-source')
    carrier = decode(read(work / 'public-packets.json', 65536))
    packets = public_pool(family, resources, tuple_value['compiled_recipe_sha256'], carrier)
    reviewed, actors = {}, set()
    for packet in packets:
        actual = child(gateway, ['review-submission', '--recipe', work / 'recipe.json',
            '--profile-lock', work / 'profile.lock.json',
            '--trusted-context', work / packet['trusted_context'], '--proof', work / packet['proof'],
            '--action', work / packet['action'], '--evaluated-at', str(carrier['evaluated_at'])])
        closed(actual, ['schema', 'actors', 'action_commitment', 'arguments', 'request'])
        require(actual['schema'] == 'auths.gateway-submission-review/1'
                and len(actual['actors']) == 1 and actual['arguments'] == packet['arguments'],
                'qualification.corpus.proof-binding')
        request = reference.request(actual['arguments'], resources, digest(actual['action_commitment']),
                                    tuple_value['compiled_recipe_sha256'])
        require(actual['request'] == request, 'qualification.corpus.request-binding')
        actors.update(actual['actors'])
        reviewed[packet['label']] = actual
    require(len(actors) == 1, 'qualification.corpus.actor-binding')
    return resources, reviewed


def compile_plan(family, resources, reviewed, recipe_digest):
    """Closed provider-specific cases, including both protected phases.

    Administrative compound probes have source-owned completion codes. Their
    harness must check the actual native refusals and counters before returning
    that completion; it cannot copy this expected observation as its result.
    """
    reference = REFERENCES.get(family)
    require(reference is not None, 'qualification.corpus.family')
    reference.resources(resources, resources['protected_run'])
    values = resources['payments'] if reference is stripe_platform else resources['records']
    require(len(values) == RESOURCES, 'qualification.corpus.resource-count')
    cases = []

    def request(label):
        value = reviewed[label]
        result = reference.request(value['arguments'], resources, value['action_commitment'], recipe_digest)
        require(value['request'] == result, 'qualification.corpus.request-binding')
        return sha256(canonical(result))

    def step(operation, outcome, code, label=None, leases=0, entries=0, confirmed=0, fresh=False):
        comparison = {'kind': 'static'}
        if fresh:
            value = reviewed[label]
            comparison = {'kind': 'independent-read-back', 'subject_sha256': fresh_evidence.subject(
                family, value['arguments'], resources, value['action_commitment'], recipe_digest)}
        return {'operation': operation, 'evidence_comparison': comparison,
            'expected': {'verdict': {'outcome': outcome, 'code': code,
                'request_sha256': None if label is None else request(label), 'evidence_sha256': None},
                'credential_leases': leases, 'provider_entries': entries,
                'confirmed_by_read_back': confirmed}}

    def complete(operation, code):
        return step(operation, 'complete', code)

    def observed(operation, label, leases=2, entries=1, confirmed=1):
        return step(operation, 'observed', 'observed-by-provider', label,
                    leases, entries, confirmed, True)

    def unknown(operation, label, leases=0, entries=0):
        return step(operation, 'unknown', 'unknown', label, leases, entries)

    def replay():
        return step('replay', 'refused', 'gateway.attempt.replay')

    def add(phase, identifier, scenario, steps, capabilities=()):
        cases.append({'id': phase + '-' + identifier, 'scenario': scenario,
            'capabilities': list(capabilities), 'phase': phase, 'steps': steps})

    for identifier, scenario, code in [
        ('source', 'clean-source', 'source-clean'),
        ('digest', 'recipe-digest-rederives', 'recipe-digest-rederived'),
        ('vectors', 'recipe-vectors', 'recipe-vectors-passed'),
        ('closed', 'closed-enumeration-hostile', 'closed-enumeration-refused')]:
        add('offline', identifier, scenario, [complete('probe', code)])
    label = 'commissioning-00'
    add('offline', 'oracle-accept', 'oracle-accepts', [
        step(operation, 'complete', 'request-mapped', label) for operation in ['oracle', 'review']])
    add('offline', 'oracle-reject', 'oracle-rejects', [
        step(operation, 'refused', 'action-outside-validity') for operation in ['oracle', 'review']])

    for phase in ['commissioning', 'live']:
        label = lambda index: phase + '-' + str(index).zfill(2)
        add(phase, 'fresh-replay', 'fresh-challenge-replay',
            [observed('submit', label(0)), replay()])
        add(phase, 'proof-replay', 'proof-replay', [observed('submit', label(1)), replay()])
        # The held owner response keeps an entered operation unresolved while
        # the second actual process races its claim. Airtable can take one
        # read-only recovery lease; its committed observation makes the
        # owner response CAS lose, so that owner takes no observation lease.
        # Stripe has no unrecorded response locator; its owner confirms later.
        add(phase, 'two-host-race', 'two-instance-race',
            [observed('race', label(2), leases=2)])
        for index, operation in [(3, 'restart'), (4, 'crash')]:
            ending = observed('replay', label(index), 1, 0, 1) if reference is airtable_record \
                else replay()
            add(phase, operation, operation, [unknown('submit', label(index), 1, 1),
                complete(operation, 'gateway-' + operation + '-completed'), ending])
        add(phase, 'ambiguous', 'ambiguous-response', [unknown('drop-response', label(5), 1, 1),
            observed('replay', label(5), 1, 0, 1) if reference is airtable_record
            else replay()])
        for index, identifier, operation, scenario in [
            (6, 'response-loss', 'drop-response', 'response-loss'),
            (7, 'visibility', 'delay-visibility', 'delayed-visibility')]:
            ending = observed('read-back', label(index), 1, 0, 1) if reference is airtable_record or index == 7 \
                else unknown('read-back', label(index))
            # Delaying the observation response exercises a second actual
            # lease, after the write response has durably supplied its locator.
            # Stripe can reconcile that locator; losing the write response
            # still cannot borrow the independent oracle's discovered locator.
            add(phase, identifier, scenario, [unknown(operation, label(index), 2 if index == 7 else 1, 1), ending],
                ('recovery',) if reference is airtable_record else ())
        add(phase, 'secret-rotation', 'provider-secret-rotation',
            [complete('rotate', 'provider-secret-rotated'), observed('submit', label(8))])
        add(phase, 'read-back', 'read-back-confirms-write', [observed('submit', label(9)),
            step('read-back', 'refused', 'gateway.reobserve.not-observable')])
        capabilities = ['echo', 'observation']
        if reference is stripe_platform:
            capabilities = ['credential-guard', 'version-pin', 'account-binding', 'denied-reads',
                            'idempotency', 'response-locator', *capabilities]
        add(phase, 'capabilities', 'declared-capability', [observed('submit', label(10)),
            complete('probe', 'provider-capabilities-confirmed')], capabilities)
        for index, language in [(11, 'python'), (12, 'typescript')]:
            consumer = observed('installed-consumer', label(index)) if phase == 'live' else \
                step('installed-consumer', 'refused', 'gateway.qualification.missing')
            add(phase, 'installed-' + language, 'installed-journey', [consumer])
            add(phase, language + '-no-source', 'no-repository-import',
                [complete('installed-consumer', 'installed-package-provenance-confirmed')])
            add(phase, language + '-no-token', 'no-provider-token',
                [complete('installed-consumer', 'provider-token-absent')])
        for identifier, scenario, code in [
            ('isolation', 'application-cannot-read-secret', 'application-secret-access-refused'),
            ('direct-provider', 'direct-provider-attempt', 'direct-provider-access-refused')]:
            add(phase, identifier, scenario, [complete('probe', code)])
        for identifier, scenario in [('forged', 'forged-proof'), ('altered', 'altered-action')]:
            add(phase, identifier, scenario,
                [step('probe', 'refused', 'gateway.verify.invalid-input')])
        for kind, scenario in [('kind', 'store-kind-drift'), ('generation', 'generation-drift'),
                               ('commitment', 'commitment-drift'), ('version', 'external-version-drift')]:
            # The real AWS adapter authenticates the exact immutable version
            # and bytes during holds(), before admission or a counted lease.
            add(phase, 'custody-' + kind, scenario,
                [step('probe', 'complete', 'custody-' + kind + '-refused')])
        if reference is stripe_platform:
            for kind, code in [('ceiling', 'gateway.relative-ceiling.above'),
                               ('currency', 'gateway.relative-ceiling.binding-mismatch')]:
                add(phase, 'guard-' + kind, 'declared-capability',
                    [step('probe', 'refused', code, leases=1)], ('ceiling',))
            for kind in ['count', 'sum']:
                budget_label = phase + '-budget-' + kind
                add(phase, 'budget-' + kind, 'declared-capability',
                    [observed('race', budget_label), complete('probe', 'budget-' + kind + '-refusal-confirmed')],
                    ('budget', 'ceiling'))
    doctor = complete('probe', 'production-readiness-passed')
    doctor['evidence_comparison'] = {'kind': 'production-doctor'}
    add('live', 'doctor', 'production-readiness', [doctor])
    return {'schema': 'auths.qualification-corpus/3', 'cases': cases}
