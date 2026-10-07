#!/usr/bin/env python3
"""Regenerate the reviewed plan/contract artifacts from their exact source.

These are unqualified source plans. This command issues no record, permit,
evidence, attestation or release index and reads no credential.
"""

from pathlib import Path
import argparse

from common import canonical, require, sha256
import airtable_record
import stripe_platform
from expand import SOURCES, decode, read
from resource_io import finish

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / 'qualification/reference'
SOURCES_TO_PIN = ['family_corpus.py', 'family_harness.py', 'family_operations.py', 'packet_plan.py',
    'author_packets.py', 'author_socket.py', 'retained_author.py', 'author_operator.py', 'production_setup.py',
    'network_fault.py', 'production_environment.py', 'production_journey.py', 'journey_session.py',
    'controller_socket.py', 'installed_submit.py', 'installed_submit.mjs', 'common.py', 'fresh_evidence.py',
    'native_observation.py', 'measure.py', 'provider_readback.py', 'resource_io.py', 'resource_summary.py',
    'expand.py', 'stripe_platform.py', 'airtable_record.py', 'stripe_resources.py', 'airtable_resources.py']


def generate(check=False):
    for reference, adr in [(stripe_platform, '0014-stripe-refund-recipe-qualification.md'),
                           (airtable_record, '0015-airtable-record-update-recipe-qualification.md')]:
        family = ROOT / 'qualification/families' / reference.FAMILY
        if not check: family.mkdir(parents=True, exist_ok=True)
        plan = {'schema': 'auths.qualification-reviewed-plan/1', 'family': reference.FAMILY,
            'resource_count': 16, 'compiled_corpus_schema': 'auths.qualification-corpus/3',
            'packet_plan_schema': 'auths.qualification-packet-plan/4',
            'public_packet_schema': 'auths.qualification-public-packets/4',
            'phases': ['offline', 'commissioning', 'live'], 'maximum_credential_leases': 64,
            'source_files': {**{name: sha256(read(REFERENCE / name, 2 * 1024 * 1024))
                                for name in SOURCES_TO_PIN},
                             'tls_fault.py': sha256(read(ROOT / 'qualification/run/tls_fault.py', 2 * 1024 * 1024))},
            'source_recipe_sha256': sha256(read(SOURCES[reference.FAMILY] / 'recipe.json', 65536)),
            'profile_lock_sha256': sha256(read(SOURCES[reference.FAMILY] / 'profile.lock.json', 65536)),
            'decision_record_sha256': sha256(read(ROOT / 'docs/adr' / adr, 65536))}
        recipe = decode(read(SOURCES[reference.FAMILY] / 'recipe.json', 65536))
        stripe = reference is stripe_platform
        assumptions = sorted([
            'The provider is independently operated; availability and concurrent outside writes are not controlled by Auths.',
            'Fresh matching state and the action-derived echo are required; HTTP success is not effect confirmation.',
            'Only the closed run-owned resource ledger is in scope; every cleanup must be freshly confirmed.',
            'Stripe test mode and the installed platform are checked by the declared guard on each lease.' if stripe else
            'The reviewed fixed Airtable base and table contain only owner-authorized disposable qualification records.',
            'Stripe idempotency is tested only inside the declared 86400-second retention interval.' if stripe else
            'Airtable supplies no idempotency key for this PATCH; durable gateway admission prevents a second entry.',
            'The 50-percent payment basis is a read, not an atomic provider balance reservation.' if stripe else
            'Only a fresh GET with the exact replacement and echo can reconcile a lost response.',
        ])
        declarations = {
            'idempotency_sha256': sha256(canonical(recipe['write'].get('idempotency'))),
            'observation_sha256': sha256(canonical({'observation': recipe['observation'], 'echo': recipe['echo']})),
            'recovery_sha256': sha256(canonical({'declared': not stripe,
                'locator': 'verified-record' if not stripe else 'recorded-response-only'})),
            'retention_sha256': sha256(canonical({'attestation_days': 30,
                'provider_idempotency_seconds': 86400 if stripe else None,
                'commissioning_seconds': 7200})),
        }
        contract = {'schema': 'auths.provider-contract/1', 'provider': 'stripe' if stripe else 'airtable',
            'api_release': '2025-03-31.basil' if stripe else 'web-api-v0-reviewed-2026-10-07',
            'manual_assumptions': assumptions, 'environment_class': reference.ENVIRONMENT,
            'corpus_manifest_sha256': sha256(canonical(plan)),
            'oracle_version': 'auths-reviewed-reference-v2', 'declarations': declarations}
        reasons = {'observer-rotation': 'The qualified reference configures no signing observer.'}
        if stripe:
            reasons['recovery'] = 'An unrecorded refund response has no verified response locator; loss remains unknown.'
        else:
            reasons.update({
                'credential-guard': 'This recipe declares no provider credential guard.',
                'version-pin': 'Airtable Web API v0 has no immutable response version pin.',
                'account-binding': 'The recipe declares no account-binding probe.',
                'denied-reads': 'The recipe declares no denied credential reads; token scope is an operator assumption.',
                'ceiling': 'The field-update profile carries no numeric amount or relative ceiling.',
                'budget': 'This recipe declares no numeric count/sum budget.',
                'idempotency': 'This PATCH declares no provider idempotency key.',
                'response-locator': 'Observation uses the verified record ID, not a write-response locator.',
            })
        record = {'provider_kind': 'stripe' if stripe else 'airtable', 'validity_days': 30,
            'not_applicable': [{'capability': name, 'reason': reason} for name, reason in sorted(reasons.items())],
            'custody_descriptor': 'aws-secrets-manager-v1 with immutable versions and a customer-managed key',
            'store_descriptor': 'postgresql-v1 schema 6 shared by two isolated gateway processes',
            'residual_assumptions': assumptions,
            'excluded_claims': sorted(['Global exactly-once effects across other actors or deployments.',
                'Provider availability, settlement, or indefinite retention.',
                'Connected-account selection or restrictions.' if stripe else
                'Gateway enforcement of the personal access token resource configuration.'])}
        outputs = {name: canonical(value) for name, value in [
            ('corpus-manifest.json', plan), ('contract.json', contract), ('record.json', record)]}
        decision = (
            '# ' + reference.FAMILY + '\n\nStatus: source plan; no production qualification.\n\n'
            'The provider decision is [ADR](../../../docs/adr/' + adr + '). Its exact digest is in the reviewed plan.\n\n'
            'The source-owned compiler expands the complete closed packet pool into the native three-phase corpus. '
            'Offline operations execute the installed SDK and shipping native reviewer. Protected operations '
            'must use PostgreSQL, actual AWS custody, two processes, fresh read-back and measured counters. '
            'An absent protected implementation refuses and emits no observation.\n\n'
            'The contract hashes this reviewed source plan; the record separately hashes its concrete native '
            'corpus expansion. This avoids a source/candidate/actor commitment cycle. The signer must '
            'reconstruct the expansion from its own reviewed source before issuing authority.\n')
        harness = ('#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n'
            "sys.dont_write_bytecode = True\nsys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'reference'))\n"
            'from family_harness import main\nmain(' + repr(reference.FAMILY) + ', sys.argv[1:])\n')
        outputs.update({'decision-record.md': decision.encode(), 'harness': harness.encode()})
        for name, value in outputs.items():
            if check:
                require(read(family / name, 2 * 1024 * 1024) == value,
                        'qualification.harness.reviewed-plan-drift')
            else:
                (family / name).write_bytes(value)
        if not check: (family / 'harness').chmod(0o755)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    finish(lambda: generate(args.check))
