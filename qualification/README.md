# Recipe qualification

What a protected run needs to qualify a recipe family, and where it finds it.
The specification is
[AP-SPEC-066](../docs/specs/0066-production-gateway-polish-and-recipe-qualification.md)
§7 and §8; the run is described in
[the protected-run plan](../docs/plans/RECIPE_QUALIFICATION_PROTECTED_RUN_PLAN.md).

No family is qualified and none is present here yet. The two launch families
arrive with their decision records.

## `families/<family>/`

One directory per recipe family, named by its `RecipeFamilyId`.

| File | Holds |
| --- | --- |
| `decision-record.md` | The family's decision record. Its digest goes into the record. |
| `contract.json` | The canonical `auths.provider-contract/1` the run qualifies against. |
| `corpus-manifest.json` | The corpus the differential, hostile, and live stages run. |
| `record.json` | What the record states that no run decides: `provider_kind`, `validity_days` (at most 90), `not_applicable` (each capability the family lacks, with the reason the decision record fixes), `custody_descriptor`, `store_descriptor`, `residual_assumptions`, `excluded_claims`. |
| `harness` | An executable the run calls as `harness offline <work-dir>` and `harness live <work-dir>`. |

The harness owns everything that means something about the provider: the
oracle, the corpus, the live cases, and how each scenario is attempted. It
reports only cases. It is given `AUTHS_GATEWAY` and `AUTHS_QUALIFICATION`, the
paths of the candidate's binaries.

`harness offline` writes:

- `tuple.json`: the tuple of the candidate gateway it installed, as
  `auths-gateway qualification-status --tuple` prints it;
- `packages.json`: the installed packages it exercised, as
  `[{"name", "version", "sha256"}]`;
- `cases/<member>.<name>.json`: case reports for the members that need no
  provider (`conformance`, `differential`, and the `hostile`, `restart`, and
  `multi-instance` cases it runs against a provider double).

`harness live` runs only in the protected live environment, with the family's
disposable provider credential in `AUTHS_QUALIFICATION_PROVIDER_CREDENTIAL`,
and writes:

- `cases/<member>.<name>.json` for `live`, `recovery`, `rotation`,
  `installed-consumer`, and any `hostile`, `restart`, or `multi-instance` case
  that needs the provider;
- `live-effects.json`: `{"entered", "confirmed_by_read_back"}`;
- `resources.json`: sanitized identifiers of the disposable resources;
- `canaries`: every secret and provider datum planted for the run, one per
  line. The live job scans everything below for them with `run/redact.sh`
  and deletes this file before it uploads anything;
- `scan/log/`, `scan/trace/`, `scan/metric/`, `scan/support-bundle/`: every
  output the run kept.

A case report is `{"id", "scenario", "capabilities", "passed",
"unauthorized_provider_entries"}`. The scenarios are the closed set in
`auths_recipe_qualification::Scenario`; a record closes only when every
scenario that set always requires has a case, every capability is either shown
by a case or listed in `not_applicable`, nothing failed, and no case observed
an unauthorized provider entry. The signer-rotation, freshness, and redaction
scenarios are run by the release tooling itself, not by the harness.

## `trust/`

Public artifacts of the offline root ceremony, committed by the owner:

- `qualification-trust-root.json`: the root a gateway release pins;
- `signer-certificate.json`: the current release signer's certificate;
- `revocation-list.json`: the current revocation list.

No private key is ever in this repository. The directory is empty until the
first ceremony, and until then the signing job refuses to run.

## `run/`

The scripts the workflow's jobs call. `offline.sh` and `assemble.sh` need no
secret and can be run on a development host. `redact.sh` runs in the live
job.

## Environments

Each family's live environment, `recipe-qualification-live-<family>`, must be
created with a required reviewer and the default branch only **before** its
credential is stored in it. The signing environment already has both rules.
The harness of a family is trusted as reviewed code on the default branch;
the run does not execute anything a harness leaves behind as a program in
the jobs that assemble, sign, or verify.
