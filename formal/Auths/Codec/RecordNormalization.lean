import Auths.Codec.KeyDerivation
import Auths.Codec.SnapshotOrdering

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.RecordNormalization

/- Actual derivation, sorting and consuming projection are composed below.
The postcondition keeps the complete derived-ID/record association. It does
not identify different records sharing an ID, or assume a hash result for an
incoming record. Independent preimage/ID meaning and all-input totality/work
remain additional obligations under the explicit SHA primitive contract. -/

def grantKey (entry : auths_model.GrantId × auths_model.SignedGrant) : List Nat :=
  ProtocolOrdering.grantIdKey entry.1

def principalStatusKey
    (entry : auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus) : List Nat :=
  ProtocolOrdering.principalStatusIdKey entry.1

def grantStatusKey
    (entry : auths_model.GrantStatusId × auths_model.SignedGrantStatus) : List Nat :=
  ProtocolOrdering.grantStatusIdKey entry.1

theorem id_relation {Id Record Key : Type} [LinearOrder Key] (view : Id → Key) :
    ProtocolSort.keyedRelation (@Prod.fst Id Record)
      (fun left right => compare (view left) (view right)) =
        StableNormalization.before (fun entry => view entry.1) := by
  funext left right
  exact propext (SnapshotOrdering.compare_is_le _ _)

syntax "auths_record_key_sort " term "," term "," term "," term "," term "," term : tactic

macro_rules
| `(tactic| auths_record_key_sort $source, $selector, $selectorLaw, $view, $comparisonLaw, $entryKey) =>
  `(tactic|
    (unfold $source
     simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut, bind_tc_ok]
     rw [ProtocolSort.slice_keyed_sort_exact _ _ _ Prod.fst
       (fun left right => compare ($view left) ($view right)) (by
         intro entry
         change (do let identifier ← $selector entry
                    ok (identifier, _)) = _
         rw [$selectorLaw]
         rfl) $comparisonLaw]
     simp only [bind_tc_ok]
     congr 1
     apply alloc.vec.contents_injective
     simp [Aeneas.Std.alloc.vec.Vec.deref_mut, alloc.vec.Vec.ofBase,
       alloc.vec.Vec.toBase, alloc.vec.Vec.val,
       auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
       auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.SizedList.toList_ofList,
       SnapshotOrdering.sortedByKey, StableNormalization.sort, id_relation, $entryKey]))

theorem grant_sort_exact
    (values : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant)) :
    canonical_value.sort_grant_keys values = ok (SnapshotOrdering.sortedByKey grantKey values) := by
  auths_record_key_sort canonical_value.sort_grant_keys,
    canonical_value.grant_sort_key, KeyDerivation.grant_sort_key_exact,
    ProtocolOrdering.grantIdKey, ProtocolOrdering.grant_id_compare, grantKey

theorem principal_status_sort_exact
    (values : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus)) :
    canonical_value.sort_principal_status_keys values =
      ok (SnapshotOrdering.sortedByKey principalStatusKey values) := by
  auths_record_key_sort canonical_value.sort_principal_status_keys,
    canonical_value.principal_status_sort_key, KeyDerivation.principal_status_sort_key_exact,
    ProtocolOrdering.principalStatusIdKey, ProtocolOrdering.principal_status_id_compare, principalStatusKey

theorem grant_status_sort_exact
    (values : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus)) :
    canonical_value.sort_grant_status_keys values =
      ok (SnapshotOrdering.sortedByKey grantStatusKey values) := by
  auths_record_key_sort canonical_value.sort_grant_status_keys,
    canonical_value.grant_status_sort_key, KeyDerivation.grant_status_sort_key_exact,
    ProtocolOrdering.grantStatusIdKey, ProtocolOrdering.grant_status_id_compare, grantStatusKey

syntax "auths_record_normalizer " term "," term "," term "," term "," term "," term
  " at " ident "," ident "," ident : tactic

macro_rules
| `(tactic| auths_record_normalizer $source, $derive, $derivePayload, $deriveConsistency,
    $sortLaw, $entryKey at $input:ident, $output:ident, $accepted:ident) =>
  `(tactic|
    (unfold $source at $accepted
     cases derived : $derive $input with
     | fail error =>
       simp only [derived] at $accepted
       auths_key_effect $accepted
     | div =>
       simp only [derived] at $accepted
       auths_key_effect $accepted
     | ok result =>
       cases result with
       | Err error =>
         simp only [derived] at $accepted
         auths_key_effect $accepted
       | Ok keyed =>
         simp only [derived] at $accepted
         auths_key_effect $accepted
         rw [$sortLaw, bind_tc_ok] at $accepted
         obtain ⟨projected, projection, payload⟩ := spec_imp_exists
           (OwnedRecords.unkey_exact (SnapshotOrdering.sortedByKey $entryKey keyed))
         simp only [projection] at $accepted
         auths_key_effect $accepted
         have same : projected = $output := $accepted
         subst $output
         refine ⟨keyed, derived, $derivePayload $input keyed derived,
           $deriveConsistency $input keyed derived, ?_⟩
         simpa only [SnapshotOrdering.sorted_by_key_contents] using payload))

variable [primitive : Auths.Crypto.Sha256Primitives]

-- These are partial source-key observations, not independent SHA or framing
-- specifications. The none branch exposes primitive/encoding refusal. Actual
-- successful derivation earns a some key for every member without an axiom.
def grantSourceKey (record : auths_model.SignedGrant) : Option (List Nat) :=
  match hash.grant_id record.statement with
  | .ok (.Ok id) => some (ProtocolOrdering.grantIdKey id)
  | _ => none

def principalStatusSourceKey (record : auths_model.SignedPrincipalStatus) : Option (List Nat) :=
  match hash.principal_status_id record.statement with
  | .ok (.Ok id) => some (ProtocolOrdering.principalStatusIdKey id)
  | _ => none

def grantStatusSourceKey (record : auths_model.SignedGrantStatus) : Option (List Nat) :=
  match hash.grant_status_id record.statement with
  | .ok (.Ok id) => some (ProtocolOrdering.grantStatusIdKey id)
  | _ => none

theorem projected_sort_from_keys {Id Record Key : Type} [LinearOrder Key]
    (idView : Id → Key) (sourceKey : Record → Option Key) (entries : List (Id × Record))
    (consistent : ∀ entry ∈ entries, sourceKey entry.2 = some (idView entry.1)) :
    (StableNormalization.sort (fun entry => idView entry.1) entries).map Prod.snd =
      StableNormalization.sort sourceKey (entries.map Prod.snd) := by
  rw [← StableNormalization.map_sort Prod.snd sourceKey entries]
  rw [StableNormalization.sort_congr_on (fun entry => sourceKey entry.2)
    (fun entry => some (idView entry.1)) entries consistent]
  rw [StableNormalization.sort_some]

/-- Successful normalization exposes actual derived keys, complete payload
preservation, exact source ID association and stable ID-byte sorting. -/
theorem grants_exact (input output : alloc.vec.Vec auths_model.SignedGrant)
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    ∃ keyed : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant),
      canonical_value.derive_grant_keys input = ok (.Ok keyed) ∧
      keyed.val.map Prod.snd = input.val ∧
      (∀ entry ∈ keyed.val, hash.grant_id entry.2.statement = ok (.Ok entry.1)) ∧
      output.val = (StableNormalization.sort grantKey keyed.val).map Prod.snd := by
  auths_record_normalizer canonical_value.normalize_grants, canonical_value.derive_grant_keys,
    KeyDerivation.grant_keys_payload, KeyDerivation.grant_keys_consistent,
    grant_sort_exact, grantKey at input, output, accepted

theorem principal_status_exact (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    ∃ keyed : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus),
      canonical_value.derive_principal_status_keys input = ok (.Ok keyed) ∧
      keyed.val.map Prod.snd = input.val ∧
      (∀ entry ∈ keyed.val, hash.principal_status_id entry.2.statement = ok (.Ok entry.1)) ∧
      output.val = (StableNormalization.sort principalStatusKey keyed.val).map Prod.snd := by
  auths_record_normalizer canonical_value.normalize_principal_status,
    canonical_value.derive_principal_status_keys,
    KeyDerivation.principal_status_keys_payload, KeyDerivation.principal_status_keys_consistent,
    principal_status_sort_exact, principalStatusKey at input, output, accepted

theorem grant_status_exact (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    ∃ keyed : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus),
      canonical_value.derive_grant_status_keys input = ok (.Ok keyed) ∧
      keyed.val.map Prod.snd = input.val ∧
      (∀ entry ∈ keyed.val, hash.grant_status_id entry.2.statement = ok (.Ok entry.1)) ∧
      output.val = (StableNormalization.sort grantStatusKey keyed.val).map Prod.snd := by
  auths_record_normalizer canonical_value.normalize_grant_status,
    canonical_value.derive_grant_status_keys,
    KeyDerivation.grant_status_keys_payload, KeyDerivation.grant_status_keys_consistent,
    grant_status_sort_exact, grantStatusKey at input, output, accepted

theorem grants_permutation (input output : alloc.vec.Vec auths_model.SignedGrant)
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    output.val.Perm input.val := by
  obtain ⟨keyed, _, payload, _, ordered⟩ := grants_exact input output accepted
  rw [ordered, ← payload]
  exact (StableNormalization.permutation grantKey keyed.val).map Prod.snd

theorem principal_status_permutation (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    output.val.Perm input.val := by
  obtain ⟨keyed, _, payload, _, ordered⟩ := principal_status_exact input output accepted
  rw [ordered, ← payload]
  exact (StableNormalization.permutation principalStatusKey keyed.val).map Prod.snd

theorem grant_status_permutation (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    output.val.Perm input.val := by
  obtain ⟨keyed, _, payload, _, ordered⟩ := grant_status_exact input output accepted
  rw [ordered, ← payload]
  exact (StableNormalization.permutation grantStatusKey keyed.val).map Prod.snd

theorem grants_count (input output : alloc.vec.Vec auths_model.SignedGrant)
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    output.val.length = input.val.length := (grants_permutation input output accepted).length_eq

theorem principal_status_count (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    output.val.length = input.val.length := (principal_status_permutation input output accepted).length_eq

theorem grant_status_count (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    output.val.length = input.val.length := (grant_status_permutation input output accepted).length_eq

theorem grants_fields (input output : alloc.vec.Vec auths_model.SignedGrant)
    (field : auths_model.SignedGrant → Prop)
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    (∀ record ∈ output.val, field record) ↔ ∀ record ∈ input.val, field record := by
  have same := grants_permutation input output accepted
  constructor
  · intro valid record member
    exact valid record (same.mem_iff.mpr member)
  · intro valid record member
    exact valid record (same.mem_iff.mp member)

theorem principal_status_fields (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (field : auths_model.SignedPrincipalStatus → Prop)
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    (∀ record ∈ output.val, field record) ↔ ∀ record ∈ input.val, field record := by
  have same := principal_status_permutation input output accepted
  constructor
  · intro valid record member
    exact valid record (same.mem_iff.mpr member)
  · intro valid record member
    exact valid record (same.mem_iff.mp member)

theorem grant_status_fields (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (field : auths_model.SignedGrantStatus → Prop)
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    (∀ record ∈ output.val, field record) ↔ ∀ record ∈ input.val, field record := by
  have same := grant_status_permutation input output accepted
  constructor
  · intro valid record member
    exact valid record (same.mem_iff.mpr member)
  · intro valid record member
    exact valid record (same.mem_iff.mp member)

/-- The actual three-stage source result is the independent stable sorting
algorithm over observed source IDs. This is not yet independent ID meaning. -/
theorem grants_normal_form (input output : alloc.vec.Vec auths_model.SignedGrant)
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    output.val = StableNormalization.sort grantSourceKey input.val := by
  obtain ⟨keyed, _, payload, consistent, ordered⟩ := grants_exact input output accepted
  rw [ordered, ← payload]
  exact projected_sort_from_keys ProtocolOrdering.grantIdKey grantSourceKey keyed.val (by
    intro entry member
    simp [grantSourceKey, consistent entry member])

theorem principal_status_normal_form (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    output.val = StableNormalization.sort principalStatusSourceKey input.val := by
  obtain ⟨keyed, _, payload, consistent, ordered⟩ := principal_status_exact input output accepted
  rw [ordered, ← payload]
  exact projected_sort_from_keys ProtocolOrdering.principalStatusIdKey principalStatusSourceKey keyed.val (by
    intro entry member
    simp [principalStatusSourceKey, consistent entry member])

theorem grant_status_normal_form (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    output.val = StableNormalization.sort grantStatusSourceKey input.val := by
  obtain ⟨keyed, _, payload, consistent, ordered⟩ := grant_status_exact input output accepted
  rw [ordered, ← payload]
  exact projected_sort_from_keys ProtocolOrdering.grantStatusIdKey grantStatusSourceKey keyed.val (by
    intro entry member
    simp [grantStatusSourceKey, consistent entry member])

theorem grants_ordered (input output : alloc.vec.Vec auths_model.SignedGrant)
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    output.val.Pairwise (StableNormalization.before grantSourceKey) := by
  rw [grants_normal_form input output accepted]
  exact StableNormalization.ordered _ _

theorem principal_status_ordered (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    output.val.Pairwise (StableNormalization.before principalStatusSourceKey) := by
  rw [principal_status_normal_form input output accepted]
  exact StableNormalization.ordered _ _

theorem grant_status_ordered (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    output.val.Pairwise (StableNormalization.before grantStatusSourceKey) := by
  rw [grant_status_normal_form input output accepted]
  exact StableNormalization.ordered _ _

/-- Exact complete-record subsequences are retained for every observed ID,
including collisions. This is stronger than a set or count claim. -/
theorem grants_ties (input output : alloc.vec.Vec auths_model.SignedGrant)
    (target : Option (List Nat))
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    StableNormalization.bucket grantSourceKey target output.val =
      StableNormalization.bucket grantSourceKey target input.val := by
  rw [grants_normal_form input output accepted]
  exact StableNormalization.bucket_preserved _ _ _

theorem principal_status_ties (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (target : Option (List Nat))
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    StableNormalization.bucket principalStatusSourceKey target output.val =
      StableNormalization.bucket principalStatusSourceKey target input.val := by
  rw [principal_status_normal_form input output accepted]
  exact StableNormalization.bucket_preserved _ _ _

theorem grant_status_ties (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (target : Option (List Nat))
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    StableNormalization.bucket grantStatusSourceKey target output.val =
      StableNormalization.bucket grantStatusSourceKey target input.val := by
  rw [grant_status_normal_form input output accepted]
  exact StableNormalization.bucket_preserved _ _ _

syntax "auths_normalizer_exists " term "," term "," term "," term "," term
  " at " ident "," ident "," ident : tactic

macro_rules
| `(tactic| auths_normalizer_exists $source, $derive, $deriveExists, $sortLaw, $entryKey
    at $input:ident, $within:ident, $hashes:ident) =>
  `(tactic|
    (obtain ⟨keyed, derived⟩ := $deriveExists $input $within $hashes
     unfold $source
     rw [derived]
     simp only [Bind.bind, Aeneas.Std.bind, bind_tc_ok,
       core.result.Result.Insts.CoreOpsTry.branch,
       core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
       core.convert.FromSame, core.convert.FromSame.from]
     rw [$sortLaw, bind_tc_ok]
     obtain ⟨output, projected, _⟩ := spec_imp_exists
       (OwnedRecords.unkey_exact (SnapshotOrdering.sortedByKey $entryKey keyed))
     exact ⟨output, by simp only [projected, bind_tc_ok]⟩))

theorem grants_exist_when_ids_succeed (input : alloc.vec.Vec auths_model.SignedGrant)
    (within : input.val.length ≤ 256)
    (hashes : ∀ record ∈ input.val, ∃ id, hash.grant_id record.statement = ok (.Ok id)) :
    ∃ output, canonical_value.normalize_grants input = ok (.Ok output) := by
  auths_normalizer_exists canonical_value.normalize_grants, canonical_value.derive_grant_keys,
    KeyDerivation.grant_keys_exist, grant_sort_exact, grantKey at input, within, hashes

theorem principal_status_exist_when_ids_succeed
    (input : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (within : input.val.length ≤ 512)
    (hashes : ∀ record ∈ input.val, ∃ id, hash.principal_status_id record.statement = ok (.Ok id)) :
    ∃ output, canonical_value.normalize_principal_status input = ok (.Ok output) := by
  auths_normalizer_exists canonical_value.normalize_principal_status,
    canonical_value.derive_principal_status_keys, KeyDerivation.principal_status_keys_exist,
    principal_status_sort_exact, principalStatusKey at input, within, hashes

theorem grant_status_exist_when_ids_succeed
    (input : alloc.vec.Vec auths_model.SignedGrantStatus)
    (within : input.val.length ≤ 512)
    (hashes : ∀ record ∈ input.val, ∃ id, hash.grant_status_id record.statement = ok (.Ok id)) :
    ∃ output, canonical_value.normalize_grant_status input = ok (.Ok output) := by
  auths_normalizer_exists canonical_value.normalize_grant_status,
    canonical_value.derive_grant_status_keys, KeyDerivation.grant_status_keys_exist,
    grant_status_sort_exact, grantStatusKey at input, within, hashes

syntax "auths_normalizer_repeats " term "," term "," term "," term "," term "," term "," term
  " at " ident "," ident "," ident : tactic

macro_rules
| `(tactic| auths_normalizer_repeats $exactLaw, $refusal, $maximum, $hashFn,
    $permutation, $exists, $normalForm at $input:ident, $output:ident, $accepted:ident) =>
  `(tactic|
    (obtain ⟨keyed, derived, payload, consistent, _⟩ := $exactLaw $input $output $accepted
     have within : $input.val.length ≤ $maximum := by
       by_contra oversized
       have refuses := $refusal $input (by omega)
       rw [refuses] at derived
       cases derived
     have same := $permutation $input $output $accepted
     have outputWithin : $output.val.length ≤ $maximum := by
       rw [same.length_eq]
       exact within
     have inputHashes : ∀ record ∈ $input.val,
         ∃ id, $hashFn record.statement = ok (.Ok id) := by
       intro record member
       rw [← payload] at member
       obtain ⟨entry, entryMember, recordSame⟩ := List.mem_map.mp member
       refine ⟨entry.1, ?_⟩
       rw [← recordSame]
       exact consistent entry entryMember
     have outputHashes : ∀ record ∈ $output.val,
         ∃ id, $hashFn record.statement = ok (.Ok id) := by
       intro record member
       exact inputHashes record (same.mem_iff.mp member)
     obtain ⟨repeated, repeats⟩ := $exists $output outputWithin outputHashes
     have firstForm := $normalForm $input $output $accepted
     have repeatedForm := $normalForm $output repeated repeats
     have sameValues : repeated.val = $output.val := by
       rw [repeatedForm, firstForm]
       exact StableNormalization.idempotent _ _
     have sameVector : repeated = $output := alloc.vec.contents_injective sameValues
     simpa only [sameVector] using repeats))

/-- No successful second run is assumed. The first source run earns bounds
and every needed actual ID result, so repeating normalization succeeds with
the exact same complete value, including collisions and signature ties. -/
theorem grants_idempotent (input output : alloc.vec.Vec auths_model.SignedGrant)
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    canonical_value.normalize_grants output = ok (.Ok output) := by
  auths_normalizer_repeats grants_exact, KeyDerivation.grants_over_limit, 256, hash.grant_id,
    grants_permutation, grants_exist_when_ids_succeed, grants_normal_form at input, output, accepted

theorem principal_status_idempotent (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    canonical_value.normalize_principal_status output = ok (.Ok output) := by
  auths_normalizer_repeats principal_status_exact, KeyDerivation.principal_status_over_limit, 512,
    hash.principal_status_id, principal_status_permutation,
    principal_status_exist_when_ids_succeed, principal_status_normal_form at input, output, accepted

theorem grant_status_idempotent (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    canonical_value.normalize_grant_status output = ok (.Ok output) := by
  auths_normalizer_repeats grant_status_exact, KeyDerivation.grant_status_over_limit, 512,
    hash.grant_status_id, grant_status_permutation,
    grant_status_exist_when_ids_succeed, grant_status_normal_form at input, output, accepted

end Auths.Codec.RecordNormalization
