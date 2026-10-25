import qualification.aeneas.generated.protocol_codec.Funs
import Auths.Codec.OwnedRecords
import Mathlib.Tactic

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.KeyDerivation

/- The actual derivation loops call the real record getters and ID functions.
These payload consequences make no successful-ID or expected-key premise:
outer failure/divergence and inner typed-error branches cannot satisfy actual
loop success. Totality and the independent ID/preimage meaning still require
the explicit SHA primitive contract and the complete encoding refinements. -/

macro "auths_key_effect" effect:ident : tactic => `(tactic|
  simp only [Bind.bind, Aeneas.Std.bind, bind_tc_ok, bind_tc_fail, bind_tc_div,
    core.result.Result.Insts.CoreOpsTry.branch,
    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
    core.convert.FromSame, core.convert.FromSame.from,
    Result.ok.injEq, core.result.Result.Ok.injEq, reduceCtorEq] at $effect)

syntax "auths_derive_payload " term "," term "," term "," term "," term "," term
  " at " ident "," ident "," ident "," ident "," ident : tactic

macro_rules
| `(tactic| auths_derive_payload $loopFn, $loopEquation, $getter, $hasher, $recordType, $idType
    at $remaining:ident, $keyed:ident, $output:ident, $capacity:ident, $accepted:ident) =>
  `(tactic|
    (have general : ∀ count (todo : alloc.vec.Vec $recordType)
        (prefix : alloc.vec.Vec ($idType × $recordType)),
        prefix.val.length + todo.val.length ≤ Usize.max →
        todo.val.length = count →
        $loopFn todo prefix = ok (.Ok $output) →
        $output.val.map Prod.snd = prefix.val.map Prod.snd ++ todo.val.reverse := by
      intro count
      induction count using Nat.strong_induction_on with
      | h count ih =>
        intro todo prefix space sized effect
        rw [$loopEquation] at effect
        simp only [alloc.vec.Vec.pop, bind_tc_ok] at effect
        cases popped : todo.val.getLast? with
        | none =>
          simp only [popped, bind_tc_ok] at effect
          auths_key_effect effect
          have noneLeft : todo.val = [] := List.getLast?_eq_none_iff.mp popped
          have same : prefix = $output := effect
          simpa [noneLeft, same]
        | some record =>
          simp only [popped, $getter, bind_tc_ok] at effect
          cases computed : $hasher record.statement with
          | fail error =>
            simp only [computed] at effect
            auths_key_effect effect
          | div =>
            simp only [computed] at effect
            auths_key_effect effect
          | ok result =>
            cases result with
            | Err error =>
              simp only [computed] at effect
              auths_key_effect effect
            | Ok identifier =>
              simp only [computed] at effect
              auths_key_effect effect
              have positive : 0 < todo.val.length := by
                by_contra absent
                have noneLeft : todo.val = [] := List.length_eq_zero.mp (by omega)
                simp [noneLeft] at popped
              have room : prefix.val.length < Usize.max := by omega
              obtain ⟨next, pushed, appended⟩ :=
                spec_imp_exists (alloc.vec.push_spec prefix (identifier, record) room)
              simp only [pushed, bind_tc_ok] at effect
              have nextSpace : next.val.length + (alloc.vec.Vec.pop_prefix todo).val.length ≤ Usize.max := by
                simp only [appended, List.length_append, List.length_singleton,
                  alloc.vec.pop_prefix_contents, List.length_dropLast]
                omega
              have smaller : (alloc.vec.Vec.pop_prefix todo).val.length < count := by
                simp only [alloc.vec.pop_prefix_contents, List.length_dropLast]
                omega
              have recurse := ih (alloc.vec.Vec.pop_prefix todo).val.length smaller
                (alloc.vec.Vec.pop_prefix todo) next nextSpace rfl effect
              have reassembled := alloc.vec.pop_reassembles todo
              rw [popped] at reassembled
              simp only [Option.toList_some] at reassembled
              have reversed : todo.val.reverse = record :: (alloc.vec.Vec.pop_prefix todo).val.reverse := by
                calc
                  todo.val.reverse = ((alloc.vec.Vec.pop_prefix todo).val ++ [record]).reverse :=
                    congrArg List.reverse reassembled.symm
                  _ = _ := by simp
              rw [recurse, appended, reversed]
              simp [List.append_assoc]
     exact general $remaining.val.length $remaining $keyed $capacity rfl $accepted))

syntax "auths_derive_key_consistency " term "," term "," term "," term "," term "," term
  " at " ident "," ident "," ident "," ident "," ident "," ident : tactic

macro_rules
| `(tactic| auths_derive_key_consistency $loopFn, $loopEquation, $getter, $hasher, $recordType, $idType
    at $remaining:ident, $keyed:ident, $output:ident, $capacity:ident, $prefixKeys:ident, $accepted:ident) =>
  `(tactic|
    (have general : ∀ count (todo : alloc.vec.Vec $recordType)
        (prefix : alloc.vec.Vec ($idType × $recordType)),
        prefix.val.length + todo.val.length ≤ Usize.max →
        todo.val.length = count →
        (∀ entry ∈ prefix.val, $hasher entry.2.statement = ok (.Ok entry.1)) →
        $loopFn todo prefix = ok (.Ok $output) →
        ∀ entry ∈ $output.val, $hasher entry.2.statement = ok (.Ok entry.1) := by
      intro count
      induction count using Nat.strong_induction_on with
      | h count ih =>
        intro todo prefix space sized labelled effect
        rw [$loopEquation] at effect
        simp only [alloc.vec.Vec.pop, bind_tc_ok] at effect
        cases popped : todo.val.getLast? with
        | none =>
          simp only [popped, bind_tc_ok] at effect
          auths_key_effect effect
          have same : prefix = $output := effect
          simpa [same] using labelled
        | some record =>
          simp only [popped, $getter, bind_tc_ok] at effect
          cases computed : $hasher record.statement with
          | fail error =>
            simp only [computed] at effect
            auths_key_effect effect
          | div =>
            simp only [computed] at effect
            auths_key_effect effect
          | ok result =>
            cases result with
            | Err error =>
              simp only [computed] at effect
              auths_key_effect effect
            | Ok identifier =>
              simp only [computed] at effect
              auths_key_effect effect
              have positive : 0 < todo.val.length := by
                by_contra absent
                have noneLeft : todo.val = [] := List.length_eq_zero.mp (by omega)
                simp [noneLeft] at popped
              have room : prefix.val.length < Usize.max := by omega
              obtain ⟨next, pushed, appended⟩ :=
                spec_imp_exists (alloc.vec.push_spec prefix (identifier, record) room)
              simp only [pushed, bind_tc_ok] at effect
              have nextSpace : next.val.length + (alloc.vec.Vec.pop_prefix todo).val.length ≤ Usize.max := by
                simp only [appended, List.length_append, List.length_singleton,
                  alloc.vec.pop_prefix_contents, List.length_dropLast]
                omega
              have nextLabelled : ∀ entry ∈ next.val,
                  $hasher entry.2.statement = ok (.Ok entry.1) := by
                intro entry member
                rw [appended] at member
                rcases List.mem_append.mp member with previous | current
                · exact labelled entry previous
                · have same : entry = (identifier, record) := List.mem_singleton.mp current
                  subst entry
                  exact computed
              have smaller : (alloc.vec.Vec.pop_prefix todo).val.length < count := by
                simp only [alloc.vec.pop_prefix_contents, List.length_dropLast]
                omega
              exact ih (alloc.vec.Vec.pop_prefix todo).val.length smaller
                (alloc.vec.Vec.pop_prefix todo) next nextSpace rfl nextLabelled effect
     exact general $remaining.val.length $remaining $keyed $capacity rfl $prefixKeys $accepted))

variable [primitive : Auths.Crypto.Sha256Primitives]

theorem grant_keys_loop_payload
    (remaining : alloc.vec.Vec auths_model.SignedGrant)
    (keyed output : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant))
    (capacity : keyed.val.length + remaining.val.length ≤ Usize.max)
    (accepted : canonical_value.derive_grant_keys_loop remaining keyed = ok (.Ok output)) :
    output.val.map Prod.snd = keyed.val.map Prod.snd ++ remaining.val.reverse := by
  auths_derive_payload canonical_value.derive_grant_keys_loop,
    canonical_value.derive_grant_keys_loop.eq_def,
    auths_model.SignedGrant.impl.statement, hash.grant_id,
    auths_model.SignedGrant, auths_model.GrantId
    at remaining, keyed, output, capacity, accepted

theorem principal_status_keys_loop_payload
    (remaining : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (keyed output : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus))
    (capacity : keyed.val.length + remaining.val.length ≤ Usize.max)
    (accepted : canonical_value.derive_principal_status_keys_loop remaining keyed = ok (.Ok output)) :
    output.val.map Prod.snd = keyed.val.map Prod.snd ++ remaining.val.reverse := by
  auths_derive_payload canonical_value.derive_principal_status_keys_loop,
    canonical_value.derive_principal_status_keys_loop.eq_def,
    auths_model.SignedPrincipalStatus.impl.statement, hash.principal_status_id,
    auths_model.SignedPrincipalStatus, auths_model.PrincipalStatusId
    at remaining, keyed, output, capacity, accepted

theorem grant_status_keys_loop_payload
    (remaining : alloc.vec.Vec auths_model.SignedGrantStatus)
    (keyed output : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus))
    (capacity : keyed.val.length + remaining.val.length ≤ Usize.max)
    (accepted : canonical_value.derive_grant_status_keys_loop remaining keyed = ok (.Ok output)) :
    output.val.map Prod.snd = keyed.val.map Prod.snd ++ remaining.val.reverse := by
  auths_derive_payload canonical_value.derive_grant_status_keys_loop,
    canonical_value.derive_grant_status_keys_loop.eq_def,
    auths_model.SignedGrantStatus.impl.statement, hash.grant_status_id,
    auths_model.SignedGrantStatus, auths_model.GrantStatusId
    at remaining, keyed, output, capacity, accepted

/-- Every newly carried ID is the result of the actual hash call for that
complete record. Prefix consistency is a loop invariant, not a successful-hash
premise imposed on the incoming records. -/
theorem grant_keys_loop_consistent
    (remaining : alloc.vec.Vec auths_model.SignedGrant)
    (keyed output : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant))
    (capacity : keyed.val.length + remaining.val.length ≤ Usize.max)
    (prefixKeys : ∀ entry ∈ keyed.val, hash.grant_id entry.2.statement = ok (.Ok entry.1))
    (accepted : canonical_value.derive_grant_keys_loop remaining keyed = ok (.Ok output)) :
    ∀ entry ∈ output.val, hash.grant_id entry.2.statement = ok (.Ok entry.1) := by
  auths_derive_key_consistency canonical_value.derive_grant_keys_loop,
    canonical_value.derive_grant_keys_loop.eq_def,
    auths_model.SignedGrant.impl.statement, hash.grant_id,
    auths_model.SignedGrant, auths_model.GrantId
    at remaining, keyed, output, capacity, prefixKeys, accepted

theorem principal_status_keys_loop_consistent
    (remaining : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (keyed output : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus))
    (capacity : keyed.val.length + remaining.val.length ≤ Usize.max)
    (prefixKeys : ∀ entry ∈ keyed.val, hash.principal_status_id entry.2.statement = ok (.Ok entry.1))
    (accepted : canonical_value.derive_principal_status_keys_loop remaining keyed = ok (.Ok output)) :
    ∀ entry ∈ output.val, hash.principal_status_id entry.2.statement = ok (.Ok entry.1) := by
  auths_derive_key_consistency canonical_value.derive_principal_status_keys_loop,
    canonical_value.derive_principal_status_keys_loop.eq_def,
    auths_model.SignedPrincipalStatus.impl.statement, hash.principal_status_id,
    auths_model.SignedPrincipalStatus, auths_model.PrincipalStatusId
    at remaining, keyed, output, capacity, prefixKeys, accepted

theorem grant_status_keys_loop_consistent
    (remaining : alloc.vec.Vec auths_model.SignedGrantStatus)
    (keyed output : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus))
    (capacity : keyed.val.length + remaining.val.length ≤ Usize.max)
    (prefixKeys : ∀ entry ∈ keyed.val, hash.grant_status_id entry.2.statement = ok (.Ok entry.1))
    (accepted : canonical_value.derive_grant_status_keys_loop remaining keyed = ok (.Ok output)) :
    ∀ entry ∈ output.val, hash.grant_status_id entry.2.statement = ok (.Ok entry.1) := by
  auths_derive_key_consistency canonical_value.derive_grant_status_keys_loop,
    canonical_value.derive_grant_status_keys_loop.eq_def,
    auths_model.SignedGrantStatus.impl.statement, hash.grant_status_id,
    auths_model.SignedGrantStatus, auths_model.GrantStatusId
    at remaining, keyed, output, capacity, prefixKeys, accepted

theorem grant_keys_payload (input : alloc.vec.Vec auths_model.SignedGrant)
    (output : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant))
    (accepted : canonical_value.derive_grant_keys input = ok (.Ok output)) :
    output.val.map Prod.snd = input.val := by
  unfold canonical_value.derive_grant_keys at accepted
  simp only [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv] at accepted
  split at accepted
  · simp at accepted
  · simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut,
      Aeneas.Std.alloc.vec.Vec.deref_mut, Aeneas.Std.core.slice.Slice.reverse, bind_tc_ok] at accepted
    have meaning := grant_keys_loop_payload _ _ output (by
      simpa [alloc.vec.Vec.with_capacity, Aeneas.Std.alloc.vec.Vec.with_capacity,
        Aeneas.Std.alloc.vec.Vec.new, alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase,
        alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
        auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.val,
        auths_composition.alloc.vec.SizedList.toList_ofList] using input.property) accepted
    simpa [alloc.vec.Vec.with_capacity, Aeneas.Std.alloc.vec.Vec.with_capacity,
      Aeneas.Std.alloc.vec.Vec.new, alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase,
      alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
      auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.val,
      auths_composition.alloc.vec.SizedList.toList_ofList] using meaning

theorem principal_status_keys_payload (input : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (output : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus))
    (accepted : canonical_value.derive_principal_status_keys input = ok (.Ok output)) :
    output.val.map Prod.snd = input.val := by
  unfold canonical_value.derive_principal_status_keys at accepted
  simp only [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv] at accepted
  split at accepted
  · simp at accepted
  · simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut,
      Aeneas.Std.alloc.vec.Vec.deref_mut, Aeneas.Std.core.slice.Slice.reverse, bind_tc_ok] at accepted
    have meaning := principal_status_keys_loop_payload _ _ output (by
      simpa [alloc.vec.Vec.with_capacity, Aeneas.Std.alloc.vec.Vec.with_capacity,
        Aeneas.Std.alloc.vec.Vec.new, alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase,
        alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
        auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.val,
        auths_composition.alloc.vec.SizedList.toList_ofList] using input.property) accepted
    simpa [alloc.vec.Vec.with_capacity, Aeneas.Std.alloc.vec.Vec.with_capacity,
      Aeneas.Std.alloc.vec.Vec.new, alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase,
      alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
      auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.val,
      auths_composition.alloc.vec.SizedList.toList_ofList] using meaning

theorem grant_status_keys_payload (input : alloc.vec.Vec auths_model.SignedGrantStatus)
    (output : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus))
    (accepted : canonical_value.derive_grant_status_keys input = ok (.Ok output)) :
    output.val.map Prod.snd = input.val := by
  unfold canonical_value.derive_grant_status_keys at accepted
  simp only [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv] at accepted
  split at accepted
  · simp at accepted
  · simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut,
      Aeneas.Std.alloc.vec.Vec.deref_mut, Aeneas.Std.core.slice.Slice.reverse, bind_tc_ok] at accepted
    have meaning := grant_status_keys_loop_payload _ _ output (by
      simpa [alloc.vec.Vec.with_capacity, Aeneas.Std.alloc.vec.Vec.with_capacity,
        Aeneas.Std.alloc.vec.Vec.new, alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase,
        alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
        auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.val,
        auths_composition.alloc.vec.SizedList.toList_ofList] using input.property) accepted
    simpa [alloc.vec.Vec.with_capacity, Aeneas.Std.alloc.vec.Vec.with_capacity,
      Aeneas.Std.alloc.vec.Vec.new, alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase,
      alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
      auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.val,
      auths_composition.alloc.vec.SizedList.toList_ofList] using meaning

syntax "auths_top_key_consistency " term "," term " at " ident "," ident "," ident : tactic

macro_rules
| `(tactic| auths_top_key_consistency $derive, $loopTheorem
    at $input:ident, $output:ident, $accepted:ident) =>
  `(tactic|
    (unfold $derive at $accepted
     simp only [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv] at $accepted
     split at $accepted
     · simp at $accepted
     · simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut,
         Aeneas.Std.alloc.vec.Vec.deref_mut, Aeneas.Std.core.slice.Slice.reverse,
         bind_tc_ok] at $accepted
       have consistent := $loopTheorem _ _ $output (by
         simpa [alloc.vec.Vec.with_capacity, Aeneas.Std.alloc.vec.Vec.with_capacity,
           Aeneas.Std.alloc.vec.Vec.new, alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase,
           alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
           auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.val,
           auths_composition.alloc.vec.SizedList.toList_ofList] using $input.property)
         (by simp [alloc.vec.with_capacity_contents]) $accepted
       exact consistent))

theorem grant_keys_consistent (input : alloc.vec.Vec auths_model.SignedGrant)
    (output : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant))
    (accepted : canonical_value.derive_grant_keys input = ok (.Ok output)) :
    ∀ entry ∈ output.val, hash.grant_id entry.2.statement = ok (.Ok entry.1) := by
  auths_top_key_consistency canonical_value.derive_grant_keys, grant_keys_loop_consistent
    at input, output, accepted

theorem principal_status_keys_consistent (input : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (output : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus))
    (accepted : canonical_value.derive_principal_status_keys input = ok (.Ok output)) :
    ∀ entry ∈ output.val, hash.principal_status_id entry.2.statement = ok (.Ok entry.1) := by
  auths_top_key_consistency canonical_value.derive_principal_status_keys,
    principal_status_keys_loop_consistent at input, output, accepted

theorem grant_status_keys_consistent (input : alloc.vec.Vec auths_model.SignedGrantStatus)
    (output : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus))
    (accepted : canonical_value.derive_grant_status_keys input = ok (.Ok output)) :
    ∀ entry ∈ output.val, hash.grant_status_id entry.2.statement = ok (.Ok entry.1) := by
  auths_top_key_consistency canonical_value.derive_grant_status_keys,
    grant_status_keys_loop_consistent at input, output, accepted

syntax "auths_derive_exists " term "," term "," term "," term "," term "," term
  " at " ident "," ident "," ident "," ident : tactic

macro_rules
| `(tactic| auths_derive_exists $loopFn, $loopEquation, $getter, $hasher, $recordType, $idType
    at $remaining:ident, $keyed:ident, $capacity:ident, $hashes:ident) =>
  `(tactic|
    (have general : ∀ count (todo : alloc.vec.Vec $recordType)
        (prefix : alloc.vec.Vec ($idType × $recordType)),
        prefix.val.length + todo.val.length ≤ Usize.max →
        todo.val.length = count →
        (∀ record ∈ todo.val, ∃ identifier, $hasher record.statement = ok (.Ok identifier)) →
        ∃ output, $loopFn todo prefix = ok (.Ok output) := by
      intro count
      induction count using Nat.strong_induction_on with
      | h count ih =>
        intro todo prefix space sized allHashes
        cases popped : todo.val.getLast? with
        | none =>
          refine ⟨prefix, ?_⟩
          rw [$loopEquation]
          simp only [alloc.vec.Vec.pop, popped, bind_tc_ok]
        | some record =>
          have reassembled := alloc.vec.pop_reassembles todo
          rw [popped] at reassembled
          simp only [Option.toList_some] at reassembled
          have member : record ∈ todo.val := by
            rw [← reassembled]
            simp
          obtain ⟨identifier, computed⟩ := allHashes record member
          have positive : 0 < todo.val.length := List.length_pos_of_mem member
          have room : prefix.val.length < Usize.max := by omega
          obtain ⟨next, pushed, appended⟩ :=
            spec_imp_exists (alloc.vec.push_spec prefix (identifier, record) room)
          have nextSpace : next.val.length + (alloc.vec.Vec.pop_prefix todo).val.length ≤ Usize.max := by
            simp only [appended, List.length_append, List.length_singleton,
              alloc.vec.pop_prefix_contents, List.length_dropLast]
            omega
          have remainingHashes : ∀ value ∈ (alloc.vec.Vec.pop_prefix todo).val,
              ∃ id, $hasher value.statement = ok (.Ok id) := by
            intro value valueMember
            apply allHashes value
            rw [← reassembled]
            exact List.mem_append_left _ valueMember
          have smaller : (alloc.vec.Vec.pop_prefix todo).val.length < count := by
            simp only [alloc.vec.pop_prefix_contents, List.length_dropLast]
            omega
          obtain ⟨output, recursive⟩ := ih (alloc.vec.Vec.pop_prefix todo).val.length smaller
            (alloc.vec.Vec.pop_prefix todo) next nextSpace rfl remainingHashes
          refine ⟨output, ?_⟩
          rw [$loopEquation]
          simp only [alloc.vec.Vec.pop, popped, $getter, computed, pushed, recursive,
            Bind.bind, Aeneas.Std.bind, bind_tc_ok,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from]
     exact general $remaining.val.length $remaining $keyed $capacity rfl $hashes))

theorem grant_keys_loop_exists
    (remaining : alloc.vec.Vec auths_model.SignedGrant)
    (keyed : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant))
    (capacity : keyed.val.length + remaining.val.length ≤ Usize.max)
    (hashes : ∀ record ∈ remaining.val, ∃ id, hash.grant_id record.statement = ok (.Ok id)) :
    ∃ output, canonical_value.derive_grant_keys_loop remaining keyed = ok (.Ok output) := by
  auths_derive_exists canonical_value.derive_grant_keys_loop,
    canonical_value.derive_grant_keys_loop.eq_def,
    auths_model.SignedGrant.impl.statement, hash.grant_id,
    auths_model.SignedGrant, auths_model.GrantId at remaining, keyed, capacity, hashes

theorem principal_status_keys_loop_exists
    (remaining : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (keyed : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus))
    (capacity : keyed.val.length + remaining.val.length ≤ Usize.max)
    (hashes : ∀ record ∈ remaining.val, ∃ id, hash.principal_status_id record.statement = ok (.Ok id)) :
    ∃ output, canonical_value.derive_principal_status_keys_loop remaining keyed = ok (.Ok output) := by
  auths_derive_exists canonical_value.derive_principal_status_keys_loop,
    canonical_value.derive_principal_status_keys_loop.eq_def,
    auths_model.SignedPrincipalStatus.impl.statement, hash.principal_status_id,
    auths_model.SignedPrincipalStatus, auths_model.PrincipalStatusId at remaining, keyed, capacity, hashes

theorem grant_status_keys_loop_exists
    (remaining : alloc.vec.Vec auths_model.SignedGrantStatus)
    (keyed : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus))
    (capacity : keyed.val.length + remaining.val.length ≤ Usize.max)
    (hashes : ∀ record ∈ remaining.val, ∃ id, hash.grant_status_id record.statement = ok (.Ok id)) :
    ∃ output, canonical_value.derive_grant_status_keys_loop remaining keyed = ok (.Ok output) := by
  auths_derive_exists canonical_value.derive_grant_status_keys_loop,
    canonical_value.derive_grant_status_keys_loop.eq_def,
    auths_model.SignedGrantStatus.impl.statement, hash.grant_status_id,
    auths_model.SignedGrantStatus, auths_model.GrantStatusId at remaining, keyed, capacity, hashes

syntax "auths_top_keys_exist " term "," term "," term
  " at " ident "," ident "," ident : tactic

macro_rules
| `(tactic| auths_top_keys_exist $derive, $loopTheorem, $maximum
    at $input:ident, $within:ident, $hashes:ident) =>
  `(tactic|
    (unfold $derive
     simp only [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv, $maximum]
     split
     · omega
     · simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut,
         Aeneas.Std.alloc.vec.Vec.deref_mut, Aeneas.Std.core.slice.Slice.reverse,
         bind_tc_ok]
       apply $loopTheorem
       · simpa [alloc.vec.Vec.with_capacity, Aeneas.Std.alloc.vec.Vec.with_capacity,
           Aeneas.Std.alloc.vec.Vec.new, alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase,
           alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
           auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.val,
           auths_composition.alloc.vec.SizedList.toList_ofList] using $input.property
       · simpa [alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.val,
           auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
           auths_composition.alloc.vec.Vec.val,
           auths_composition.alloc.vec.SizedList.toList_ofList] using $hashes))

/-- A local hash-success condition is exposed explicitly here, rather than
silently treating an arbitrary foreign primitive instance as total. The
normalizer's repeated-success theorem earns this condition from its first run. -/
theorem grant_keys_exist (input : alloc.vec.Vec auths_model.SignedGrant)
    (within : input.val.length ≤ 256)
    (hashes : ∀ record ∈ input.val, ∃ id, hash.grant_id record.statement = ok (.Ok id)) :
    ∃ output, canonical_value.derive_grant_keys input = ok (.Ok output) := by
  auths_top_keys_exist canonical_value.derive_grant_keys, grant_keys_loop_exists,
    auths_model.HARD_MAX_GRANTS at input, within, hashes

theorem principal_status_keys_exist (input : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (within : input.val.length ≤ 512)
    (hashes : ∀ record ∈ input.val, ∃ id, hash.principal_status_id record.statement = ok (.Ok id)) :
    ∃ output, canonical_value.derive_principal_status_keys input = ok (.Ok output) := by
  auths_top_keys_exist canonical_value.derive_principal_status_keys, principal_status_keys_loop_exists,
    auths_model.HARD_MAX_PRINCIPAL_STATUS at input, within, hashes

theorem grant_status_keys_exist (input : alloc.vec.Vec auths_model.SignedGrantStatus)
    (within : input.val.length ≤ 512)
    (hashes : ∀ record ∈ input.val, ∃ id, hash.grant_status_id record.statement = ok (.Ok id)) :
    ∃ output, canonical_value.derive_grant_status_keys input = ok (.Ok output) := by
  auths_top_keys_exist canonical_value.derive_grant_status_keys, grant_status_keys_loop_exists,
    auths_model.HARD_MAX_GRANT_STATUS at input, within, hashes

theorem grants_over_limit (input : alloc.vec.Vec auths_model.SignedGrant)
    (over : 256 < input.val.length) :
    canonical_value.derive_grant_keys input = ok (.Err .LimitExceeded) := by
  unfold canonical_value.derive_grant_keys
  simp [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv, over]

theorem principal_status_over_limit (input : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (over : 512 < input.val.length) :
    canonical_value.derive_principal_status_keys input = ok (.Err .LimitExceeded) := by
  unfold canonical_value.derive_principal_status_keys
  simp [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv, over]

theorem grant_status_over_limit (input : alloc.vec.Vec auths_model.SignedGrantStatus)
    (over : 512 < input.val.length) :
    canonical_value.derive_grant_status_keys input = ok (.Err .LimitExceeded) := by
  unfold canonical_value.derive_grant_status_keys
  simp [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv, over]

theorem grant_sort_key_exact (entry : auths_model.GrantId × auths_model.SignedGrant) :
    canonical_value.grant_sort_key entry = ok entry.1 := rfl

theorem principal_status_sort_key_exact
    (entry : auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus) :
    canonical_value.principal_status_sort_key entry = ok entry.1 := rfl

theorem grant_status_sort_key_exact
    (entry : auths_model.GrantStatusId × auths_model.SignedGrantStatus) :
    canonical_value.grant_status_sort_key entry = ok entry.1 := rfl

end Auths.Codec.KeyDerivation
