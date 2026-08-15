import Auths.Rich.Theorems
import qualification.aeneas.generated.authority.Funs
import Mathlib.Tactic

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP

namespace Auths.Refinement

open auths_authority

set_option maxHeartbeats 2000000

def StringBounded (value : String) : Prop :=
  value.utf8ByteSize ≤ Std.U32.max

def stringBytes (value : String) : List Std.U8 :=
  value.toByteArray.toList.map fun byte =>
    ⟨byte.toNat, by
      cases byte
      simp only [UInt8.toNat_ofBitVec, UScalarTy.U8_numBits_eq,
        Nat.reducePow]
      omega⟩

def criticalExtensionKey (extension : auths_model.CriticalExtension) :
    List Std.U8 × List Std.U8 :=
  (stringBytes extension.id, extension.bytes.val)

def criticalExtensionsKey (extensions : auths_model.CriticalExtensions) :
    List (List Std.U8 × List Std.U8) :=
  extensions.val.map criticalExtensionKey

def CriticalExtensionsBounded
    (extensions : auths_model.CriticalExtensions) : Prop :=
  ∀ extension ∈ extensions.val, StringBounded extension.id

@[step] theorem string_as_bytes_spec
    (value : String) (bounded : StringBounded value) :
    alloc.string.String.as_bytes value
      ⦃ bytes => bytes.val = stringBytes value ⦄ := by
  unfold StringBounded at bounded
  unfold alloc.string.String.as_bytes
  simp [bounded, stringBytes, Std.toStr]

@[step] theorem byte_slices_equal_spec
    (left right : Slice Std.U8) :
    auths_model.byte_slices_equal left right
      ⦃ result => result ↔ left = right ⦄ := by
  unfold auths_model.byte_slices_equal
  apply core.slice.cmp.PartialEqSlice.eq_homo_spec
  intro x y
  simp [core.cmp.impls.PartialEqU8.ne]

def CriticalExtensionPrefixEqual
    (child parent : auths_model.CriticalExtensions)
    (limit : Nat) : Prop :=
  ∀ index,
    (childInBounds : index < child.val.length) →
    (parentInBounds : index < parent.val.length) →
    index < limit →
    criticalExtensionKey child.val[index] =
      criticalExtensionKey parent.val[index]

@[step] theorem critical_extensions_equal_spec
    (child parent : auths_model.CriticalExtensions)
    (childBounded : CriticalExtensionsBounded child)
    (parentBounded : CriticalExtensionsBounded parent) :
    auths_model.critical_extensions_equal child parent
      ⦃ result => result ↔
        criticalExtensionsKey child = criticalExtensionsKey parent ⦄ := by
  unfold auths_model.critical_extensions_equal
  dsimp only
  split <;> rename_i lengthCondition
  · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
      false_iff]
    intro keysEqual
    have rawLengthEqual : child.val.length = parent.val.length := by
      simpa [criticalExtensionsKey] using congrArg List.length keysEqual
    have vectorLengthEqual :
        alloc.vec.Vec.len child = alloc.vec.Vec.len parent := by
      scalar_tac
    simp_all
  · have lengthEqual : child.val.length = parent.val.length := by
      simpa using lengthCondition
    unfold auths_model.critical_extensions_equal_loop
    apply loop.spec_decr_nat
      (measure := fun index => child.val.length - index.val)
      (inv := fun index =>
        index.val ≤ child.val.length ∧
        CriticalExtensionPrefixEqual child parent index.val)
    · intro index
      rintro ⟨indexBound, prefixEqual⟩
      unfold auths_model.critical_extensions_equal_loop.body
      dsimp only
      split <;> rename_i withinBounds
      · have childInBounds : index.val < child.val.length := by
          simpa using withinBounds
        have parentInBounds : index.val < parent.val.length := by
          simpa [← lengthEqual] using childInBounds
        step as ⟨childExtension, childExtensionEq⟩
        step as ⟨parentExtension, parentExtensionEq⟩
        have childExtensionMember : childExtension ∈ child.val := by
          rw [childExtensionEq]
          exact List.getElem_mem childInBounds
        have parentExtensionMember : parentExtension ∈ parent.val := by
          rw [parentExtensionEq]
          exact List.getElem_mem parentInBounds
        have childIdBounded : StringBounded childExtension.id :=
          childBounded childExtension childExtensionMember
        have parentIdBounded : StringBounded parentExtension.id :=
          parentBounded parentExtension parentExtensionMember
        step with string_as_bytes_spec as
          ⟨childId, childIdBytes⟩
        step with string_as_bytes_spec as
          ⟨parentId, parentIdBytes⟩
        step with byte_slices_equal_spec as ⟨idsEqual, idsIff⟩
        split <;> rename_i idCondition
        · step with byte_slices_equal_spec as
            ⟨payloadsEqual, payloadsIff⟩
          split <;> rename_i payloadCondition
          · step as ⟨nextIndex, nextIndexPost⟩
            constructor
            · scalar_tac
            · constructor
              · intro prior priorChildIn priorParentIn priorBound
                by_cases priorAtCurrent : prior = index.val
                · subst prior
                  rw [← childExtensionEq, ← parentExtensionEq]
                  apply Prod.ext
                  · simp only [criticalExtensionKey]
                    rw [← childIdBytes, ← parentIdBytes]
                    exact congrArg (fun slice : Slice Std.U8 => slice.val)
                      (idsIff.mp idCondition)
                  · simp only [criticalExtensionKey]
                    exact congrArg (fun slice : Slice Std.U8 => slice.val)
                      (payloadsIff.mp payloadCondition)
                · exact prefixEqual prior priorChildIn priorParentIn
                    (by scalar_tac)
              · scalar_tac
          · simp only [WP.spec, WP.theta, WP.wp_return,
              Bool.false_eq_true, false_iff]
            intro keysEqual
            have currentEqual := congrArg
              (fun values => values[index.val]?) keysEqual
            simp [criticalExtensionsKey, criticalExtensionKey,
              childInBounds, parentInBounds] at currentEqual
            rw [← childExtensionEq, ← parentExtensionEq] at currentEqual
            exact payloadCondition
              (payloadsIff.mpr (Subtype.ext currentEqual.2))
        · simp only [WP.spec, WP.theta, WP.wp_return,
            Bool.false_eq_true, false_iff]
          intro keysEqual
          have currentEqual := congrArg
            (fun values => values[index.val]?) keysEqual
          simp [criticalExtensionsKey, criticalExtensionKey,
            childInBounds, parentInBounds] at currentEqual
          rw [← childExtensionEq, ← parentExtensionEq] at currentEqual
          apply idCondition
          apply idsIff.mpr
          apply Subtype.ext
          rw [childIdBytes, parentIdBytes]
          exact currentEqual.1
      · simp only [WP.spec, WP.theta, WP.wp_return]
        have atEnd : index.val = child.val.length := by
          have notWithin : ¬index.val < child.val.length := by
            simpa using withinBounds
          omega
        constructor
        · intro _
          apply List.ext_get
          · simpa [criticalExtensionsKey] using lengthEqual
          · intro position childPosition parentPosition
            have childRawPosition : position < child.val.length := by
              simpa [criticalExtensionsKey] using childPosition
            have parentRawPosition : position < parent.val.length := by
              simpa [criticalExtensionsKey] using parentPosition
            simpa [criticalExtensionsKey] using
              prefixEqual position childRawPosition parentRawPosition
                (by omega)
        · intro
          trivial
    · constructor
      · simp
      · intro index childIn parentIn impossible
        simp at impossible

def OptionalCriticalExtensionsAttenuate
    (child : auths_model.CriticalExtensions)
    (parent : Option auths_model.CriticalExtensions) : Prop :=
  match parent with
  | none => True
  | some parent =>
      criticalExtensionsKey child = criticalExtensionsKey parent

instance (child : auths_model.CriticalExtensions)
    (parent : Option auths_model.CriticalExtensions) :
    Decidable (OptionalCriticalExtensionsAttenuate child parent) := by
  unfold OptionalCriticalExtensionsAttenuate
  cases parent <;> simp <;> infer_instance

@[step] theorem optional_critical_extensions_attenuate_spec
    (child : auths_model.CriticalExtensions)
    (parent : Option auths_model.CriticalExtensions)
    (childBounded : CriticalExtensionsBounded child)
    (parentBounded : ∀ extensions ∈ parent,
      CriticalExtensionsBounded extensions) :
    (match parent with
     | none => ok true
     | some parent => auths_model.critical_extensions_equal child parent)
      ⦃ result => result ↔
        OptionalCriticalExtensionsAttenuate child parent ⦄ := by
  cases parentCase : parent with
  | none =>
      simp [OptionalCriticalExtensionsAttenuate,
        WP.spec, WP.theta, WP.wp_return]
  | some parentExtensions =>
      apply spec_mono
        (critical_extensions_equal_spec child parentExtensions childBounded
          (parentBounded parentExtensions (by simp [parentCase])))
      intro result resultIff
      simpa [parentCase, OptionalCriticalExtensionsAttenuate] using resultIff

theorem slice_eq_iff_val_eq {α : Type} (left right : Slice α) :
    left = right ↔ left.val = right.val :=
  Subtype.ext_iff

@[step] theorem principal_id_equal_spec
    (left right : auths_model.PrincipalId)
    (leftBounded : StringBounded left)
    (rightBounded : StringBounded right) :
  auths_model.principal_id_equal left right
      ⦃ result => result ↔ stringBytes left = stringBytes right ⦄ := by
  unfold auths_model.principal_id_equal
  step with string_as_bytes_spec as ⟨leftSlice, leftBytes⟩
  step with string_as_bytes_spec as ⟨rightSlice, rightBytes⟩
  step with byte_slices_equal_spec as ⟨result, resultIff⟩
  rw [resultIff, slice_eq_iff_val_eq, leftBytes, rightBytes]

@[step] theorem profile_ref_equal_spec
    (left right : auths_model.ProfileRef)
    (leftBounded : StringBounded left.id)
    (rightBounded : StringBounded right.id) :
    auths_model.profile_ref_equal left right
      ⦃ result =>
        result ↔
          (left.version.val, stringBytes left.id) =
            (right.version.val, stringBytes right.id) ⦄ := by
  unfold auths_model.profile_ref_equal
  split <;> rename_i versionCondition
  · step with string_as_bytes_spec as ⟨leftSlice, leftBytes⟩
    step with string_as_bytes_spec as ⟨rightSlice, rightBytes⟩
    step with byte_slices_equal_spec as ⟨result, resultIff⟩
    rw [resultIff, slice_eq_iff_val_eq, leftBytes, rightBytes]
    constructor
    · intro equality
      exact ⟨congrArg UScalar.val versionCondition, equality⟩
    · rintro ⟨_, equality⟩
      exact equality
  · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
      false_iff, Prod.mk.injEq]
    rintro ⟨versionEquality, _⟩
    apply versionCondition
    have bitsEquality : left.version.bv = right.version.bv := by
      apply BitVec.toNat_injective
      exact versionEquality
    exact congrArg UScalar.mk bitsEquality

def ProfileSliceBounded
    (profiles : Slice auths_model.ProfileRef) : Prop :=
  ∀ profile ∈ profiles.val, StringBounded profile.id

def profileKey (profile : auths_model.ProfileRef) :
    Nat × List Std.U8 :=
  (profile.version.val, stringBytes profile.id)

def ProfilePrefixMissing
    (profiles : List auths_model.ProfileRef)
    (limit : Nat)
  (profile : auths_model.ProfileRef) : Prop :=
  ∀ index, (inBounds : index < profiles.length) → index < limit →
    profileKey profiles[index] ≠ profileKey profile

def selectedProfileAllows
    (selected : Option auths_model.ProfileRef)
    (allowed : Slice auths_model.ProfileRef)
    (child : auths_model.ProfileRef) : Prop :=
  match selected with
  | none => profileKey child ∈ allowed.val.map profileKey
  | some parent => profileKey child = profileKey parent

@[step] theorem profile_slice_contains_spec
    (profiles : Slice auths_model.ProfileRef)
    (profile : auths_model.ProfileRef)
    (profilesBounded : ProfileSliceBounded profiles)
    (profileBounded : StringBounded profile.id) :
    auths_model.profile_slice_contains profiles profile
      ⦃ result =>
        result ↔
          profileKey profile ∈ profiles.val.map profileKey ⦄ := by
  unfold auths_model.profile_slice_contains
  unfold auths_model.profile_slice_contains_loop
  apply loop.spec_decr_nat
    (measure := fun index => profiles.val.length - index.val)
    (inv := fun index =>
      index.val ≤ profiles.val.length ∧
      ProfilePrefixMissing profiles.val index.val profile)
  · intro index
    rintro ⟨indexBound, prefixMissing⟩
    unfold auths_model.profile_slice_contains_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have indexWithin : index.val < profiles.val.length := by
        simpa using withinBounds
      step as ⟨currentProfile, currentProfileEq⟩
      have currentInProfiles : currentProfile ∈ profiles.val := by
        rw [currentProfileEq]
        exact List.getElem_mem indexWithin
      have currentBounded : StringBounded currentProfile.id :=
        profilesBounded currentProfile currentInProfiles
      step with profile_ref_equal_spec as ⟨equal, equalIff⟩
      split <;> rename_i equalityCondition
      · simp only [WP.spec, WP.theta, WP.wp_return]
        constructor
        · intro
          apply List.mem_map.mpr
          exact ⟨currentProfile, currentInProfiles,
            by simpa [profileKey] using equalIff.mp equalityCondition⟩
        · intro
          trivial
      · step as ⟨nextIndex, nextIndexPost⟩
        constructor
        · scalar_tac
        · constructor
          · intro prior priorInBounds priorBound
            by_cases priorAtCurrent : prior = index.val
            · subst prior
              rw [← currentProfileEq]
              simpa [profileKey] using equalIff.not.mp equalityCondition
            · exact prefixMissing prior priorInBounds (by omega)
          · scalar_tac
    · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
        false_iff]
      intro member
      rcases List.mem_map.mp member with
        ⟨candidate, candidateInProfiles, candidateEquality⟩
      obtain ⟨candidateIndex, candidateIndexBound, candidateAtIndex⟩ :=
        List.getElem_of_mem candidateInProfiles
      have notWithin : ¬index.val < profiles.val.length := by
        simpa using withinBounds
      have indexAtEnd : index.val = profiles.val.length := by omega
      have missing :=
        prefixMissing candidateIndex candidateIndexBound (by omega)
      apply missing
      rw [candidateAtIndex]
      exact candidateEquality
  · constructor
    · simp
    · intro index inBounds impossible
      simp at impossible

@[step] theorem selected_profile_attenuates_spec
    (selected : Option auths_model.ProfileRef)
    (allowed : Slice auths_model.ProfileRef)
    (child : auths_model.ProfileRef)
    (selectedBounded : ∀ profile ∈ selected, StringBounded profile.id)
    (allowedBounded : ProfileSliceBounded allowed)
    (childBounded : StringBounded child.id) :
    auths_authority.selected_profile_attenuates selected allowed child
      ⦃ result =>
        result ↔ selectedProfileAllows selected allowed child ⦄ := by
  cases selectedEq : selected with
  | none =>
      simp only [auths_authority.selected_profile_attenuates]
      apply spec_mono
        (profile_slice_contains_spec allowed child allowedBounded childBounded)
      intro result resultIff
      simpa [selectedProfileAllows, selectedEq] using resultIff
  | some parent =>
      simp only [auths_authority.selected_profile_attenuates]
      apply spec_mono
        (profile_ref_equal_spec parent child
          (by simpa [selectedEq] using selectedBounded parent)
          childBounded)
      intro result resultIff
      rw [resultIff]
      simp [selectedProfileAllows, profileKey, eq_comm]

@[step] theorem assurance_policy_id_equal_spec
    (left right : auths_model.AssurancePolicyId)
    (leftBounded : StringBounded left)
    (rightBounded : StringBounded right) :
  auths_model.assurance_policy_id_equal left right
      ⦃ result => result ↔ stringBytes left = stringBytes right ⦄ := by
  unfold auths_model.assurance_policy_id_equal
  step with string_as_bytes_spec as ⟨leftSlice, leftBytes⟩
  step with string_as_bytes_spec as ⟨rightSlice, rightBytes⟩
  step with byte_slices_equal_spec as ⟨result, resultIff⟩
  rw [resultIff, slice_eq_iff_val_eq, leftBytes, rightBytes]

def grantIdKey (grantId : auths_model.GrantId) : List Std.U8 :=
  grantId.val

def optionalGrantIdEqual
    (left right : Option auths_model.GrantId) : Prop :=
  match left, right with
  | none, none => True
  | some left, some right => grantIdKey left = grantIdKey right
  | _, _ => False

@[step] theorem grant_id_equal_spec
    (left right : auths_model.GrantId) :
    auths_model.grant_id_equal left right
      ⦃ result => result ↔ grantIdKey left = grantIdKey right ⦄ := by
  unfold auths_model.grant_id_equal
  unfold auths_model.GrantId.as_bytes auths_model.Digest.as_bytes
  step as ⟨leftSlice, leftSliceEq⟩
  step as ⟨rightSlice, rightSliceEq⟩
  step with byte_slices_equal_spec as ⟨result, resultIff⟩
  rw [resultIff, slice_eq_iff_val_eq, leftSliceEq, rightSliceEq]
  rfl

@[step] theorem optional_grant_id_equal_spec
    (left right : Option auths_model.GrantId) :
    auths_model.optional_grant_id_equal left right
      ⦃ result =>
        result ↔ optionalGrantIdEqual left right ⦄ := by
  cases leftEq : left <;> cases rightEq : right <;>
    simp only [auths_model.optional_grant_id_equal]
  case some.some =>
    apply spec_mono (grant_id_equal_spec _ _)
    intro result resultIff
    simpa [optionalGrantIdEqual, leftEq, rightEq] using resultIff
  all_goals
    simp [optionalGrantIdEqual,
      WP.spec, WP.theta, WP.wp_return]

@[step] theorem validity_window_contains_spec
    (parent child : auths_model.ValidityWindow) :
    auths_model.validity_window_contains parent child
      ⦃ result =>
        result ↔
          parent.not_before.val ≤ child.not_before.val ∧
          child.expires_at.val ≤ parent.expires_at.val ⦄ := by
  unfold auths_model.validity_window_contains
  unfold auths_model.inclusive_window_contains
  dsimp only
  split
  · simp_all
  · simp_all

def permissionKey (permission : auths_model.Permission) :
    List Std.U8 × List Std.U8 :=
  (stringBytes permission.capability, stringBytes permission.resource)

def PermissionBounded (permission : auths_model.Permission) : Prop :=
  StringBounded permission.capability ∧ StringBounded permission.resource

@[step] theorem permissions_equal_spec
    (left right : auths_model.Permission)
    (leftBounded : PermissionBounded left)
    (rightBounded : PermissionBounded right) :
    auths_model.permissions_equal left right
      ⦃ result => result ↔ permissionKey left = permissionKey right ⦄ := by
  unfold auths_model.permissions_equal
  step with string_as_bytes_spec as ⟨leftCapability, leftCapabilityBytes⟩
  step with string_as_bytes_spec as ⟨rightCapability, rightCapabilityBytes⟩
  step with byte_slices_equal_spec as ⟨capabilitiesEqual, capabilitiesIff⟩
  split <;> rename_i capabilityCondition
  · step with string_as_bytes_spec as ⟨leftResource, leftResourceBytes⟩
    step with string_as_bytes_spec as ⟨rightResource, rightResourceBytes⟩
    step with byte_slices_equal_spec as ⟨resourcesEqual, resourcesIff⟩
    rw [resourcesIff, slice_eq_iff_val_eq, leftResourceBytes,
      rightResourceBytes]
    have capabilityEquality : stringBytes left.capability =
        stringBytes right.capability := by
      rw [← leftCapabilityBytes, ← rightCapabilityBytes]
      exact congrArg (fun slice : Slice Std.U8 => slice.val)
        (capabilitiesIff.mp capabilityCondition)
    simp [permissionKey, capabilityEquality]
  · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
      false_iff]
    intro equality
    have capabilityEquality : stringBytes left.capability =
        stringBytes right.capability := congrArg Prod.fst equality
    apply capabilityCondition
    apply capabilitiesIff.mpr
    apply (slice_eq_iff_val_eq leftCapability rightCapability).mpr
    rw [leftCapabilityBytes, rightCapabilityBytes]
    exact capabilityEquality

def PermissionSetBounded (set : auths_model.PermissionSet) : Prop :=
  ∀ permission ∈ set.val, PermissionBounded permission

def PermissionPrefixMissing
    (permissions : List auths_model.Permission)
    (limit : Nat)
    (permission : auths_model.Permission) : Prop :=
  ∀ index, (inBounds : index < permissions.length) → index < limit →
    permissionKey permissions[index] ≠ permissionKey permission

@[step] theorem permission_set_contains_spec
    (permissionSet : auths_model.PermissionSet)
    (permission : auths_model.Permission)
    (setBounded : PermissionSetBounded permissionSet)
    (permissionBounded : PermissionBounded permission) :
    auths_model.permission_set_contains permissionSet permission
      ⦃ result =>
        result ↔
          permissionKey permission ∈ permissionSet.val.map permissionKey ⦄ := by
  unfold auths_model.permission_set_contains
  unfold auths_model.permission_set_contains_loop
  apply loop.spec_decr_nat
    (measure := fun state => permissionSet.val.length - state.2.val)
    (inv := fun state =>
      state.1 = permissionSet ∧
      state.2.val ≤ permissionSet.val.length ∧
      PermissionPrefixMissing permissionSet.val state.2.val permission)
  · rintro ⟨currentSet, index⟩ ⟨rfl, indexBound, prefixMissing⟩
    have indexBound' : index.val ≤ currentSet.val.length := by
      simpa using indexBound
    have prefixMissing' :
        PermissionPrefixMissing currentSet.val index.val permission := by
      simpa using prefixMissing
    unfold auths_model.permission_set_contains_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have indexWithin : index.val < currentSet.val.length := by
        simpa using withinBounds
      step as ⟨currentPermission, currentPermissionEq⟩
      have currentInSet : currentPermission ∈ currentSet.val := by
        rw [currentPermissionEq]
        exact List.getElem_mem indexWithin
      have currentBounded : PermissionBounded currentPermission :=
        setBounded currentPermission currentInSet
      step with permissions_equal_spec as ⟨equal, equalIff⟩
      split <;> rename_i equalityCondition
      · simp only [WP.spec, WP.theta, WP.wp_return]
        constructor
        · intro
          apply List.mem_map.mpr
          exact ⟨currentPermission, currentInSet,
            equalIff.mp equalityCondition⟩
        · intro
          trivial
      · step as ⟨nextIndex, nextIndexPost⟩
        constructor
        · scalar_tac
        · constructor
          · intro prior priorInBounds priorBound
            by_cases priorAtCurrent : prior = index.val
            · subst prior
              rw [← currentPermissionEq]
              exact equalIff.not.mp equalityCondition
            · exact prefixMissing' prior priorInBounds (by omega)
          · scalar_tac
    · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
        false_iff]
      intro member
      rcases List.mem_map.mp member with ⟨candidate, candidateInSet,
        candidateEquality⟩
      obtain ⟨candidateIndex, candidateIndexBound, candidateAtIndex⟩ :=
        List.getElem_of_mem candidateInSet
      have notWithin : ¬index.val < currentSet.val.length := by
        simpa using withinBounds
      have indexAtEnd : index.val = currentSet.val.length := by omega
      have missing := prefixMissing' candidateIndex candidateIndexBound (by omega)
      apply missing
      rw [candidateAtIndex]
      exact candidateEquality
  · constructor
    · rfl
    · constructor
      · simp
      · intro index inBounds impossible
        simp at impossible

def PermissionPrefixContained
    (child parent : List auths_model.Permission)
    (limit : Nat) : Prop :=
  ∀ index, (inBounds : index < child.length) → index < limit →
    permissionKey child[index] ∈ parent.map permissionKey

@[step] theorem permission_set_is_subset_spec
    (child parent : auths_model.PermissionSet)
    (childBounded : PermissionSetBounded child)
    (parentBounded : PermissionSetBounded parent) :
    auths_model.permission_set_is_subset child parent
      ⦃ result =>
        result ↔
          ∀ key ∈ child.val.map permissionKey,
            key ∈ parent.val.map permissionKey ⦄ := by
  unfold auths_model.permission_set_is_subset
  unfold auths_model.permission_set_is_subset_loop
  apply loop.spec_decr_nat
    (measure := fun state => child.val.length - state.2.val)
    (inv := fun state =>
      state.1 = child ∧
      state.2.val ≤ child.val.length ∧
      PermissionPrefixContained child.val parent.val state.2.val)
  · rintro ⟨currentChild, index⟩ ⟨rfl, indexBound, prefixContained⟩
    have indexBound' : index.val ≤ currentChild.val.length := by
      simpa using indexBound
    have prefixContained' :
        PermissionPrefixContained currentChild.val parent.val index.val := by
      simpa using prefixContained
    unfold auths_model.permission_set_is_subset_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have indexWithin : index.val < currentChild.val.length := by
        simpa using withinBounds
      step as ⟨currentPermission, currentPermissionEq⟩
      have currentInChild : currentPermission ∈ currentChild.val := by
        rw [currentPermissionEq]
        exact List.getElem_mem indexWithin
      have currentBounded : PermissionBounded currentPermission :=
        childBounded currentPermission currentInChild
      step with permission_set_contains_spec as ⟨contained, containedIff⟩
      split <;> rename_i containmentCondition
      · step as ⟨nextIndex, nextIndexPost⟩
        constructor
        · scalar_tac
        · constructor
          · intro prior priorInBounds priorBound
            by_cases priorAtCurrent : prior = index.val
            · subst prior
              rw [← currentPermissionEq]
              exact containedIff.mp containmentCondition
            · exact prefixContained' prior priorInBounds (by omega)
          · scalar_tac
      · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
          false_iff]
        intro allContained
        apply containmentCondition
        apply containedIff.mpr
        apply allContained (permissionKey currentPermission)
        apply List.mem_map.mpr
        exact ⟨currentPermission, currentInChild, rfl⟩
    · simp only [WP.spec, WP.theta, WP.wp_return]
      constructor
      · intro _ key keyInChild
        rcases List.mem_map.mp keyInChild with
          ⟨candidate, candidateInChild, rfl⟩
        obtain ⟨candidateIndex, candidateIndexBound, candidateAtIndex⟩ :=
          List.getElem_of_mem candidateInChild
        have notWithin : ¬index.val < currentChild.val.length := by
          simpa using withinBounds
        have indexAtEnd : index.val = currentChild.val.length := by omega
        have covered :=
          prefixContained' candidateIndex candidateIndexBound (by omega)
        simpa [candidateAtIndex] using covered
      · intro
        trivial
  · constructor
    · rfl
    · constructor
      · simp
      · intro index inBounds impossible
        simp at impossible

@[step] theorem permission_set_is_subset_extensional_spec
    (child parent : auths_model.PermissionSet)
    (childBounded : PermissionSetBounded child)
    (parentBounded : PermissionSetBounded parent) :
    auths_model.permission_set_is_subset child parent
      ⦃ result =>
        result ↔ ∀ candidate ∈ child.val,
          ∃ parentCandidate ∈ parent.val,
            permissionKey parentCandidate = permissionKey candidate ⦄ := by
  apply spec_mono
    (permission_set_is_subset_spec child parent childBounded parentBounded)
  intro result resultIff
  rw [resultIff]
  simp

def audienceKey (audience : auths_model.Audience) : List Std.U8 :=
  stringBytes audience

def AudienceSetBounded (set : auths_model.AudienceSet) : Prop :=
  ∀ audience ∈ set.val, StringBounded audience

@[step] theorem audiences_equal_spec
    (left right : auths_model.Audience)
    (leftBounded : StringBounded left)
    (rightBounded : StringBounded right) :
    auths_model.audiences_equal left right
      ⦃ result => result ↔ audienceKey left = audienceKey right ⦄ := by
  unfold auths_model.audiences_equal audienceKey
  step with string_as_bytes_spec as ⟨leftSlice, leftBytes⟩
  step with string_as_bytes_spec as ⟨rightSlice, rightBytes⟩
  step with byte_slices_equal_spec as ⟨result, resultIff⟩
  rw [resultIff, slice_eq_iff_val_eq, leftBytes, rightBytes]

def AudiencePrefixMissing
    (audiences : List auths_model.Audience)
    (limit : Nat)
    (audience : auths_model.Audience) : Prop :=
  ∀ index, (inBounds : index < audiences.length) → index < limit →
    audienceKey audiences[index] ≠ audienceKey audience

@[step] theorem audience_set_contains_spec
    (audienceSet : auths_model.AudienceSet)
    (audience : auths_model.Audience)
    (setBounded : AudienceSetBounded audienceSet)
    (audienceBounded : StringBounded audience) :
    auths_model.audience_set_contains audienceSet audience
      ⦃ result =>
        result ↔ audienceKey audience ∈ audienceSet.val.map audienceKey ⦄ := by
  unfold auths_model.audience_set_contains
  unfold auths_model.audience_set_contains_loop
  apply loop.spec_decr_nat
    (measure := fun state => audienceSet.val.length - state.2.val)
    (inv := fun state =>
      state.1 = audienceSet ∧
      state.2.val ≤ audienceSet.val.length ∧
      AudiencePrefixMissing audienceSet.val state.2.val audience)
  · rintro ⟨currentSet, index⟩ ⟨rfl, indexBound, prefixMissing⟩
    have indexBound' : index.val ≤ currentSet.val.length := by
      simpa using indexBound
    have prefixMissing' :
        AudiencePrefixMissing currentSet.val index.val audience := by
      simpa using prefixMissing
    unfold auths_model.audience_set_contains_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have indexWithin : index.val < currentSet.val.length := by
        simpa using withinBounds
      step as ⟨currentAudience, currentAudienceEq⟩
      have currentInSet : currentAudience ∈ currentSet.val := by
        rw [currentAudienceEq]
        exact List.getElem_mem indexWithin
      have currentBounded : StringBounded currentAudience :=
        setBounded currentAudience currentInSet
      step with audiences_equal_spec as ⟨equal, equalIff⟩
      split <;> rename_i equalityCondition
      · simp only [WP.spec, WP.theta, WP.wp_return]
        constructor
        · intro
          apply List.mem_map.mpr
          exact ⟨currentAudience, currentInSet,
            equalIff.mp equalityCondition⟩
        · intro
          trivial
      · step as ⟨nextIndex, nextIndexPost⟩
        constructor
        · scalar_tac
        · constructor
          · intro prior priorInBounds priorBound
            by_cases priorAtCurrent : prior = index.val
            · subst prior
              rw [← currentAudienceEq]
              exact equalIff.not.mp equalityCondition
            · exact prefixMissing' prior priorInBounds (by omega)
          · scalar_tac
    · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
        false_iff]
      intro member
      rcases List.mem_map.mp member with
        ⟨candidate, candidateInSet, candidateEquality⟩
      obtain ⟨candidateIndex, candidateIndexBound, candidateAtIndex⟩ :=
        List.getElem_of_mem candidateInSet
      have notWithin : ¬index.val < currentSet.val.length := by
        simpa using withinBounds
      have indexAtEnd : index.val = currentSet.val.length := by omega
      have missing :=
        prefixMissing' candidateIndex candidateIndexBound (by omega)
      apply missing
      rw [candidateAtIndex]
      exact candidateEquality
  · constructor
    · rfl
    · constructor
      · simp
      · intro index inBounds impossible
        simp at impossible

def AudiencePrefixContained
    (child parent : List auths_model.Audience)
    (limit : Nat) : Prop :=
  ∀ index, (inBounds : index < child.length) → index < limit →
    audienceKey child[index] ∈ parent.map audienceKey

@[step] theorem audience_set_is_subset_spec
    (child parent : auths_model.AudienceSet)
    (childBounded : AudienceSetBounded child)
    (parentBounded : AudienceSetBounded parent) :
    auths_model.audience_set_is_subset child parent
      ⦃ result =>
        result ↔
          ∀ key ∈ child.val.map audienceKey,
            key ∈ parent.val.map audienceKey ⦄ := by
  unfold auths_model.audience_set_is_subset
  unfold auths_model.audience_set_is_subset_loop
  apply loop.spec_decr_nat
    (measure := fun state => child.val.length - state.2.val)
    (inv := fun state =>
      state.1 = child ∧
      state.2.val ≤ child.val.length ∧
      AudiencePrefixContained child.val parent.val state.2.val)
  · rintro ⟨currentChild, index⟩ ⟨rfl, indexBound, prefixContained⟩
    have indexBound' : index.val ≤ currentChild.val.length := by
      simpa using indexBound
    have prefixContained' :
        AudiencePrefixContained currentChild.val parent.val index.val := by
      simpa using prefixContained
    unfold auths_model.audience_set_is_subset_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have indexWithin : index.val < currentChild.val.length := by
        simpa using withinBounds
      step as ⟨currentAudience, currentAudienceEq⟩
      have currentInChild : currentAudience ∈ currentChild.val := by
        rw [currentAudienceEq]
        exact List.getElem_mem indexWithin
      have currentBounded : StringBounded currentAudience :=
        childBounded currentAudience currentInChild
      step with audience_set_contains_spec as ⟨contained, containedIff⟩
      split <;> rename_i containmentCondition
      · step as ⟨nextIndex, nextIndexPost⟩
        constructor
        · scalar_tac
        · constructor
          · intro prior priorInBounds priorBound
            by_cases priorAtCurrent : prior = index.val
            · subst prior
              rw [← currentAudienceEq]
              exact containedIff.mp containmentCondition
            · exact prefixContained' prior priorInBounds (by omega)
          · scalar_tac
      · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
          false_iff]
        intro allContained
        apply containmentCondition
        apply containedIff.mpr
        apply allContained (audienceKey currentAudience)
        apply List.mem_map.mpr
        exact ⟨currentAudience, currentInChild, rfl⟩
    · simp only [WP.spec, WP.theta, WP.wp_return]
      constructor
      · intro _ key keyInChild
        rcases List.mem_map.mp keyInChild with
          ⟨candidate, candidateInChild, rfl⟩
        obtain ⟨candidateIndex, candidateIndexBound, candidateAtIndex⟩ :=
          List.getElem_of_mem candidateInChild
        have notWithin : ¬index.val < currentChild.val.length := by
          simpa using withinBounds
        have indexAtEnd : index.val = currentChild.val.length := by omega
        have covered :=
          prefixContained' candidateIndex candidateIndexBound (by omega)
        simpa [candidateAtIndex] using covered
      · intro
        trivial
  · constructor
    · rfl
    · constructor
      · simp
      · intro index inBounds impossible
        simp at impossible

@[step] theorem audience_set_is_subset_extensional_spec
    (child parent : auths_model.AudienceSet)
    (childBounded : AudienceSetBounded child)
    (parentBounded : AudienceSetBounded parent) :
    auths_model.audience_set_is_subset child parent
      ⦃ result =>
        result ↔ ∀ candidate ∈ child.val,
          ∃ parentCandidate ∈ parent.val,
            audienceKey parentCandidate = audienceKey candidate ⦄ := by
  apply spec_mono
    (audience_set_is_subset_spec child parent childBounded parentBounded)
  intro result resultIff
  rw [resultIff]
  simp

def digestKey (digest : auths_model.Digest) : List Std.U8 :=
  digest.val

@[step] theorem digests_equal_spec
    (left right : auths_model.Digest) :
  auths_model.digests_equal left right
      ⦃ result => result ↔ digestKey left = digestKey right ⦄ := by
  unfold auths_model.digests_equal
  unfold core.array.Array.as_slice
  step with byte_slices_equal_spec as ⟨result, resultIff⟩
  rw [resultIff, slice_eq_iff_val_eq]
  rfl

def DigestPrefixMissing
    (digests : List auths_model.Digest)
    (limit : Nat)
    (digest : auths_model.Digest) : Prop :=
  ∀ index, (inBounds : index < digests.length) → index < limit →
    digestKey digests[index] ≠ digestKey digest

@[step] theorem body_digest_set_contains_spec
    (digestSet : auths_model.BodyDigestSet)
    (digest : auths_model.Digest) :
    auths_model.body_digest_set_contains digestSet digest
      ⦃ result =>
        result ↔ digestKey digest ∈ digestSet.val.map digestKey ⦄ := by
  unfold auths_model.body_digest_set_contains
  unfold auths_model.body_digest_set_contains_loop
  apply loop.spec_decr_nat
    (measure := fun state => digestSet.val.length - state.2.val)
    (inv := fun state =>
      state.1 = digestSet ∧
      state.2.val ≤ digestSet.val.length ∧
      DigestPrefixMissing digestSet.val state.2.val digest)
  · rintro ⟨currentSet, index⟩ ⟨rfl, indexBound, prefixMissing⟩
    have indexBound' : index.val ≤ currentSet.val.length := by
      simpa using indexBound
    have prefixMissing' :
        DigestPrefixMissing currentSet.val index.val digest := by
      simpa using prefixMissing
    unfold auths_model.body_digest_set_contains_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have indexWithin : index.val < currentSet.val.length := by
        simpa using withinBounds
      step as ⟨currentDigest, currentDigestEq⟩
      have currentInSet : currentDigest ∈ currentSet.val := by
        rw [currentDigestEq]
        exact List.getElem_mem indexWithin
      step with digests_equal_spec as ⟨equal, equalIff⟩
      split <;> rename_i equalityCondition
      · simp only [WP.spec, WP.theta, WP.wp_return]
        constructor
        · intro
          apply List.mem_map.mpr
          exact ⟨currentDigest, currentInSet,
            equalIff.mp equalityCondition⟩
        · intro
          trivial
      · step as ⟨nextIndex, nextIndexPost⟩
        · have currentSetLengthBound :
              currentSet.val.length ≤ Std.Usize.max := currentSet.property
          scalar_tac
        constructor
        · scalar_tac
        · constructor
          · intro prior priorInBounds priorBound
            by_cases priorAtCurrent : prior = index.val
            · subst prior
              rw [← currentDigestEq]
              exact equalIff.not.mp equalityCondition
            · exact prefixMissing' prior priorInBounds (by omega)
          · scalar_tac
    · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
        false_iff]
      intro member
      rcases List.mem_map.mp member with
        ⟨candidate, candidateInSet, candidateEquality⟩
      obtain ⟨candidateIndex, candidateIndexBound, candidateAtIndex⟩ :=
        List.getElem_of_mem candidateInSet
      have notWithin : ¬index.val < currentSet.val.length := by
        simpa using withinBounds
      have indexAtEnd : index.val = currentSet.val.length := by omega
      have missing :=
        prefixMissing' candidateIndex candidateIndexBound (by omega)
      apply missing
      rw [candidateAtIndex]
      exact candidateEquality
  · constructor
    · rfl
    · constructor
      · simp
      · intro index inBounds impossible
        simp at impossible

def DigestPrefixContained
    (child parent : List auths_model.Digest)
    (limit : Nat) : Prop :=
  ∀ index, (inBounds : index < child.length) → index < limit →
    digestKey child[index] ∈ parent.map digestKey

@[step] theorem body_digest_set_is_subset_spec
    (child parent : auths_model.BodyDigestSet) :
    auths_model.body_digest_set_is_subset child parent
      ⦃ result =>
        result ↔
          ∀ key ∈ child.val.map digestKey,
            key ∈ parent.val.map digestKey ⦄ := by
  unfold auths_model.body_digest_set_is_subset
  unfold auths_model.body_digest_set_is_subset_loop
  apply loop.spec_decr_nat
    (measure := fun state => child.val.length - state.2.val)
    (inv := fun state =>
      state.1 = child ∧
      state.2.val ≤ child.val.length ∧
      DigestPrefixContained child.val parent.val state.2.val)
  · rintro ⟨currentChild, index⟩ ⟨rfl, indexBound, prefixContained⟩
    have indexBound' : index.val ≤ currentChild.val.length := by
      simpa using indexBound
    have prefixContained' :
        DigestPrefixContained currentChild.val parent.val index.val := by
      simpa using prefixContained
    unfold auths_model.body_digest_set_is_subset_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have indexWithin : index.val < currentChild.val.length := by
        simpa using withinBounds
      step as ⟨currentDigest, currentDigestEq⟩
      have currentInChild : currentDigest ∈ currentChild.val := by
        rw [currentDigestEq]
        exact List.getElem_mem indexWithin
      step with body_digest_set_contains_spec as ⟨contained, containedIff⟩
      split <;> rename_i containmentCondition
      · step as ⟨nextIndex, nextIndexPost⟩
        · have currentChildLengthBound :
              currentChild.val.length ≤ Std.Usize.max := currentChild.property
          scalar_tac
        constructor
        · scalar_tac
        · constructor
          · intro prior priorInBounds priorBound
            by_cases priorAtCurrent : prior = index.val
            · subst prior
              rw [← currentDigestEq]
              exact containedIff.mp containmentCondition
            · exact prefixContained' prior priorInBounds (by omega)
          · scalar_tac
      · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
          false_iff]
        intro allContained
        apply containmentCondition
        apply containedIff.mpr
        apply allContained (digestKey currentDigest)
        apply List.mem_map.mpr
        exact ⟨currentDigest, currentInChild, rfl⟩
    · simp only [WP.spec, WP.theta, WP.wp_return]
      constructor
      · intro _ key keyInChild
        rcases List.mem_map.mp keyInChild with
          ⟨candidate, candidateInChild, rfl⟩
        obtain ⟨candidateIndex, candidateIndexBound, candidateAtIndex⟩ :=
          List.getElem_of_mem candidateInChild
        have notWithin : ¬index.val < currentChild.val.length := by
          simpa using withinBounds
        have indexAtEnd : index.val = currentChild.val.length := by omega
        have covered :=
          prefixContained' candidateIndex candidateIndexBound (by omega)
        simpa [candidateAtIndex] using covered
      · intro
        trivial
  · constructor
    · rfl
    · constructor
      · simp
      · intro index inBounds impossible
        simp at impossible

def DigestPrefixOnly
    (digests : List auths_model.Digest)
    (limit : Nat)
    (digest : auths_model.Digest) : Prop :=
  ∀ index, (inBounds : index < digests.length) → index < limit →
    digestKey digests[index] = digestKey digest

@[step] theorem body_digest_set_only_contains_spec
    (digestSet : auths_model.BodyDigestSet)
    (digest : auths_model.Digest) :
    auths_model.body_digest_set_only_contains digestSet digest
      ⦃ result =>
        result ↔ ∀ key ∈ digestSet.val.map digestKey,
          key = digestKey digest ⦄ := by
  unfold auths_model.body_digest_set_only_contains
  unfold auths_model.body_digest_set_only_contains_loop
  apply loop.spec_decr_nat
    (measure := fun state => digestSet.val.length - state.2.val)
    (inv := fun state =>
      state.1 = digestSet ∧
      state.2.val ≤ digestSet.val.length ∧
      DigestPrefixOnly digestSet.val state.2.val digest)
  · rintro ⟨currentSet, index⟩ ⟨rfl, indexBound, prefixOnly⟩
    have indexBound' : index.val ≤ currentSet.val.length := by
      simpa using indexBound
    have prefixOnly' :
        DigestPrefixOnly currentSet.val index.val digest := by
      simpa using prefixOnly
    unfold auths_model.body_digest_set_only_contains_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have indexWithin : index.val < currentSet.val.length := by
        simpa using withinBounds
      step as ⟨currentDigest, currentDigestEq⟩
      have currentInSet : currentDigest ∈ currentSet.val := by
        rw [currentDigestEq]
        exact List.getElem_mem indexWithin
      step with digests_equal_spec as ⟨equal, equalIff⟩
      split <;> rename_i equalityCondition
      · step as ⟨nextIndex, nextIndexPost⟩
        · have currentSetLengthBound :
              currentSet.val.length ≤ Std.Usize.max := currentSet.property
          scalar_tac
        constructor
        · scalar_tac
        · constructor
          · intro prior priorInBounds priorBound
            by_cases priorAtCurrent : prior = index.val
            · subst prior
              rw [← currentDigestEq]
              exact equalIff.mp equalityCondition
            · exact prefixOnly' prior priorInBounds (by omega)
          · scalar_tac
      · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
          false_iff]
        intro allEqual
        apply equalityCondition
        apply equalIff.mpr
        exact allEqual (digestKey currentDigest)
          (List.mem_map.mpr ⟨currentDigest, currentInSet, rfl⟩)
    · simp only [WP.spec, WP.theta, WP.wp_return]
      constructor
      · intro _ key keyInSet
        rcases List.mem_map.mp keyInSet with
          ⟨candidate, candidateInSet, rfl⟩
        obtain ⟨candidateIndex, candidateIndexBound, candidateAtIndex⟩ :=
          List.getElem_of_mem candidateInSet
        have notWithin : ¬index.val < currentSet.val.length := by
          simpa using withinBounds
        have indexAtEnd : index.val = currentSet.val.length := by omega
        have covered :=
          prefixOnly' candidateIndex candidateIndexBound (by omega)
        simpa [candidateAtIndex] using covered
      · intro
        trivial
  · constructor
    · rfl
    · constructor
      · simp
      · intro index inBounds impossible
        simp at impossible

abbrev productionVocabulary : Auths.Rich.Vocabulary where
  PrincipalCarrier := List Std.U8
  ProfileCarrier := Nat × List Std.U8
  PermissionCarrier := List Std.U8 × List Std.U8
  AudienceCarrier := List Std.U8
  DigestCarrier := List Std.U8
  BudgetAlgebraCarrier := List Std.U8
  StatusMethodCarrier := List Std.U8
  AssuranceCarrier := List Std.U8
  GrantIdCarrier := List Std.U8
  ExtensionIdCarrier := List Std.U8
  ExtensionBodyCarrier := List Std.U8
  principalDecidableEq := inferInstance
  profileDecidableEq := inferInstance
  permissionDecidableEq := inferInstance
  audienceDecidableEq := inferInstance
  digestDecidableEq := inferInstance
  budgetAlgebraDecidableEq := inferInstance
  statusMethodDecidableEq := inferInstance
  assuranceDecidableEq := inferInstance
  grantIdDecidableEq := inferInstance
  extensionIdDecidableEq := inferInstance
  extensionBodyDecidableEq := inferInstance

abbrev ProductionVocabulary := productionVocabulary

/-!
### Critical extensions

`criticalExtensionKey` already reads one translated extension as its canonical
`(identifier bytes, payload bytes)` pair.  The rich carrier is that same pair
in named fields, so the representation map is injective and the model's
positional equality is exactly `critical_extensions_equal`.
-/

def richCriticalExtensionOfKey (key : List Std.U8 × List Std.U8) :
    Auths.Rich.CriticalExtension ProductionVocabulary where
  id := ⟨key.1⟩
  body := ⟨key.2⟩

theorem richCriticalExtensionOfKey_injective :
    Function.Injective richCriticalExtensionOfKey := by
  rintro ⟨leftId, leftBody⟩ ⟨rightId, rightBody⟩ equality
  simpa [richCriticalExtensionOfKey, Prod.ext_iff] using equality

def richCriticalExtension (extension : auths_model.CriticalExtension) :
    Auths.Rich.CriticalExtension ProductionVocabulary :=
  richCriticalExtensionOfKey (criticalExtensionKey extension)

/--
The representation invariants `CriticalExtensions::new` establishes.

The Rust constructor rejects a repeated identifier with
`ModelError::DuplicateExtension` and rejects more than `HARD_MAX_EXTENSIONS`
entries, so every value the shipping code can hold satisfies both.  The Aeneas
translation erases the constructor, leaving a bare `Vec`, so the obligations are
carried here — the same pattern as `ValidityWindowValid` and
`SelectedProfileValid`.
-/
structure CriticalExtensionsCanonical
    (extensions : auths_model.CriticalExtensions) : Prop where
  distinctIds :
    (extensions.val.map fun extension => stringBytes extension.id).Nodup
  size : extensions.val.length ≤ Auths.Rich.hardMaxExtensions

theorem richCriticalExtension_entries
    (extensions : auths_model.CriticalExtensions) :
    extensions.val.map richCriticalExtension =
      (criticalExtensionsKey extensions).map richCriticalExtensionOfKey := by
  simp [criticalExtensionsKey, richCriticalExtension, List.map_map,
    Function.comp_def]

def richCriticalExtensions
    (extensions : auths_model.CriticalExtensions)
    (canonical : CriticalExtensionsCanonical extensions) :
    Auths.Rich.CriticalExtensions ProductionVocabulary where
  entries := extensions.val.map richCriticalExtension
  distinctIds := by
    have nodup :
        (extensions.val.map fun extension => stringBytes extension.id).Pairwise
          (· ≠ ·) := canonical.distinctIds
    rw [List.pairwise_map] at nodup
    rw [List.pairwise_map]
    refine nodup.imp ?_
    intro left right different equality
    exact different (by
      simpa [richCriticalExtension, richCriticalExtensionOfKey,
        criticalExtensionKey] using equality)
  bounded := by
    simpa using canonical.size

/--
Rich equality of two translated extension sets is exactly key-list equality.

No canonicalisation argument is needed in either direction: the rich carrier is
an ordered sequence precisely because `critical_extensions_equal` compares the
two canonical vectors positionally.
-/
@[simp] theorem richCriticalExtensions_eq_iff
    (child parent : auths_model.CriticalExtensions)
    (childCanonical : CriticalExtensionsCanonical child)
    (parentCanonical : CriticalExtensionsCanonical parent) :
    richCriticalExtensions child childCanonical =
        richCriticalExtensions parent parentCanonical ↔
      criticalExtensionsKey child = criticalExtensionsKey parent := by
  rw [Auths.Rich.CriticalExtensions.ext_iff]
  show child.val.map richCriticalExtension =
      parent.val.map richCriticalExtension ↔ _
  rw [richCriticalExtension_entries, richCriticalExtension_entries]
  exact (List.map_injective_iff.mpr richCriticalExtensionOfKey_injective).eq_iff

def richOptionalCriticalExtensions
    (extensions : Option auths_model.CriticalExtensions)
    (canonical : ∀ value ∈ extensions, CriticalExtensionsCanonical value) :
    Option (Auths.Rich.CriticalExtensions ProductionVocabulary) :=
  match extensions with
  | none => none
  | some value =>
      some (richCriticalExtensions value (canonical value rfl))

@[simp] theorem richOptionalCriticalExtensions_none
    (canonical : ∀ value ∈ (none : Option auths_model.CriticalExtensions),
      CriticalExtensionsCanonical value) :
    richOptionalCriticalExtensions none canonical = none := rfl

@[simp] theorem richOptionalCriticalExtensions_some
    (value : auths_model.CriticalExtensions)
    (canonical : ∀ candidate ∈ some value,
      CriticalExtensionsCanonical candidate) :
    richOptionalCriticalExtensions (some value) canonical =
      some (richCriticalExtensions value (canonical value rfl)) := rfl

/--
The shipping kernel's optional extension gate is exactly the rich relation.

This is what lets `Auths.Rich.evaluateGrant` own dimension 11 outright.  Before
the rich model had an `extensions` field the delegation refinement had to wrap
the rich decision in `extensionAwareDelegationDecision`, because the eleventh
dimension lived only on the Rust side of the bridge.
-/
theorem extensions_le_rich_iff
    (child : auths_model.CriticalExtensions)
    (parent : Option auths_model.CriticalExtensions)
    (childCanonical : CriticalExtensionsCanonical child)
    (parentCanonical : ∀ value ∈ parent, CriticalExtensionsCanonical value) :
    Auths.Rich.extensionsLe
        (some (richCriticalExtensions child childCanonical))
        (richOptionalCriticalExtensions parent parentCanonical) ↔
      OptionalCriticalExtensionsAttenuate child parent := by
  cases parent with
  | none =>
      simp [OptionalCriticalExtensionsAttenuate, Auths.Rich.extensionsLe]
  | some parentExtensions =>
      simp [OptionalCriticalExtensionsAttenuate, Auths.Rich.extensionsLe]

def richDigest (digest : auths_model.Digest) :
    Auths.Rich.Digest ProductionVocabulary :=
  ⟨digestKey digest⟩

theorem richDigest_eq_iff
    (left right : auths_model.Digest) :
    richDigest left = richDigest right ↔ digestKey left = digestKey right := by
  simp [richDigest]

def richActionConstraint (constraint : auths_model.ActionConstraint) :
    Auths.Rich.ActionConstraint ProductionVocabulary :=
  match constraint with
  | .AnyBody => .anyBody
  | .ExactBodyDigest digest => .exactBodyDigest (richDigest digest)
  | .AllowedBodyDigests digests =>
      .allowedBodyDigests
        ((digests.val.map richDigest).toFinset)

@[step] theorem digests_equal_rich_spec
    (left right : auths_model.Digest) :
    auths_model.digests_equal left right
      ⦃ result => result ↔ richDigest left = richDigest right ⦄ := by
  apply spec_mono (digests_equal_spec left right)
  intro result resultIff
  rw [resultIff]
  exact richDigest_eq_iff left right |>.symm

@[step] theorem body_digest_set_contains_rich_spec
    (digestSet : auths_model.BodyDigestSet)
    (digest : auths_model.Digest) :
    auths_model.body_digest_set_contains digestSet digest
      ⦃ result =>
        result ↔ ∃ candidate ∈ digestSet.val,
          richDigest candidate = richDigest digest ⦄ := by
  apply spec_mono (body_digest_set_contains_spec digestSet digest)
  intro result resultIff
  rw [resultIff]
  simp [richDigest]

@[step] theorem body_digest_set_is_subset_rich_spec
    (child parent : auths_model.BodyDigestSet) :
    auths_model.body_digest_set_is_subset child parent
      ⦃ result =>
        result ↔ ∀ candidate ∈ child.val,
          ∃ parentCandidate ∈ parent.val,
            richDigest parentCandidate = richDigest candidate ⦄ := by
  apply spec_mono (body_digest_set_is_subset_spec child parent)
  intro result resultIff
  rw [resultIff]
  simp [richDigest]

@[step] theorem body_digest_set_only_contains_rich_spec
    (digestSet : auths_model.BodyDigestSet)
    (digest : auths_model.Digest) :
    auths_model.body_digest_set_only_contains digestSet digest
      ⦃ result => result ↔
        (digestSet.val.map richDigest).toFinset ⊆ {richDigest digest} ⦄ := by
  apply spec_mono (body_digest_set_only_contains_spec digestSet digest)
  intro result resultIff
  rw [resultIff]
  simp [richDigest, Finset.subset_iff]

@[step] theorem action_constraint_allows_spec
    (constraint : auths_model.ActionConstraint)
    (digest : auths_model.Digest) :
    auths_model.action_constraint_allows constraint digest
      ⦃ result =>
        result ↔ Auths.Rich.actionConstraintAllows
          (richActionConstraint constraint) (richDigest digest) ⦄ := by
  cases constraintEq : constraint with
  | AnyBody =>
      simp [auths_model.action_constraint_allows, richActionConstraint,
        Auths.Rich.actionConstraintAllows, WP.spec, WP.theta, WP.wp_return]
  | ExactBodyDigest expected =>
      simp only [auths_model.action_constraint_allows]
      step with digests_equal_spec as ⟨result, resultIff⟩
      rw [resultIff]
      simp [richActionConstraint, richDigest,
        Auths.Rich.actionConstraintAllows, eq_comm]
  | AllowedBodyDigests allowed =>
      simp only [auths_model.action_constraint_allows]
      step with body_digest_set_contains_spec as ⟨result, resultIff⟩
      rw [resultIff]
      simp [richActionConstraint, richDigest,
        Auths.Rich.actionConstraintAllows]

@[step] theorem action_constraint_attenuates_spec
    (child parent : auths_model.ActionConstraint) :
    auths_model.action_constraint_attenuates child parent
      ⦃ result =>
        result ↔ Auths.Rich.actionConstraintLe
          (richActionConstraint child) (richActionConstraint parent) ⦄ := by
  cases parentEq : parent <;> cases childEq : child <;>
    simp only [auths_model.action_constraint_attenuates]
  case ExactBodyDigest.ExactBodyDigest =>
    exact digests_equal_rich_spec _ _
  case ExactBodyDigest.AllowedBodyDigests =>
    apply spec_mono (body_digest_set_only_contains_rich_spec _ _)
    intro result resultIff
    rw [resultIff]
    simp [richActionConstraint, Auths.Rich.actionConstraintLe]
  case AllowedBodyDigests.ExactBodyDigest =>
    apply spec_mono (body_digest_set_contains_rich_spec _ _)
    intro result resultIff
    rw [resultIff]
    simp [richActionConstraint, Auths.Rich.actionConstraintLe]
  case AllowedBodyDigests.AllowedBodyDigests =>
    apply spec_mono (body_digest_set_is_subset_rich_spec _ _)
    intro result resultIff
    rw [resultIff]
    simp only [richActionConstraint, Auths.Rich.actionConstraintLe,
      Finset.subset_iff, List.mem_toFinset, List.mem_map]
    aesop
  all_goals
    simp [richActionConstraint, Auths.Rich.actionConstraintLe,
      WP.spec, WP.theta, WP.wp_return]

def BudgetBounded (budget : auths_model.BudgetCeiling) : Prop :=
  StringBounded budget.algebra

def richBudget (budget : auths_model.BudgetCeiling) :
    Auths.Rich.BudgetCeiling ProductionVocabulary where
  algebra := ⟨stringBytes budget.algebra⟩
  value := budget.value.val

@[step] theorem budget_ceiling_attenuates_spec
    (child parent : auths_model.BudgetCeiling)
    (childBounded : BudgetBounded child)
    (parentBounded : BudgetBounded parent) :
    auths_model.budget_ceiling_attenuates child parent
      ⦃ result =>
        result ↔ Auths.Rich.budgetLe
          (some (richBudget child)) (some (richBudget parent)) ⦄ := by
  unfold BudgetBounded at childBounded parentBounded
  unfold auths_model.budget_ceiling_attenuates
  step with string_as_bytes_spec as ⟨childAlgebra, childAlgebraBytes⟩
  step with string_as_bytes_spec as ⟨parentAlgebra, parentAlgebraBytes⟩
  step with byte_slices_equal_spec as ⟨algebrasEqual, algebrasIff⟩
  split <;> rename_i algebraCondition
  · simp only [WP.spec, WP.theta, WP.wp_return]
    have algebraEquality :
        stringBytes child.algebra = stringBytes parent.algebra := by
      have equality := congrArg (fun slice : Slice Std.U8 => slice.val)
        (algebrasIff.mp algebraCondition)
      rw [childAlgebraBytes, parentAlgebraBytes] at equality
      exact equality
    simp [Auths.Rich.budgetLe, richBudget, algebraEquality]
  · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
      false_iff]
    intro attenuation
    apply algebraCondition
    apply algebrasIff.mpr
    apply (slice_eq_iff_val_eq childAlgebra parentAlgebra).mpr
    rw [childAlgebraBytes, parentAlgebraBytes]
    have wrappedEquality := attenuation.1
    exact congrArg
      (fun algebra : Auths.Rich.BudgetAlgebra ProductionVocabulary =>
        algebra.value)
      wrappedEquality

def OptionalBudgetBounded
    (budget : Option auths_model.BudgetCeiling) : Prop :=
  ∀ value ∈ budget, BudgetBounded value

@[step] theorem optional_budget_attenuates_spec
    (child parent : Option auths_model.BudgetCeiling)
    (childBounded : OptionalBudgetBounded child)
    (parentBounded : OptionalBudgetBounded parent) :
    auths_model.optional_budget_attenuates child parent
      ⦃ result =>
        result ↔ Auths.Rich.budgetLe
          (child.map richBudget) (parent.map richBudget) ⦄ := by
  cases parentEq : parent <;> cases childEq : child <;>
    simp only [auths_model.optional_budget_attenuates]
  all_goals try
    simp [Auths.Rich.budgetLe, WP.spec, WP.theta, WP.wp_return]
  case some.some =>
    apply budget_ceiling_attenuates_spec
    · simpa [OptionalBudgetBounded, childEq] using childBounded
    · simpa [OptionalBudgetBounded, parentEq] using parentBounded

/--
The one input class on which the pinned Aeneas translation of
`auths_model::optional_budget_covers` is known to be stale.

The shipping Rust now answers `false` for a present ceiling with an absent
request — an action that declares no bound on what it may spend is exactly the
authority a ceiling exists to deny.  The translation replayed here predates
that correction and still answers `true` on that one pair
(`formal/qualification/aeneas/generated/model/Funs.lean`, `optional_budget_covers`,
`| none => ok true`).

Hand-editing the generated body would fabricate the claim the translation pin
asserts — "this Lean was produced from this source" — so the gap is carried as
an explicit hypothesis instead, exactly as `AuthorityStateAnchored` carries the
missing `root` field.  `translated_budget_coverage_gap_is_the_absent_request`
below pins the gap precisely and stops compiling the moment the translation is
regenerated, which is what forces this hypothesis to be deleted then.
-/
def TranslatedBudgetCoverageCurrent
    (ceiling requested : Option auths_model.BudgetCeiling) : Prop :=
  ceiling = none ∨ requested ≠ none

@[step] theorem optional_budget_covers_spec
    (ceiling requested : Option auths_model.BudgetCeiling)
    (ceilingBounded : OptionalBudgetBounded ceiling)
    (requestedBounded : OptionalBudgetBounded requested)
    (translationCurrent : TranslatedBudgetCoverageCurrent ceiling requested) :
    auths_model.optional_budget_covers ceiling requested
      ⦃ result =>
        result ↔ Auths.Rich.budgetCovers
          (ceiling.map richBudget) (requested.map richBudget) ⦄ := by
  cases ceilingEq : ceiling <;> cases requestedEq : requested <;>
    simp only [auths_model.optional_budget_covers]
  case some.none =>
    exact absurd translationCurrent (by simp [TranslatedBudgetCoverageCurrent,
      ceilingEq, requestedEq])
  case some.some =>
    unfold auths_model.BudgetCeiling.covers
    unfold auths_model.BudgetCeiling.attenuates
    apply spec_mono
      (budget_ceiling_attenuates_spec _ _
        (by simpa [OptionalBudgetBounded, requestedEq] using requestedBounded)
        (by simpa [OptionalBudgetBounded, ceilingEq] using ceilingBounded))
    intro result resultIff
    simpa [Auths.Rich.budgetCovers, Auths.Rich.budgetLe,
      ceilingEq, requestedEq] using resultIff
  all_goals
    simp [Auths.Rich.budgetCovers,
      WP.spec, WP.theta, WP.wp_return]

/--
The translation gap is exactly one pair, and it is a fail-open one.

For every bounded ceiling the pinned translation answers `true` where the
shipping semantics answer `false`.  Stating it as a theorem rather than a
comment means the staleness is itself checked evidence: once the translation is
regenerated this stops being provable, and the hypothesis
`TranslatedBudgetCoverageCurrent` must be removed in the same change.
-/
theorem translated_budget_coverage_gap_is_the_absent_request
    (ceiling : auths_model.BudgetCeiling) :
    auths_model.optional_budget_covers (some ceiling) none = ok true ∧
      ¬ Auths.Rich.budgetCovers (some (richBudget ceiling)) none := by
  constructor
  · rfl
  · simp [Auths.Rich.budgetCovers]

def StatusPolicyValid (policy : auths_model.StatusPolicy) : Prop :=
  match policy with
  | .ExpiryOnly => True
  | .SnapshotRequired method age =>
      StringBounded method ∧ 0 < age.val

def richStatus (policy : auths_model.StatusPolicy)
    (valid : StatusPolicyValid policy) :
    Auths.Rich.StatusPolicy ProductionVocabulary :=
  match policy with
  | .ExpiryOnly => .expiryOnly
  | .SnapshotRequired method age =>
      .snapshotRequired ⟨stringBytes method⟩ ⟨age.val, valid.2⟩

@[step] theorem status_policy_attenuates_spec
    (child parent : auths_model.StatusPolicy)
    (childValid : StatusPolicyValid child)
    (parentValid : StatusPolicyValid parent) :
    auths_model.status_policy_attenuates child parent
      ⦃ result =>
        result ↔ Auths.Rich.statusLe
          (richStatus child childValid) (richStatus parent parentValid) ⦄ := by
  revert childValid parentValid
  cases parent <;> cases child <;> intro childValid parentValid <;>
    simp only [auths_model.status_policy_attenuates]
  case SnapshotRequired.SnapshotRequired =>
    rename_i parentMethodValue parentAge childMethodValue childAge
    simp only [StatusPolicyValid] at childValid parentValid
    step with string_as_bytes_spec as ⟨childMethod, childMethodBytes⟩
    step with string_as_bytes_spec as ⟨parentMethod, parentMethodBytes⟩
    step with byte_slices_equal_spec as ⟨methodsEqual, methodsIff⟩
    split <;> rename_i methodCondition
    · simp only [WP.spec, WP.theta, WP.wp_return]
      have methodEquality :
          stringBytes childMethodValue =
            stringBytes parentMethodValue := by
        rw [← childMethodBytes, ← parentMethodBytes]
        exact congrArg (fun slice : Slice Std.U8 => slice.val)
          (methodsIff.mp methodCondition)
      simp [richStatus, Auths.Rich.statusLe, methodEquality]
    · simp only [WP.spec, WP.theta, WP.wp_return, Bool.false_eq_true,
        false_iff]
      intro attenuation
      apply methodCondition
      apply methodsIff.mpr
      apply (slice_eq_iff_val_eq childMethod parentMethod).mpr
      rw [childMethodBytes, parentMethodBytes]
      simpa [richStatus, Auths.Rich.statusLe] using attenuation.1
  all_goals
    simp [richStatus, Auths.Rich.statusLe, WP.spec, WP.theta, WP.wp_return]

def richProfile (profile : auths_model.ProfileRef) :
    Auths.Rich.Profile ProductionVocabulary :=
  ⟨(profile.version.val, stringBytes profile.id)⟩

def richPrincipal (principal : auths_model.PrincipalId) :
    Auths.Rich.Principal ProductionVocabulary :=
  ⟨stringBytes principal⟩

def richGrantId (grantId : auths_model.GrantId) :
    Auths.Rich.GrantId ProductionVocabulary :=
  ⟨grantIdKey grantId⟩

def richProfileSet (profiles : Slice auths_model.ProfileRef) :
    Auths.Rich.FiniteSet (Auths.Rich.Profile ProductionVocabulary) :=
  (profiles.val.map richProfile).toFinset

def richPermission (permission : auths_model.Permission) :
    Auths.Rich.Permission ProductionVocabulary :=
  ⟨permissionKey permission⟩

def richPermissionSet (permissions : auths_model.PermissionSet) :
    Auths.Rich.FiniteSet (Auths.Rich.Permission ProductionVocabulary) :=
  (permissions.val.map richPermission).toFinset

def richAudience (audience : auths_model.Audience) :
    Auths.Rich.Audience ProductionVocabulary :=
  ⟨audienceKey audience⟩

def richAudienceSet (audiences : auths_model.AudienceSet) :
    Auths.Rich.FiniteSet (Auths.Rich.Audience ProductionVocabulary) :=
  (audiences.val.map richAudience).toFinset

def ValidityWindowValid (window : auths_model.ValidityWindow) : Prop :=
  window.not_before.val ≤ window.expires_at.val

def richWindow (window : auths_model.ValidityWindow)
    (valid : ValidityWindowValid window) :
    Auths.Rich.InclusiveWindow where
  start := window.not_before.val
  finish := window.expires_at.val
  wellFormed := valid

def richAssurance (assurance : auths_model.AssurancePolicyId) :
    Auths.Rich.AssurancePolicy ProductionVocabulary :=
  ⟨stringBytes assurance⟩

@[simp] theorem richProfile_eq_iff
    (left right : auths_model.ProfileRef) :
    richProfile left = richProfile right ↔
      (left.version.val, stringBytes left.id) =
        (right.version.val, stringBytes right.id) := by
  simp [richProfile]

@[simp] theorem richPrincipal_eq_iff
    (left right : auths_model.PrincipalId) :
    richPrincipal left = richPrincipal right ↔
      stringBytes left = stringBytes right := by
  simp [richPrincipal]

@[simp] theorem richGrantId_eq_iff
    (left right : auths_model.GrantId) :
    richGrantId left = richGrantId right ↔
      grantIdKey left = grantIdKey right := by
  simp [richGrantId]

@[simp] theorem richProfileSet_mem_iff
    (profiles : Slice auths_model.ProfileRef)
    (profile : auths_model.ProfileRef) :
    richProfile profile ∈ richProfileSet profiles ↔
      profileKey profile ∈ profiles.val.map profileKey := by
  simp [richProfileSet, richProfile, profileKey]

@[simp] theorem richPermissionSet_subset_iff
    (child parent : auths_model.PermissionSet) :
    richPermissionSet child ⊆ richPermissionSet parent ↔
      ∀ key ∈ child.val.map permissionKey,
        key ∈ parent.val.map permissionKey := by
  simp only [richPermissionSet, Finset.subset_iff, List.mem_toFinset,
    List.mem_map]
  simp [richPermission]

@[simp] theorem richPermissionSet_mem_iff
    (permissions : auths_model.PermissionSet)
    (permission : auths_model.Permission) :
    richPermission permission ∈ richPermissionSet permissions ↔
      permissionKey permission ∈ permissions.val.map permissionKey := by
  simp [richPermissionSet, richPermission]

@[simp] theorem richAudienceSet_subset_iff
    (child parent : auths_model.AudienceSet) :
    richAudienceSet child ⊆ richAudienceSet parent ↔
      ∀ key ∈ child.val.map audienceKey,
        key ∈ parent.val.map audienceKey := by
  simp only [richAudienceSet, Finset.subset_iff, List.mem_toFinset,
    List.mem_map]
  simp [richAudience]

@[simp] theorem richAudienceSet_mem_iff
    (audiences : auths_model.AudienceSet)
    (audience : auths_model.Audience) :
    richAudience audience ∈ richAudienceSet audiences ↔
      audienceKey audience ∈ audiences.val.map audienceKey := by
  simp [richAudienceSet, richAudience]

@[simp] theorem richWindow_contained_iff
    (child parent : auths_model.ValidityWindow)
    (childValid : ValidityWindowValid child)
    (parentValid : ValidityWindowValid parent) :
    Auths.Rich.windowContained
      (richWindow child childValid) (richWindow parent parentValid) ↔
        parent.not_before.val ≤ child.not_before.val ∧
        child.expires_at.val ≤ parent.expires_at.val := by
  simp [Auths.Rich.windowContained, richWindow]

@[simp] theorem richAssurance_eq_iff
    (left right : auths_model.AssurancePolicyId) :
    richAssurance left = richAssurance right ↔
      stringBytes left = stringBytes right := by
  simp [richAssurance]

structure ScopeAuthorityViewValid
    (view : auths_model.ScopeAuthorityView) : Prop where
  profile : StringBounded view.profile.id
  permissions : PermissionSetBounded view.permissions
  validity : ValidityWindowValid view.validity
  audiences : AudienceSetBounded view.audiences
  budget : OptionalBudgetBounded view.budget_ceiling
  status : StatusPolicyValid view.status_policy
  assurance : StringBounded view.assurance_floor
  extensions : CriticalExtensionsBounded view.extensions
  extensionsCanonical : CriticalExtensionsCanonical view.extensions

structure SelectedProfileValid
    (selected : Option auths_model.ProfileRef)
    (allowed : Slice auths_model.ProfileRef) : Prop where
  bounded :
    ∀ profile ∈ selected, StringBounded profile.id
  allowed :
    ∀ profile ∈ selected,
      profileKey profile ∈ allowed.val.map profileKey

def richProfileScope
    (selected : Option auths_model.ProfileRef)
    (allowed : Slice auths_model.ProfileRef)
    (valid : SelectedProfileValid selected allowed) :
    Auths.Rich.ProfileScope ProductionVocabulary where
  rootAllowed := richProfileSet allowed
  selected := selected.map richProfile
  selectedAllowed := by
    intro profile equality
    cases selectedEq : selected with
    | none => simp [selectedEq] at equality
    | some selectedProfile =>
        have profileEquality :
            profile = richProfile selectedProfile := by
          simpa [selectedEq] using equality.symm
        rw [profileEquality]
        have selectedMember :
            profileKey selectedProfile ∈
              allowed.val.map profileKey := by
          exact valid.allowed selectedProfile (by simp [selectedEq])
        exact (richProfileSet_mem_iff allowed selectedProfile).mpr
          selectedMember

@[simp] theorem selected_profile_allows_rich_iff
    (selected : Option auths_model.ProfileRef)
    (allowed : Slice auths_model.ProfileRef)
    (child : auths_model.ProfileRef)
    (valid : SelectedProfileValid selected allowed) :
    selectedProfileAllows selected allowed child ↔
      Auths.Rich.profileAllows
        (richProfileScope selected allowed valid) (richProfile child) := by
  simp only [selectedProfileAllows, richProfileScope,
    Auths.Rich.profileAllows]
  cases selected <;>
    simp [richProfileSet, profileKey, richProfile, eq_comm]

@[simp] theorem optional_grant_id_equal_rich_iff
    (left right : Option auths_model.GrantId) :
    optionalGrantIdEqual left right ↔
      left.map richGrantId = right.map richGrantId := by
  cases leftEq : left <;> cases rightEq : right <;>
    simp [optionalGrantIdEqual, richGrantId_eq_iff]

structure AuthorityStateViewValid
    (view : auths_authority.AuthorityStateView) : Prop where
  subject : StringBounded view.subject
  allowedProfiles : ProfileSliceBounded view.allowed_profiles
  selectedProfile :
    SelectedProfileValid view.profile view.allowed_profiles
  permissions : PermissionSetBounded view.permissions
  validity : ValidityWindowValid view.validity
  audiences : AudienceSetBounded view.audiences
  budget : OptionalBudgetBounded view.budget_ceiling
  status : StatusPolicyValid view.status_policy
  assurance : StringBounded view.assurance_policy
  extensions : ∀ extensions ∈ view.extensions,
    CriticalExtensionsBounded extensions
  extensionsCanonical : ∀ extensions ∈ view.extensions,
    CriticalExtensionsCanonical extensions

structure GrantAuthorityViewValid
    (view : auths_model.GrantAuthorityView) : Prop where
  issuer : StringBounded view.issuer
  subject : StringBounded view.subject
  profile : StringBounded view.profile.id
  permissions : PermissionSetBounded view.permissions
  validity : ValidityWindowValid view.validity
  audiences : AudienceSetBounded view.audiences
  budget : OptionalBudgetBounded view.budget_ceiling
  status : StatusPolicyValid view.status_policy
  assurance : StringBounded view.assurance_floor
  extensions : CriticalExtensionsBounded view.extensions
  extensionsCanonical : CriticalExtensionsCanonical view.extensions

structure ActionAuthorityViewValid
    (view : auths_model.ActionAuthorityView) : Prop where
  actor : StringBounded view.actor
  profile : StringBounded view.profile.id
  permission : PermissionBounded view.permission
  requestedBudget : OptionalBudgetBounded view.requested_budget
  audience : StringBounded view.audience
  validity : ValidityWindowValid view.validity

/--
The trust root supplied to `richAuthorityState` is the root the production
state actually descends from.

`auths_authority::AuthorityStateView` gained a `root` field so the shipping
kernel can compute `root_preserved` instead of asserting it; the Aeneas
translation replayed here predates that field, so the correspondence between
the Rust root and the model root must be carried as an explicit hypothesis
until the translation is regenerated.  Regenerating it lets this predicate be
discharged as `richPrincipal view.root = root` rather than assumed.
-/
def AuthorityStateAnchored
    (root : Auths.Rich.Principal ProductionVocabulary)
    (view : auths_authority.AuthorityStateView) : Prop :=
  (view.last_grant.map richGrantId).isSome = true ∨
    root = richPrincipal view.subject

def richAuthorityState
    (root : Auths.Rich.Principal ProductionVocabulary)
    (view : auths_authority.AuthorityStateView)
    (valid : AuthorityStateViewValid view) :
    Auths.Rich.ChainState ProductionVocabulary where
  root := root
  subject := richPrincipal view.subject
  scope := {
    profileScope :=
      richProfileScope view.profile view.allowed_profiles
        valid.selectedProfile
    permissions := richPermissionSet view.permissions
    validity := richWindow view.validity valid.validity
    audiences := richAudienceSet view.audiences
    actionConstraint := richActionConstraint view.action_constraint
    budget := view.budget_ceiling.map richBudget
    status := richStatus view.status_policy valid.status
    assurance := richAssurance view.assurance_policy
    extensions :=
      richOptionalCriticalExtensions view.extensions valid.extensionsCanonical
  }
  remainingDepth := view.remaining_depth.val
  lastGrant := view.last_grant.map richGrantId

def richGrant
    (view : auths_model.GrantAuthorityView)
    (valid : GrantAuthorityViewValid view) :
    Auths.Rich.Grant ProductionVocabulary where
  issuer := richPrincipal view.issuer
  subject := richPrincipal view.subject
  profile := richProfile view.profile
  permissions := richPermissionSet view.permissions
  validity := richWindow view.validity valid.validity
  audiences := richAudienceSet view.audiences
  actionConstraint := richActionConstraint view.action_constraint
  budget := view.budget_ceiling.map richBudget
  remainingDepth := view.remaining_depth.val
  parent := view.parent.map richGrantId
  status := richStatus view.status_policy valid.status
  assurance := richAssurance view.assurance_floor
  extensions := richCriticalExtensions view.extensions valid.extensionsCanonical

def richAction
    (view : auths_model.ActionAuthorityView)
    (valid : ActionAuthorityViewValid view) :
    Auths.Rich.Action ProductionVocabulary where
  actor := richPrincipal view.actor
  terminalGrant := view.terminal_grant.map richGrantId
  profile := richProfile view.profile
  permission := richPermission view.permission
  validity := richWindow view.validity valid.validity
  audience := richAudience view.audience
  bodyDigest := richDigest view.canonical_body_digest
  requestedBudget := view.requested_budget.map richBudget

def expectedAcceptedTransition
    (grantId : auths_model.GrantId)
    (grant : auths_model.GrantAuthorityView) :
    auths_authority.AcceptedTransition where
  subject := grant.subject
  profile := grant.profile
  permissions := grant.permissions
  validity := grant.validity
  audiences := grant.audiences
  action_constraint := grant.action_constraint
  budget_ceiling := grant.budget_ceiling
  remaining_depth := grant.remaining_depth
  grant_id := grantId
  status_policy := grant.status_policy
  extensions := grant.extensions

def productionDelegationOutcome
    (decision : Auths.Rich.DelegationDecision ProductionVocabulary)
    (grantId : auths_model.GrantId)
    (grant : auths_model.GrantAuthorityView) :
    auths_authority.DelegationOutcome :=
  match decision with
  | .accepted _ =>
      .Accepted (expectedAcceptedTransition grantId grant)
  | .denied .brokenGrantChain =>
      .Denied auths_model.DenialReason.BrokenGrantChain
  | .denied .delegationExpanded =>
      .Denied auths_model.DenialReason.DelegationExpanded

def productionCoverageDecision
    (decision : Auths.Rich.CoverageDecision) :
    auths_authority.CoverageDecision :=
  match decision with
  | .authorized => .Authorized
  | .denied .brokenGrantChain =>
      .Denied auths_model.DenialReason.BrokenGrantChain
  | .denied .permissionNotGranted =>
      .Denied auths_model.DenialReason.PermissionNotGranted
  | .denied .actionOutsideValidity =>
      .Denied auths_model.DenialReason.ActionOutsideValidity
  | .denied .audienceMismatch =>
      .Denied auths_model.DenialReason.AudienceMismatch
  | .denied .actionConstraintMismatch =>
      .Denied auths_model.DenialReason.ActionConstraintMismatch
  | .denied .budgetCeilingExceeded =>
      .Denied auths_model.DenialReason.BudgetCeilingExceeded

@[step] theorem principal_id_equal_rich_spec
    (left right : auths_model.PrincipalId)
    (leftBounded : StringBounded left)
    (rightBounded : StringBounded right) :
    auths_model.principal_id_equal left right
      ⦃ result =>
        result ↔ richPrincipal left = richPrincipal right ⦄ := by
  apply spec_mono
    (principal_id_equal_spec left right leftBounded rightBounded)
  intro result resultIff
  simpa using resultIff

@[step] theorem optional_grant_id_equal_rich_spec
    (left right : Option auths_model.GrantId) :
    auths_model.optional_grant_id_equal left right
      ⦃ result =>
        result ↔ left.map richGrantId = right.map richGrantId ⦄ := by
  apply spec_mono (optional_grant_id_equal_spec left right)
  intro result resultIff
  exact resultIff.trans (optional_grant_id_equal_rich_iff left right)

@[step] theorem selected_profile_attenuates_rich_spec
    (selected : Option auths_model.ProfileRef)
    (allowed : Slice auths_model.ProfileRef)
    (child : auths_model.ProfileRef)
    (selectedValid : SelectedProfileValid selected allowed)
    (allowedBounded : ProfileSliceBounded allowed)
    (childBounded : StringBounded child.id) :
    auths_authority.selected_profile_attenuates selected allowed child
      ⦃ result =>
        result ↔ Auths.Rich.profileAllows
          (richProfileScope selected allowed selectedValid)
          (richProfile child) ⦄ := by
  apply spec_mono
    (selected_profile_attenuates_spec selected allowed child
      selectedValid.bounded allowedBounded childBounded)
  intro result resultIff
  exact resultIff.trans
    (selected_profile_allows_rich_iff
      selected allowed child selectedValid)

@[step] theorem permission_set_contains_rich_spec
    (permissions : auths_model.PermissionSet)
    (permission : auths_model.Permission)
    (permissionsBounded : PermissionSetBounded permissions)
    (permissionBounded : PermissionBounded permission) :
    auths_model.permission_set_contains permissions permission
      ⦃ result =>
        result ↔ richPermission permission ∈
          richPermissionSet permissions ⦄ := by
  apply spec_mono
    (permission_set_contains_spec permissions permission
      permissionsBounded permissionBounded)
  intro result resultIff
  simpa using resultIff

@[step] theorem audience_set_contains_rich_spec
    (audiences : auths_model.AudienceSet)
    (audience : auths_model.Audience)
    (audiencesBounded : AudienceSetBounded audiences)
    (audienceBounded : StringBounded audience) :
    auths_model.audience_set_contains audiences audience
      ⦃ result =>
        result ↔ richAudience audience ∈ richAudienceSet audiences ⦄ := by
  apply spec_mono
    (audience_set_contains_spec audiences audience
      audiencesBounded audienceBounded)
  intro result resultIff
  simpa using resultIff

@[step] theorem validity_window_contains_rich_spec
    (parent child : auths_model.ValidityWindow)
    (parentValid : ValidityWindowValid parent)
    (childValid : ValidityWindowValid child) :
    auths_model.validity_window_contains parent child
      ⦃ result =>
        result ↔ Auths.Rich.windowContained
          (richWindow child childValid)
          (richWindow parent parentValid) ⦄ := by
  apply spec_mono (validity_window_contains_spec parent child)
  intro result resultIff
  simpa using resultIff

@[step] theorem permission_set_is_subset_rich_spec
    (child parent : auths_model.PermissionSet)
    (childBounded : PermissionSetBounded child)
    (parentBounded : PermissionSetBounded parent) :
    auths_model.permission_set_is_subset child parent
      ⦃ result =>
        result ↔ richPermissionSet child ⊆
          richPermissionSet parent ⦄ := by
  apply spec_mono
    (permission_set_is_subset_spec child parent
      childBounded parentBounded)
  intro result resultIff
  simpa using resultIff

@[step] theorem audience_set_is_subset_rich_spec
    (child parent : auths_model.AudienceSet)
    (childBounded : AudienceSetBounded child)
    (parentBounded : AudienceSetBounded parent) :
    auths_model.audience_set_is_subset child parent
      ⦃ result =>
        result ↔ richAudienceSet child ⊆
          richAudienceSet parent ⦄ := by
  apply spec_mono
    (audience_set_is_subset_spec child parent
      childBounded parentBounded)
  intro result resultIff
  simpa using resultIff

@[step] theorem assurance_policy_id_equal_rich_spec
    (left right : auths_model.AssurancePolicyId)
    (leftBounded : StringBounded left)
    (rightBounded : StringBounded right) :
    auths_model.assurance_policy_id_equal left right
      ⦃ result =>
        result ↔ richAssurance left = richAssurance right ⦄ := by
  apply spec_mono
    (assurance_policy_id_equal_spec left right
      leftBounded rightBounded)
  intro result resultIff
  simpa using resultIff

@[step] theorem attenuation_checks_accept_spec
    (checks :
      auths_authority.auths_algebra_kernel.generated.AttenuationChecks) :
    auths_algebra_kernel.generated.attenuation_checks_accept
      checks
      ⦃ result =>
        result ↔
          checks.root_preserved ∧
          checks.depth_decreases ∧
          checks.profile_attenuates ∧
          checks.permissions_attenuate ∧
          checks.validity_attenuates ∧
          checks.audiences_attenuate ∧
          checks.action_constraint_attenuates ∧
          checks.budget_attenuates ∧
          checks.status_attenuates ∧
          checks.assurance_attenuates ∧
          checks.extensions_attenuate ⦄ := by
  unfold
    auths_algebra_kernel.generated.attenuation_checks_accept
  split <;> simp_all [WP.spec, WP.theta, WP.wp_return]
  split <;> simp_all [WP.wp_return]
  split <;> simp_all [WP.wp_return]
  split <;> simp_all [WP.wp_return]
  split <;> simp_all [WP.wp_return]
  split <;> simp_all [WP.wp_return]
  split <;> simp_all [WP.wp_return]
  split <;> simp_all [WP.wp_return]
  split <;> simp_all [WP.wp_return]
  split <;> simp_all [WP.wp_return]

def richAuthorScopeDecision
    (parent child : auths_model.ScopeAuthorityView)
    (parentValid : ScopeAuthorityViewValid parent)
    (childValid : ScopeAuthorityViewValid child) :
    auths_authority.AuthorScopeDecision :=
  if richProfile child.profile = richProfile parent.profile then
    if richPermissionSet child.permissions ⊆
        richPermissionSet parent.permissions then
      if Auths.Rich.windowContained
          (richWindow child.validity childValid.validity)
          (richWindow parent.validity parentValid.validity) then
        if richAudienceSet child.audiences ⊆
            richAudienceSet parent.audiences then
          if Auths.Rich.actionConstraintLe
              (richActionConstraint child.action_constraint)
              (richActionConstraint parent.action_constraint) then
            if Auths.Rich.budgetLe
                (child.budget_ceiling.map richBudget)
                (parent.budget_ceiling.map richBudget) then
              if parent.remaining_depth = 0#u16 ∨
                  child.remaining_depth ≥ parent.remaining_depth then
                .Denied .DelegationDepth
              else if Auths.Rich.statusLe
                  (richStatus child.status_policy childValid.status)
                  (richStatus parent.status_policy parentValid.status) then
                if richAssurance child.assurance_floor =
                    richAssurance parent.assurance_floor then
                  if Auths.Rich.extensionsLe
                      (some (richCriticalExtensions child.extensions
                        childValid.extensionsCanonical))
                      (some (richCriticalExtensions parent.extensions
                        parentValid.extensionsCanonical)) then
                    .Accepted
                  else .Denied .Extensions
                else .Denied .Assurance
              else .Denied .Status
            else .Denied .Budget
          else .Denied .ActionConstraint
        else .Denied .Audiences
      else .Denied .Validity
    else .Denied .Permissions
  else .Denied .Profile

/--
The mechanically translated shipping author-scope evaluator returns exactly
the decision selected by the rich authority relations, including the first
failing dimension.  Its only premises are validated Rust representation
invariants; it assumes no semantic behavior from a Rust leaf predicate.
-/
theorem translated_rust_refines_rich_spec
    (parent child : auths_model.ScopeAuthorityView)
    (parentValid : ScopeAuthorityViewValid parent)
    (childValid : ScopeAuthorityViewValid child) :
    auths_authority.evaluate_author_scope_view parent child
      ⦃ result =>
        result = richAuthorScopeDecision
          parent child parentValid childValid ⦄ := by
  rcases parentValid with
    ⟨parentProfile, parentPermissions, parentWindow, parentAudiences,
      parentBudget, parentStatus, parentAssurance, parentExtensions,
      parentExtensionsCanonical⟩
  rcases childValid with
    ⟨childProfile, childPermissions, childWindow, childAudiences,
      childBudget, childStatus, childAssurance, childExtensions,
      childExtensionsCanonical⟩
  unfold auths_authority.evaluate_author_scope_view
  unfold richAuthorScopeDecision
  step with profile_ref_equal_spec as ⟨profileAccepted, profileIff⟩
  split <;> rename_i profileCondition
  · step with permission_set_is_subset_extensional_spec as
      ⟨permissionsAccepted, permissionsIff⟩
    have profileSemantic :
        richProfile child.profile = richProfile parent.profile := by
      simpa using profileIff.mp profileCondition
    split <;> rename_i permissionsCondition
    · step with validity_window_contains_spec as
        ⟨validityAccepted, validityIff⟩
      have permissionsSemantic :
          richPermissionSet child.permissions ⊆
            richPermissionSet parent.permissions := by
        simpa using permissionsIff.mp permissionsCondition
      split <;> rename_i validityCondition
      · step with audience_set_is_subset_extensional_spec as
          ⟨audiencesAccepted, audiencesIff⟩
        have validitySemantic :
            Auths.Rich.windowContained
              (richWindow child.validity childWindow)
              (richWindow parent.validity parentWindow) := by
          simpa using validityIff.mp validityCondition
        split <;> rename_i audiencesCondition
        · step with action_constraint_attenuates_spec as
            ⟨actionAccepted, actionIff⟩
          have audiencesSemantic :
              richAudienceSet child.audiences ⊆
                richAudienceSet parent.audiences := by
            simpa using audiencesIff.mp audiencesCondition
          split <;> rename_i actionCondition
          · step with optional_budget_attenuates_spec as
              ⟨budgetAccepted, budgetIff⟩
            have actionSemantic :
                Auths.Rich.actionConstraintLe
                  (richActionConstraint child.action_constraint)
                  (richActionConstraint parent.action_constraint) :=
              actionIff.mp actionCondition
            split <;> rename_i budgetCondition
            · have budgetSemantic :
                  Auths.Rich.budgetLe
                    (child.budget_ceiling.map richBudget)
                    (parent.budget_ceiling.map richBudget) :=
                budgetIff.mp budgetCondition
              split <;> rename_i parentDepthCondition
              · simp_all
              · split <;> rename_i childDepthCondition
                · simp_all
                · step with status_policy_attenuates_spec as
                    ⟨statusAccepted, statusIff⟩
                  split <;> rename_i statusCondition
                  · step with assurance_policy_id_equal_spec as
                      ⟨assuranceAccepted, assuranceIff⟩
                    have statusSemantic :
                        Auths.Rich.statusLe
                          (richStatus child.status_policy childStatus)
                          (richStatus parent.status_policy parentStatus) :=
                      statusIff.mp statusCondition
                    split <;> rename_i assuranceCondition
                    · have assuranceSemantic :
                          richAssurance child.assurance_floor =
                            richAssurance parent.assurance_floor := by
                        simpa using assuranceIff.mp assuranceCondition
                      step with critical_extensions_equal_spec as
                        ⟨extensionsAccepted, extensionsIff⟩
                      have extensionsRich :
                          Auths.Rich.extensionsLe
                            (some (richCriticalExtensions child.extensions
                              childExtensionsCanonical))
                            (some (richCriticalExtensions parent.extensions
                              parentExtensionsCanonical)) ↔
                            criticalExtensionsKey child.extensions =
                              criticalExtensionsKey parent.extensions := by
                        simp [Auths.Rich.extensionsLe]
                      split <;> rename_i extensionsCondition
                      · have extensionsSemantic :
                            criticalExtensionsKey child.extensions =
                              criticalExtensionsKey parent.extensions :=
                          extensionsIff.mp extensionsCondition
                        simp_all
                      · have extensionsSemantic :
                            criticalExtensionsKey child.extensions ≠
                              criticalExtensionsKey parent.extensions :=
                          extensionsIff.not.mp extensionsCondition
                        simp_all
                    · have assuranceSemantic :
                          richAssurance child.assurance_floor ≠
                            richAssurance parent.assurance_floor := by
                        intro semantic
                        exact assuranceCondition
                          (assuranceIff.mpr (by simpa using semantic))
                      simp_all
                  · have statusSemantic :
                        ¬Auths.Rich.statusLe
                          (richStatus child.status_policy childStatus)
                          (richStatus parent.status_policy parentStatus) := by
                      intro semantic
                      exact statusCondition (statusIff.mpr semantic)
                    simp_all
            · have budgetSemantic :
                  ¬Auths.Rich.budgetLe
                    (child.budget_ceiling.map richBudget)
                    (parent.budget_ceiling.map richBudget) := by
                intro semantic
                exact budgetCondition (budgetIff.mpr semantic)
              simp_all
          · have actionSemantic :
                ¬Auths.Rich.actionConstraintLe
                  (richActionConstraint child.action_constraint)
                  (richActionConstraint parent.action_constraint) := by
              intro semantic
              exact actionCondition (actionIff.mpr semantic)
            simp_all
        · have audiencesSemantic :
              ¬richAudienceSet child.audiences ⊆
                richAudienceSet parent.audiences := by
            intro semantic
            exact audiencesCondition
              (audiencesIff.mpr (by simpa using semantic))
          simp_all
      · have validitySemantic :
            ¬Auths.Rich.windowContained
              (richWindow child.validity childWindow)
              (richWindow parent.validity parentWindow) := by
          intro semantic
          exact validityCondition
            (validityIff.mpr (by simpa using semantic))
        simp_all
    · have permissionsSemantic :
          ¬richPermissionSet child.permissions ⊆
            richPermissionSet parent.permissions := by
        intro semantic
        exact permissionsCondition
          (permissionsIff.mpr (by simpa using semantic))
      simp_all
  · have profileSemantic :
        richProfile child.profile ≠ richProfile parent.profile := by
      intro semantic
      exact profileCondition
        (profileIff.mpr (by simpa using semantic))
    simp [profileSemantic]

/--
The mechanically translated terminal-coverage evaluator returns exactly the
ordered rich coverage decision.  Permission and audience checks are proved as
membership.

A bounded ceiling with an absent requested budget is **excluded** by
`budgetTranslationCurrent`: on that one pair the pinned translation still
returns the pre-correction answer, so the statement would be false rather than
weak if it claimed that case.  See `TranslatedBudgetCoverageCurrent` and
`translated_budget_coverage_gap_is_the_absent_request`.
-/
theorem translated_coverage_refines_rich_spec
    (root : Auths.Rich.Principal ProductionVocabulary)
    (authority : auths_authority.AuthorityStateView)
    (action : auths_model.ActionAuthorityView)
    (authorityValid : AuthorityStateViewValid authority)
    (actionValid : ActionAuthorityViewValid action)
    (anchored : AuthorityStateAnchored root authority)
    (budgetTranslationCurrent :
      TranslatedBudgetCoverageCurrent
        authority.budget_ceiling action.requested_budget) :
    auths_authority.evaluate_action_coverage_view authority action
      ⦃ result =>
        result = productionCoverageDecision
          (Auths.Rich.evaluateCoverage
            (richAuthorityState root authority authorityValid)
            (richAction action actionValid)) ⦄ := by
  rcases authorityValid with
    ⟨authoritySubject, allowedProfiles, selectedProfile,
      authorityPermissions, authorityWindow, authorityAudiences,
      authorityBudget, authorityStatus, authorityAssurance,
      authorityExtensions, authorityExtensionsCanonical⟩
  rcases actionValid with
    ⟨actionActor, actionProfile, actionPermission, requestedBudget,
      actionAudience, actionWindow⟩
  unfold auths_authority.evaluate_action_coverage_view
  step with principal_id_equal_rich_spec as ⟨actorAccepted, actorIff⟩
  split <;> rename_i actorCondition
  · have actorSemantic :
        richPrincipal action.actor =
          richPrincipal authority.subject :=
      actorIff.mp actorCondition
    step with optional_grant_id_equal_rich_spec as
      ⟨grantAccepted, grantIff⟩
    split <;> rename_i grantCondition
    · have grantSemantic :
          action.terminal_grant.map richGrantId =
            authority.last_grant.map richGrantId :=
        grantIff.mp grantCondition
      step with selected_profile_attenuates_rich_spec as
        ⟨profileAccepted, profileIff⟩
      split <;> rename_i profileCondition
      · have profileSemantic :
            Auths.Rich.profileAllows
              (richProfileScope authority.profile
                authority.allowed_profiles selectedProfile)
              (richProfile action.profile) :=
          profileIff.mp profileCondition
        step with permission_set_contains_rich_spec as
          ⟨permissionAccepted, permissionIff⟩
        split <;> rename_i permissionCondition
        · have permissionSemantic :
              richPermission action.permission ∈
                richPermissionSet authority.permissions :=
            permissionIff.mp permissionCondition
          step with validity_window_contains_rich_spec as
            ⟨validityAccepted, validityIff⟩
          split <;> rename_i validityCondition
          · have validitySemantic :
                Auths.Rich.windowContained
                  (richWindow action.validity actionWindow)
                  (richWindow authority.validity authorityWindow) :=
              validityIff.mp validityCondition
            step with audience_set_contains_rich_spec as
              ⟨audienceAccepted, audienceIff⟩
            split <;> rename_i audienceCondition
            · have audienceSemantic :
                  richAudience action.audience ∈
                    richAudienceSet authority.audiences :=
                audienceIff.mp audienceCondition
              step with action_constraint_allows_spec as
                ⟨constraintAccepted, constraintIff⟩
              split <;> rename_i constraintCondition
              · have constraintSemantic :
                    Auths.Rich.actionConstraintAllows
                      (richActionConstraint
                        authority.action_constraint)
                      (richDigest action.canonical_body_digest) :=
                  constraintIff.mp constraintCondition
                step with optional_budget_covers_spec as
                  ⟨budgetAccepted, budgetIff⟩
                split <;> rename_i budgetCondition
                · have budgetSemantic :
                      Auths.Rich.budgetCovers
                        (authority.budget_ceiling.map richBudget)
                        (action.requested_budget.map richBudget) :=
                    budgetIff.mp budgetCondition
                  simp_all [Auths.Rich.evaluateCoverage, Auths.Rich.rooted, AuthorityStateAnchored,
                    productionCoverageDecision, richAuthorityState,
                    richAction]
                · have budgetSemantic :
                      ¬Auths.Rich.budgetCovers
                        (authority.budget_ceiling.map richBudget)
                        (action.requested_budget.map richBudget) := by
                    intro semantic
                    exact budgetCondition (budgetIff.mpr semantic)
                  simp_all [Auths.Rich.evaluateCoverage, Auths.Rich.rooted, AuthorityStateAnchored,
                    productionCoverageDecision, richAuthorityState,
                    richAction]
              · have constraintSemantic :
                    ¬Auths.Rich.actionConstraintAllows
                      (richActionConstraint
                        authority.action_constraint)
                      (richDigest action.canonical_body_digest) := by
                  intro semantic
                  exact constraintCondition
                    (constraintIff.mpr semantic)
                simp_all [Auths.Rich.evaluateCoverage, Auths.Rich.rooted, AuthorityStateAnchored,
                  productionCoverageDecision, richAuthorityState,
                  richAction]
            · have audienceSemantic :
                  richAudience action.audience ∉
                    richAudienceSet authority.audiences := by
                intro semantic
                exact audienceCondition
                  (audienceIff.mpr semantic)
              simp_all [Auths.Rich.evaluateCoverage, Auths.Rich.rooted, AuthorityStateAnchored,
                productionCoverageDecision, richAuthorityState,
                richAction]
          · have validitySemantic :
                ¬Auths.Rich.windowContained
                  (richWindow action.validity actionWindow)
                  (richWindow authority.validity authorityWindow) := by
              intro semantic
              exact validityCondition (validityIff.mpr semantic)
            simp_all [Auths.Rich.evaluateCoverage, Auths.Rich.rooted, AuthorityStateAnchored,
              productionCoverageDecision, richAuthorityState,
              richAction]
        · have permissionSemantic :
              richPermission action.permission ∉
                richPermissionSet authority.permissions := by
            intro semantic
            exact permissionCondition (permissionIff.mpr semantic)
          simp_all [Auths.Rich.evaluateCoverage, Auths.Rich.rooted, AuthorityStateAnchored,
            productionCoverageDecision, richAuthorityState,
            richAction]
      · have profileSemantic :
            ¬Auths.Rich.profileAllows
              (richProfileScope authority.profile
                authority.allowed_profiles selectedProfile)
              (richProfile action.profile) := by
          intro semantic
          exact profileCondition (profileIff.mpr semantic)
        simp_all [Auths.Rich.evaluateCoverage, Auths.Rich.rooted, AuthorityStateAnchored,
          productionCoverageDecision, richAuthorityState, richAction]
    · have grantSemantic :
          action.terminal_grant.map richGrantId ≠
            authority.last_grant.map richGrantId := by
        intro semantic
        exact grantCondition (grantIff.mpr semantic)
      simp_all [Auths.Rich.evaluateCoverage, Auths.Rich.rooted, AuthorityStateAnchored,
        productionCoverageDecision, richAuthorityState, richAction]
  · have actorSemantic :
        richPrincipal action.actor ≠
          richPrincipal authority.subject := by
      intro semantic
      exact actorCondition (actorIff.mpr semantic)
    simp_all [Auths.Rich.evaluateCoverage, Auths.Rich.rooted, AuthorityStateAnchored,
      productionCoverageDecision, richAuthorityState, richAction]

/--
The mechanically translated delegation evaluator returns the same ordered rich
delegation decision and the accepted production transition is the exact field
projection of the rich accepted next state.

All eleven attenuation dimensions are now decided by `Auths.Rich.evaluateGrant`
itself.  This statement previously wrapped the rich decision in
`extensionAwareDelegationDecision`, a post-filter that re-applied the critical
extension gate outside the model — necessarily, because `Auths.Rich.Grant` had
no `extensions` field and `delegationProjection.extensionsAttenuate` was the
literal `true`.  Removing the wrapper is what makes this a refinement of eleven
dimensions rather than of ten plus a patch.
-/
theorem translated_delegation_refines_rich_spec
    (root : Auths.Rich.Principal ProductionVocabulary)
    (parent : auths_authority.AuthorityStateView)
    (grantId : auths_model.GrantId)
    (grant : auths_model.GrantAuthorityView)
    (parentValid : AuthorityStateViewValid parent)
    (grantValid : GrantAuthorityViewValid grant)
    (anchored : AuthorityStateAnchored root parent) :
    auths_authority.evaluate_grant_view parent grantId grant
      ⦃ result =>
        result.outcome = productionDelegationOutcome
          (Auths.Rich.evaluateGrant
            (richAuthorityState root parent parentValid)
            (richGrantId grantId)
            (richGrant grant grantValid))
          grantId grant ⦄ := by
  rcases parentValid with
    ⟨parentSubject, allowedProfiles, selectedProfile,
      parentPermissions, parentWindow, parentAudiences,
      parentBudget, parentStatus, parentAssurance, parentExtensions,
      parentExtensionsCanonical⟩
  rcases grantValid with
    ⟨grantIssuer, grantSubject, grantProfile, grantPermissions,
      grantWindow, grantAudiences, grantBudget, grantStatus,
      grantAssurance, grantExtensions, grantExtensionsCanonical⟩
  unfold auths_authority.evaluate_grant_view
  split <;> rename_i parentDepthCondition
  all_goals
    step with selected_profile_attenuates_rich_spec as
      ⟨profileAccepted, profileIff⟩
    step with permission_set_is_subset_rich_spec as
      ⟨permissionsAccepted, permissionsIff⟩
    step with validity_window_contains_rich_spec as
      ⟨validityAccepted, validityIff⟩
    step with audience_set_is_subset_rich_spec as
      ⟨audiencesAccepted, audiencesIff⟩
    step with action_constraint_attenuates_spec as
      ⟨constraintAccepted, constraintIff⟩
    step with optional_budget_attenuates_spec as
      ⟨budgetAccepted, budgetIff⟩
    step with status_policy_attenuates_spec as
      ⟨statusAccepted, statusIff⟩
    step with assurance_policy_id_equal_rich_spec as
      ⟨assuranceAccepted, assuranceIff⟩
    step with optional_critical_extensions_attenuate_spec as
      ⟨extensionsAccepted, extensionsIff⟩
    step with principal_id_equal_rich_spec as
      ⟨issuerAccepted, issuerIff⟩
    split <;> rename_i issuerCondition
    · step with optional_grant_id_equal_rich_spec as
        ⟨parentGrantAccepted, parentGrantIff⟩
      split <;> rename_i parentGrantCondition
      · step with attenuation_checks_accept_spec as
          ⟨scopeAccepted, scopeIff⟩
        split <;> rename_i scopeCondition
        · simp_all [Auths.Rich.evaluateGrant, Auths.Rich.linked,
            Auths.Rich.rootPreserved, Auths.Rich.rooted, AuthorityStateAnchored,
            Auths.Rich.scopeDepthChecks, Auths.Rich.grantScopeChecks,
            productionDelegationOutcome, expectedAcceptedTransition,
            extensions_le_rich_iff, OptionalCriticalExtensionsAttenuate,
            richAuthorityState, richGrant]
        · have failedScope :
              ¬(grant.remaining_depth.val < parent.remaining_depth.val ∧
                Auths.Rich.profileAllows
                  (richProfileScope parent.profile
                    parent.allowed_profiles selectedProfile)
                  (richProfile grant.profile) ∧
                (∀ candidate ∈ grant.permissions.val,
                  ∃ parentCandidate ∈ parent.permissions.val,
                    permissionKey parentCandidate =
                      permissionKey candidate) ∧
                parent.validity.not_before.val ≤
                  grant.validity.not_before.val ∧
                grant.validity.expires_at.val ≤
                  parent.validity.expires_at.val ∧
                (∀ candidate ∈ grant.audiences.val,
                  ∃ parentCandidate ∈ parent.audiences.val,
                    audienceKey parentCandidate =
                      audienceKey candidate) ∧
                Auths.Rich.actionConstraintLe
                  (richActionConstraint grant.action_constraint)
                  (richActionConstraint parent.action_constraint) ∧
                Auths.Rich.budgetLe
                  (grant.budget_ceiling.map richBudget)
                  (parent.budget_ceiling.map richBudget) ∧
                Auths.Rich.statusLe
                  (richStatus grant.status_policy grantStatus)
                  (richStatus parent.status_policy parentStatus) ∧
                stringBytes grant.assurance_floor =
                  stringBytes parent.assurance_policy ∧
                OptionalCriticalExtensionsAttenuate
                  grant.extensions parent.extensions) := by
            rintro ⟨depth, profile, permissions, validityStart,
              validityEnd, audiences, constraint, budget, status,
              assurance, extensions⟩
            have permissionsRich :
                richPermissionSet grant.permissions ⊆
                  richPermissionSet parent.permissions := by
              simpa using permissions
            have audiencesRich :
                richAudienceSet grant.audiences ⊆
                  richAudienceSet parent.audiences := by
              simpa using audiences
            have assuranceRich :
                richAssurance grant.assurance_floor =
                  richAssurance parent.assurance_policy := by
              simpa using assurance
            have scopeTrue : scopeAccepted = true := by
              apply scopeIff.mpr
              simp_all
            simp_all
          have scopeSemantic :
              ¬Auths.Rich.scopeDepthChecks
                (richAuthorityState root parent
                  {
                    subject := parentSubject
                    allowedProfiles := allowedProfiles
                    selectedProfile := selectedProfile
                    permissions := parentPermissions
                    validity := parentWindow
                    audiences := parentAudiences
                    budget := parentBudget
                    status := parentStatus
                    assurance := parentAssurance
                    extensions := parentExtensions
                    extensionsCanonical := parentExtensionsCanonical
                  })
                (richGrant grant
                  {
                    issuer := grantIssuer
                    subject := grantSubject
                    profile := grantProfile
                    permissions := grantPermissions
                    validity := grantWindow
                    audiences := grantAudiences
                    budget := grantBudget
                    status := grantStatus
                    assurance := grantAssurance
                    extensions := grantExtensions
                    extensionsCanonical := grantExtensionsCanonical
                  }) := by
            intro checks
            apply failedScope
            have richChecks := checks.2
            simpa [Auths.Rich.scopeDepthChecks,
              Auths.Rich.grantScopeChecks, richAuthorityState,
              richGrant, extensions_le_rich_iff] using richChecks
          have linkedSemantic :
              Auths.Rich.linked
                (richAuthorityState root parent
                  {
                    subject := parentSubject
                    allowedProfiles := allowedProfiles
                    selectedProfile := selectedProfile
                    permissions := parentPermissions
                    validity := parentWindow
                    audiences := parentAudiences
                    budget := parentBudget
                    status := parentStatus
                    assurance := parentAssurance
                    extensions := parentExtensions
                    extensionsCanonical := parentExtensionsCanonical
                  })
                (richGrant grant
                  {
                    issuer := grantIssuer
                    subject := grantSubject
                    profile := grantProfile
                    permissions := grantPermissions
                    validity := grantWindow
                    audiences := grantAudiences
                    budget := grantBudget
                    status := grantStatus
                    assurance := grantAssurance
                    extensions := grantExtensions
                    extensionsCanonical := grantExtensionsCanonical
                  }) := by
            simp_all [Auths.Rich.linked, Auths.Rich.rootPreserved,
              Auths.Rich.rooted, AuthorityStateAnchored, richAuthorityState,
              richGrant]
          simp [Auths.Rich.evaluateGrant, linkedSemantic,
            scopeSemantic, productionDelegationOutcome]
      · simp_all [Auths.Rich.evaluateGrant, Auths.Rich.linked,
            Auths.Rich.rootPreserved, Auths.Rich.rooted, AuthorityStateAnchored,
          productionDelegationOutcome,
          richAuthorityState, richGrant]
    · simp_all [Auths.Rich.evaluateGrant, Auths.Rich.linked,
            Auths.Rich.rootPreserved, Auths.Rich.rooted, AuthorityStateAnchored,
        productionDelegationOutcome,
        richAuthorityState, richGrant]

end Auths.Refinement
