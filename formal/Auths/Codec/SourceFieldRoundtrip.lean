import Auths.Codec.NativeFieldInverse
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.SourceFieldRoundtrip
open Refinement ProtocolEncode ObjectEncode DecodedFields NativeFieldInverse

/-- These theorems compose the real translated writer and reader. Their
well-formedness premises describe constructor-valid values independently;
they do not assume an expected parse or expected intermediate bytes. -/

@[step] theorem profile_roundtrip (self : cbor.Encoder) (value : auths_codec.auths_model.ProfileRef)
    (valid : ProfileValid (stringBytes value.id) value.version.val)
    (space : self.output.val.length + (45 + value.id.toByteArray.size) ≤ Usize.max) :
    encode.encode_profile_ref self value ⦃ encoded =>
      encoded.1 = .Ok () ∧
      decode.profile_ref ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len self.output⟩
        ⦃ decoded => decoded.1 = .Ok value ∧
          decoded.2.position.val = self.output.val.length + (profileEncoding (stringBytes value.id) value.version.val).length ⦄ ⦄ := by
  have firstBound := (identifier_earns_bound _ _ valid.1).2.1
  rw [stringBytes_length] at firstBound
  have firstCarrier : value.id.toByteArray.size ≤ U32.max := by scalar_tac
  apply spec_mono (ObjectEncode.profile_exact self value firstCarrier space)
  rintro encoded ⟨success, written⟩
  refine ⟨success, ?_⟩
  have inputBytes : byteList (alloc.vec.Vec.deref encoded.2.output).val =
      byteList self.output.val ++ (profileEncoding (stringBytes value.id) value.version.val) ++ [] := by
    simpa only [alloc.vec.Vec.deref, List.append_nil] using written
  apply spec_mono (NativeFieldInverse.profile_inverse
    ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len self.output⟩ value
    (byteList self.output.val) [] inputBytes
    (by simp [byteList, alloc.vec.Vec.len_val]) valid)
  rintro decoded ⟨same, position, _⟩
  exact ⟨same, by simpa [byteList] using position⟩

@[step] theorem permission_roundtrip (self : cbor.Encoder) (value : auths_codec.auths_model.Permission)
    (valid : PermissionValid (stringBytes value.capability) (stringBytes value.resource))
    (space : self.output.val.length + (45 + value.capability.toByteArray.size + value.resource.toByteArray.size) ≤ Usize.max) :
    encode.encode_permission self value ⦃ encoded =>
      encoded.1 = .Ok () ∧
      decode.permission ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len self.output⟩
        ⦃ decoded => decoded.1 = .Ok value ∧
          decoded.2.position.val = self.output.val.length + (permissionEncoding (stringBytes value.capability) (stringBytes value.resource)).length ⦄ ⦄ := by
  have firstBound := (identifier_earns_bound _ _ valid.1).2.1
  rw [stringBytes_length] at firstBound
  have firstCarrier : value.capability.toByteArray.size ≤ U32.max := by scalar_tac
  have secondBound := (identifier_earns_bound _ _ valid.2).2.1
  rw [stringBytes_length] at secondBound
  have secondCarrier : value.resource.toByteArray.size ≤ U32.max := by scalar_tac
  apply spec_mono (ObjectEncode.permission_exact self value firstCarrier secondCarrier space)
  rintro encoded ⟨success, written⟩
  refine ⟨success, ?_⟩
  have inputBytes : byteList (alloc.vec.Vec.deref encoded.2.output).val =
      byteList self.output.val ++ (permissionEncoding (stringBytes value.capability) (stringBytes value.resource)) ++ [] := by
    simpa only [alloc.vec.Vec.deref, List.append_nil] using written
  apply spec_mono (NativeFieldInverse.permission_inverse
    ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len self.output⟩ value
    (byteList self.output.val) [] inputBytes
    (by simp [byteList, alloc.vec.Vec.len_val]) valid)
  rintro decoded ⟨same, position, _⟩
  exact ⟨same, by simpa [byteList] using position⟩

@[step] theorem budget_roundtrip (self : cbor.Encoder) (value : auths_codec.auths_model.BudgetCeiling)
    (valid : BudgetValid (stringBytes value.algebra) value.value.val)
    (space : self.output.val.length + (45 + value.algebra.toByteArray.size) ≤ Usize.max) :
    encode.encode_budget self value ⦃ encoded =>
      encoded.1 = .Ok () ∧
      decode.budget ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len self.output⟩
        ⦃ decoded => decoded.1 = .Ok value ∧
          decoded.2.position.val = self.output.val.length + (budgetEncoding (stringBytes value.algebra) value.value.val).length ⦄ ⦄ := by
  have firstBound := (identifier_earns_bound _ _ valid.1).2.1
  rw [stringBytes_length] at firstBound
  have firstCarrier : value.algebra.toByteArray.size ≤ U32.max := by scalar_tac
  apply spec_mono (ObjectEncode.budget_exact self value firstCarrier space)
  rintro encoded ⟨success, written⟩
  refine ⟨success, ?_⟩
  have inputBytes : byteList (alloc.vec.Vec.deref encoded.2.output).val =
      byteList self.output.val ++ (budgetEncoding (stringBytes value.algebra) value.value.val) ++ [] := by
    simpa only [alloc.vec.Vec.deref, List.append_nil] using written
  apply spec_mono (NativeFieldInverse.budget_inverse
    ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len self.output⟩ value
    (byteList self.output.val) [] inputBytes
    (by simp [byteList, alloc.vec.Vec.len_val]) valid)
  rintro decoded ⟨same, position, _⟩
  exact ⟨same, by simpa [byteList] using position⟩

@[step] theorem optional_budget_roundtrip (self : cbor.Encoder)
    (value : Option auths_codec.auths_model.BudgetCeiling)
    (valid : ∀ budget ∈ value, BudgetValid (stringBytes budget.algebra) budget.value.val)
    (space : self.output.val.length + optionalBudgetCost value ≤ Usize.max) :
    encode.encode_optional_budget self value ⦃ encoded => encoded.1 = .Ok () ∧
      decode.optional_budget ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len self.output⟩
        ⦃ decoded => decoded.1 = .Ok value ∧ decoded.2.position.val = self.output.val.length +
          (optionalBudgetEncoding (value.map ObjectEncode.budgetView)).length ⦄ ⦄ := by
  have carriers : optionalBudgetStringsBounded value := by
    intro budget member
    have bounded := (identifier_earns_bound _ _ (valid budget member).1).2.1
    rw [stringBytes_length] at bounded
    scalar_tac
  apply spec_mono (ObjectEncode.optional_budget_exact self value carriers space)
  rintro encoded ⟨success, written⟩
  refine ⟨success, ?_⟩
  have inputBytes : byteList (alloc.vec.Vec.deref encoded.2.output).val = byteList self.output.val ++
      optionalBudgetEncoding (value.map ObjectEncode.budgetView) ++ [] := by
    simpa only [alloc.vec.Vec.deref, List.append_nil] using written
  apply spec_mono (NativeFieldInverse.optional_budget_inverse
    ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len self.output⟩ value
    (byteList self.output.val) [] inputBytes (by simp [byteList, alloc.vec.Vec.len_val]) valid)
  rintro decoded ⟨same, position, _⟩
  exact ⟨same, by simpa [byteList] using position⟩

end Auths.Codec.SourceFieldRoundtrip
