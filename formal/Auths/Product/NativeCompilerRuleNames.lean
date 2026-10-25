import Auths.Product.NativeCompilerRulesModel

namespace Auths.Product.NativeCompiler.Rules
open FieldProjection ScalarProjection
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

theorem name_bytes_round_trip (raw : List Nat) (bounded : ByteRange raw) :
    (nameBytes raw).toList.map UInt8.toNat = raw := by
  have converted : (raw.map UInt8.ofNat).map UInt8.toNat = raw := by
    induction raw with
    | nil => rfl
    | cons first rest ih =>
        have firstBound : first < 256 := bounded first (by simp)
        have tailBound : ByteRange rest := fun byte member => bounded byte (by simp [member])
        simpa only [List.map_cons, UInt8.toNat_ofNat_of_lt' firstBound] using
          congrArg (List.cons first) (ih tailBound)
  simpa only [nameBytes, List.toList_data_toByteArray] using converted

/-- Successful decoding is lossless. Different original byte names cannot
become aliases through UTF-8 conversion or modular UInt8 construction. -/
theorem decoded_name_has_original_bytes (raw : List Nat) (name : String)
    (decoded : decodeName raw = some name) : textBytes name = raw := by
  unfold decodeName at decoded
  split at decoded <;> rename_i bounded
  · unfold String.fromUTF8? at decoded
    split at decoded <;> rename_i valid
    · cases decoded
      simpa only [textBytes, String.fromUTF8] using name_bytes_round_trip raw bounded
    · contradiction
  · contradiction

private theorem ascii_char_encoding (byte : Nat) (ascii : byte < 128) :
    String.utf8EncodeChar (Char.ofNat byte) = [UInt8.ofNat byte] := by
  interval_cases byte <;> rfl

private theorem ascii_encoding (raw : List Nat) (ascii : ∀ byte ∈ raw, byte < 128) :
    (raw.map Char.ofNat).utf8Encode = nameBytes raw := by
  induction raw with
  | nil => simp [nameBytes]
  | cons first rest ih =>
      have firstAscii : first < 128 := ascii first (by simp)
      have tailAscii : ∀ byte ∈ rest, byte < 128 := fun byte member => ascii byte (by simp [member])
      simpa only [List.map_cons, List.utf8Encode_cons, List.utf8Encode_singleton,
        ascii_char_encoding first firstAscii, nameBytes, List.map_cons,
        ← List.toByteArray_append, List.singleton_append] using
        congrArg (fun tail => [UInt8.ofNat first].toByteArray ++ tail) (ih tailAscii)

theorem ascii_has_lossless_name (raw : List Nat) (ascii : ∀ byte ∈ raw, byte < 128) :
    ∃ name, decodeName raw = some name ∧ textBytes name = raw := by
  have bounded : ByteRange raw := by
    intro byte member
    have smaller := ascii byte member
    omega
  have valid : (nameBytes raw).IsValidUTF8 := by
    rw [← ascii_encoding raw ascii]
    exact ByteArray.isValidUTF8_utf8Encode
  let name := String.fromUTF8 (nameBytes raw) valid
  have decoded : decodeName raw = some name := by
    simp only [decodeName, if_pos bounded, String.fromUTF8?, dif_pos valid]
    rfl
  exact ⟨name, decoded, decoded_name_has_original_bytes raw name decoded⟩

theorem token_bytes_are_ascii (raw : List Nat) (maximum : Nat)
    (token : OperationIdentity.validToken raw maximum = true) : ∀ byte ∈ raw, byte < 128 := by
  cases raw with
  | nil => simp [OperationIdentity.validToken] at token
  | cons first rest =>
      simp only [OperationIdentity.validToken, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at token
      intro byte member
      rcases List.mem_cons.mp member with rfl | tail
      · have valid := token.1.2
        unfold OperationIdentity.Alphanumeric at valid
        omega
      · have valid : OperationIdentity.TailByte byte := by simpa using token.2 byte tail
        unfold OperationIdentity.TailByte OperationIdentity.Alphanumeric at valid
        omega

theorem lexical_fields_have_decoding (fields : List Field)
    (lexical : ∀ field ∈ fields, OperationIdentity.validToken field.name 64 = true) :
    ∃ decoded, decodeFields fields = some decoded := by
  induction fields with
  | nil => exact ⟨[], rfl⟩
  | cons field rest ih =>
      obtain ⟨name, nameAt, _⟩ := ascii_has_lossless_name field.name
        (token_bytes_are_ascii field.name 64 (lexical field (by simp)))
      obtain ⟨tail, tailAt⟩ := ih (fun other member => lexical other (by simp [member]))
      exact ⟨(name, field.schema) :: tail, by simp [decodeFields, nameAt, tailAt]⟩

theorem decoded_fields_keep_name_bytes (fields : List Field) (decoded : List Entry)
    (parsed : decodeFields fields = some decoded) :
    decoded.map (fun entry => textBytes entry.1) = FieldProjection.names fields := by
  have paired := decode_fields_original fields decoded parsed
  induction paired with
  | nil => rfl
  | @cons field entry rest decoded head tail ih =>
      have nameBytes := decoded_name_has_original_bytes field.name entry.1 head.1
      simp only [List.map_cons, FieldProjection.names, nameBytes]
      simpa only [FieldProjection.names] using congrArg (List.cons field.name) ih

/-- The kernel parser's independently valid layout earns every UTF-8 decode
and unique String key. No native decode-success or map-success premise is needed. -/
theorem layout_earns_rule_admission (fields : List Field) (valid : LayoutValid fields) : Admitted fields := by
  obtain ⟨decoded, parsed⟩ := lexical_fields_have_decoding fields valid.2.2
  have bytesColumn := decoded_fields_keep_name_bytes fields decoded parsed
  have bytesUnique : (decoded.map (fun entry => textBytes entry.1)).Nodup := by
    rw [bytesColumn]
    exact valid.2.1
  have namesUnique : (decoded.map Prod.fst).Nodup :=
    List.Nodup.of_map textBytes (by simpa only [List.map_map, Function.comp_def] using bytesUnique)
  exact ⟨decoded, parsed, namesUnique⟩

theorem meaning_keeps_every_original (fields : List Field) (entries : List Entry)
    (meaning : Meaning fields entries) :
    ∀ field ∈ fields, ∃ entry ∈ entries, textBytes entry.1 = field.name ∧ entry.2 = field.schema := by
  obtain ⟨decoded, parsed, _, complete, _⟩ := meaning
  have paired := decode_fields_original fields decoded parsed
  have original : ∀ field ∈ fields, ∃ entry ∈ decoded,
      textBytes entry.1 = field.name ∧ entry.2 = field.schema := by
    induction paired with
    | nil => simp
    | @cons field entry rest decoded head tail ih =>
        intro wanted member
        rcases List.mem_cons.mp member with rfl | later
        · exact ⟨entry, by simp, decoded_name_has_original_bytes _ _ head.1, head.2⟩
        · obtain ⟨found, present, name, schema⟩ := ih wanted later
          exact ⟨found, by simp [present], name, schema⟩
  intro field member
  obtain ⟨entry, present, name, schema⟩ := original field member
  exact ⟨entry, complete.mem_iff.mpr present, name, schema⟩

theorem meaning_has_no_extra_entries (fields : List Field) (entries : List Entry)
    (meaning : Meaning fields entries) :
    ∀ entry ∈ entries, ∃ field ∈ fields, textBytes entry.1 = field.name ∧ entry.2 = field.schema := by
  obtain ⟨decoded, parsed, _, complete, _⟩ := meaning
  have paired := decode_fields_original fields decoded parsed
  have original : ∀ entry ∈ decoded, ∃ field ∈ fields,
      textBytes entry.1 = field.name ∧ entry.2 = field.schema := by
    induction paired with
    | nil => simp
    | @cons field entry rest decoded head tail ih =>
        intro wanted member
        rcases List.mem_cons.mp member with rfl | later
        · exact ⟨field, by simp, decoded_name_has_original_bytes _ _ head.1, head.2⟩
        · obtain ⟨found, present, name, schema⟩ := ih wanted later
          exact ⟨found, by simp [present], name, schema⟩
  intro entry member
  exact original entry (complete.mem_iff.mp member)

theorem meaning_keeps_complete_count (fields : List Field) (entries : List Entry)
    (meaning : Meaning fields entries) : entries.length = fields.length := by
  obtain ⟨decoded, parsed, _, complete, _⟩ := meaning
  exact complete.length_eq.trans (decode_fields_original fields decoded parsed).length_eq.symm

end Auths.Product.NativeCompiler.Rules
