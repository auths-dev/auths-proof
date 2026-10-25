import Auths.Codec.ObjectFields
import Auths.Codec.ObjectEncode
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.WireInverse
open ProfileDecode ObjectEncode EncoderState

/-- Prefix parsing is compositional and permits a suffix. Public object
acceptance must separately reject a suffix and compare canonical bytes. -/
def Consumes {α : Type} (read : List Nat → Nat → core.result.Result α error.CodecError × Nat)
    (encoding : List Nat) (value : α) : Prop :=
  ∀ leading trailing, read (leading ++ encoding ++ trailing) leading.length =
    (.Ok value, leading.length + encoding.length)

theorem consumes_then {α β : Type}
    (first : List Nat → Nat → core.result.Result α error.CodecError × Nat)
    (next : α → List Nat → Nat → core.result.Result β error.CodecError × Nat)
    (firstBytes nextBytes : List Nat) (value : α) (result : β)
    (firstExact : Consumes first firstBytes value)
    (nextExact : Consumes (next value) nextBytes result) :
    Consumes (fun input position => andThen (first input position) fun value position =>
      next value input position) (firstBytes ++ nextBytes) result := by
  intro leading trailing
  have firstRead := firstExact leading (nextBytes ++ trailing)
  have secondRead := nextExact (leading ++ firstBytes) trailing
  simp only [List.length_append] at secondRead ⊢
  simpa only [List.append_assoc, firstRead, andThen, secondRead, Nat.add_assoc]

theorem consumes_return {α : Type} (value : α) :
    Consumes (fun _ position => (.Ok value, position)) [] value := by
  intro leading trailing
  simp

theorem typed_head_prefix (head : Head) (valid : head.Valid) (leading trailing : List Nat) :
    Cursor.typedHead (leading ++ encodeHead head ++ trailing) leading.length head.major =
      (some head.argument, leading.length + (encodeHead head).length) := by
  have parsed := readHead_encodeHead head valid trailing
  simp only [Cursor.typedHead, List.drop_left, parsed, ↓reduceIte,
    List.length_append]
  omega

theorem header_not_indefinite (head : Head) :
    (encodeHead head)[0]? ≠ some (head.major * 32 + 31) := by
  have bound : additionalTag head.argument ≤ 27 := by
    unfold additionalTag
    split_ifs <;> omega
  simp only [encodeHead, List.getElem?_cons_zero, ne_eq, Option.some.injEq]
  omega

theorem map_consumes (fields : Nat) (bounded : fields < 2 ^ 64) :
    Consumes (fun input position => Fields.mapAt input position fields) (encodeHead ⟨5, fields⟩) () := by
  intro leading trailing
  have headExact := typed_head_prefix ⟨5, fields⟩ ⟨by decide, bounded⟩ leading trailing
  have noMarker := header_not_indefinite ⟨5, fields⟩
  have firstByte : (leading ++ encodeHead ⟨5, fields⟩ ++ trailing)[leading.length]? ≠ some 191 := by
    simpa [List.getElem?_append, encodeHead] using noMarker
  simp [Fields.mapAt, Collection.collectionAt, firstByte, headExact]

theorem key_consumes (key : Nat) (bounded : key ≤ 255) :
    Consumes (fun input position => Fields.keyAt input position key) (encodeHead ⟨0, key⟩) () := by
  intro leading trailing
  have valid : (Head.mk 0 key).Valid := ⟨by decide, by omega⟩
  have headExact := typed_head_prefix ⟨0, key⟩ valid leading trailing
  simp [Fields.keyAt, Cursor.narrowHead, headExact, bounded, Option.filter]

theorem payload_prefix (major : Nat) (majorBound : major < 8) (bytes leading trailing : List Nat)
    (lengthBound : bytes.length < 2 ^ 64) :
    Payload.payloadAt (leading ++ payloadEncoding major bytes ++ trailing) leading.length major =
      (some bytes, leading.length + (payloadEncoding major bytes).length) := by
  have headExact := typed_head_prefix ⟨major, bytes.length⟩ ⟨majorBound, lengthBound⟩ leading
    (bytes ++ trailing)
  have suffix : (leading ++ payloadEncoding major bytes ++ trailing).drop
      (leading.length + (encodeHead ⟨major, bytes.length⟩).length) = bytes ++ trailing := by
    simp [payloadEncoding, List.append_assoc, List.drop_append, List.drop_drop]
  have available : leading.length + (encodeHead ⟨major, bytes.length⟩).length + bytes.length ≤
      (leading ++ payloadEncoding major bytes ++ trailing).length := by
    simp only [payloadEncoding, List.length_append]
    omega
  simp only [payloadEncoding, List.append_assoc] at headExact
  simp only [Payload.payloadAt, payloadEncoding, List.append_assoc, headExact, available,
    ↓reduceIte, suffix, List.take_left, List.length_append]
  omega

theorem text_consumes (bytes : List Nat) (lengthBound : bytes.length < 2 ^ 64)
    (utf8 : Payload.validUtf8 bytes = true) :
    Consumes Fields.textAt (payloadEncoding 3 bytes) bytes := by
  intro leading trailing
  have payload := payload_prefix 3 (by decide) bytes leading trailing lengthBound
  simp [Fields.textAt, Payload.textAt, payload, Option.filter, utf8]

theorem word_consumes (word : Nat) (bounded : word ≤ 65535) :
    Consumes ProfileDecode.wordAt (encodeHead ⟨0, word⟩) word := by
  intro leading trailing
  have exactHead := typed_head_prefix ⟨0, word⟩ ⟨by decide, by omega⟩ leading trailing
  simp [ProfileDecode.wordAt, Cursor.narrowHead, exactHead, bounded, Option.filter]

def word64At (input : List Nat) (position : Nat) : core.result.Result Nat error.CodecError × Nat :=
  let (word, next) := Cursor.typedHead input position 0
  (match word with | none => .Err .Malformed | some word => .Ok word, next)

theorem word64_consumes (word : Nat) (bounded : word < 2 ^ 64) :
    Consumes word64At (encodeHead ⟨0, word⟩) word := by
  intro leading trailing
  have exactHead := typed_head_prefix ⟨0, word⟩ ⟨by decide, bounded⟩ leading trailing
  simp [word64At, exactHead]

theorem profile_roundtrip (id : List Nat) (version : Nat)
    (idValid : identifierDecision id 128 = true)
    (utf8 : Payload.validUtf8 id = true) (lengthBound : id.length < 2 ^ 64)
    (versionPositive : 0 < version) (versionBound : version ≤ 65535) :
    Consumes profileAt (profileEncoding id version) (id, version) := by
  have finalWord : Consumes
      (fun input position => andThen (ProfileDecode.wordAt input position) fun found position =>
        if found = 0 then (.Err (.Model .InvalidProfile), position)
        else (.Ok (id, found), position))
      (encodeHead ⟨0, version⟩) (id, version) := by
    intro leading trailing
    have parsed := word_consumes version versionBound leading trailing
    simp [parsed, andThen, Nat.ne_of_gt versionPositive]
  have versionKey := consumes_then
    (fun input position => Fields.keyAt input position 1)
    (fun _ input position => andThen (ProfileDecode.wordAt input position) fun found position =>
      if found = 0 then (.Err (.Model .InvalidProfile), position) else (.Ok (id, found), position))
    _ _ () (id, version) (key_consumes 1 (by decide)) finalWord
  have identifier : Consumes
      (fun input position => andThen (Fields.textAt input position) fun found position =>
        if identifierDecision found 128 then
          andThen (Fields.keyAt input position 1) fun _ position =>
          andThen (ProfileDecode.wordAt input position) fun version position =>
          if version = 0 then (.Err (.Model .InvalidProfile), position) else (.Ok (found, version), position)
        else (.Err (.Model .InvalidProfile), position))
      (payloadEncoding 3 id ++ (encodeHead ⟨0, 1⟩ ++ encodeHead ⟨0, version⟩)) (id, version) := by
    apply consumes_then Fields.textAt _ _ _ id (id, version) (text_consumes id lengthBound utf8)
    simpa only [idValid, ↓reduceIte] using versionKey
  have key := consumes_then (fun input position => Fields.keyAt input position 0)
    (fun _ input position => andThen (Fields.textAt input position) fun found position =>
      if identifierDecision found 128 then
        andThen (Fields.keyAt input position 1) fun _ position =>
        andThen (ProfileDecode.wordAt input position) fun version position =>
        if version = 0 then (.Err (.Model .InvalidProfile), position) else (.Ok (found, version), position)
      else (.Err (.Model .InvalidProfile), position))
    _ _ () (id, version) (key_consumes 0 (by decide)) identifier
  have complete := consumes_then (fun input position => Fields.mapAt input position 2)
    (fun _ input position => andThen (Fields.keyAt input position 0) fun _ position =>
      andThen (Fields.textAt input position) fun found position =>
      if identifierDecision found 128 then
        andThen (Fields.keyAt input position 1) fun _ position =>
        andThen (ProfileDecode.wordAt input position) fun version position =>
        if version = 0 then (.Err (.Model .InvalidProfile), position) else (.Ok (found, version), position)
      else (.Err (.Model .InvalidProfile), position))
    _ _ () (id, version) (map_consumes 2 (by decide)) key
  simpa only [profileAt, profileEncoding, encodeHead, additionalTag, argumentWidth, bigEndian,
    List.cons_append, List.nil_append, List.append_assoc] using complete

theorem permission_roundtrip (capability resource : List Nat)
    (capabilityValid : identifierDecision capability 128 = true)
    (resourceValid : identifierDecision resource 1024 = true)
    (capabilityUtf8 : Payload.validUtf8 capability = true)
    (resourceUtf8 : Payload.validUtf8 resource = true)
    (capabilityBound : capability.length < 2 ^ 64) (resourceBound : resource.length < 2 ^ 64) :
    Consumes PermissionDecode.permissionAt (permissionEncoding capability resource) (capability, resource) := by
  unfold PermissionDecode.permissionAt permissionEncoding
  change Consumes _ (encodeHead ⟨5, 2⟩ ++ (encodeHead ⟨0, 0⟩ ++
    (payloadEncoding 3 capability ++ (encodeHead ⟨0, 1⟩ ++
    (payloadEncoding 3 resource ++ []))))) (capability, resource)
  apply consumes_then _ _ (encodeHead ⟨5, 2⟩) _ () _ (map_consumes 2 (by decide))
  apply consumes_then _ _ (encodeHead ⟨0, 0⟩) _ () _ (key_consumes 0 (by decide))
  apply consumes_then _ _ (payloadEncoding 3 capability) _ capability _
    (text_consumes capability capabilityBound capabilityUtf8)
  simp only [capabilityValid, ↓reduceIte]
  apply consumes_then _ _ (encodeHead ⟨0, 1⟩) _ () _ (key_consumes 1 (by decide))
  apply consumes_then _ _ (payloadEncoding 3 resource) [] resource _
    (text_consumes resource resourceBound resourceUtf8)
  simp only [resourceValid, ↓reduceIte]
  exact consumes_return (capability, resource)

theorem budget_roundtrip (algebra : List Nat) (amount : Nat)
    (algebraValid : identifierDecision algebra 128 = true)
    (algebraUtf8 : Payload.validUtf8 algebra = true)
    (algebraBound : algebra.length < 2 ^ 64) (amountBound : amount < 2 ^ 64) :
    Consumes BudgetDecode.budgetAt (budgetEncoding algebra amount) (algebra, amount) := by
  unfold BudgetDecode.budgetAt budgetEncoding
  change Consumes _ (encodeHead ⟨5, 2⟩ ++ (encodeHead ⟨0, 0⟩ ++
    (payloadEncoding 3 algebra ++ (encodeHead ⟨0, 1⟩ ++
    (encodeHead ⟨0, amount⟩ ++ []))))) (algebra, amount)
  apply consumes_then _ _ (encodeHead ⟨5, 2⟩) _ () _ (map_consumes 2 (by decide))
  apply consumes_then _ _ (encodeHead ⟨0, 0⟩) _ () _ (key_consumes 0 (by decide))
  apply consumes_then _ _ (payloadEncoding 3 algebra) _ algebra _
    (text_consumes algebra algebraBound algebraUtf8)
  simp only [algebraValid, ↓reduceIte]
  apply consumes_then _ _ (encodeHead ⟨0, 1⟩) _ () _ (key_consumes 1 (by decide))
  apply consumes_then _ _ (encodeHead ⟨0, amount⟩) [] amount _
    (by simpa only [BudgetDecode.wordAt, word64At] using word64_consumes amount amountBound)
  exact consumes_return (algebra, amount)

theorem null_consumes : Consumes Fields.nullAt [246] () := by
  intro leading trailing
  simp [Fields.nullAt, Cursor.nullAt, List.getElem?_append]

theorem optional_budget_none_roundtrip : Consumes BudgetDecode.optionalAt [246] none := by
  intro leading trailing
  simp [BudgetDecode.optionalAt, Fields.isNullAt, Cursor.typeAt, Cursor.classify,
    List.getElem?_append, Fields.nullAt, Cursor.nullAt]

theorem optional_budget_some_roundtrip (algebra : List Nat) (amount : Nat)
    (algebraValid : identifierDecision algebra 128 = true)
    (algebraUtf8 : Payload.validUtf8 algebra = true)
    (algebraBound : algebra.length < 2 ^ 64) (amountBound : amount < 2 ^ 64) :
    Consumes BudgetDecode.optionalAt (budgetEncoding algebra amount) (some (algebra, amount)) := by
  intro leading trailing
  have budget := budget_roundtrip algebra amount algebraValid algebraUtf8 algebraBound amountBound leading trailing
  have query : Fields.isNullAt (leading ++ budgetEncoding algebra amount ++ trailing) leading.length = .Ok false := by
    simp [Fields.isNullAt, Cursor.typeAt, Cursor.classify, budgetEncoding,
      List.getElem?_append]
  simp [BudgetDecode.optionalAt, query, budget, andThen]

@[step] theorem permission_source_roundtrip (self : cbor.Decoder) (capability resource : List Nat)
    (leading trailing : List Nat)
    (inputBytes : Refinement.byteList self.input.val = leading ++ permissionEncoding capability resource ++ trailing)
    (atStart : self.position.val = leading.length)
    (capabilityValid : identifierDecision capability 128 = true)
    (resourceValid : identifierDecision resource 1024 = true)
    (capabilityUtf8 : Payload.validUtf8 capability = true)
    (resourceUtf8 : Payload.validUtf8 resource = true)
    (capabilityBound : capability.length < 2 ^ 64) (resourceBound : resource.length < 2 ^ 64) :
    decode.permission self ⦃ actual =>
      PermissionDecode.permissionView actual.1 = .Ok (capability, resource) ∧
      actual.2.position.val = leading.length + (permissionEncoding capability resource).length ∧
      actual.2.input = self.input ⦄ := by
  apply spec_mono (PermissionDecode.permission_exact self)
  rintro actual ⟨meaning, sameInput⟩
  rw [inputBytes, atStart, permission_roundtrip capability resource capabilityValid resourceValid
    capabilityUtf8 resourceUtf8 capabilityBound resourceBound leading trailing] at meaning
  exact ⟨(Prod.mk.inj meaning).1, (Prod.mk.inj meaning).2, sameInput⟩

@[step] theorem budget_source_roundtrip (self : cbor.Decoder) (algebra : List Nat) (amount : Nat)
    (leading trailing : List Nat)
    (inputBytes : Refinement.byteList self.input.val = leading ++ budgetEncoding algebra amount ++ trailing)
    (atStart : self.position.val = leading.length)
    (algebraValid : identifierDecision algebra 128 = true)
    (algebraUtf8 : Payload.validUtf8 algebra = true)
    (algebraBound : algebra.length < 2 ^ 64) (amountBound : amount < 2 ^ 64) :
    decode.budget self ⦃ actual =>
      BudgetDecode.budgetView actual.1 = .Ok (algebra, amount) ∧
      actual.2.position.val = leading.length + (budgetEncoding algebra amount).length ∧
      actual.2.input = self.input ⦄ := by
  apply spec_mono (BudgetDecode.budget_exact self)
  rintro actual ⟨meaning, sameInput⟩
  rw [inputBytes, atStart, budget_roundtrip algebra amount algebraValid algebraUtf8
    algebraBound amountBound leading trailing] at meaning
  exact ⟨(Prod.mk.inj meaning).1, (Prod.mk.inj meaning).2, sameInput⟩

/-- This source corollary earns success from constructor-valid bytes. It
assumes a chosen encoding as input, never that the parser already succeeded. -/
@[step] theorem profile_source_roundtrip (self : cbor.Decoder) (id : List Nat) (version : Nat)
    (leading trailing : List Nat)
    (inputBytes : Refinement.byteList self.input.val = leading ++ profileEncoding id version ++ trailing)
    (atStart : self.position.val = leading.length)
    (idValid : identifierDecision id 128 = true)
    (utf8 : Payload.validUtf8 id = true) (lengthBound : id.length < 2 ^ 64)
    (versionPositive : 0 < version) (versionBound : version ≤ 65535) :
    decode.profile_ref self ⦃ actual =>
      ProfileDecode.profileView actual.1 = .Ok (id, version) ∧
      actual.2.position.val = leading.length + (profileEncoding id version).length ∧
      actual.2.input = self.input ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact self)
  rintro actual ⟨meaning, sameInput⟩
  rw [inputBytes, atStart, profile_roundtrip id version idValid utf8 lengthBound
    versionPositive versionBound leading trailing] at meaning
  exact ⟨(Prod.mk.inj meaning).1, (Prod.mk.inj meaning).2, sameInput⟩

end Auths.Codec.WireInverse
