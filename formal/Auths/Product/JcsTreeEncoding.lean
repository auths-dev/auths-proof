import Auths.Product.AdmittedIntegerBytes
import Auths.Product.JcsObjectBytes
import Auths.Product.FullJsonUniqueness

/-!
Complete expected canonical trees over the earned admitted integer domain.
Every original array child and object member has its own recursive encoding;
no caller supplies complete child bytes or a canonicalization success flag.
Objects use the existing UTF-16/quoted-name/full-property-buffer reference.
Duplicate names follow its first-property behavior; no-loss consequences
require earned original uniqueness. This is not native Serialize/JCS, ryu,
strict-byte parsing, hash provenance or physical allocation/time adequacy.
-/
namespace Auths.Product.JcsTreeEncoding
open FullJsonValue JcsObjectBuffer

def arrayContents : Bool → List Bytes → Bytes
  | _, [] => []
  | first, value :: rest => (if first then [] else [44]) ++ value ++ arrayContents false rest

def arrayBytes (values : List Bytes) : Bytes := 91 :: (arrayContents true values ++ [93])

mutual
  inductive Encoding : Value → Bytes → Prop where
    | null : Encoding .null [110, 117, 108, 108]
    | boolean (value : Bool) : Encoding (.boolean value)
        (if value then [116, 114, 117, 101] else [102, 97, 108, 115, 101])
    | text (value : String) : Encoding (.text value) (JcsStringEncoding.quoted value)
    | number {value : Number} {bytes : Bytes} (original : AdmittedIntegerBytes.encode value = some bytes) :
        Encoding (.number value) bytes
    | array {values : List Value} {bytes : List Bytes} (children : ValuesEncoding values bytes) :
        Encoding (.array values) (arrayBytes bytes)
    | object {members : List (String × Value)} {bytes : List (String × Bytes)}
        (children : MembersEncoding members bytes) : Encoding (.object members) (JcsObjectBytes.originalObject bytes)

  inductive ValuesEncoding : List Value → List Bytes → Prop where
    | nil : ValuesEncoding [] []
    | cons {value : Value} {bytes : Bytes} {rest : List Value} {outputs : List Bytes}
        (head : Encoding value bytes) (tail : ValuesEncoding rest outputs) : ValuesEncoding (value :: rest) (bytes :: outputs)

  inductive MembersEncoding : List (String × Value) → List (String × Bytes) → Prop where
    | nil : MembersEncoding [] []
    | cons (name : String) {value : Value} {bytes : Bytes} {rest : List (String × Value)} {outputs : List (String × Bytes)}
        (head : Encoding value bytes) (tail : MembersEncoding rest outputs) :
        MembersEncoding ((name, value) :: rest) ((name, bytes) :: outputs)
end

private theorem collect_values (values : List Value) (each : ∀ value ∈ values, ∃ bytes, Encoding value bytes) :
    ∃ bytes, ValuesEncoding values bytes := by
  revert each
  induction values with
  | nil => intro _; exact ⟨[], .nil⟩
  | cons first rest ih =>
      intro each
      obtain ⟨bytes, head⟩ := each first (by simp)
      obtain ⟨outputs, tail⟩ := ih (fun value member => each value (List.mem_cons_of_mem _ member))
      exact ⟨bytes :: outputs, .cons head tail⟩

private theorem collect_members (members : List (String × Value))
    (each : ∀ member ∈ members, ∃ bytes, Encoding member.2 bytes) : ∃ bytes, MembersEncoding members bytes := by
  revert each
  induction members with
  | nil => intro _; exact ⟨[], .nil⟩
  | cons first rest ih =>
      intro each
      obtain ⟨bytes, head⟩ := each first (by simp)
      obtain ⟨outputs, tail⟩ := ih (fun member present => each member (List.mem_cons_of_mem _ present))
      cases first with
      | mk name value => exact ⟨(name, bytes) :: outputs, .cons name head tail⟩

theorem complete_encoding_exists (value : Value) (safe : FullJsonNumericSafety.SafeNumbers value) :
    ∃ bytes, Encoding value bytes := by
  induction safe with
  | null => exact ⟨_, .null⟩
  | boolean value => exact ⟨_, .boolean value⟩
  | text value => exact ⟨_, .text value⟩
  | signed value bounded => exact ⟨_, .number (by simp [AdmittedIntegerBytes.encode, bounded])⟩
  | unsigned value bounded => exact ⟨_, .number (by simp [AdmittedIntegerBytes.encode, bounded])⟩
  | array values each ih =>
      obtain ⟨bytes, children⟩ := collect_values values ih
      exact ⟨_, .array children⟩
  | object members each ih =>
      obtain ⟨bytes, children⟩ := collect_members members ih
      exact ⟨_, .object children⟩

mutual
  theorem complete_encoding_is_unique {input : Value} {first second : Bytes}
      (left : Encoding input first) (right : Encoding input second) : first = second := by
    cases left with
    | null => cases right; rfl
    | boolean value => cases right; rfl
    | text value => cases right; rfl
    | number original =>
        cases right with
        | number other => exact Option.some.inj (original.symm.trans other)
    | array children =>
        cases right with
        | array other => rw [values_encoding_is_unique children other]
    | object children =>
        cases right with
        | object other => rw [members_encoding_is_unique children other]
  termination_by structural left

  theorem values_encoding_is_unique {inputs : List Value} {first second : List Bytes}
      (left : ValuesEncoding inputs first) (right : ValuesEncoding inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons head tail =>
        cases right with
        | cons otherHead otherTail => rw [complete_encoding_is_unique head otherHead, values_encoding_is_unique tail otherTail]
  termination_by structural left

  theorem members_encoding_is_unique {inputs : List (String × Value)} {first second : List (String × Bytes)}
      (left : MembersEncoding inputs first) (right : MembersEncoding inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons name head tail =>
        cases right with
        | cons name otherHead otherTail => rw [complete_encoding_is_unique head otherHead, members_encoding_is_unique tail otherTail]
  termination_by structural left
end

theorem encoded_values_keep_count {values : List Value} {bytes : List Bytes} (original : ValuesEncoding values bytes) :
    bytes.length = values.length := by induction original <;> simp_all

theorem encoded_members_keep_original_names {members : List (String × Value)} {bytes : List (String × Bytes)}
    (original : MembersEncoding members bytes) : bytes.map Prod.fst = members.map Prod.fst := by
  induction original <;> simp_all

theorem encoded_members_keep_count {members : List (String × Value)} {bytes : List (String × Bytes)}
    (original : MembersEncoding members bytes) : bytes.length = members.length := by
  have names := congrArg List.length (encoded_members_keep_original_names original)
  simpa only [List.length_map] using names

/-- No original unique object property is lost to the sorting set. Each value
buffer comes from a complete recursive child encoding, never a selected child
or caller-chosen raw bytes. -/
theorem unique_object_keeps_every_original_property {members : List (String × Value)} {bytes : List (String × Bytes)}
    (original : MembersEncoding members bytes) (unique : FullJsonValue.Unique (.object members)) :
    (collect (originalProperties bytes)).Perm (originalProperties bytes) ∧
      (collect (originalProperties bytes)).length = members.length := by
  have names : (bytes.map Prod.fst).Nodup := by
    rw [encoded_members_keep_original_names original]
    exact ((FullJsonValue.object_unique_iff members).mp unique).1
  exact ⟨original_collection_keeps_all_columns bytes names,
    (original_collection_keeps_count bytes names).trans (encoded_members_keep_count original)⟩

end Auths.Product.JcsTreeEncoding
