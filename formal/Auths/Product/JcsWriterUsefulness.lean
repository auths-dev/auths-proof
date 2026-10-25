import Auths.Product.JcsStringRoundtrip
import Auths.Product.JcsWriterFrames
import Auths.Product.JcsStringEvents

/-!
Closed useful object schedules. Every original String earns its own key read
through quoted-byte roundtrip; no parser result/name/success flag is supplied.
Child bytes are complete original buffers. Their canonical serialization and
actual transparent Auths Serialize/formatter adequacy remain outer obligations.
-/
namespace Auths.Product.JcsWriterUsefulness
open JcsObjectBuffer JcsWriterFrames

def propertyEvents (name : String) (value : Bytes) : List Event :=
  .beginKey :: (JcsStringEvents.stringEvents name ++ [.endKey, .beginValue, .bytes value, .endValue])

def memberEvents : List (String × Bytes) → List Event
  | [] => []
  | (name, value) :: rest => propertyEvents name value ++ memberEvents rest

def objectEvents (members : List (String × Bytes)) : List Event :=
  .beginObject :: (memberEvents members ++ [.endObject])

theorem property_string_dispatch_matches_owned_key_buffer (name : String) (value : Bytes) (state : State) :
    run (propertyEvents name value) state =
      run [.beginKey, .bytes (JcsStringEncoding.quoted name), .endKey, .beginValue, .bytes value, .endValue] state := by
  change run (JcsStringEvents.stringEvents name ++ [.endKey, .beginValue, .bytes value, .endValue])
      {state with buffers := [] :: state.buffers} =
    run (.bytes (JcsStringEncoding.quoted name) :: [.endKey, .beginValue, .bytes value, .endValue])
      {state with buffers := [] :: state.buffers}
  rw [run_append, JcsStringEvents.string_schedule]
  rfl

theorem named_property_schedule (state : State) (object : List Property) (objects : List (List Property))
    (objectAt : state.objects = object :: objects) (name : String) (value : Bytes) :
    run (propertyEvents name value) state =
      (.ok (), {state with objects := (insert (originalProperty name value) object).2 :: objects}) := by
  rw [property_string_dispatch_matches_owned_key_buffer]
  rw [property_schedule_keeps_parent_frames state object objects objectAt]
  rw [JcsStringRoundtrip.property_quote_roundtrip]

theorem named_members_schedule (members : List (String × Bytes)) (output : Bytes)
    (object : List Property) (objects : List (List Property)) (keys buffers : List Bytes) :
    run (memberEvents members) ⟨output, object :: objects, keys, buffers⟩ =
      (.ok (), ⟨output, collectFrom object (originalProperties members) :: objects, keys, buffers⟩) := by
  induction members generalizing object with
  | nil => rfl
  | cons member rest ih =>
      obtain ⟨name, value⟩ := member
      rw [memberEvents, run_append]
      rw [named_property_schedule _ object objects rfl name value]
      simpa [originalProperties, collectFrom] using ih (insert (originalProperty name value) object).2

/-- A complete named object succeeds for every original String and preserves
all parent frames. Duplicate names follow the specified first-property set
behavior; completeness/permutation consequences require original uniqueness. -/
theorem named_object_schedule (members : List (String × Bytes)) (state : State) :
    run (objectEvents members) state = (.ok (), emit (JcsObjectBytes.originalObject members) state) := by
  cases state with
  | mk output objects keys buffers =>
      change run (memberEvents members ++ [.endObject]) ⟨output, [] :: objects, keys, buffers⟩ =
        (.ok (), emit (JcsObjectBytes.originalObject members) ⟨output, objects, keys, buffers⟩)
      rw [run_append, named_members_schedule members output [] objects keys buffers]
      rfl

theorem unique_object_writer_keeps_all_properties (members : List (String × Bytes)) (state : State)
    (unique : (members.map Prod.fst).Nodup) :
    ∃ properties, properties.Perm (originalProperties members) ∧
      run (objectEvents members) state = (.ok (), emit (JcsObjectBytes.renderObject properties) state) := by
  refine ⟨collect (originalProperties members), original_collection_keeps_all_columns members unique, ?_⟩
  exact named_object_schedule members state

theorem unique_object_writer_is_permutation_invariant (left right : List (String × Bytes)) (state : State)
    (unique : (left.map Prod.fst).Nodup) (same : left.Perm right) :
    run (objectEvents left) state = run (objectEvents right) state := by
  rw [named_object_schedule, named_object_schedule,
    JcsObjectBytes.original_object_is_permutation_invariant left right unique same]

end Auths.Product.JcsWriterUsefulness
