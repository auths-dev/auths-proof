import Auths.Product.JcsTreeEncoding
import Auths.Product.JcsWriterUsefulness

/-!
Complete recursive formatter-event grammar and useful schedules. Every
original child earns its own events/bytes; numeric primitive sink writes use
the closed admitted-integer reference, strings use actual reference escape
events, and nested objects own their key/value buffers. Native Serialize,
cast/ryu/formatter/library adequacy remains an outer obligation.
-/
namespace Auths.Product.JcsTreeWriter
open FullJsonValue JcsObjectBuffer JcsWriterFrames JcsTreeEncoding

def propertyEvents (name : String) (child : List Event) : List Event :=
  (.beginKey :: (JcsStringEvents.stringEvents name ++ [.endKey, .beginValue])) ++ child ++ [.endValue]

mutual
  inductive Trace : Value → Bytes → List Event → Prop where
    | null : Trace .null [110, 117, 108, 108] [.null]
    | boolean (value : Bool) : Trace (.boolean value)
        (if value then [116, 114, 117, 101] else [102, 97, 108, 115, 101]) [.boolean value]
    | text (value : String) : Trace (.text value) (JcsStringEncoding.quoted value) (JcsStringEvents.stringEvents value)
    | number {value : Number} {bytes : Bytes} (original : AdmittedIntegerBytes.encode value = some bytes) :
        Trace (.number value) bytes [.bytes bytes]
    | array {values : List Value} {bytes : List Bytes} {events : List Event}
        (children : ValuesTrace true values bytes events) :
        Trace (.array values) (arrayBytes bytes) (.beginArray :: (events ++ [.endArray]))
    | object {members : List (String × Value)} {bytes : List (String × Bytes)} {events : List Event}
        (children : MembersTrace members bytes events) :
        Trace (.object members) (JcsObjectBytes.originalObject bytes) (.beginObject :: (events ++ [.endObject]))

  inductive ValuesTrace : Bool → List Value → List Bytes → List Event → Prop where
    | nil (first : Bool) : ValuesTrace first [] [] []
    | cons (first : Bool) {value : Value} {bytes : Bytes} {events : List Event}
        {rest : List Value} {outputs : List Bytes} {later : List Event}
        (head : Trace value bytes events) (tail : ValuesTrace false rest outputs later) :
        ValuesTrace first (value :: rest) (bytes :: outputs)
          (.beginArrayValue first :: (events ++ (.endArrayValue :: later)))

  inductive MembersTrace : List (String × Value) → List (String × Bytes) → List Event → Prop where
    | nil : MembersTrace [] [] []
    | cons (name : String) {value : Value} {bytes : Bytes} {events : List Event}
        {rest : List (String × Value)} {outputs : List (String × Bytes)} {later : List Event}
        (head : Trace value bytes events) (tail : MembersTrace rest outputs later) :
        MembersTrace ((name, value) :: rest) ((name, bytes) :: outputs) (propertyEvents name events ++ later)
end

mutual
  theorem complete_encoding_earns_trace {value : Value} {bytes : Bytes} (original : Encoding value bytes) :
      ∃ events, Trace value bytes events := by
    cases original with
    | null => exact ⟨_, .null⟩
    | boolean value => exact ⟨_, .boolean value⟩
    | text value => exact ⟨_, .text value⟩
    | number original => exact ⟨_, .number original⟩
    | array children =>
        obtain ⟨events, trace⟩ := values_encoding_earns_trace children true
        exact ⟨_, .array trace⟩
    | object children =>
        obtain ⟨events, trace⟩ := members_encoding_earns_trace children
        exact ⟨_, .object trace⟩
  termination_by structural original

  theorem values_encoding_earns_trace {values : List Value} {bytes : List Bytes}
      (original : ValuesEncoding values bytes) (first : Bool) : ∃ events, ValuesTrace first values bytes events := by
    cases original with
    | nil => exact ⟨[], .nil first⟩
    | cons head tail =>
        obtain ⟨headEvents, headTrace⟩ := complete_encoding_earns_trace head
        obtain ⟨tailEvents, tailTrace⟩ := values_encoding_earns_trace tail false
        exact ⟨_, .cons first headTrace tailTrace⟩
  termination_by structural original

  theorem members_encoding_earns_trace {members : List (String × Value)} {bytes : List (String × Bytes)}
      (original : MembersEncoding members bytes) : ∃ events, MembersTrace members bytes events := by
    cases original with
    | nil => exact ⟨[], .nil⟩
    | cons name head tail =>
        obtain ⟨headEvents, headTrace⟩ := complete_encoding_earns_trace head
        obtain ⟨tailEvents, tailTrace⟩ := members_encoding_earns_trace tail
        exact ⟨_, .cons name headTrace tailTrace⟩
  termination_by structural original
end

private theorem replace_complete_segment (prefix first second suffix : List Event) (state : State)
    (same : ∀ before, run first before = run second before) :
    run ((prefix ++ first) ++ suffix) state = run ((prefix ++ second) ++ suffix) state := by
  simp only [run_append, same]

private theorem recursive_property_schedule (name : String) (child : List Event) (bytes : Bytes)
    (childSchedule : ∀ before, run child before = (.ok (), emit bytes before))
    (output : Bytes) (object : List Property) (objects : List (List Property)) (keys buffers : List Bytes) :
    run (propertyEvents name child) ⟨output, object :: objects, keys, buffers⟩ =
      (.ok (), ⟨output, (insert (originalProperty name bytes) object).2 :: objects, keys, buffers⟩) := by
  have replaced := replace_complete_segment
    (.beginKey :: (JcsStringEvents.stringEvents name ++ [.endKey, .beginValue])) child [.bytes bytes] [.endValue]
    ⟨output, object :: objects, keys, buffers⟩ (by intro before; rw [childSchedule]; rfl)
  have same : run (propertyEvents name child) ⟨output, object :: objects, keys, buffers⟩ =
      run (JcsWriterUsefulness.propertyEvents name bytes) ⟨output, object :: objects, keys, buffers⟩ := by
    simpa only [propertyEvents, JcsWriterUsefulness.propertyEvents, List.append_assoc, List.cons_append, List.nil_append] using replaced
  rw [same]
  exact JcsWriterUsefulness.named_property_schedule _ object objects rfl name bytes

mutual
  theorem complete_trace_restores_parent_frames {value : Value} {bytes : Bytes} {events : List Event}
      (trace : Trace value bytes events) (state : State) : run events state = (.ok (), emit bytes state) := by
    cases trace with
    | null => rfl
    | boolean value => rfl
    | text value => exact JcsStringEvents.string_schedule value state
    | number original => rfl
    | array children =>
        change run (_ ++ [.endArray]) (emit [91] state) = (.ok (), emit (arrayBytes _) state)
        rw [run_append, complete_values_trace_restores_parent_frames children]
        change (.ok (), emit [93] (emit (arrayContents true _) (emit [91] state))) = _
        rw [emit_composes, emit_composes]
        rfl
    | object children =>
        cases state with
        | mk output objects keys buffers =>
            change run (_ ++ [.endObject]) ⟨output, [] :: objects, keys, buffers⟩ =
              (.ok (), emit (JcsObjectBytes.originalObject _) ⟨output, objects, keys, buffers⟩)
            rw [run_append, complete_members_trace_restores_parent_frames children]
            rfl
  termination_by structural trace

  theorem complete_values_trace_restores_parent_frames {first : Bool} {values : List Value}
      {bytes : List Bytes} {events : List Event} (trace : ValuesTrace first values bytes events) (state : State) :
      run events state = (.ok (), emit (arrayContents first bytes) state) := by
    cases trace with
    | nil first => simp only [run, arrayContents, JcsStringEvents.empty_emit_keeps_state]
    | @cons first value headBytes headEvents rest outputs later head tail =>
        let started := if first then state else emit [44] state
        change run (headEvents ++ (.endArrayValue :: later)) started = _
        rw [run_append, complete_trace_restores_parent_frames head]
        change run later (emit headBytes started) = _
        rw [complete_values_trace_restores_parent_frames tail, emit_composes]
        cases first <;> simp [started, arrayContents, emit_composes, List.append_assoc]
  termination_by structural trace

  theorem complete_members_trace_restores_parent_frames {members : List (String × Value)}
      {bytes : List (String × Bytes)} {events : List Event} (trace : MembersTrace members bytes events)
      (output : Bytes) (object : List Property) (objects : List (List Property)) (keys buffers : List Bytes) :
      run events ⟨output, object :: objects, keys, buffers⟩ =
        (.ok (), ⟨output, collectFrom object (originalProperties bytes) :: objects, keys, buffers⟩) := by
    cases trace with
    | nil => rfl
    | @cons name value headBytes headEvents rest outputs later head tail =>
        rw [run_append, recursive_property_schedule name headEvents headBytes (complete_trace_restores_parent_frames head)]
        simpa only [originalProperties, List.map_cons, collectFrom] using
          complete_members_trace_restores_parent_frames tail output (insert (originalProperty name headBytes) object).2 objects keys buffers
  termination_by structural trace
end

/-- Complete useful reference output and event production are constructed
from every original child, not supplied by the caller. This schedule works
under arbitrary parent object/key/buffer stacks and outer output prefixes. -/
theorem complete_safe_tree_earns_useful_writer (value : Value) (safe : FullJsonNumericSafety.SafeNumbers value) :
    ∃ bytes events, Encoding value bytes ∧ Trace value bytes events ∧
      ∀ state, run events state = (.ok (), emit bytes state) := by
  obtain ⟨bytes, encoded⟩ := complete_encoding_exists value safe
  obtain ⟨events, trace⟩ := complete_encoding_earns_trace encoded
  exact ⟨bytes, events, encoded, trace, complete_trace_restores_parent_frames trace⟩

end Auths.Product.JcsTreeWriter
