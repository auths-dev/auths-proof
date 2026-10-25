import Auths.Product.JsonStringDocument
import Auths.Product.JcsObjectBytes

/-!
Concrete formatter stack mechanics for the to_vec sink. Lists represent
native Vec stacks with the top at the head. Failed end-value operations retain
the effects of already completed pops, in their actual source order. Key
parsing is the closed byte reader, not a caller-supplied name or success flag.
This does not model numeric/ryu dispatch, arbitrary io::Write partial failures,
native library adequacy or aggregate physical resources. Native to_vec writes
to Vec; allocation failure still requires the separate resource argument.
-/
namespace Auths.Product.JcsWriterFrames
open JcsObjectBuffer

structure State where
  output : Bytes
  objects : List (List Property)
  keys : List Bytes
  buffers : List Bytes
  deriving DecidableEq

def empty : State := ⟨[], [], [], []⟩

inductive Error where
  | missingObject | missingKeyBuffer | missingValueBuffer | missingKey
  | invalidKey | rawFragment
  deriving DecidableEq

abbrev Outcome := Except Error Unit × State

def emit (bytes : Bytes) (state : State) : State :=
  match state.buffers with
  | [] => {state with output := state.output ++ bytes}
  | buffer :: rest => {state with buffers := (buffer ++ bytes) :: rest}

def beginObject (state : State) : Outcome := (.ok (), {state with objects := [] :: state.objects})

def endObject (state : State) : Outcome :=
  match state.objects with
  | [] => (.error .missingObject, state)
  | object :: rest => (.ok (), emit (JcsObjectBytes.renderObject object) {state with objects := rest})

def beginKey (state : State) : Outcome := (.ok (), {state with buffers := [] :: state.buffers})

def endKey (state : State) : Outcome :=
  match state.buffers with
  | [] => (.error .missingKeyBuffer, state)
  | key :: rest => (.ok (), {state with buffers := rest, keys := key :: state.keys})

def beginValue (state : State) : Outcome := (.ok (), {state with buffers := [] :: state.buffers})

def endValue (state : State) : Outcome :=
  match state.buffers with
  | [] => (.error .missingValueBuffer, state)
  | value :: buffers =>
      let poppedValue := {state with buffers := buffers}
      match state.keys with
      | [] => (.error .missingKey, poppedValue)
      | key :: keys =>
          let poppedKey := {poppedValue with keys := keys}
          match state.objects with
          | [] => (.error .missingObject, poppedKey)
          | object :: objects =>
              match JsonStringDocument.property key value with
              | .error () => (.error .invalidKey, poppedKey)
              | .ok property => (.ok (), {poppedKey with objects := (insert property object).2 :: objects})

inductive Escape where
  | quote | reverseSolidus | solidus | backspace | formFeed | lineFeed | carriageReturn | tab
  | asciiControl (byte : Fin 256)
  deriving DecidableEq

def escapeBytes : Escape → Bytes
  | .quote => [92, 34]
  | .reverseSolidus => [92, 92]
  | .solidus => [47]
  | .backspace => [92, 98]
  | .formFeed => [92, 102]
  | .lineFeed => [92, 110]
  | .carriageReturn => [92, 114]
  | .tab => [92, 116]
  | .asciiControl byte => [92, 117, 48, 48, JcsStringEncoding.hex (byte.val / 16), JcsStringEncoding.hex (byte.val % 16)]

/-- Bytes is the primitive sink-write action, not an assertion that arbitrary
bytes are a valid scalar or canonical child. Actual serializer/number dispatch
must earn the event stream and every complete child value. -/
inductive Event where
  | bytes (value : Bytes)
  | beginObject | endObject | beginKey | endKey | beginValue | endValue
  | beginArray | endArray | beginArrayValue (first : Bool) | endArrayValue
  | beginString | endString | fragment (value : String) | escape (value : Escape)
  | null | boolean (value : Bool) | rawFragment
  deriving DecidableEq

def step : Event → State → Outcome
  | .bytes bytes, state => (.ok (), emit bytes state)
  | .beginObject, state => beginObject state
  | .endObject, state => endObject state
  | .beginKey, state => beginKey state
  | .endKey, state => endKey state
  | .beginValue, state => beginValue state
  | .endValue, state => endValue state
  | .beginArray, state => (.ok (), emit [91] state)
  | .endArray, state => (.ok (), emit [93] state)
  | .beginArrayValue first, state => (.ok (), if first then state else emit [44] state)
  | .endArrayValue, state => (.ok (), state)
  | .beginString, state => (.ok (), emit [34] state)
  | .endString, state => (.ok (), emit [34] state)
  | .fragment value, state => (.ok (), emit (NativeCompiler.textBytes value) state)
  | .escape value, state => (.ok (), emit (escapeBytes value) state)
  | .null, state => (.ok (), emit [110, 117, 108, 108] state)
  | .boolean value, state => (.ok (), emit (if value then [116, 114, 117, 101] else [102, 97, 108, 115, 101]) state)
  | .rawFragment, state => (.error .rawFragment, state)

def run : List Event → State → Outcome
  | [], state => (.ok (), state)
  | event :: rest, state =>
      match step event state with
      | (.error error, next) => (.error error, next)
      | (.ok (), next) => run rest next

theorem emit_keeps_objects_and_keys (bytes : Bytes) (state : State) :
    (emit bytes state).objects = state.objects ∧ (emit bytes state).keys = state.keys := by
  cases selected : state.buffers <;> simp [emit, selected]

theorem emit_to_outer_sink (bytes : Bytes) (state : State) (outer : state.buffers = []) :
    emit bytes state = {state with output := state.output ++ bytes} := by simp [emit, outer]

theorem emit_to_owned_buffer (bytes buffer : Bytes) (rest : List Bytes) (state : State)
    (owned : state.buffers = buffer :: rest) :
    emit bytes state = {state with buffers := (buffer ++ bytes) :: rest} := by simp [emit, owned]

theorem emit_composes (first second : Bytes) (state : State) :
    emit second (emit first state) = emit (first ++ second) state := by
  cases selected : state.buffers <;> simp [emit, selected, List.append_assoc]

theorem end_value_missing_value_preserves_state (state : State) (absent : state.buffers = []) :
    endValue state = (.error .missingValueBuffer, state) := by simp [endValue, absent]

theorem end_value_missing_key_keeps_completed_pop (state : State) (value : Bytes) (buffers : List Bytes)
    (present : state.buffers = value :: buffers) (absent : state.keys = []) :
    endValue state = (.error .missingKey, {state with buffers := buffers}) := by simp [endValue, present, absent]

theorem end_value_missing_object_keeps_completed_pops (state : State) (value key : Bytes)
    (buffers keys : List Bytes) (valueAt : state.buffers = value :: buffers)
    (keyAt : state.keys = key :: keys) (absent : state.objects = []) :
    endValue state = (.error .missingObject, {state with buffers := buffers, keys := keys}) := by
  simp [endValue, valueAt, keyAt, absent]

theorem end_value_bad_key_keeps_completed_pops (state : State) (value key : Bytes)
    (buffers keys : List Bytes) (object : List Property) (objects : List (List Property))
    (valueAt : state.buffers = value :: buffers) (keyAt : state.keys = key :: keys)
    (objectAt : state.objects = object :: objects) (refused : JsonStringDocument.property key value = .error ()) :
    endValue state = (.error .invalidKey, {state with buffers := buffers, keys := keys}) := by
  simp [endValue, valueAt, keyAt, objectAt, refused]

theorem end_value_uses_actual_decoded_property (state : State) (value key : Bytes)
    (buffers keys : List Bytes) (object : List Property) (objects : List (List Property)) (property : Property)
    (valueAt : state.buffers = value :: buffers) (keyAt : state.keys = key :: keys)
    (objectAt : state.objects = object :: objects) (decoded : JsonStringDocument.property key value = .ok property) :
    endValue state = (.ok (), {state with buffers := buffers, keys := keys, objects := (insert property object).2 :: objects}) := by
  simp [endValue, valueAt, keyAt, objectAt, decoded]

theorem empty_nested_object_returns_to_parent_sink (state : State) :
    run [.beginObject, .endObject] state = (.ok (), emit [123, 125] state) := rfl

/-- Property-local key/value buffers restore all parent stacks and preserve
the original output. A malformed key also restores them, after its own pops;
it does not insert a property. Children here are already complete bytes. -/
theorem property_schedule_keeps_parent_frames (state : State) (object : List Property)
    (objects : List (List Property)) (objectAt : state.objects = object :: objects) (key value : Bytes) :
    run [.beginKey, .bytes key, .endKey, .beginValue, .bytes value, .endValue] state =
      match JsonStringDocument.property key value with
      | .error () => (.error .invalidKey, state)
      | .ok property => (.ok (), {state with objects := (insert property object).2 :: objects}) := by
  cases state with
  | mk output actualObjects keys buffers =>
      simp only [State.objects] at objectAt
      subst actualObjects
      cases decoded : JsonStringDocument.property key value with
      | error error =>
          cases error
          simp [run, step, beginKey, emit, endKey, beginValue, endValue, decoded]
      | ok property => simp [run, step, beginKey, emit, endKey, beginValue, endValue, decoded]

theorem run_append (first second : List Event) (state : State) :
    run (first ++ second) state =
      match run first state with
      | (.error error, next) => (.error error, next)
      | (.ok (), next) => run second next := by
  induction first generalizing state with
  | nil => rfl
  | cons event rest ih =>
      cases outcome : step event state with
      | mk result next =>
          cases result with
          | error error => simp [run, outcome]
          | ok unit => cases unit; simpa only [List.cons_append, run, outcome] using ih next

theorem run_stops_on_first_error (event : Event) (rest : List Event) (state next : State) (error : Error)
    (failed : step event state = (.error error, next)) : run (event :: rest) state = (.error error, next) := by
  simp [run, failed]

theorem raw_fragment_refusal_preserves_state (state : State) : step .rawFragment state = (.error .rawFragment, state) := rfl

end Auths.Product.JcsWriterFrames
