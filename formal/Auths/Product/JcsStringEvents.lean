import Auths.Product.JcsStringDispatch
import Auths.Product.NativeUtf8KeyOrder

/-!
Concrete string formatter event production and its byte meaning. Reference
content emits one character fragment at a time; fragment merge/composition
earns batching equivalence. The actual native byte loop must still earn its
complete original span partition and dispatch against the pinned table.
No expected quoted bytes or successful writer result is an input.
-/
namespace Auths.Product.JcsStringEvents
open JcsObjectBuffer JcsWriterFrames JcsStringDispatch

def characterEvents (character : Char) : List Event :=
  match byteEscape character.toNat with
  | some escape => [.escape escape]
  | none => [.fragment (String.singleton character)]

def contentEvents (characters : List Char) : List Event := characters.flatMap characterEvents

def stringEvents (input : String) : List Event := .beginString :: (contentEvents input.toList ++ [.endString])

def dispatchedBytes (character : Char) : Bytes :=
  match byteEscape character.toNat with
  | some escape => escapeBytes escape
  | none => NativeUtf8KeyOrder.scalar character.toNat

theorem text_bytes_append (left right : String) :
    NativeCompiler.textBytes (left ++ right) = NativeCompiler.textBytes left ++ NativeCompiler.textBytes right := by
  simp only [NativeUtf8KeyOrder.text_bytes_are_complete_encoding, NativeUtf8KeyOrder.characters,
    String.toList_append, List.flatMap_append]

theorem text_bytes_singleton (character : Char) :
    NativeCompiler.textBytes (String.singleton character) = NativeUtf8KeyOrder.scalar character.toNat := by
  simp only [NativeUtf8KeyOrder.text_bytes_are_complete_encoding, NativeUtf8KeyOrder.characters,
    String.toList_singleton, List.flatMap_cons, List.flatMap_nil, List.append_nil]

theorem empty_emit_keeps_state (state : State) : emit [] state = state := by
  cases state with
  | mk output objects keys buffers => cases buffers <;> simp [emit]

theorem fragment_schedule (input : String) (state : State) :
    run [.fragment input] state = (.ok (), emit (NativeCompiler.textBytes input) state) := rfl

/-- Fragment concatenation is a sink-write fact. Arbitrary fragments are not
thereby admitted as unescaped string content; native span selection must earn
that separate property before using this batching statement. -/
theorem adjacent_fragments_merge (left right : String) (state : State) :
    run [.fragment left, .fragment right] state = run [.fragment (left ++ right)] state := by
  change (.ok (), emit (NativeCompiler.textBytes right) (emit (NativeCompiler.textBytes left) state)) =
    (.ok (), emit (NativeCompiler.textBytes (left ++ right)) state)
  rw [emit_composes, text_bytes_append]

theorem dispatch_is_complete_scalar_encoding (character : Char) :
    dispatchedBytes character = JcsStringEncoding.scalar character.toNat := by
  unfold dispatchedBytes byteEscape JcsStringEncoding.scalar
  repeat' split <;> rfl

theorem character_schedule (character : Char) (state : State) :
    run (characterEvents character) state = (.ok (), emit (JcsStringEncoding.scalar character.toNat) state) := by
  have bytes := dispatch_is_complete_scalar_encoding character
  cases selected : byteEscape character.toNat with
  | none =>
      have original : NativeUtf8KeyOrder.scalar character.toNat = JcsStringEncoding.scalar character.toNat := by
        simpa [dispatchedBytes, selected] using bytes
      simpa only [characterEvents, selected, text_bytes_singleton, original] using
        fragment_schedule (String.singleton character) state
  | some escape =>
      have original : escapeBytes escape = JcsStringEncoding.scalar character.toNat := by
        simpa [dispatchedBytes, selected] using bytes
      simp [characterEvents, selected, run, step, original]

theorem content_schedule (characters : List Char) (state : State) :
    run (contentEvents characters) state = (.ok (), emit (JcsStringEncoding.characters characters) state) := by
  induction characters generalizing state with
  | nil => simp [contentEvents, JcsStringEncoding.characters, run, empty_emit_keeps_state]
  | cons character rest ih =>
      simp only [contentEvents, List.flatMap_cons]
      rw [run_append, character_schedule]
      simpa only [JcsStringEncoding.characters, List.flatMap_cons, emit_composes] using
        ih (emit (JcsStringEncoding.scalar character.toNat) state)

theorem string_schedule (input : String) (state : State) :
    run (stringEvents input) state = (.ok (), emit (JcsStringEncoding.quoted input) state) := by
  change run (contentEvents input.toList ++ [.endString]) (emit [34] state) =
    (.ok (), emit (JcsStringEncoding.quoted input) state)
  rw [run_append, content_schedule]
  change (.ok (), emit [34] (emit (JcsStringEncoding.characters input.toList) (emit [34] state))) =
    (.ok (), emit (JcsStringEncoding.quoted input) state)
  rw [emit_composes, emit_composes]
  simp only [JcsStringEncoding.quoted, List.singleton_append, List.cons_append, List.nil_append]

def fragmentEvents (chunks : List String) : List Event := chunks.map Event.fragment

def joinedText : List String → String
  | [] => ""
  | first :: rest => first ++ joinedText rest

theorem joined_text_keeps_all_original_bytes (chunks : List String) :
    NativeCompiler.textBytes (joinedText chunks) = chunks.flatMap NativeCompiler.textBytes := by
  induction chunks with
  | nil => simp [joinedText, NativeUtf8KeyOrder.text_bytes_are_complete_encoding, NativeUtf8KeyOrder.characters]
  | cons first rest ih => simp only [joinedText, text_bytes_append, ih, List.flatMap_cons]

theorem fragment_chunks_schedule (chunks : List String) (state : State) :
    run (fragmentEvents chunks) state = (.ok (), emit (NativeCompiler.textBytes (joinedText chunks)) state) := by
  induction chunks generalizing state with
  | nil => simp [fragmentEvents, joinedText, run, NativeUtf8KeyOrder.text_bytes_are_complete_encoding,
      NativeUtf8KeyOrder.characters, empty_emit_keeps_state]
  | cons first rest ih =>
      change run (fragmentEvents rest) (emit (NativeCompiler.textBytes first) state) = _
      rw [ih, emit_composes]
      simp only [joinedText, text_bytes_append]

end Auths.Product.JcsStringEvents
