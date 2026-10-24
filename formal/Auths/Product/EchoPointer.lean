import Auths.Product.TemplateMembers

namespace Auths.Product.EchoPointer
open RequestConstruction TemplateMembers
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def encode (tokens : List Bytes) : Bytes := tokens.flatMap (fun token => 47 :: token)

/-- Independent exact original-pointer meaning. Token grammar excludes slash
and escapes; no decoder result or returned validity flag appears here. -/
def Meaning (pointer : Bytes) (tokens : List Bytes) : Prop :=
  pointer = encode tokens ∧ PointerDomain tokens

def finish (prefix : List Bytes) (token : Bytes) : Except Error (List Bytes) :=
  if prefix.length < 6 ∧ OperationIdentity.validToken token 64 = true then
    .ok (prefix ++ [token])
  else .error .echoConflict

def scan (prefix : List Bytes) (token : Bytes) : Bytes → Except Error (List Bytes)
  | [] => finish prefix token
  | byte :: rest =>
    if byte = 47 then
      match finish prefix token with
      | .error error => .error error
      | .ok next => scan next [] rest
    else if token.length < 64 then scan prefix (token ++ [byte]) rest
    else .error .echoConflict

def decode (pointer : Bytes) : Except Error (List Bytes) :=
  match pointer with
  | 47 :: rest => if pointer.length ≤ 128 then scan [] [] rest else .error .echoConflict
  | _ => .error .echoConflict

theorem encode_append (first second : List Bytes) : encode (first ++ second) = encode first ++ encode second := by
  simp [encode, List.flatMap_append]

theorem encode_size (tokens : List Bytes) : (encode tokens).length =
    (tokens.map (fun token => token.length + 1)).sum := by
  induction tokens with
  | nil => rfl
  | cons token rest ih => simp [encode, ih]; omega

theorem token_excludes_slash (token : Bytes) (valid : OperationIdentity.validToken token 64 = true) : 47 ∉ token := by
  cases token with
  | nil => simp [OperationIdentity.validToken] at valid
  | cons first rest =>
    simp only [OperationIdentity.validToken, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at valid
    intro present
    rcases List.mem_cons.mp present with head | tail
    · have alpha := valid.1.2
      unfold OperationIdentity.Alphanumeric at alpha
      omega
    · have accepted := valid.2 47 tail
      simp only [decide_eq_true_eq] at accepted
      unfold OperationIdentity.TailByte OperationIdentity.Alphanumeric at accepted
      omega

theorem token_size (token : Bytes) (valid : OperationIdentity.validToken token 64 = true) : token.length ≤ 64 := by
  cases token with
  | nil => simp [OperationIdentity.validToken] at valid
  | cons first rest =>
    simp only [OperationIdentity.validToken, Bool.and_eq_true, decide_eq_true_eq] at valid
    exact valid.1.1

theorem finish_success (prefix : List Bytes) (token : Bytes) (output : List Bytes)
    (accepted : finish prefix token = .ok output) :
    output = prefix ++ [token] ∧ prefix.length < 6 ∧ OperationIdentity.validToken token 64 = true := by
  unfold finish at accepted
  split at accepted
  · rename_i allowed
    exact ⟨by simpa using accepted.symm, allowed.1, allowed.2⟩
  · contradiction

theorem scan_sound (remaining : Bytes) (prefix : List Bytes) (token : Bytes) (output : List Bytes)
    (earlier : ∀ name ∈ prefix, OperationIdentity.validToken name 64 = true)
    (accepted : scan prefix token remaining = .ok output) :
    0 < output.length ∧ output.length ≤ 6 ∧
      (∀ name ∈ output, OperationIdentity.validToken name 64 = true) ∧
      encode output = encode prefix ++ [47] ++ token ++ remaining := by
  induction remaining generalizing prefix token with
  | nil =>
    have done := finish_success prefix token output accepted
    rw [done.1]
    refine ⟨by simp, by simp; omega, ?_, ?_⟩
    · intro name member
      rcases List.mem_append.mp member with old | final
      · exact earlier name old
      · have same : name = token := List.mem_singleton.mp final
        simpa [same] using done.2.2
    · simp [encode_append, encode, List.append_assoc]
  | cons byte rest ih =>
    by_cases slash : byte = 47
    · cases finished : finish prefix token with
      | error error => simp [scan, slash, finished] at accepted
      | ok next =>
        have nextMeaning := finish_success prefix token next finished
        have nextEarlier : ∀ name ∈ next, OperationIdentity.validToken name 64 = true := by
          intro name present
          rw [nextMeaning.1] at present
          rcases List.mem_append.mp present with old | final
          · exact earlier name old
          · have same : name = token := List.mem_singleton.mp final
            simpa [same] using nextMeaning.2.2
        have recursive := ih next [] nextEarlier (by simpa [scan, slash, finished] using accepted)
        refine ⟨recursive.1, recursive.2.1, recursive.2.2.1, ?_⟩
        simpa [nextMeaning.1, slash, encode_append, encode, List.append_assoc] using recursive.2.2.2
    · by_cases room : token.length < 64
      · have recursive := ih prefix (token ++ [byte]) earlier (by simpa [scan, slash, room] using accepted)
        refine ⟨recursive.1, recursive.2.1, recursive.2.2.1, ?_⟩
        simpa [List.append_assoc] using recursive.2.2.2
      · simp [scan, slash, room] at accepted

theorem decode_sound (pointer : Bytes) (tokens : List Bytes) (accepted : decode pointer = .ok tokens) : Meaning pointer tokens := by
  cases pointer with
  | nil => simp [decode] at accepted
  | cons first rest =>
    by_cases slash : first = 47
    · subst first
      by_cases bounded : (47 :: rest).length ≤ 128
      · have parsed : scan [] [] rest = .ok tokens := by simpa [decode, bounded] using accepted
        have meaning := scan_sound rest [] [] tokens (by simp) parsed
        have exact : encode tokens = 47 :: rest := by simpa [encode] using meaning.2.2.2
        refine ⟨exact.symm, meaning.1, meaning.2.1, meaning.2.2.1, ?_⟩
        rw [← encode_size, exact]
        exact bounded
      · simp [decode, bounded] at accepted
    · simp [decode, slash] at accepted

private theorem scan_one_token (bytes : Bytes) (prefix : List Bytes) (consumed rest : Bytes)
    (noSlash : 47 ∉ bytes) (bounded : (consumed ++ bytes).length ≤ 64) :
    scan prefix consumed (bytes ++ rest) = scan prefix (consumed ++ bytes) rest := by
  induction bytes generalizing consumed with
  | nil => simp
  | cons byte tail ih =>
    have different : byte ≠ 47 := by intro same; exact noSlash (by simp [same])
    have tailFree : 47 ∉ tail := fun member => noSlash (List.mem_cons_of_mem _ member)
    have room : consumed.length < 64 := by simp at bounded; omega
    rw [List.cons_append, scan, if_neg different, if_pos room]
    simpa [List.append_assoc] using ih (consumed ++ [byte]) tailFree (by simpa [List.append_assoc] using bounded)

private theorem scan_valid_tokens (tokens prefix : List Bytes) (nonempty : tokens ≠ [])
    (valid : ∀ token ∈ tokens, OperationIdentity.validToken token 64 = true)
    (count : prefix.length + tokens.length ≤ 6) :
    scan prefix [] (tokens.headD [] ++ encode tokens.tail) = .ok (prefix ++ tokens) := by
  induction tokens generalizing prefix with
  | nil => contradiction
  | cons token rest ih =>
    have tokenValid := valid token (by simp)
    have free := token_excludes_slash token tokenValid
    have bounded := token_size token tokenValid
    have room : prefix.length < 6 := by simp at count; omega
    have finishAt : finish prefix token = .ok (prefix ++ [token]) := by simp [finish, room, tokenValid]
    simp only [List.headD_cons, List.tail_cons]
    rw [scan_one_token token prefix [] (encode rest) free (by simpa using bounded)]
    simp only [List.nil_append]
    cases rest with
    | nil => simpa [encode, scan] using finishAt
    | cons next later =>
      simp only [encode, List.flatMap_cons, List.cons_append, scan, ↓reduceIte, finishAt]
      have remainingValid : ∀ value ∈ next :: later, OperationIdentity.validToken value 64 = true :=
        fun value member => valid value (List.mem_cons_of_mem _ member)
      have nextCount : (prefix ++ [token]).length + (next :: later).length ≤ 6 := by simp at count ⊢; omega
      have recursive := ih (prefix ++ [token]) (by simp) remainingValid nextCount
      simpa [List.headD_cons, List.tail_cons, encode, List.append_assoc] using recursive

theorem decode_complete (pointer : Bytes) (tokens : List Bytes) (meaning : Meaning pointer tokens) : decode pointer = .ok tokens := by
  obtain ⟨rfl, positive, count, valid, byteBound⟩ := meaning
  have nonempty : tokens ≠ [] := List.ne_nil_of_length_pos positive
  have bounded : (encode tokens).length ≤ 128 := by simpa [encode_size] using byteBound
  cases tokens with
  | nil => contradiction
  | cons first rest =>
    have parsed := scan_valid_tokens (first :: rest) [] (by simp) valid (by simpa using count)
    simpa [decode, encode, bounded] using parsed

theorem decode_exact (pointer : Bytes) (tokens : List Bytes) : decode pointer = .ok tokens ↔ Meaning pointer tokens :=
  ⟨decode_sound pointer tokens, decode_complete pointer tokens⟩

theorem accepted_pointer_is_unique (pointer : Bytes) (first second : List Bytes)
    (left : Meaning pointer first) (right : Meaning pointer second) : first = second := by
  have same := (decode_complete pointer first left).symm.trans (decode_complete pointer second right)
  simpa using same

theorem encoded_names_are_injective (first second : List Bytes) (left : PointerDomain first) (right : PointerDomain second)
    (same : encode first = encode second) : first = second :=
  accepted_pointer_is_unique (encode first) first second ⟨rfl, left⟩ ⟨same, right⟩

theorem scan_error_class (remaining : Bytes) (prefix : List Bytes) (token : Bytes) (error : Error)
    (refused : scan prefix token remaining = .error error) : error = .echoConflict := by
  induction remaining generalizing prefix token with
  | nil => unfold scan finish at refused; split at refused <;> simp_all
  | cons byte rest ih =>
    unfold scan at refused
    split at refused
    · cases done : finish prefix token with
      | error actual => unfold finish at done; split at done <;> simp_all
      | ok next => exact ih next [] (by simpa [done] using refused)
    · split at refused
      · exact ih _ _ refused
      · simpa using refused.symm

theorem decode_error_class (pointer : Bytes) (error : Error) (refused : decode pointer = .error error) : error = .echoConflict := by
  cases pointer with
  | nil => simpa [decode] using refused.symm
  | cons first rest =>
    by_cases slash : first = 47
    · subst first
      by_cases bounded : (47 :: rest).length ≤ 128
      · exact scan_error_class rest [] [] error (by simpa [decode, bounded] using refused)
      · simpa [decode, bounded] using refused.symm
    · simpa [decode, slash] using refused.symm

theorem refusal_exact (pointer : Bytes) : decode pointer = .error .echoConflict ↔ ¬∃ tokens, Meaning pointer tokens := by
  constructor
  · rintro refused ⟨tokens, meaning⟩
    have accepted := decode_complete pointer tokens meaning
    simp [refused] at accepted
  · intro invalid
    cases result : decode pointer with
    | error error => simpa [decode_error_class pointer error result] using result
    | ok tokens => exact False.elim (invalid ⟨tokens, decode_sound pointer tokens result⟩)

end Auths.Product.EchoPointer
