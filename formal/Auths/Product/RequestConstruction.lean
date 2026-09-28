import Mathlib.Data.List.Basic

/-!
# Closed request construction

A compiled recipe lowers to closed plans; construction turns a plan and the
verified argument values into request bytes. This model follows the shipping
leaf's structure: validation, then total rendering, then bounds. Bytes are
natural numbers; the refinement maps the translated `u8` values onto them.

Each theorem holds for every plan and every argument list, so for every
compiled recipe and every argument map the compiler and the gateway shell
produce:

* `method_and_origin_fixed`: a write uses exactly the plan's method, an
  action read is a GET, and both URLs start with the pinned origin;
* `path_from_declared_segments`: the path is exactly the declared segments in
  order, each a fixed segment or the percent-encoding of a verified text
  argument, and an encoding never contains `/`, `?`, or `#`;
* `headers_within_declaration`: every header is a declared version header, the
  declared account-scope header, or the derived idempotency header;
* `account_scope_header_exact`: the write and every action read carry the
  account-scope header with exactly the verified value, a credential read
  carries only the version headers, and without a declared scope no request
  carries anything but version headers and the idempotency header;
* `credential_reads_fixed`: a credential read is a function of its plan
  alone, with the plan's method and its fixed segments;
* `body_bounded`: a body is 1 to 16 384 bytes and depends only on the
  arguments the plan references.
-/

namespace Auths.Product.RequestConstruction

abbrev Bytes := List Nat

inductive Arg where
  | text (value : Bytes)
  | integer (digits : Bytes)
  | boolean (value : Bool)
  deriving DecidableEq

inductive Segment where
  | fixed (value : Bytes)
  | field (index : Nat)
  deriving DecidableEq

structure Header where
  name : Bytes
  value : Bytes
  deriving DecidableEq

structure ScopePlan where
  name : Bytes
  field : Nat
  deriving DecidableEq

structure HeaderPlan where
  versions : List Header
  scope : Option ScopePlan
  deriving DecidableEq

inductive JsonPiece where
  | raw (value : Bytes)
  | field (index : Nat)
  | echo
  deriving DecidableEq

inductive FormPiece where
  | raw (value : Bytes)
  | field (index : Nat)
  | json (pieces : List JsonPiece)
  | echo
  deriving DecidableEq

inductive BodyPlan where
  | json (pieces : List JsonPiece)
  | form (pieces : List FormPiece)
  deriving DecidableEq

inductive Method where
  | get
  | head
  | post
  | put
  | patch
  | delete
  deriving DecidableEq

structure WritePlan where
  method : Method
  origin : Bytes
  path : List Segment
  headers : HeaderPlan
  idempotency : Option Bytes
  body : BodyPlan

structure ReadPlan where
  origin : Bytes
  path : List Segment
  headers : HeaderPlan

structure CredentialPlan where
  method : Method
  origin : Bytes
  path : List Bytes
  versions : List Header

structure Request where
  method : Method
  url : Bytes
  headers : List Header
  body : Bytes

inductive ConstructError where
  | argumentMismatch
  | unsafeSegment
  | pathTooLong
  | headerValue
  | bodySize
  deriving DecidableEq

/-! ## Bytes -/

def maxBodyBytes : Nat := 16384
def maxSegmentValueBytes : Nat := 4096
def maxPathBytes : Nat := 8192

def alphanumeric (byte : Nat) : Bool :=
  (48 ≤ byte && byte ≤ 57) || (65 ≤ byte && byte ≤ 90) || (97 ≤ byte && byte ≤ 122)

def pathLiteral (byte : Nat) : Bool :=
  alphanumeric byte || byte == 45 || byte == 95 || byte == 46 || byte == 126

def formLiteral (byte : Nat) : Bool :=
  alphanumeric byte || byte == 42 || byte == 45 || byte == 46 || byte == 95

def hexUpper (nibble : Nat) : Nat :=
  if nibble < 10 then 48 + nibble else 65 + (nibble - 10)

def hexLower (nibble : Nat) : Nat :=
  if nibble < 10 then 48 + nibble else 97 + (nibble - 10)

def percent (byte : Nat) : Bytes :=
  [37, hexUpper (byte / 16), hexUpper (byte % 16)]

def pathByte (byte : Nat) : Bytes :=
  if pathLiteral byte then [byte] else percent byte

def pathEncode (text : Bytes) : Bytes :=
  text.flatMap pathByte

def formByte (byte : Nat) : Bytes :=
  if byte == 32 then [43] else if formLiteral byte then [byte] else percent byte

def formEncode (text : Bytes) : Bytes :=
  text.flatMap formByte

def jsonByte (byte : Nat) : Bytes :=
  if byte == 34 || byte == 92 then [92, byte]
  else if byte == 8 then [92, 98]
  else if byte == 9 then [92, 116]
  else if byte == 10 then [92, 110]
  else if byte == 12 then [92, 102]
  else if byte == 13 then [92, 114]
  else if byte < 32 then [92, 117, 48, 48, hexLower (byte / 16), hexLower (byte % 16)]
  else [byte]

def jsonEscape (text : Bytes) : Bytes :=
  text.flatMap jsonByte

def jsonString (text : Bytes) : Bytes :=
  34 :: jsonEscape text ++ [34]

/-! ## Paths -/

def segmentValueValid (text : Bytes) : Bool :=
  !text.isEmpty && decide (text.length ≤ maxSegmentValueBytes) &&
    text != [46] && text != [46, 46]

def segmentError (arguments : List Arg) : Segment → Option ConstructError
  | .fixed _ => none
  | .field index =>
      match arguments[index]? with
      | some (.text text) => if segmentValueValid text then none else some .unsafeSegment
      | _ => some .argumentMismatch

def pathError (arguments : List Arg) : List Segment → Option ConstructError
  | [] => none
  | segment :: rest =>
      match segmentError arguments segment with
      | some error => some error
      | none => pathError arguments rest

def segmentBytes (arguments : List Arg) : Segment → Bytes
  | .fixed value => value
  | .field index =>
      match arguments[index]? with
      | some (.text text) => pathEncode text
      | _ => []

def renderPath (arguments : List Arg) (path : List Segment) : Bytes :=
  path.flatMap fun segment => 47 :: segmentBytes arguments segment

def buildUrl (origin : Bytes) (path : List Segment) (arguments : List Arg) :
    Except ConstructError Bytes :=
  match pathError arguments path with
  | some error => .error error
  | none =>
      if maxPathBytes < (renderPath arguments path).length then .error .pathTooLong
      else .ok (origin ++ renderPath arguments path)

def fixedUrl (origin : Bytes) (path : List Bytes) : Bytes :=
  origin ++ path.flatMap fun segment => 47 :: segment

/-! ## Headers -/

def accountByte (byte : Nat) : Bool :=
  alphanumeric byte || byte == 95

def scopeValueValid (value : Bytes) : Bool :=
  decide (13 ≤ value.length) && decide (value.length ≤ 64) &&
    value.take 5 == [97, 99, 99, 116, 95] && (value.drop 5).all accountByte

def scopeHeader (scope : ScopePlan) (arguments : List Arg) : Except ConstructError Header :=
  match arguments[scope.field]? with
  | some (.text value) =>
      if scopeValueValid value then .ok ⟨scope.name, value⟩ else .error .headerValue
  | _ => .error .argumentMismatch

def actionHeaders (plan : HeaderPlan) (arguments : List Arg) :
    Except ConstructError (List Header) :=
  match plan.scope with
  | none => .ok plan.versions
  | some scope =>
      match scopeHeader scope arguments with
      | .ok header => .ok (plan.versions ++ [header])
      | .error error => .error error

/-! ## Bodies -/

def jsonArgument : Arg → Bytes
  | .text text => jsonString text
  | .integer digits => digits
  | .boolean true => [116, 114, 117, 101]
  | .boolean false => [102, 97, 108, 115, 101]

def jsonPieceValid (arguments : List Arg) : JsonPiece → Bool
  | .field index => decide (index < arguments.length)
  | .raw _ | .echo => true

def renderJsonPiece (arguments : List Arg) (echo : Bytes) : JsonPiece → Bytes
  | .raw value => value
  | .field index =>
      match arguments[index]? with
      | some argument => jsonArgument argument
      | none => []
  | .echo => jsonString echo

def renderJson (arguments : List Arg) (echo : Bytes) (pieces : List JsonPiece) : Bytes :=
  pieces.flatMap (renderJsonPiece arguments echo)

def formPieceValid (arguments : List Arg) : FormPiece → Bool
  | .raw _ | .echo => true
  | .field index =>
      match arguments[index]? with
      | some (.text _) | some (.integer _) => true
      | _ => false
  | .json pieces => pieces.all (jsonPieceValid arguments)

def renderFormPiece (arguments : List Arg) (echo : Bytes) : FormPiece → Bytes
  | .raw value => value
  | .field index =>
      match arguments[index]? with
      | some (.text text) => formEncode text
      | some (.integer digits) => formEncode digits
      | _ => []
  | .json pieces => formEncode (renderJson arguments echo pieces)
  | .echo => formEncode echo

def bodyValid (arguments : List Arg) : BodyPlan → Bool
  | .json pieces => pieces.all (jsonPieceValid arguments)
  | .form pieces => pieces.all (formPieceValid arguments)

def renderBody (arguments : List Arg) (echo : Bytes) : BodyPlan → Bytes
  | .json pieces => renderJson arguments echo pieces
  | .form pieces => pieces.flatMap (renderFormPiece arguments echo)

def buildBody (plan : BodyPlan) (arguments : List Arg) (echo : Bytes) :
    Except ConstructError Bytes :=
  if bodyValid arguments plan then
    if (renderBody arguments echo plan).length = 0 ||
        maxBodyBytes < (renderBody arguments echo plan).length then .error .bodySize
    else .ok (renderBody arguments echo plan)
  else .error .argumentMismatch

/-! ## Requests -/

def writeHeaders (plan : WritePlan) (headers : List Header) (key : Bytes) : List Header :=
  match plan.idempotency with
  | some name => headers ++ [⟨name, key⟩]
  | none => headers

def constructWrite (plan : WritePlan) (arguments : List Arg) (echo key : Bytes) :
    Except ConstructError Request :=
  match buildUrl plan.origin plan.path arguments with
  | .error error => .error error
  | .ok url =>
      match buildBody plan.body arguments echo with
      | .error error => .error error
      | .ok body =>
          match actionHeaders plan.headers arguments with
          | .error error => .error error
          | .ok headers => .ok ⟨plan.method, url, writeHeaders plan headers key, body⟩

def constructActionRead (plan : ReadPlan) (arguments : List Arg) :
    Except ConstructError Request :=
  match buildUrl plan.origin plan.path arguments with
  | .error error => .error error
  | .ok url =>
      match actionHeaders plan.headers arguments with
      | .error error => .error error
      | .ok headers => .ok ⟨.get, url, headers, []⟩

def constructCredentialRead (plan : CredentialPlan) : Request :=
  ⟨plan.method, fixedUrl plan.origin plan.path, plan.versions, []⟩

/-! ## Lemmas -/

theorem buildUrl_ok {origin : Bytes} {path : List Segment} {arguments : List Arg}
    {url : Bytes} (built : buildUrl origin path arguments = .ok url) :
    url = origin ++ renderPath arguments path ∧ pathError arguments path = none ∧
      (renderPath arguments path).length ≤ maxPathBytes := by
  unfold buildUrl at built
  split at built
  · cases built
  · rename_i valid
    split at built
    · cases built
    · rename_i fits
      cases built
      exact ⟨rfl, valid, Nat.le_of_not_lt fits⟩

theorem pathError_none_iff {arguments : List Arg} {path : List Segment} :
    pathError arguments path = none ↔ ∀ segment ∈ path, segmentError arguments segment = none := by
  induction path with
  | nil => simp [pathError]
  | cons segment rest inductive_hypothesis =>
      unfold pathError
      cases equation : segmentError arguments segment <;> simp [equation, inductive_hypothesis]

theorem buildBody_ok {plan : BodyPlan} {arguments : List Arg} {echo body : Bytes}
    (built : buildBody plan arguments echo = .ok body) :
    body = renderBody arguments echo plan ∧ bodyValid arguments plan = true ∧
      0 < body.length ∧ body.length ≤ maxBodyBytes := by
  unfold buildBody at built
  split at built
  · rename_i valid
    split at built
    · cases built
    · rename_i fits
      cases built
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at fits
      exact ⟨rfl, valid, Nat.pos_of_ne_zero fits.1, Nat.le_of_not_lt fits.2⟩
  · cases built

theorem actionHeaders_ok {plan : HeaderPlan} {arguments : List Arg} {headers : List Header}
    (built : actionHeaders plan arguments = .ok headers) :
    match plan.scope with
    | none => headers = plan.versions
    | some scope => ∃ value, arguments[scope.field]? = some (.text value) ∧
        scopeValueValid value = true ∧ headers = plan.versions ++ [⟨scope.name, value⟩] := by
  unfold actionHeaders at built
  cases scopeEquation : plan.scope with
  | none =>
      simp only [scopeEquation] at built
      cases built
      rfl
  | some scope =>
      simp only [scopeEquation] at built
      split at built
      · rename_i header headerEquation
        cases built
        unfold scopeHeader at headerEquation
        split at headerEquation
        · rename_i value argumentEquation
          split at headerEquation
          · rename_i valid
            cases headerEquation
            exact ⟨value, argumentEquation, valid, rfl⟩
          · cases headerEquation
        · cases headerEquation
      · cases built

theorem constructWrite_ok {plan : WritePlan} {arguments : List Arg} {echo key : Bytes}
    {request : Request} (built : constructWrite plan arguments echo key = .ok request) :
    ∃ url body headers,
      buildUrl plan.origin plan.path arguments = .ok url ∧
      buildBody plan.body arguments echo = .ok body ∧
      actionHeaders plan.headers arguments = .ok headers ∧
      request = ⟨plan.method, url, writeHeaders plan headers key, body⟩ := by
  unfold constructWrite at built
  split at built
  · cases built
  · rename_i url urlEquation
    split at built
    · cases built
    · rename_i body bodyEquation
      split at built
      · cases built
      · rename_i headers headerEquation
        cases built
        exact ⟨url, body, headers, urlEquation, bodyEquation, headerEquation, rfl⟩

theorem constructActionRead_ok {plan : ReadPlan} {arguments : List Arg} {request : Request}
    (built : constructActionRead plan arguments = .ok request) :
    ∃ url headers,
      buildUrl plan.origin plan.path arguments = .ok url ∧
      actionHeaders plan.headers arguments = .ok headers ∧
      request = ⟨.get, url, headers, []⟩ := by
  unfold constructActionRead at built
  split at built
  · cases built
  · rename_i url urlEquation
    split at built
    · cases built
    · rename_i headers headerEquation
      cases built
      exact ⟨url, headers, urlEquation, headerEquation, rfl⟩

theorem percent_separator_free (byte : Nat) (separator : Nat)
    (isSeparator : separator = 47 ∨ separator = 63 ∨ separator = 35) :
    separator ∉ percent byte := by
  have high : byte / 16 % 16 < 16 := Nat.mod_lt _ (by decide)
  unfold percent hexUpper
  rcases isSeparator with rfl | rfl | rfl <;>
    simp only [List.mem_cons, List.not_mem_nil, or_false, not_or] <;>
    refine ⟨by decide, ?_, ?_⟩ <;> split <;> omega

theorem pathEncode_separator_free (text : Bytes) (separator : Nat)
    (isSeparator : separator = 47 ∨ separator = 63 ∨ separator = 35) :
    separator ∉ pathEncode text := by
  unfold pathEncode
  simp only [List.mem_flatMap, not_exists, not_and]
  intro byte _
  unfold pathByte
  split
  · rename_i literal
    simp only [List.mem_singleton]
    rintro rfl
    rcases isSeparator with rfl | rfl | rfl <;> simp [pathLiteral, alphanumeric] at literal
  · exact percent_separator_free byte separator isSeparator

/-! ## The construction theorems -/

/-- A write uses exactly the plan's method and an action read is a GET; both
URLs start with the pinned origin. -/
theorem method_and_origin_fixed :
    (∀ (plan : WritePlan) arguments echo key request,
      constructWrite plan arguments echo key = .ok request →
        request.method = plan.method ∧ plan.origin <+: request.url) ∧
    (∀ (plan : ReadPlan) arguments request,
      constructActionRead plan arguments = .ok request →
        request.method = .get ∧ plan.origin <+: request.url) := by
  constructor
  · intro plan arguments echo key request built
    obtain ⟨url, body, headers, urlOk, _, _, rfl⟩ := constructWrite_ok built
    obtain ⟨rfl, _, _⟩ := buildUrl_ok urlOk
    exact ⟨rfl, List.prefix_append _ _⟩
  · intro plan arguments request built
    obtain ⟨url, headers, urlOk, _, rfl⟩ := constructActionRead_ok built
    obtain ⟨rfl, _, _⟩ := buildUrl_ok urlOk
    exact ⟨rfl, List.prefix_append _ _⟩

/-- The URL is the origin followed by exactly the declared segments in order:
a fixed segment verbatim, or the percent-encoding of the verified text
argument a field names, which is valid and never contains `/`, `?`, or `#`. -/
theorem path_from_declared_segments :
    (∀ (plan : WritePlan) arguments echo key request,
      constructWrite plan arguments echo key = .ok request →
        request.url = plan.origin ++ renderPath arguments plan.path ∧
        ∀ segment ∈ plan.path, match segment with
          | .fixed _ => True
          | .field index => ∃ text, arguments[index]? = some (.text text) ∧
              segmentValueValid text = true ∧ segmentBytes arguments segment = pathEncode text) ∧
    (∀ (plan : ReadPlan) arguments request,
      constructActionRead plan arguments = .ok request →
        request.url = plan.origin ++ renderPath arguments plan.path) ∧
    (∀ text separator, separator = 47 ∨ separator = 63 ∨ separator = 35 →
      separator ∉ pathEncode text) := by
  refine ⟨?_, ?_, pathEncode_separator_free⟩
  · intro plan arguments echo key request built
    obtain ⟨url, body, headers, urlOk, _, _, rfl⟩ := constructWrite_ok built
    obtain ⟨rfl, valid, _⟩ := buildUrl_ok urlOk
    refine ⟨rfl, ?_⟩
    intro segment member
    have segmentValid := pathError_none_iff.mp valid segment member
    cases segment with
    | fixed _ => trivial
    | field index =>
        simp only [segmentError] at segmentValid
        split at segmentValid
        · rename_i text equation
          split at segmentValid
          · rename_i textValid
            exact ⟨text, equation, textValid, by simp [segmentBytes, equation]⟩
          · cases segmentValid
        · cases segmentValid
  · intro plan arguments request built
    obtain ⟨url, headers, urlOk, _, rfl⟩ := constructActionRead_ok built
    exact (buildUrl_ok urlOk).1

/-- Every header of a write is a declared version header, the declared
account-scope header, or the derived idempotency header. -/
theorem headers_within_declaration (plan : WritePlan) (arguments : List Arg)
    (echo key : Bytes) (request : Request)
    (built : constructWrite plan arguments echo key = .ok request) :
    ∀ header ∈ request.headers,
      header ∈ plan.headers.versions ∨
        (∃ scope, plan.headers.scope = some scope ∧ header.name = scope.name) ∨
        (∃ name, plan.idempotency = some name ∧ header = ⟨name, key⟩) := by
  obtain ⟨url, body, headers, _, _, headersOk, rfl⟩ := constructWrite_ok built
  have shape := actionHeaders_ok headersOk
  intro header member
  have inHeaders : header ∈ headers ∨
      ∃ name, plan.idempotency = some name ∧ header = ⟨name, key⟩ := by
    unfold writeHeaders at member
    split at member
    · rename_i name equation
      rcases List.mem_append.mp member with inner | last
      · exact .inl inner
      · exact .inr ⟨name, equation, List.mem_singleton.mp last⟩
    · exact .inl member
  rcases inHeaders with inner | idempotent
  · revert shape
    cases scopeEquation : plan.headers.scope with
    | none =>
        intro shape
        simp only at shape
        subst shape
        exact .inl inner
    | some scope =>
        intro shape
        obtain ⟨value, _, _, rfl⟩ := shape
        rcases List.mem_append.mp inner with version | scopeMember
        · exact .inl version
        · exact .inr (.inl ⟨scope, rfl, by rw [List.mem_singleton.mp scopeMember]⟩)
  · exact .inr (.inr idempotent)

/-- The write and every action read carry the declared account-scope header
with exactly the verified value, which matches its grammar; a credential read
carries only the version headers; and without a declared scope, a write
carries only version headers and the idempotency header and an action read
only version headers. -/
theorem account_scope_header_exact :
    (∀ (plan : WritePlan) arguments echo key request scope,
      constructWrite plan arguments echo key = .ok request →
      plan.headers.scope = some scope →
        ∃ value, arguments[scope.field]? = some (.text value) ∧
          scopeValueValid value = true ∧ ⟨scope.name, value⟩ ∈ request.headers) ∧
    (∀ (plan : ReadPlan) arguments request scope,
      constructActionRead plan arguments = .ok request →
      plan.headers.scope = some scope →
        ∃ value, arguments[scope.field]? = some (.text value) ∧
          scopeValueValid value = true ∧ request.headers = plan.headers.versions ++ [⟨scope.name, value⟩]) ∧
    (∀ plan : CredentialPlan, (constructCredentialRead plan).headers = plan.versions) ∧
    (∀ (plan : WritePlan) arguments echo key request,
      constructWrite plan arguments echo key = .ok request →
      plan.headers.scope = none →
        request.headers = writeHeaders plan plan.headers.versions key) ∧
    (∀ (plan : ReadPlan) arguments request,
      constructActionRead plan arguments = .ok request →
      plan.headers.scope = none → request.headers = plan.headers.versions) := by
  refine ⟨?_, ?_, fun _ => rfl, ?_, ?_⟩
  · intro plan arguments echo key request scope built scopeEquation
    obtain ⟨url, body, headers, _, _, headersOk, rfl⟩ := constructWrite_ok built
    have shape := actionHeaders_ok headersOk
    rw [scopeEquation] at shape
    obtain ⟨value, argument, valid, rfl⟩ := shape
    refine ⟨value, argument, valid, ?_⟩
    unfold writeHeaders
    split <;> simp
  · intro plan arguments request scope built scopeEquation
    obtain ⟨url, headers, _, headersOk, rfl⟩ := constructActionRead_ok built
    have shape := actionHeaders_ok headersOk
    rw [scopeEquation] at shape
    exact shape
  · intro plan arguments echo key request built scopeEquation
    obtain ⟨url, body, headers, _, _, headersOk, rfl⟩ := constructWrite_ok built
    have shape := actionHeaders_ok headersOk
    rw [scopeEquation] at shape
    simp only at shape
    subst shape
    rfl
  · intro plan arguments request built scopeEquation
    obtain ⟨url, headers, _, headersOk, rfl⟩ := constructActionRead_ok built
    have shape := actionHeaders_ok headersOk
    rw [scopeEquation] at shape
    exact shape

/-- A credential read is a function of its plan alone: the plan's method, the
origin and fixed segments, the version headers, and no body. A `GET` or `HEAD`
plan gives a `GET` or `HEAD` request. -/
theorem credential_reads_fixed (plan : CredentialPlan) :
    (constructCredentialRead plan).method = plan.method ∧
      (constructCredentialRead plan).url = plan.origin ++ plan.path.flatMap (fun segment => 47 :: segment) ∧
      (constructCredentialRead plan).headers = plan.versions ∧
      (constructCredentialRead plan).body = [] ∧
      (plan.method = .get ∨ plan.method = .head →
        (constructCredentialRead plan).method = .get ∨ (constructCredentialRead plan).method = .head) :=
  ⟨rfl, rfl, rfl, rfl, id⟩

/-- The argument indices a body plan reads. -/
def jsonFields : List JsonPiece → List Nat
  | [] => []
  | .field index :: rest => index :: jsonFields rest
  | _ :: rest => jsonFields rest

def formFields : List FormPiece → List Nat
  | [] => []
  | .field index :: rest => index :: formFields rest
  | .json pieces :: rest => jsonFields pieces ++ formFields rest
  | _ :: rest => formFields rest

def bodyFields : BodyPlan → List Nat
  | .json pieces => jsonFields pieces
  | .form pieces => formFields pieces

theorem renderJson_congr (echo : Bytes) (pieces : List JsonPiece) (left right : List Arg)
    (agree : ∀ index ∈ jsonFields pieces, left[index]? = right[index]?) :
    renderJson left echo pieces = renderJson right echo pieces := by
  induction pieces with
  | nil => rfl
  | cons piece rest inductive_hypothesis =>
      cases piece with
      | raw value =>
          simp only [renderJson, List.flatMap_cons, renderJsonPiece] at *
          rw [inductive_hypothesis (by simpa [jsonFields] using agree)]
      | echo =>
          simp only [renderJson, List.flatMap_cons, renderJsonPiece] at *
          rw [inductive_hypothesis (by simpa [jsonFields] using agree)]
      | field index =>
          simp only [jsonFields, List.mem_cons, forall_eq_or_imp] at agree
          simp only [renderJson, List.flatMap_cons, renderJsonPiece] at *
          rw [agree.1, inductive_hypothesis agree.2]

theorem renderForm_congr (echo : Bytes) (pieces : List FormPiece) (left right : List Arg)
    (agree : ∀ index ∈ formFields pieces, left[index]? = right[index]?) :
    pieces.flatMap (renderFormPiece left echo) = pieces.flatMap (renderFormPiece right echo) := by
  induction pieces with
  | nil => rfl
  | cons piece rest inductive_hypothesis =>
      cases piece with
      | raw value =>
          simp only [List.flatMap_cons, renderFormPiece] at *
          rw [inductive_hypothesis (by simpa [formFields] using agree)]
      | echo =>
          simp only [List.flatMap_cons, renderFormPiece] at *
          rw [inductive_hypothesis (by simpa [formFields] using agree)]
      | field index =>
          simp only [formFields, List.mem_cons, forall_eq_or_imp] at agree
          simp only [List.flatMap_cons, renderFormPiece] at *
          rw [agree.1, inductive_hypothesis agree.2]
      | json inner =>
          simp only [formFields, List.mem_append] at agree
          simp only [List.flatMap_cons, renderFormPiece] at *
          rw [renderJson_congr echo inner left right (fun index member => agree index (.inl member)),
            inductive_hypothesis (fun index member => agree index (.inr member))]

/-- A write body is 1 to 16 384 bytes, is the rendering of the plan, and
depends only on the arguments the plan references. -/
theorem body_bounded :
    (∀ (plan : WritePlan) arguments echo key request,
      constructWrite plan arguments echo key = .ok request →
        0 < request.body.length ∧ request.body.length ≤ maxBodyBytes ∧
          request.body = renderBody arguments echo plan.body) ∧
    (∀ (plan : BodyPlan) echo (left right : List Arg),
      (∀ index ∈ bodyFields plan, left[index]? = right[index]?) →
        renderBody left echo plan = renderBody right echo plan) := by
  constructor
  · intro plan arguments echo key request built
    obtain ⟨url, body, headers, _, bodyOk, _, rfl⟩ := constructWrite_ok built
    obtain ⟨rfl, _, positive, bounded⟩ := buildBody_ok bodyOk
    exact ⟨positive, bounded, rfl⟩
  · intro plan echo left right agree
    cases plan with
    | json pieces => exact renderJson_congr echo pieces left right agree
    | form pieces => exact renderForm_congr echo pieces left right agree

end Auths.Product.RequestConstruction
