import Std.Tactic
namespace Auths.StatusSelection.Model

inductive Scope where
  | ownAnchor
  | anchors (ids : List String)
  | anyAnchor
  deriving DecidableEq
structure Rule where
  method : String
  issuer : String
  floor : Nat
  scope : Scope
  deriving DecidableEq
inductive View where
  | anchor (id principal : String)
  | approver
  deriving DecidableEq

def scopeCovers (scope : Scope) (issuer : String) : View → Bool
  | .anchor id principal => match scope with
    | .ownAnchor => principal == issuer
    | .anchors ids => ids.contains id
    | .anyAnchor => true
  | .approver => match scope with
    | .anyAnchor => true
    | _ => false

def visible (rules : List Rule) (issuer : String) (view : View) : Bool :=
  rules.all (fun rule => rule.issuer != issuer || scopeCovers rule.scope issuer view)

theorem visible_cons (rule : Rule) (rules : List Rule) (issuer : String) (view : View) :
    visible (rule :: rules) issuer view =
      if rule.issuer == issuer then scopeCovers rule.scope issuer view && visible rules issuer view
      else visible rules issuer view := by
  cases matched : (rule.issuer == issuer) <;> simp_all [visible, bne_eq]

def sequenceFloor (rules : List Rule) (method issuer : String) : Option Nat :=
  (rules.find? (fun rule => rule.method == method && rule.issuer == issuer)).map Rule.floor

def floorScan (rules : List Rule) (method issuer : String) (found : Option Nat) : Option Nat :=
  match found with
  | some value => some value
  | none => sequenceFloor rules method issuer

inductive Decision where
  | active | revoked | missing | stale | rollback | untrusted | wrongMethod
  deriving DecidableEq
structure Evaluation where
  decision : Decision
  through : Nat
  deriving DecidableEq
inductive Policy where
  | expiryOnly
  | required (method : String) (maximumAge : Nat)
  deriving DecidableEq
structure Statement (Subject : Type) where
  subject : Subject
  method : String
  issuer : String
  sequence : Nat
  observed : Nat
  expiresAt : Nat
  active : Bool
  deriving DecidableEq

def fresh (age observed expiresAt now : Nat) : Bool :=
  decide (observed ≤ now ∧ now ≤ expiresAt ∧ now - observed ≤ age)

def wordMaximum : Nat := 2^64 - 1

def deadline (age observed expiresAt : Nat) : Nat :=
  min expiresAt (min wordMaximum (observed + age))

/-- Independent list/filter specification: trust uses the first exact rule;
    rollback considers every trusted candidate; only the highest sequence's
    entire tie set supplies freshness, revocation and the inclusive horizon. -/
def evaluate {Subject : Type} [BEq Subject]
    (id : String) (policy : Policy) (observed expiresAt : Nat)
    (rules : List Rule) (statements : List (Statement Subject))
    (subject : Subject) (view : View) (now : Nat) : Evaluation :=
  match policy with
  | .expiryOnly => ⟨.active, wordMaximum⟩
  | .required method age =>
    if method != id then ⟨.wrongMethod, now⟩
    else if observed > now || expiresAt < now then ⟨.stale, now⟩
    else
      let candidates := statements.filter (fun row => row.subject == subject && visible rules row.issuer view)
      let matching := candidates.filter (fun row => row.method == method)
      let trusted := matching.filterMap (fun row => (sequenceFloor rules method row.issuer).map (fun floor => (row, floor)))
      if candidates.isEmpty then ⟨.missing, expiresAt⟩
      else if matching.isEmpty then ⟨.wrongMethod, now⟩
      else if trusted.isEmpty then ⟨.untrusted, now⟩
      else if trusted.any (fun (row, floor) => row.sequence < floor) then ⟨.rollback, now⟩
      else
        let maximum := trusted.foldl (fun maximum (row, _) => max maximum row.sequence) 0
        let latest := trusted.filter (fun (row, _) => row.sequence == maximum)
        if latest.any (fun (row, _) => !fresh age row.observed row.expiresAt now) then ⟨.stale, now⟩
        else
          ⟨if latest.any (fun (row, _) => !row.active) then .revoked else .active,
            latest.foldl (fun horizon (row, _) => min horizon (deadline age row.observed row.expiresAt)) expiresAt⟩

/-- Operational accumulator, to be related to the independent filter/max spec. -/
structure Scan where
  candidateSeen : Bool
  methodSeen : Bool
  rollback : Bool
  maximum : Option Nat
  stale : Bool
  revoked : Bool
  through : Nat
  deriving DecidableEq

def initial (expiresAt : Nat) : Scan := ⟨false, false, false, none, false, false, expiresAt⟩

def contribute {Subject : Type} (expiresAt age now : Nat) (row : Statement Subject) (state : Scan) : Scan :=
  let newer := match state.maximum with | none => true | some previous => decide (previous < row.sequence)
  let equal := match state.maximum with | none => false | some previous => row.sequence == previous
  let base := if newer then {state with maximum := some row.sequence, stale := false, revoked := false, through := expiresAt} else state
  if newer || equal then
    {base with
      stale := (base.stale || !(fresh age row.observed row.expiresAt now)),
      revoked := (base.revoked || !row.active),
      through := min base.through (deadline age row.observed row.expiresAt)}
  else base

def record {Subject : Type} [BEq Subject] (expiresAt age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View)
    (row : Statement Subject) (state : Scan) : Scan :=
  if row.subject == subject && visible rules row.issuer view then
    let seen := {state with candidateSeen := true}
    if row.method == method then
      let matched := {seen with methodSeen := true}
      match sequenceFloor rules method row.issuer with
      | none => matched
      | some floor => if row.sequence < floor then {matched with rollback := true}
        else contribute expiresAt age now row matched
    else seen
  else state

def scan {Subject : Type} [BEq Subject] (expiresAt age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View) :
    List (Statement Subject) → Scan → Scan
  | [], state => state
  | row :: rest, state => if state.rollback then state
      else scan expiresAt age now method rules subject view rest (record expiresAt age now method rules subject view row state)

def finish (expiresAt now : Nat) (state : Scan) : Evaluation :=
  let decision := if state.rollback then .rollback
    else if !state.candidateSeen then .missing
    else if !state.methodSeen then .wrongMethod
    else if state.maximum.isNone then .untrusted
    else if state.stale then .stale
    else if state.revoked then .revoked else .active
  ⟨decision, match decision with | .missing => expiresAt | .active | .revoked => state.through | _ => now⟩
def evaluateScan {Subject : Type} [BEq Subject]
    (id : String) (policy : Policy) (observed expiresAt : Nat)
    (rules : List Rule) (statements : List (Statement Subject))
    (subject : Subject) (view : View) (now : Nat) : Evaluation :=
  match policy with
  | .expiryOnly => ⟨.active, wordMaximum⟩
  | .required method age =>
    if method != id then ⟨.wrongMethod, now⟩
    else if observed > now || expiresAt < now then ⟨.stale, now⟩
    else finish expiresAt now (scan expiresAt age now method rules subject view statements (initial expiresAt))
end Auths.StatusSelection.Model
