import Auths.Support.NativeBorrowProtocol

/-!
Executable routing of existing payloads between native backward boundary ports.
The full native type and selected sub-abstraction level stay in each port. A
checked route must preserve the actual symbolic identity, level and normalized
type. Payload normalization/layout, projected-value meaning and native heap/loan
adequacy remain separate requirements; no payload operation/result is assumed.
-/
namespace Auths.Support.NativeBorrowWiring
open SourceClosureRegions
universe u

inductive Edge where
  | root (index : Nat)
  | field (index : Nat)
  | child
  | givenBack
  | consumed (index : Nat)
  | borrowReprojection (index : Nat)
  | loanReprojection (index : Nat)
  | argument (group index : Nat)
  | continuationInput
  | continuationOutput
  deriving DecidableEq, Repr

structure Port where
  identity : Nat
  nativeType : Expr
  payloadType : Expr
  abstraction : Nat
  group : Nat
  inputAbstraction : Bool
  level : Nat
  givenBack : Bool
  abstractPath : List Edge
  continuationPath : List Edge
  deriving DecidableEq, Repr

structure Event where
  abstraction : Nat
  group : Nat
  inputAbstraction : Bool
  level : Nat
  ports : List Port
  deriving DecidableEq, Repr

/-- An internal source link records two actual event ports. It supplies no
payload and does not execute either event. -/
structure Internal where
  producerEvent : Nat
  consumerEvent : Nat
  producer : Port
  consumer : Port
  deriving DecidableEq, Repr

structure Program where
  target : Nat
  events : List Event
  inputs : List Port
  outputs : List Port
  routes : List Nat
  internal : List Internal
  typeFuel : Nat
  deriving Repr

def externalInput (port : Port) : Bool :=
  port.givenBack && (if port.level == 0 then !port.inputAbstraction else port.inputAbstraction)

def externalOutput (port : Port) : Bool :=
  !port.givenBack && (if port.level == 0 then port.inputAbstraction else !port.inputAbstraction)

def validPort (program : Program) (port : Port) : Bool :=
  port.group == program.target &&
    decide (NativeBorrowProtocol.typeShape program.typeFuel port.nativeType = some port.payloadType)

def internalPort (port : Port) : Bool := !externalInput port && !externalOutput port

def eventValid (program : Program) (event : Event) : Bool :=
  event.ports.all fun port =>
    port.abstraction == event.abstraction && port.group == event.group &&
    port.inputAbstraction == event.inputAbstraction && port.level == event.level &&
    decide (NativeBorrowProtocol.typeShape program.typeFuel port.nativeType = some port.payloadType)

def eventContains (program : Program) (index : Nat) (port : Port) : Bool :=
  match program.events[index]? with
  | none => false
  | some event => decide (port ∈ event.ports)

def internalValid (program : Program) (link : Internal) : Bool :=
  decide (link.producerEvent < link.consumerEvent) &&
  eventContains program link.producerEvent link.producer &&
  eventContains program link.consumerEvent link.consumer &&
  validPort program link.producer && validPort program link.consumer &&
  internalPort link.producer && internalPort link.consumer &&
  link.producer.givenBack && !link.consumer.givenBack &&
  link.producer.identity == link.consumer.identity &&
  link.producer.level == link.consumer.level &&
  decide (link.producer.payloadType = link.consumer.payloadType)

def ownedPorts (program : Program) : List Port :=
  (program.events.filter fun event => event.group == program.target).flatMap Event.ports

def accountedPorts (program : Program) : List Port :=
  program.inputs ++ program.outputs ++ program.internal.flatMap fun link => [link.producer, link.consumer]

/-- Every actual owned event port occurs exactly once in the boundary or in an
internal link. Complete ports, including both source paths, are compared. -/
def completeCoverage (program : Program) : Bool :=
  let owned := ownedPorts program
  let accounted := accountedPorts program
  owned.length == accounted.length &&
  owned.all (fun port => owned.count port == 1 && accounted.count port == 1) &&
  accounted.all (fun port => owned.count port == 1 && accounted.count port == 1)

/-- Propositional statement of the source link. Actual port membership and
event order are independent of any proposed runtime payload or default. -/
def InternalFollows (program : Program) (link : Internal) : Prop :=
  ∃ producerEvent consumerEvent,
    program.events[link.producerEvent]? = some producerEvent ∧
    program.events[link.consumerEvent]? = some consumerEvent ∧
    link.producer ∈ producerEvent.ports ∧ link.consumer ∈ consumerEvent.ports ∧
    link.producerEvent < link.consumerEvent ∧
    validPort program link.producer = true ∧ validPort program link.consumer = true ∧
    internalPort link.producer = true ∧ internalPort link.consumer = true ∧
    link.producer.givenBack = true ∧ link.consumer.givenBack = false ∧
    link.producer.identity = link.consumer.identity ∧ link.producer.level = link.consumer.level ∧
    link.producer.payloadType = link.consumer.payloadType

theorem eventContains_sound (program : Program) (index : Nat) (port : Port)
    (accepted : eventContains program index port = true) :
    ∃ event, program.events[index]? = some event ∧ port ∈ event.ports := by
  cases source : program.events[index]? with
  | none => simp [eventContains, source] at accepted
  | some event =>
      exact ⟨event, source, by simpa [eventContains, source] using accepted⟩

theorem internalValid_sound (program : Program) (link : Internal)
    (accepted : internalValid program link = true) : InternalFollows program link := by
  have facts : link.producerEvent < link.consumerEvent ∧
      eventContains program link.producerEvent link.producer = true ∧
      eventContains program link.consumerEvent link.consumer = true ∧
      validPort program link.producer = true ∧ validPort program link.consumer = true ∧
      internalPort link.producer = true ∧ internalPort link.consumer = true ∧
      link.producer.givenBack = true ∧ link.consumer.givenBack = false ∧
      link.producer.identity = link.consumer.identity ∧ link.producer.level = link.consumer.level ∧
      link.producer.payloadType = link.consumer.payloadType := by
    simpa only [internalValid, Bool.and_eq_true, Bool.not_eq_true, beq_iff_eq,
      decide_eq_true_eq, and_assoc] using accepted
  rcases facts with ⟨ordered, producer, consumer, producerValid, consumerValid,
    producerInternal, consumerInternal, produces, consumes, identity, level, payloadType⟩
  obtain ⟨producerEvent, producerPresent, producerPort⟩ := eventContains_sound _ _ _ producer
  obtain ⟨consumerEvent, consumerPresent, consumerPort⟩ := eventContains_sound _ _ _ consumer
  exact ⟨producerEvent, consumerEvent, producerPresent, consumerPresent,
    producerPort, consumerPort, ordered, producerValid, consumerValid,
    producerInternal, consumerInternal, produces, consumes, identity, level, payloadType⟩

/-- Coverage counts complete source records, rather than just normalized keys.
Deleting a channel or changing either original path cannot satisfy this law. -/
theorem completeCoverage_sound (program : Program)
    (accepted : completeCoverage program = true) :
    (ownedPorts program).length = (accountedPorts program).length ∧
    (∀ port ∈ ownedPorts program,
      (ownedPorts program).count port = 1 ∧ (accountedPorts program).count port = 1) ∧
    (∀ port ∈ accountedPorts program,
      (ownedPorts program).count port = 1 ∧ (accountedPorts program).count port = 1) := by
  simpa only [completeCoverage, Bool.and_eq_true, beq_iff_eq,
    List.all_eq_true, and_assoc] using accepted

def routesValid (inputs : List Port) : List Port → List Nat → Bool
  | [], [] => true
  | output :: outputs, index :: routes =>
      match inputs[index]? with
      | none => false
      | some input =>
          input.identity == output.identity && input.level == output.level &&
          decide (input.payloadType = output.payloadType) && routesValid inputs outputs routes
  | _, _ => false

/-- Logical meaning of a boundary route, independent of the Boolean checker. -/
inductive Follows (inputs : List Port) : List Port → List Nat → Prop where
  | nil : Follows inputs [] []
  | cons {input output outputs index routes}
      (source : inputs[index]? = some input)
      (identity : input.identity = output.identity)
      (level : input.level = output.level)
      (sort : input.payloadType = output.payloadType)
      (tail : Follows inputs outputs routes) :
      Follows inputs (output :: outputs) (index :: routes)

theorem routesValid_sound (inputs outputs : List Port) (routes : List Nat)
    (accepted : routesValid inputs outputs routes = true) : Follows inputs outputs routes := by
  induction outputs generalizing routes with
  | nil =>
      cases routes with
      | nil => exact .nil
      | cons index routes => simp [routesValid] at accepted
  | cons output outputs ih =>
      cases routes with
      | nil => simp [routesValid] at accepted
      | cons index routes =>
          cases source : inputs[index]? with
          | none => simp [routesValid, source] at accepted
          | some input =>
              have facts : input.identity = output.identity ∧ input.level = output.level ∧
                  input.payloadType = output.payloadType ∧ routesValid inputs outputs routes = true := by
                simpa only [routesValid, source, Bool.and_eq_true, beq_iff_eq,
                  decide_eq_true_eq, and_assoc] using accepted
              exact .cons source facts.1 facts.2.1 facts.2.2.1 (ih routes facts.2.2.2)

def check (program : Program) : Bool :=
  let inputKeys := program.inputs.map fun port => (port.identity, port.level)
  let outputKeys := program.outputs.map fun port => (port.identity, port.level)
  let producerKeys := program.internal.map fun link => (link.producer.identity, link.producer.level)
  let consumerKeys := program.internal.map fun link => (link.consumer.identity, link.consumer.level)
  !program.inputs.isEmpty && program.inputs.length == program.outputs.length &&
  inputKeys.eraseDups.length == inputKeys.length && outputKeys.eraseDups.length == outputKeys.length &&
  program.routes.eraseDups.length == program.routes.length &&
  producerKeys.eraseDups.length == producerKeys.length &&
  consumerKeys.eraseDups.length == consumerKeys.length &&
  program.events.all (eventValid program) &&
  program.internal.all (internalValid program) && completeCoverage program &&
  program.inputs.all (fun port => validPort program port && externalInput port) &&
  program.outputs.all (fun port => validPort program port && externalOutput port) &&
  routesValid program.inputs program.outputs program.routes

inductive Values (Payload : Expr → Type u) : List Expr → Type u where
  | nil : Values Payload []
  | cons {sort rest} (first : Payload sort) (tail : Values Payload rest) :
      Values Payload (sort :: rest)

inductive Slot : List Expr → Expr → Type where
  | here {sort rest} : Slot (sort :: rest) sort
  | there {sort other rest} (slot : Slot rest sort) : Slot (other :: rest) sort

def select {Payload : Expr → Type u} : {sorts : List Expr} → {sort : Expr} →
    Slot sorts sort → Values Payload sorts → Payload sort
  | _, _, .here, .cons first _ => first
  | _, _, .there slot, .cons _ rest => select slot rest

def position : {sorts : List Expr} → {sort : Expr} → Slot sorts sort → Nat
  | _, _, .here => 0
  | _, _, .there slot => 1 + position slot

inductive Route (inputs : List Expr) : List Expr → Type where
  | nil : Route inputs []
  | cons {sort rest} (source : Slot inputs sort) (tail : Route inputs rest) :
      Route inputs (sort :: rest)

def indices : {inputs outputs : List Expr} → Route inputs outputs → List Nat
  | _, _, .nil => []
  | _, _, .cons source tail => position source :: indices tail

def execute {Payload : Expr → Type u} : {inputs outputs : List Expr} →
    Route inputs outputs → Values Payload inputs → Values Payload outputs
  | _, _, .nil, _ => .nil
  | _, _, .cons source tail, inputs => .cons (select source inputs) (execute tail inputs)

def origin : {inputs outputs : List Expr} → {sort : Expr} →
    Route inputs outputs → Slot outputs sort → Slot inputs sort
  | _, _, _, .nil, output => nomatch output
  | _, _, _, .cons source _, .here => source
  | _, _, _, .cons _ tail, .there output => origin tail output

/-- Every routed payload is exactly an existing input payload. This says nothing
about native permissions, and creates no ordinary callback result. -/
theorem executed_output_has_exact_input_origin {Payload : Expr → Type u}
    {inputs outputs : List Expr} (route : Route inputs outputs)
    (values : Values Payload inputs) {sort : Expr} (output : Slot outputs sort) :
    select output (execute route values) = select (origin route output) values := by
  induction route generalizing sort with
  | nil => cases output
  | cons source tail ih =>
      cases output with
      | here => rfl
      | there output => exact ih output

end Auths.Support.NativeBorrowWiring
