# Native callback declaration origins: construction inspector

This read-only tool uses the pinned Charon OCaml parser (Charon 0.1.225,
commit 527ea8e3b5dcb52edd6aef0f7bc34cc09c11dd59). It resolves LLBC's shared
type references through that parser; it does not approximate the JSON
`Deduplicated` indices with a separate hand-written decoder.

It compares a normal shipping-library intermediate with a specialized
intermediate. Both must retain the actual local `compile_source_bytes` body.
For each Auths Serde method, its declaration key includes source file/range,
lexical path, implemented trait and original closed Self carrier. Only
instantiation segments and lifetime labels are omitted from this declaration
identity. Actual instance names, IDs, source ranges, local/body flags remain
in the report. Genuinely generic/non-record Self carriers are unsupported and
reported; they are never silently merged into an existing declaration.

The baseline must contain callback declarations and must not collapse two
original declarations to one origin. Every retained origin needs a local
structured candidate body. Missing/unusable origins, empty/ambiguous baselines
and unsupported metadata produce a nonzero exit. Output always says
`qualified = false`. This is not lifetime recovery, type-checking, semantic
body equivalence, graph reachability, callback execution, or proof/qualification
evidence. The ordinary native callback/code-unit presence gate remains intact;
this tool is not a bypass for its exact inventory.

With the pinned Charon OCaml library available to Dune:

```sh
dune build --root formal/qualification/aeneas/toolchain/callback-origins \
  --build-dir "$PWD/target/formal/callback-origin-construction-build" callback_origins.exe

target/formal/callback-origin-construction-build/default/callback_origins.exe \
  BASELINE.llbc CANDIDATE.llbc OUTPUT.json
```

Construction builds the inspector executable only. Its tests and all final
source/model/proof/clean-reproduction/hosted gates remain deferred. Compare
source bytes, concrete argument bindings and the full call graph separately
before adopting a specialization. Presence/counts alone cannot qualify one.


## Lifetime-preserving function argument planning

`region_shape.ml` factors the original generic argument tree into a pattern,
explicit region parameters and their original arguments. Region equality is
retained as an alias partition; static regions and locally bound higher-ranked
regions stay intact. Captured bound regions are shifted across binders. An
exact reconstruction check is part of constructing a factorization. Already
erased lifetimes are refused, rather than guessed or promoted to static.
Reference kinds, pointees, type/const arguments and trait references remain.

This is preparatory code for specialization on the original polymorphic AST,
where lifetimes are still available. It is not an active compiler pass and
does not resolve traits, produce specialized functions, recover erased
lifetimes, or qualify a program. Regression cases for aliases, alpha-renaming,
mutability, higher-ranked capture, static/empty/erased inputs are authored and
unrun. The public-root planner can be built and run for interface construction:

```sh
dune build --root formal/qualification/aeneas/toolchain/callback-origins \
  --build-dir "$PWD/target/formal/callback-origin-construction-build" argument_shapes.exe

target/formal/callback-origin-construction-build/default/argument_shapes.exe \
  ORIGINAL.llbc PLAN.json
```

The plan retains original arguments and exact factorization instances, and
always says qualified=false. Its scope is only the public compiler's direct
function operands. It does not claim a closed transitive call graph or native
serde success. No test target is run by these construction commands.


`instance_view.ml` applies the pinned Charon substitution to the original
signature, local types, structured body and inherited region/type/outlives
requirements. It binds the actual trait Self instance when applicable and
refuses an Auths instance without its real body. These are views only: old
generic parameter lists in the requirements have not been rebuilt into new
declarations, parent/associated trait projections in these views have not been resolved,
call edges have not been specialized, and the program has not been emitted.
The argument planner records these views alongside each root call. No native
proof or Rust behavior change is claimed from constructing a view.

`static_targets.ml` resolves actual implementation/default-method references,
parent clauses and associated types from the pinned AST. Parent evidence is
selected by clause identifier, preserving sparse IDs. Missing, ambiguous,
dynamic, higher-ranked or unresolved evidence is refused. A concrete method
must instantiate the complete expected trait predicate. Self evidence is
factored together with arguments so that shared lifetime aliases and distinct
default-method instances cannot be lost in the worklist key.

Actual implementation methods reconstruct Self from their own source owner
and complete call arguments; the selected method must belong to the referenced
implementation, trait and associated method. Default trait methods retain
explicit Self evidence. Strict lookup refuses mismatches of the method/parent
predicates it compares; this is not complete type checking of every generic
argument or associated-type dictionary. The diagnostic planner opts
into `candidate_only`: it can follow a compiler-selected target with a
region-only discrepancy, but records the complete original predicates and
binders as **unsatisfied**. A local shape comparison classifies the discrepancy;
its erased result never becomes a type argument or an emitted program. Such a
report still exits nonzero. No erased/static/alias/outlives/higher-ranked
obligation is discharged by identifying a target.

`closure_plan.ml` follows function references in instantiated source bodies
and local types from all twenty-one roots. Root lifetimes remain parameters;
non-region root generics require an explicit closed instantiation. Every
referenced function is scheduled by its original ID, argument pattern and
Self evidence. Ordinary foreign leaves remain visible as requiring models;
an absent Auths body is an error. Unsupported edges remain in the report and
make the process fail. The construction-only depth/instance limits refuse
excessive metadata; they do not become shipping-input or theorem bounds.

```sh
dune build --root formal/qualification/aeneas/toolchain/callback-origins \
  --build-dir "$PWD/target/formal/callback-origin-construction-build" closure_plan.exe

target/formal/callback-origin-construction-build/default/closure_plan.exe \
  ORIGINAL.llbc CONSTRUCTION-ARGUMENTS.json CLOSURE.json
```

This reports only function references visible in the selected structured
bodies, without following opaque foreign bodies or global initializer/type
declaration dependencies. It emits no specialized program and does not prove
callback coverage, dispatch/type/lifetime preservation, body equivalence or
termination. Every output is qualified=false. Resolution/normalization are
construction code that still needs independent final review and regression
coverage before any emitted program could use it.

## Source associated types and function frames

Charon's `expand_associated_types` pass explicitly erases quantified regions
while collecting type constraints (pinned source lines 442–455). Leaving
associated types unlifted still runs that normalization. The archive
`native-recipe-21-pre-normalization-construction` requests the source before
normalization, retaining ADT clauses and original associated types. Both Charon
type-check phases and warnings-as-errors remain enabled. This is an interface
construction choice; it is not an adopted qualification recipe or evidence
that the required normalized/type/borrow gates passed.

Static target lookup resolves plain associated-item bounds through the actual
trait declaration and implementation, selected by clause ID. Explicit generic
parameters/evidence require separate instantiation and are refused. Bounds with
no explicit arguments can still contain `Ok`/`Error` type equalities. Their
source/implementation predicates are substituted and retained in a worklist;
each equality is normalized through actual definitions. Strict lookup requires
complete equality. Diagnostic regional discrepancies stay unsatisfied, and
unsupported outlives/quantified requirements stop construction. No declared
where clause is discarded to resolve an item.

`region_equations.ml` solves equalities for existential regions in one source
body. Signature/free and quantified regions stay rigid. Erased regions,
body-to-static guesses, quantified capture and conflicting signature parameters
are refused. Every equation remains in the certificate. Replay rebuilds the
bindings from the original complete predicate/type ASTs, rejecting altered or
additional bindings. This is a construction witness replayer, not a
kernel-checked proof of the OCaml implementation or native type/borrow adequacy.

`function_frame.ml` prepares an actual instantiated source body in two stages:
collect ordinary call constraints in one body scope, then replay the complete
solution and resolve the calls again strictly. It retains source/direct call
bindings and associated requirements. Default methods needing a cloned Self
environment are refused. Actual destructor statements/pointers and calls on
their unwind paths remain explicit, with unresolved drop boundaries. No callee,
global or type declaration is emitted. A frame proves no whole-program or
physical-cost property.

```sh
dune build --root formal/qualification/aeneas/toolchain/callback-origins \
  --build-dir "$PWD/target/formal/callback-origin-construction-build" frame_plan.exe

target/formal/callback-origin-construction-build/default/frame_plan.exe \
  SOURCE.llbc CONSTRUCTION-ARGUMENTS.json FRAMES.json
```

The constructor records the staged body/locals/signature, exact references,
replay equations, associated facts and preserved drops. It always reports
qualified=false/program_emitted=false. Failed frames, pending drops or primitive
contracts cause a nonzero exit. Explicit constructor builds do not build/run
the regression targets. Final qualification, proof, type/borrow, model, source,
reproduction and hosted gates remain required.

## Unqualified isolated Charon indexing-borrow patch

`../index-borrow-regions-v1.patch` targets Charon commit
527ea8e3b5dcb52edd6aef0f7bc34cc09c11dd59. Its index-lowering pass currently adds
an actual borrow with erased input/builtin/output lifetime labels. The patch
allocates one fresh body-scoped region per introduced indexing borrow, uses it
consistently at those three sites, and records the enlarged body-region count.
It preserves existing region IDs, rejects identifier exhaustion, and changes
no element/range arithmetic, reference mutability, pointer metadata, source
instruction ordering or primitive target. This derives scope at borrow
creation; it does not guess a static region for an existing erased argument.

The patch is applied and compiled in an isolated source construction. Base
commit, patch digest and copied executable hashes are recorded in
`target/formal/charon-index-regions-ae81a58bef00-construction/construction-identity.json`.
It remains **unqualified**; the active Charon lock/installed binary is unchanged.
Its source fixture covers all eight
array/slice × shared/mutable × element/range shapes, two borrows in one body
and a preexisting borrow. Focused AST assertions, application/build/version
identity and source/borrow/model review must precede adoption. The authoritative
reproducer must not claim the original Charon identity for a patched binary.
Fixture/regression execution remains deferred.

## Positive source evidence for implementation arguments

`region_match.ml` matches a complete Self carrier or trait predicate against
an actual source implementation template. `impl_regions.ml` exposes typed
interfaces; associated-bound lookup uses the whole declared predicate, so
lifetimes outside Self remain part of the match. Type/const/evidence arguments
and known region arguments remain unchanged. Private matching variables never
enter the result. Full AST equality and independent replay are required.
Undetermined, conflicting, erased, static or escaping quantified evidence is
refused. Original arguments and predicates remain in each reconstruction ledger.

`predicate_metadata.ml` handles a different case: a selected implementation
retains its arguments but the informative predicate omits some region labels.
Only erased positions may be completed from that implementation's actual source
predicate. Known labels stay unchanged; any remaining discrepancy is still a
complete predicate obligation. This does not repair an erased source value.

The resolver validates every selected function's declared dictionary clauses in
the caller's scope before factoring callee arguments. Its full inherited where/
outlives requirements stay recorded; they are not discharged by matching trait
predicates. The per-resolution normalization cache uses complete reference AST
keys. It reuses retained facts only after successful checking, never assumes an
active recursive reference, and does not change strict/candidate refusal rules.

## Universally quantified dictionaries

`quantified_dictionary.ml` distinguishes `for<'de> Deserialize<'de>` from one
representative implementation at one lifetime. An actual source generic
implementation can supply a family: open the entire original binder with fresh
rigid parameters, instantiate the actual source template, and reconstruct the
complete original binder exactly. Representative call arguments remain recorded
and unchanged. Concrete dictionary conditions identical before/after generalization remain
explicit premises, validated against their actual source implementations.
Varying conditions and outlives/type-equality family requirements need separate
proofs and are refused. A fixed/static implementation cannot establish a universal
family. A concrete use may vary only parameters established as universal;
fixed regions and every type/const/evidence argument remain unchanged.
Universal-to-universal binder composition remains unsupported. These are
construction certificates, not kernel-checked compiler correctness proofs.

## Prepared source closure

`source_closure.ml` and `prepared_plan.ml` build the callee graph from actual
prepared frames. Each caller's common body-region equations must replay and its
references must resolve strictly before its callees are factored. Failed frames
remain failures; there is no fallback to speculative targets. Original function
IDs, signatures, locals, structured bodies, body-region counts, source spans,
where requirements and default-method Self evidence remain available. Body
regions outside the original source scope are refused. Drops remain explicit
source statements and unresolved boundaries. Ordinary leaves and builtins require
reviewed contracts. No callee/global/type declarations or whole program are
emitted; callback presence/partial reachability is not execution adequacy.

The array-unsize overlay preserves the exact input reference lifetime in
ArrayToSliceShared/Mut lowering. It introduces no fresh lifetime and changes no
operand, destination type, mutability, length, element or execution order. It and
the index-borrow overlay are compiled only in an isolated compiler construction;
the authoritative installed Charon lock/binary is unchanged. Source fixtures,
AST assertions, compiler version/source identity, borrow/model review and all
qualification gates remain required before adoption.

All reports remain qualified=false/program_emitted=false. Necessary constructor
compilation and source-interface extraction are not tests or qualification.
Regression sources remain unbuilt/unrun until the final validation batch.


## Scoped substitution and retained equality binders

The isolated scoped-substitution overlay corrects binder movement in pinned
Charon OCaml: locally bound variables inside inserted types stay local, captured
variables move under the new binder, and negative placeholders receive their
compensating restoration. It changes neither source predicates nor strict
comparison. The installed library/authoritative compiler remains unchanged;
source/library/version identity and final overlay qualification are required.

Source function associated-type equalities now normalize and replay under the
entire original binder, including an empty one. QuantifiedType premises retain
that binder in shape and complete-AST replay. Body regions can agree with outer
signature parameters, but cannot capture quantified locals. Universal families
retain known implementation lifetime arguments absent from their source
predicate; an absent unknown argument remains refused. Conditional family
requirements and binder composition remain open.

## Globals and report storage

Global_view preserves actual source values, kinds, types and inherited
requirements. It refuses unbound body scopes, missing trait-default Self and
opaque Auths constants. The source closure follows referenced globals and their
initializer functions. Cyclic references remain edges, not assumed initialized
values. Ordinary opaque/global initialization, complete caller-side global
preconditions, type closure, vtable/ABI/source/borrow adequacy and emission remain
explicit requirements. The constructor never replaces a global with a fixture.

The report writer streams one complete frame at a time, optionally through a
direct gzip process, and publishes only after successful closure. Display-only
source-file interning preserves exact file identities, ranges, generated spans,
original optional-text presence and full contents in source_file_table. It never
changes checked ASTs. Versioned report schemas describe the reference marker;
conflicting contents refuse. Source-table materialization follows global display
construction. No same-scope runtime/memory improvement is claimed without the
final required measurements. See AP-SPEC-069 §13.191 for exact outcomes and
remaining implementation. New regressions/source fixtures remain unbuilt/unrun.


## Caller global bounds and source Self

Source global dictionary/type-equality conditions now enter the caller's common
body-region replay before factorization. Nested implementation requirements are
retained and checked as well. Default-global and initializer Self is selected
only from an exact, unique, explicitly provided concrete source dictionary.
Initializer/global trait/item ownership must agree. Self follows the same
factorization as all supplied arguments; no lifetime context leaks across views.

Universal families retain a complete fixed-argument predicate in addition to
invariant source prerequisites. Strict instantiation requires agreement; a
candidate discrepancy remains a full pending predicate until body replay. A
known fixed slot cannot silently change to fit a caller. Quantified parent
inheritance uses the actual declared source clause under the original universal
binder and retains the originally selected dictionary. It still refuses extra
binder composition and Self-dependent parent projections without explicit proofs.

## Closure-signature overlay

closure-signature-regions-v1.patch completes omitted virtual closure input and
FnOnce Output labels from the actual registered source signature. Complete
non-region structure must match, known labels stay unchanged and Output retains
its associated binder. It also updates method source predicates. The isolated
three-overlay Rust frontend builds/extracts all 21 roots and retains all 192
Auths source callback declarations; no code/model/borrow/native qualification
follows. All toolchain overlays remain unqualified/unadopted; installed tools
and the authoritative reproducer are unchanged. See AP-SPEC-069 §13.192.


Function-item calls and universal associated outputs (§13.193)
----------------------------------------------------------

`callable_instance.ml` derives actual TFnDef source signatures/targets and own
late-bound lifetimes from complete input tuples. Strict frames preserve and
check the actual receiver/tuple/result ABI. Source closure follows real bodies
through explicit pending CallableAdapter edges; no tuple call is rewritten as
a flat call. Adapter semantics remain undischarged.

`quantified_projection.ml` opens the full original universal predicate,
projects the actual implementation-family/FnDef output, and closes it under the
same binder. It retains representative metadata, source conditions, fixed and
full input equality obligations. Varying prerequisites and unsupported binder
composition refuse; Body-to-Bound unification remains forbidden. Both new
regression modules and `quantified_callable_output_fixture.rs` are authored,
unrun. `source_slice.exe` reads selected actual declarations through the pinned
parser; it emits no transformed program and proves no qualification claim.

See §13.193 for exact immutable construction archives and remaining full gates.


Declared parent arguments and source-fixed static metadata (§13.194)
-----------------------------------------------------------------

Missing selected parent lifetime arguments come only from the complete actual
source-declared parent predicate; known informative labels remain original.
`source_slice.exe` exposes these actual declarations via the pinned parser.
Reports retain original full region premises, and closing a quantified output
requires exact reopen/reconstruction. The final regression suite remains unrun.

`source-static-implementation-regions-v1.patch` is a fourth unadopted Rust
frontend candidate. It preserves literal source static metadata while erasing
other free/inference/escaping regions. Source-preserving selection must agree
with the erased baseline on implementation identity and complete erased generic
arguments; disagreement refuses. It does not allow Body-to-Static unification.
The static object fixture distinguishes owned static output from actual borrowed
objects. All source/ABI/body/model/usefulness and full final gates still apply.


Source-static argument witness and ADT closure (§13.195)
------------------------------------------------------

The v2 source-static overlay reconstructs only unresolved direct implementation
lifetime arguments from literal source statics and requires exact reconstructed
whole-predicate agreement. It keeps the baseline selected implementation and
erased argument shape; no Body-to-Static equation is allowed. The immutable
48f47f3b7ab0… input constructs all 3,192 function instances in the prior frozen
function/global scope, with zero reference/global failures. This does not close
the 925 ordinary leaves, 63,406 drops, primitive or full program gates.

`type_view.ml` and the expanded source closure now retain actual ADT fields,
variants, pointer metadata, caller/type/associated conditions and source
function/global/type edges. Source layouts, ordinary opaque types and unions
have explicit pending contracts; Auths opacity, source errors and missing field
lifetime provenance refuse. Final typing/borrow/emission/model gates remain.
The expanded type constructor exposes additional source environment/outlives/
field provenance obligations. `type_closure_fixture.rs` is authored, unrun.
See §13.195 for exact immutable inputs/executables, live handle and resume work.


Whole-frame types and source lifetime witnesses (§13.196)
-------------------------------------------------------

Complete frame normalization now includes inherited requirements and pending
destructor pointer types in one common region replay. Reports retain each
original/replayed/normalized pointer and full source normalization evidence.
Drop kind/place/unwind and all destructor semantic contracts remain explicit.
The terminal frame-types construction has three type failures, down from
2,398: two digest associated outlives requirements and the generated Serde
Expected vtable's erased dynamic-object lifetime bound. See §13.196 for exact
immutable report/input/executable identities and evidence limits.

`closed_type.ml` derives conservative static-lifetime witnesses from actual
instantiated source declarations and fields. Associated outlives witnesses
retain complete original binders/targets and replay their source derivations;
unknown/borrowed/erased/opaque/unsupported recursive cases refuse. It is not
a complete source well-formedness, borrow, layout or execution proof. The new
implementation compiles into constructor executables, but no source graph or
regression has exercised it. No type/borrow/native/qualification gate closes.
The new OCaml cases and Rust projected-drop/static-family fixtures are authored
and registered, unbuilt/unrun. Generated-vtable representation, full emission,
all ordinary contracts/models and every final spec gate remain required.

`source_slice.exe` additionally accepts `type` and exact `#ID` selectors and
shows implementation associated-type bodies through the pinned source parser.
Its source display is interned and remains read-only/non-emitting/unqualified.

`region_scope.ml` additionally checks exact normalized free/body/local lifetime
provenance in function frames, global values and type fields. Empty binders
retain their de Bruijn depth; undeclared parameters, escaping captures, erased
labels and body lifetimes in globals/types refuse. This checks scope only.
Constructor executables compile; no graph has traversed these new guards and
all new regression modules remain unbuilt/unrun pending the final batch.


Generated vtable source lifetime and method routing (§13.197)
-----------------------------------------------------------

`vtable_shape.ml` retains the actual generated owner/fields/roles and exposes
only its erased object annotation through a fresh field-local parameter, with
complete original signature replay. This is a candidate representation; the
source-provenance refusal in Type_view remains unchanged.

`vtable_initializer.ml` retains actual static-global/initializer/assignment/
storage/move/cast/aggregate/shim source flow. It keeps layout operations symbolic
and refuses missing bodies or unsupported effects/values. `method_instance.ml`
reconstructs every method argument under its declared own lifetime binder after
explicit owner/shim substitution, preserving fixed and nested arguments.
Source views construct all four Expected instance routes; the opaque ordinary
Write initializer refuses. Exact artifacts and their IDs are in §13.197.

The new Lean lifetime/source-slot models and OCaml/Rust regressions are authored,
unbuilt/unrun. Constructor executables compile and source views emit diagnostics;
no full new graph, program/native ABI, loan/ownership/drop/execution or proof
qualification follows. Original receiver liveness, source/initializer/cast/
method ABI, typed lowering, full source preservation and every final gate are
still required. Raw TFnPtr forward translation is unsupported by pinned Aeneas.


Source cast, receiver lowering and actual injection candidates (§13.198)
---------------------------------------------------------------------

`vtable_field.ml` reconstructs each actual stored field after full template
substitution, changing only its explicit object annotation parameter.
`vtable_cast.ml` reconstructs the original generated function-item cast and
full shim ABI. Captured arguments stay rigid; only the exact declared own
late suffix is re-exposed. Fresh placeholders must be distinct and disjoint
from captured/stored source lifetimes. Original operands and where predicates
remain recorded; no general Body-to-Bound/Static solver rule is enabled.

`vtable_receiver.ml` constructs isolated concrete receiver signatures/bodies
from actual implementation Self and actual generated shims. Only the unique
concretization becomes a typed move; other calls, drops, cleanup blocks,
storage and statement IDs survive. Other dynamic flows or ABIs refuse.
No candidate is installed in the source crate or emitted as a native program.

`vtable_injection.ml` binds the actual unique caller statement, source value,
dictionary, literal static vtable reference/global/initializer and concrete
Self. Complete argument/predicate/type reconstruction constraints replay.
Borrowed carriers retain distinct source/target labels and explicit lifetime
obligations. Owned Box carriers retain exact types and the actual move, with
allocation/layout/unique-ownership/drop/unwind proofs still required. Copied
boxes/exclusive borrows and erased object provenance refuse. `source_slice`
accepts `vtable-injections` and `*` to construct these actual source views.

The new same-21-root extraction includes the real std::io::Write and
std::io::impls definitions. All five actual initializers and 16 function-field
candidates construct. The latest view constructs 98 MetaVTable injections in
93 functions: 96 borrowed, two owned Box, no candidate errors. The exact
immutable new input/artifacts/outcomes and unqualified flags are in §13.198.
The old input's opaque Write refusal remains in its historical archives.

New Lean finite typed receiver constructors/restoration/dispatch/liveness
proofs and OCaml regression sources are authored, unbuilt/unrun. They do not
establish the source producer, runtime value flow, owned Box simulation,
mutable ownership, source/Aeneas loans, drop/unwind, ABI or execution adequacy.
No new complete graph or qualification ran. Full faithful lowering/emission,
source/callback closure and every E1–E5/M6/final gate remain required.


Receiver-linked dispatch and concrete function candidates (§13.199)
-----------------------------------------------------------------

`signature_instance.ml` opens only a function-pointer's original lifetime
binder against its complete actual input/result signature. Fixed/captured
regions, nested binders, dictionary/type structure and ABI remain rigid.
Erased, inconsistent, nested-captured or undetermined lifetimes refuse.

`vtable_dispatch.ml` binds the actual raw metadata/nominal field lookup to the
same complete receiver place passed to the indirect call. It tracks original
arguments, initialized/live locals, moves/copies, paired reborrows and storage
through the actual source prefix. Another parent's metadata, unknown values,
unmodeled effects/control flow and copied exclusive/owned carriers refuse.
Actual source statements, reborrow/liveness/type constraints and unwind blocks
remain. The current source has one explicit FnOpDynamic call, with four real
available Expected templates; this is not closed native exhaustiveness.

`vtable_specialization.ml` builds two isolated function AST candidates per
actual template: a concrete caller and the actual concrete shim. Capture
lifetimes are fresh beyond both caller/shim scopes; the callee's own binder
stays separate. The recognized source reborrow keeps its data/borrow kind and
uses sized unit metadata; the actual indirect call becomes a direct call to
the fresh shim. The whole instantiated call signature must agree exactly.
Original calls to implementation methods, drops, storage and unwind paths
survive. Source object/Self liveness and where requirements are retained.
Unit metadata/layout and source value/loan/ownership simulation remain required.
No source crate or Auths namespace is rewritten and no program is emitted.

Constructor 95679 constructs all four pairs (eight signature/local/body ASTs)
with complete replay. See §13.199 for immutable input/executable/artifact
identities, current-source/model revision boundaries and all remaining scope.
`source_slice indirect-calls '*'` exposes these source-only constructions.
New signature/lookup/capture regressions and Lean finite paired-reborrow laws
are authored, unbuilt/unrun. Closed instances, actual constructor selection,
interprocedural/control-flow/owned-Box simulation, complete source closure and
every native/qualification/final spec gate remain required.


Actual capture instances and prepared dependency integration (§13.200)
--------------------------------------------------------------------

`closed_arguments.ml` refuses free source type/const/dictionary placeholders,
unbound Self, opaque constants and escaping/duplicate local binders. Captured
regions and executable body regions have distinct validated scopes.
`vtable_instance.ml` instantiates a concrete family from an actual strict
Global_view with complete separate enclosing caller/shim substitutions. It
retains unrelated own lifetime parameters, imports capture aliases once with
fresh IDs, binds real dictionaries and verifies both new-call and actual
implementation-method signatures. No body result is manufactured.

`vtable_instances_plan SOURCE.llbc OUTPUT.json` constructs from raw actual
injection seeds. The corrected immutable v2 run has three capture instances,
23 applications, 73 explicitly unclosed generic sites and two unmatched Write
sites. The incomplete capture-only substitution's original failed archive and
diagnostic backtrace remain; source scope/where guards were not weakened.

`vtable_graph.ml` feeds the same instance API actual prepared globals and links
real source method nodes. Missing implementation methods can be scheduled as
additional source dependencies without changing the 21 public roots. Pending
ordinary interface bindings, unmatched globals, instance failures and missing
methods remain visible. `prepared_plan` includes these adapter records.

The completed whole-source construction has 45 instantiated adapter pairs,
zero adapter errors and all 45 implementation-method nodes present. It is not
a qualified program: 106 generated-shim erasure failures, one Dyn Write method
failure and four type failures remain, with ordinary leaves/drop/primitive
contracts and all other gates still open. The current optimization schedules
only missing method dependencies; it compiles but has not traversed the graph.
§13.200 retains exact inputs, full compressed report, outcomes, identities and
the separately snapshotted newer code/owned-Box model revision.

The new Lean ownership-transfer model preserves heap/payload, typing, unique
allocation ownership and source-handle consumption for one trait's indexed
Box family. It does not prove source interpretation, native layout/allocator,
inner borrow exclusivity/liveness or drop/unwind behavior. All new Lean and
OCaml tests/proofs remain unbuilt/unrun until the final batch. Full native
runtime selection/source/loan simulation, faithful emission and every other
E1–E5/M6/final requirement remain required.

## Virtual interfaces and actual source producer/return routes (§13.201)

The exact native entry set is centralized in `source_roots.ml`. `dynamic_method`
constructs the actual Dyn method/field/full-ABI interface; it does not select a
concrete implementation. `virtual_shim` constructs a concrete source slot per
actual prepared capture. `virtual_receiver` binds the original receiver and
argument routes, including the non-owning temporary Box access and its actual
metadata. Native loan/ownership/source simulation remains required.

`prepared_injection` links every actual source cast to its real closed static/
dictionary capture and replays its exact concrete Self under the already
recorded source equations. The latest full construction has 130 producers
(128 borrowed, two Box), 45 Expected and two Write candidates, all 47 source
method nodes, and zero adapter/producer errors or unmatched globals. It still
has 106 actual generated-shim failures and four type failures. No program is
emitted or qualified.

`capture_return` follows normal source Box return routes through exact source
branches, moves and object-bound casts; unknown/omitted/unsupported flows refuse.
Calls remain unevaluated and unwinds/native simulation remain obligations.
`adapter_graph_plan SOURCE.llbc ROOT-ARGUMENTS.json OUTPUT.json` constructs the
complete interface but omits unrelated frame text from its diagnostic index.
`box_return_plan SOURCE.llbc ROOT-ARGUMENTS.json SOURCE-NAME-SUBSTRING OUTPUT.json`
and `virtual_frame_plan` construct focused frames, not whole-program evidence.

Final-batch regressions are authored and unbuilt/unrun: `source_roots_cases`
under `dune runtest`, plus `virtual_source_cases SOURCE.llbc ROOT-ARGUMENTS.json`
and `prepared_source_cases SOURCE.llbc ROOT-ARGUMENTS.json`. They require the
actual pinned source and complete exact native root set. Their future execution
is not a substitute for source/loan qualification or the full spec gates.

The complete source-return graph also constructs both normal `get_writer`
return routes, preserving its original enum branches, linear Box moves and
two empty-vtable object-bound casts. Full original local/read/cast operand/
cast destination/return typing premises accumulate per paired value. Cast
source/target object lifetimes are never equated; narrowing, four original
unwind blocks and every native simulation remain obligations. The exact frozen
artifact/outcomes are in §13.201. Immediate remaining work is actual call/result
and receiver binding across the callers, with any surviving callee-body capture
lifetimes scoped to their callee activation rather than reinterpreted in the
caller. Constructor/build jobs are terminal; tests remain deferred.

## Actual source call scopes and Box receiver paths (§13.202)

`Instance_view.replay` recovers original pre-factorization argument/Self labels.
`source_call` binds actual source frames, pointer/edge, declared parameter
instantiation and full caller input/result typing premises. `capture_scope`
normalizes each callee capture only in its own source certificate and imports
only declared parameters from actual caller arguments; private callee regions
never become caller labels or guessed static. `capture_callsite` retains both
actual normal returned cases with the original source call.

`box_receiver_call` tracks the same returned owner through source moves and
borrows into the actual receiver argument. Unsupported effects, carrier escapes,
copies, overwrite/drop/control-flow paths refuse. The latest complete graph has
12 call bindings, 24 returned cases and 12 direct Box receiver paths. It retains
one explicit nested end_object/iterator-closure path at statement 1427891,
plus the unchanged 106 shim and four type failures. Zero native program/proof/
qualification flags are claimed. The private activation/loan, source ownership,
closure/CFG and runtime typed selection obligations remain.

The authored Lean `VTableCallScopeModel` and expanded scope/call/receiver
regressions are imported/registered, unbuilt/unelaborated/unrun. §13.202 has the
exact immutable input/executable/report identities, source revision boundaries,
terminal construction outcomes and full E1–E5/M6 resume scope.


## Iterator source and captured closure values (§13.203)

The construction-only extraction now includes the actual try_for_each,
try_fold and enumeration bodies under the same complete 21 public roots.
source_path retains original branch selectors/indices without supplying an
outcome. box_carrier records the actual Box wrapper forwarding footprint;
neither it nor a completed constructor proves native carrier preservation.

closure_capture binds actual source aggregate fields, captured Self,
universally quantified original callable methods and strict normalized closed
signatures. All actual method nodes join the source dependency closure.
closure_invocation binds the actual closure receiver, implementation dictionary
and complete own-lifetime method routing. closure_receiver binds the JSON
callback's four original field/address-load/reborrow/Box-consumer accesses.
It retains the entire conditional prefix as an outstanding effect obligation;
a shallow address access creates no owner or independent exclusive loan.
closure_argument binds an actual aggregate through linear source moves to its
actual call argument. It does not create a value route from nominal type
similarity, copy an exclusive capture, invent a callback result or discharge
callee activation/field/effect correspondence.

The invocation and captured-field graphs construct five callback invocations,
four captured-field accessors, two closure aggregates and all 51 actual source
method dependencies. The latter retains one aggregate-crossing end_object
receiver failure. Expanded source coverage exposes an additional erased
lifetime in an enumeration helper's returned-closure signature: 107 function
failures and four type failures remain explicit. 3,351 scheduled instances,
3,244 nodes/2,330 frames, 914 ordinary leaves and 64,389 preserved drops are
construction coverage only. All new execution-binding counters keep
prepared_plan refusing emission. All regressions remain unbuilt/unrun.

§13.203 records immutable input/source/executable/report identities and the
full resume scope. Source effects, actual creator/callback activation and
capture values, loop invariants, native loans/aliases/ownership/drop/unwind,
complete source closure/emission and every E1–E5/M6/final gate remain. Installed
tools, locks and the qualification reproducer are unchanged; overlays remain
unadopted, all new work unqualified. The final argument-route graph constructs one actual aggregate-to-iterator
argument route and retains the single aggregate-crossing effect refusal. Its
terminal outcome and exact identity are in §13.203. A subsequent explicit
Copy-refusal guard and README edits postdate that frozen executable; the
guard/regressions remain unbuilt/unrun. All construction jobs are terminal.


## Actual carrier effects and helper returns (§13.204)

carrier_effect traverses complete actual callback/iterator bodies and follows
real carrier-bearing source call dependencies. Direct carrier replacement,
captured-field writes, unsupported escapes and hidden Box owner loss refuse.
Every ordinary/payload call and destructor remains an effect obligation;
branches, loops, early exits, unwind and MIR retags remain explicit. Projected
counter/data writes require native disjointness, not a type-based assumption
of semantic preservation. The first graph preserved the actual loop and
counter write but refused the real YesRetag iterator move; the current source
retains that retag with its native loan obligation. The previous single
aggregate-crossing adapter refusal remains separate from footprint failures.

closure_value_path shares exact aggregate/move/statement provenance with
closure_argument and closure_return. closure_return retains every original
normal return and its actual closure aggregate/value slot. closure_return_call
binds the real returned value and fields to the actual source caller/callee
call, using separate callee-return and caller-call lifetime certificates.
Private callee labels never become caller/static labels; native activation
freshness and returned loan liveness remain required. Carrier-bearing results
without an actual source return mapping remain unresolved. The erased
signature of the enumeration helper is not bypassed.

All new modules are registered in mandatory source inventories and emission
refusal gates. The new body/return/storage/retag regressions are authored,
unbuilt/unrun. §13.204 records exact immutable construction identities and
terminal outcomes, revision boundaries and the full unchanged
E1–E5/M6/§13.5/§10 resume scope. No native program or preservation theorem is
qualified. The final loop/retag/counter regression assertions and README edits
postdate the first returned-closure/carrier executable. The corrected instance
graph includes their source inventory; no constructor executes them.


The corrected final graph is terminal: ten source footprints, zero footprint
refusals, one helper closure return and one actual returned-closure call link.
The original aggregate-crossing adapter refusal and 107 function/four type
failures remain, as do all native effect/activation/loan/retag/loop/destructor
proof obligations. The whole source graph and 21 public roots are unchanged.
§13.204 records its exact immutable identity; only later documentation changes
postdate that final frozen source inventory. All jobs are terminal, and no
regression, Lean proof or qualification gate ran.


## Source-derived erased output captures (§13.205)

return_signature constructs a strict candidate only for the actual whole-input
move/closure aggregate/return shape. Each erased top-level output region slot
must derive uniquely from the declared type of that very moved source input
through the original nominal field schema. Known lifetimes, binders and every
type/const/dictionary argument remain rigid. Unknown/nested/escaping/conflicting
slots, copies, duplicated or projected inputs, reborrows and other body effects
refuse. Temporary matching markers are never emitted; static is available only
from an actual declared static input, never an absent provenance guess.

The original erased signature/body/aggregate/return and full source typing
premises remain attached to Function_frame and actual call reports. Native
original opaque-interface refinement and entry/return loan simulation remain a
mandatory new emission-refusal gate, not an assumed contract or qualified proof.
Installed tools/locks/reproducer and frontend guards are unchanged. The source
input/public roots remain identical. The complete graph constructs one such
witness, both actual helper returns/call links and all 53 method dependencies;
106 shim/four type failures and the original aggregate-crossing writer effect
remain. Thirteen source body footprints construct with zero footprint refusals,
retaining all source calls/drops/retags/branches/loop/data-write obligations.

§13.205 records the immutable construction/outcome and complete resume scope.
The later copied/duplicated-input and signature/completion mutation assertions
are authored, unbuilt/unrun; they rebuild actual mutated source views. These
assertions, a diagnostic-key clarification and later docs postdate the frozen
executable, whose exercised reconstruction logic is unchanged. All jobs are
terminal. No native program, semantic preservation theorem or new claim is
qualified; every E1–E5/M6/final gate remains in scope.


## Actual source value definitions and destinations (§13.206)

iteration_path retains a lexical prefix within an actual loop iteration with
an explicit loop-head value invariant obligation. It does not weaken normal
Source_path dominance or claim an entry value survives previous iterations.
Both interfaces require unique original statement identities.

value_origin reconstructs actual moves/retags, sized borrows, typed struct/
reference/Box accesses, original aggregates and actual closure/Box return
bindings. It refuses copied/constant carriers, unsupported or unmapped results,
dead/consumed/replaced slots and unhandled conditional definitions. A current
parameter slot is not an assertion of its initial value. Every full preceding
source effect, branch, unwind and loop remains a semantic obligation.

value_flow binds those trees to exact capture-field indices and actual source
callee parameter positions. It includes ordinary counter references in actual
returned-closure constructors without supplying arbitrary ordinary results.
Native activation/parameter/field/return/origin composition and alias/loan/loop
simulation remain required; all emission refusal counters remain intact.

The continuation-aware source graph constructs 33 value edges with zero
value-origin refusals, retaining the single aggregate-crossing writer adapter
refusal and every earlier native proof requirement. Source_call.site_resolution
also reconstructs a normalized call's original Self dictionary only from that
exact original call site under the caller certificate, requiring its complete
recorded frame and dependency binding. It does not guess a default-method
context from another pointer/type. §13.206 records immutable construction
identities, terminal outcomes and the full unchanged E1–E5/M6 resume scope.
The final source-Self graph is terminal and recorded there. New iteration,
value-edge and source-Self mutation regressions are authored, unbuilt/unrun.
No source constructor qualifies a native preservation theorem or program.


The final original-Self/value-flow graph constructs 34 edges with zero
value-origin refusals: four actual capture fields and 30 actual call parameter
positions, rooted at the actual Box/closure returns, original aggregate or
current parameter storage. The captured writer's source borrow/get_writer
origin and both returned helper values are represented; one edge keeps its
loop invariant obligation. Original default-method Self evidence binds the
inner try_fold call and all 15 carrier-bearing calls have actual source call
bindings. The original aggregate-crossing writer effect, opaque-interface
refinement, 106 shim/four type boundaries and every native source/value/loan/
alias/loop/activation/drop/ownership proof remain. §13.206 records exact frozen
identities and full resume scope. All jobs are terminal; only documentation
postdates the final frozen code/inventory, and no new test/proof/qualification
suite ran. The full E1–E5/M6 goal remains incomplete.


## Actual closure-constructor component certificate (§13.207)

`return_capture_plan SOURCE.llbc ROOT-ARGUMENTS.json OUTPUT.lean` constructs the
complete unchanged 21-root graph, replays each actual Return_signature witness,
and emits original local numbers, nominal closure identity, move operands and
statement IDs alongside proposed SourceClosureCapture commands. OUTPUT must not
already exist. The complete certificate is rendered before exclusive creation;
a refusal cannot leave a partial earlier-witness certificate. Write failures
remove the incomplete output. Original source statement IDs must be unique.

SourceClosureSyntax supplies an independent restricted source interpreter and
checked lowering. The generated actual helper-1866 case states exact source IDs,
unique IDs, source-to-command lowering, all-input coverage, field order, nominal
return, source/command agreement for arbitrary inputs and consumption/storage
ends for both original inputs. Copies, projected/out-of-range moves, a moved
return place, a different nominal closure, wrong field count and unsupported
instructions cannot lower. The command and source interpreters consume moves;
they do not create another owner for a repeated source input.

All new Lean statements/proof scripts and source mutation assertions are
unelaborated/unrun. These are component artifacts, not a native function body or
qualification result. Values remain opaque; the full LLBC/native interpretation,
entry/return reference validity and retags, original opaque-interface refinement,
fresh activation and loan/alias/ownership/loop/drop/unwind/allocator/layout
simulation remain mandatory. prepared_plan's original opaque-return and every
other native emission gate remain intact. The 106 shim/four type boundaries,
writer effect and all E1–E5/M6/final requirements remain in scope.

§13.207 records three immutable constructor revisions and terminal outcomes.
The final revision includes the source-ID uniqueness guard, duplicate-ID source
mutant and complete-buffer output. New support modules, emitter and generated
case are mandatory inventory inputs; the generated case is imported by the
qualification root. Construction does not run Lean, tests, qualification or CI.


## Structural return-lifetime component (§13.208)

return_region_certificate reflects the actual supported Charon type, argument
and dictionary tree, preserving nominal IDs, reference kinds, complete trait
references, region binder scopes/metadata and names as UTF-8 bytes. Decoding
must recover the exact original AST. Unknown types/traits and nonempty constant
expressions refuse reflection; this is not a general native type interpreter.
Temporary matching markers become explicit output-slot holes in the Lean data.

SourceClosureRegions independently pairs field patterns with actual moved-input
types and infers from an empty assignment set. Every other node and known region
is rigid. Output holes accept only actual static or declared free input regions;
body/bound/erased/undeclared candidates and conflicts refuse. Every erased slot
must be constrained and no additional assignment is accepted. Replacing the
original output's top-level region vector retains every other argument and
must leave a completely scoped reflected type.

The extended actual-source case records these full trees, exact input pairing,
original and completed output regions, and authored kernel proof scripts for
inference, exact output structure and refusal of a guessed output lifetime.
All scripts and new source reflection regressions remain unelaborated/unrun.
§13.208 records the frozen constructor outcome and revision identities. The
pinned LLBC/native typed-reference interpretation, original opaque interface,
loan/alias/ownership/activation/loop/drop/unwind/layout and complete native
emission remain separate required proofs, as do every E1–E5/M6/final gate.
No prepared_plan refusal condition or frontend/source closure guard is removed.


## Pinned native constructor bridge (§13.209)

`native_capture_plan SOURCE.llbc ROOT-ARGUMENTS.json OUTPUT.json` constructs the
complete original 21-root graph, then builds an isolated actual-source capture
constructor for native Aeneas region hierarchy and symbolic interpretation.
A fresh identity/name is added; every original function/root/body remains
unchanged. This component is not a whole-program extraction or qualification.
The staged frame/source return witness and exact argument factorization replay.
Original caller-scoped arguments and factored candidate arguments stay separate.
Declaration-only specialized region/type/const metadata is retained as evidence;
all predicates are preserved, and the complete emitted signature/locals/body/
predicates must pass closed-variable and exact region-scope checks.

Required type declarations are closed transitively with whole original recursive
groups. Missing/mixed groups, erased or escaped source scopes, dynamic values
and unsupported function values refuse. The pinned native type-analysis dyn
shortcut is not usable as a source semantics rule. No calls/globals/drops are
silently externalized in this move-only constructor. Full native emission still
must cover those boundaries elsewhere. Native errors/panics and the absence of
a value-returning path refuse the component report.

The native tool links unmodified pinned Aeneas source rebuilt in an isolated
construction directory against the existing scoped Charon ML interface. Installed
binaries, locks and qualified reproducer are unchanged; the rebuild is unadopted
and unqualified. §13.209 records the interface mismatch, exact archive/library
identities, source-scope repairs and terminal outcomes. All new source mutants
remain unbuilt/unrun. Native original-source/opaque-interface/loan/value/alias/
ownership/activation/loop/drop/unwind/layout proof, faithful full 21-root emission
and every other E1–E5/M6/final obligation remain required.


The native bridge distinguishes source pointer-layout metadata from the value
representations analyzed by pinned TypesAnalysis. Every original descriptor is
scope-checked and retained, with its source type ID, in metadata_obligations;
all layout/source representation refinement flags remain false. Native value
fields and predicates still close transitively with whole original SCCs and
reject unsupported dynamic/function values. Original source type maps are
unchanged. The move-only source body has no metadata-reading operation; its
symbolic interpretation cannot prove its native physical representation.
Omitting this obligation list fails source replay. The full program must still
qualify metadata layouts, vtable callbacks, ownership/drop and every dependent
source interface. This component boundary never earns that qualification.


The final §13.209 native attempt is terminal/refused: genuine value type 315
(the JCS end_object FnMut closure) contains an exclusive reference to a dynamic
Write Box. Its own metadata is NoMetadata. The corrected source scope and
explicit layout boundary remain implemented, but native symbolic interpretation
has not run successfully. Next is the actual typed closed Write runtime carrier
and Box/getter/closure/loan opening relation, not a dynamic-analysis shortcut.
No native body/report or new qualified claim was emitted. All jobs are terminal.

## Conditional source writer carrier and native ingress (§13.210)

The extended constructor accepts an explicit actual writer-owner type:

```text
native_capture_plan SOURCE.llbc ROOT-ARGUMENTS.json 315 OUTPUT.json
```

It still constructs the complete exact 21-root source graph. `writer_runtime.ml`
derives two distinct cases from the actual prepared Write globals and owned Box
producers. For this input they are prepared globals 47 and 48, both instantiated
from source global 116. The main writer's Self is `&mut &mut Vec<u8>`; the object
buffer's Self is `&mut Vec<u8>`. A global declaration ID alone cannot identify
the case. Complete capture arguments, concrete Self, actual method dependencies
and actual source Box injection statements must replay.

The isolated logical datatype has `MainWriter(&mut W)` and
`ObjectBuffer(&mut Vec<u8>)` variants. It preserves the invariant inner `W` and
proposes narrowing only the outer reference to the object borrow. The native
type overlay explicitly adds `W: object_borrow`; that is an unproved invariant
of source-reachable inputs, not a premise already established by parsing or
source type equality. Source tag/value origin, Box allocation, exclusive loans,
aliasing, layout, opening, drop/unwind and every other source/native relation
remain required. Original source maps and functions are preserved; the isolated
native view replaces the writer field only for conditional component analysis.

`OUTPUT.json.writer.lean` is rendered completely before exclusive creation. It
contains full reflected source/native payload schemas, original nominal/field
and global identities, plus unelaborated statements about the two source inner
types and unchanged invariant inner references. `ClosedWriterRuntime.lean`
supplies the reference topology: the main writer follows its original inner
reference cell; the object buffer references its buffer directly. These address
records convey no exclusive permission by themselves. The generated actual
case is registered in both mandatory inventories and imported by Model.lean.

At native ingress the constructor invokes pinned `PrePasses.erase_body_regions`
on the isolated function. The full source frame and signature are retained;
only executable body/local/place annotations use the interpreter's erased
representation. This does not infer source regions. A declaration/signature
change outside the body refuses. This fixed the observed local/value type
mismatch and exposed the later backward-loan lookup failure.

After symbolic construction the tool now proceeds through pinned pure
translation and Lean extraction. It requires the sole transparent constructor,
no introduced loop, no undeclared global/trait emission dependency, no native
errors/panics, and no extracted opaque declaration. Every private output
directory carries `UNQUALIFIED.txt`. These source files are construction
artifacts; their presence is not Lean elaboration or source refinement evidence.
No full-program refusal or qualification gate is removed.

A complete symbolic phase is separately sealed at
`OUTPUT.json.symbolic-source-node-ID.json` before attempting pure translation.
It retains the actual symbolic body/hierarchy, exact candidate/source arguments,
source metadata obligations and pinned analysis of every required native value
type. Its pure/Lean/refinement/qualification flags remain false. The final
OUTPUT.json is produced only when all requested component stages complete.
The pure-body guard also rejects EError, loops, failure/assertion paths and opaque
decompositions. A partial later extraction never upgrades the sealed symbolic
artifact into a complete native program.

## Isolated loan-projector traversal repair

`loan-lookup-single-traversal-v1.patch` changes the two visitors in pinned
`InterpBorrowsCore.lookup_aproj_loans_opt`. Previously a nonmatching borrow or
ended projector invoked the inherited child traversal in its match branch and
again after the match. One nested loan could consequently be counted twice.
The patch retains the unconditional traversal and removes the redundant branch
traversal for both abstract and continuation projectors. All uniqueness and
abstraction checks remain. Two actual projector occurrences, including two
occurrences of the same record, must still fail.

The patch is unadopted and unqualified. It is applied only to an isolated archive
of the pinned Aeneas source, linked against the existing scoped Charon library.
Installed tools, translation locks and the qualified reproducer are unchanged.
The final batch must build/run `loan_lookup_cases.exe SOURCE.llbc` against this
library, covering nested borrow/ended nodes, direct and nested real duplicates,
continuation input/output duplicates, absence and abstraction isolation. These
regressions remain unbuilt/unrun. The actual-source native constructor is a
separate integration construction, not a substitute for the final regression,
Lean, axiom, source-interface, whole-program or clean-reproduction gates.

With this patch the actual isolated constructor reached complete symbolic
interpretation and then the pinned pure translator refused an ADT containing
nested mutable borrows. That original guard remains unchanged. Supporting the
actual nested Box/reference/closure carrier and its backward continuations is
a separate implementation and source-refinement requirement; omitting the ADT,
using an opaque handle contract or simply removing the guard cannot discharge it.

## Typed capture projections (§13.211)

`borrow_projection.ml` expands the actual native component's regionful input
and output types into indexed pure-data shapes. It retains nominal arguments,
variant identities, field positions/names, Box/reference structure, native
region groups and their parents, and instantiated declaration requirements.
These declarations include the conditional writer overlay; they are not all
unchanged original Rust declarations. Borrow-bearing recursive, opaque,
unresolved or unsupported containers refuse. Borrow-free atoms carry existing
values indexed by their complete reflected type; they supply no operation or
callback result.

The constructor also replays the actual move-only source body. It requires
every input exactly once, the original aggregate and return identities, ended
input storage, and complete regionful equality between each moved input and
its destination field. Copies, projected operands, other effects, reordered
fields and unexplained tails refuse. Generated Lean source connects these
actual local moves to a typed capture constructor and derives the corresponding
field packing, unpacking and input restoration for each actual region group.

`Auths.Support.BorrowProjection` defines typed selection and partial restoration.
Its authored laws cover round trips, untouched fields and refusal to switch a
partially selected enum branch. Whole owned values may be replaced where the
plan selects the complete value. Shared references have no mutable view in
this pure algebra; this says nothing about Rust interior mutability or native
permission to end a loan. Unselected sums can retain ghost branch tags and unit
fields. These views are not yet the native backward-function ABI.

Before the unchanged pinned pure translation, the constructor seals
`OUTPUT.json.projection-source-node-ID.json` and `.lean`. The generated case
includes restoration statements for arbitrary successful updates, not only
restoring an unchanged view. All Lean scripts and mutation regressions remain
unelaborated/unrun. Both mandatory inventories and Model.lean register the
actual generated case. No SymbolicAST projector/continuation lowering, native
atom binding, borrow-level mapping, original source-interface adequacy,
heap/loan/layout relation or whole-program claim follows from these files.
Those remain the next implementation boundary; the pinned nested-mutable-ADT
guard stays intact.

## Actual native forward value lowering (§13.212)

`native_capture_value.ml` consumes the input symbolic values and expression
returned by the actual pinned interpreter. Input identities are never guessed.
A complete, injective source-to-native public-region instantiation is derived
from full input type/dictionary trees; erased, static guesses, conflicting
occurrences and merged public regions refuse. Every subsequent symbolic value
must have its exact complete instantiated source type and a fresh identity.

The supported forward grammar lowers actual exclusive-reference, record and
Box expansions, then the actual return delimiter/value. It retains every field
and checks the stored delimiter value against the actual return. Mutable borrow
reconstruction needs a previously expanded actual borrow identity and its full
regionful source type. Literal/shared/enum branching, effects, unknown values,
missing/retyped inputs and unsupported terms require explicit implementations;
none has an opaque or arbitrary-result fallback. All native backward branch
identities must remain present. Their bodies remain in the original sealed
symbolic artifact and are not discharged by this forward component.

`Auths.Support.NativeCaptureValue` supplies an independent pure-data interpreter
for the emitted input names, expansion steps and returned value. It checks fresh
bindings, unique expansion/borrow names, complete record fields and exact typed
restoration. Evaluation uses an explicit structural-depth fuel bound; exhaustion
returns none. The generated actual case states equality between this program's
result and the existing source-move capture constructor for arbitrary typed
input values. The statement and refusal scripts await Lean elaboration; the
model conveys no native heap address or exclusive permission.

The constructor seals `OUTPUT.json.forward-value-source-node-ID.json` and
`.lean` before the unchanged pinned pure translator. Native backward projector/
continuation lowering, parent/level ABI, original opaque-return interface,
source/native value/loan/layout adequacy, useful whole-program emission and all
qualification gates remain required. These artifacts cannot upgrade the
conditional writer overlay or stand in for a successful full native translation.

## Ordered backward producer protocol (§13.213)

`native_borrow_protocol.ml` walks every actual backward branch through its
ordered EndAbs events to its void return. It retains abstraction/group/kind,
owned native regions and levels, and projects name/type-shape observations
from both abstract values and continuations. Both sides start with the same
incoming symbolic scope and must independently produce identical complete
binding records. Input/output calls must name that exact event's region/kind.
Unsupported effects, joins, shared forms, lexical binders and producer metadata
whose origins are not yet implemented refuse explicitly.

Initial symbol and borrow names/types come from the actual forward witness.
Reads require a known producer; updates require a known symbolic or exclusive
borrow origin. Full declaration types, owners and origins must agree when the
same metadata producer is observed again. Every observation is retained. This
does not deduplicate native projector occurrences or execute repeated metadata
as repeated writes. Projection type-*shape* comparison erases region labels;
all complete type trees stay in the report. Lifetime/projected-value validity
does not follow from that comparison. Ignored metadata supplies no observation
or value, and this is not a reflection of complete native heap semantics.

The independent Lean checker requires an actual target/ancestor group, empty
remaining native parents, endability, consecutive descending levels, one
input/output abstraction per observed group and completed level zero. Thus the
actual deepest branch's level-1 reprojection and later level-0 endings remain
separate events. Missing, reversed, repeated or unfinished endings refuse.
The emitter seals `OUTPUT.json.backward-protocol-source-node-ID.json` and `.lean`
before the original pure translator. Generated protocol-check scripts and new
mutation regressions remain unelaborated/unrun.

This establishes source for an ordered name/type-shape component only. Actual
projected values and regions, dependent backward functions, ABI, heap/loan
ending, aliasing/layout and original source adequacy remain unproved. No pure
guard or final whole-program/qualification requirement is removed.

## Level-aware backward payload routing (§13.214)

`native_borrow_wiring.ml` returns to the original native tavalue/tevalue trees.
It tracks the current sub-abstraction level through projector children and
ended given-back values, following the pinned native traversal rules. Ignored
outer mutable wrappers retain the current level. Actual consumed and given-back
ports are selected only at the event's ending level. Both abstract and
continuation traversals must independently agree on the complete native port
types, symbolic names, polarity and order. Both field/projector paths remain.
Unsupported values, active owned projections at the selected level, enum field
layouts and nested reconstruction cases refuse rather than supplying a result.

The boundary uses given-back ports at output level zero and input higher levels
as arguments; consumed ports at input level zero and output higher levels become
results. Stable level sorting preserves native field order. Each actual output
must match exactly one input of the same symbolic identity, level and complete
region-erased payload type. All channels must form a bijection. Thus equal
payload types do not permit swapping names or merging levels. Ancestor events
and their actual ports remain in the report; their default-value computation
is explicitly not lowered by this boundary component.

`Auths.Support.NativeBorrowWiring` defines typed heterogeneous payload packs,
input slots, routes and an executable router. It routes existing payloads and
has no payload constructor, ordinary operation or callback-result contract.
The authored general origin statement says every routed output equals its
selected input payload. An independent checker binds route indices to actual
native identities/levels and computes normalization from the full native type.
Generated cases define actual typed backward routing functions and statements
for arbitrary payloads, with recorded-route/index agreement. All scripts and
new channel-swap/duplication/omission/level mutation regressions remain unrun.

The emitter seals `OUTPUT.json.backward-wiring-source-node-ID.json` and `.lean`
before the unchanged pinned pure translator. Normalized payload sorts do not
establish projected-value meaning: instantiate them with the actual typed
views, reconstruct nominal fields/defaults, prove region/layout/native value
adapters and then earn the complete backward ABI and source/heap/loan relation.
No full-program gate, original body or nested-borrow refusal is removed.

## Concrete candidate-regionful backward views (§13.215)

The forward witness now retains every actual native symbol's complete candidate
type and expanded shape. `native_borrow_view.ml` follows each actual backward
port's metadata producer chain to one of those forward symbols or an actual
forward exclusive borrow. Direct owned level-zero borrow ports carry the whole
pointee. Symbolic projections use the exact selected native candidate region
group on the carrier. A scalar pointee therefore retains its payload rather
than becoming an empty region selection.

Each normalized payload key must identify one complete candidate type, shape
and projection plan within its branch. Region erasure never chooses between
incompatible source contexts. All actual port identities, levels, routes,
origin chains and roots remain. A missing/cyclic/ambiguous origin, wrong owned
region, unsupported carrier root or incompatible view family refuses. Types
and inherited candidate/conditional nominal requirements stay recorded.

For every port, the existing exact region factorizer also derives one complete
candidate/native alpha pattern. Both factorizations must reconstruct their full
type/dictionary trees and preserve the alias partition, known static lifetimes
and local binders. Erased, body/captured-binder instantiations and merging
distinct region names refuse. Generated independent structural inference and
distinct-binding scripts check these actual type instances. This is syntactic
alpha correspondence, not an outlives or native reference-validity theorem.

`Auths.Support.NativeBorrowView` instantiates payloads with the actual typed
pure-data views and provides extraction/restoration operations. Unknown keys
have the empty type; they receive no unit value or result fallback. Independent
scripts check complete source-region scoping, shape root types, normalized keys
and selected mutable components. Authored laws cover extracting/restoring the
same carrier, exact successful updates and whole-pointee restoration. Generated
cases instantiate the four actual routers with concrete view families and
state their routing equations for arbitrary view values. Scripts and new origin/
schema/opaque-carrier mutation regressions remain unelaborated/unrun.

The constructor seals `OUTPUT.json.backward-views-source-node-ID.json` and
`.lean` before the original pure translation. Candidate carriers include the
conditional closed writer representation; they are not a proved interpretation
of the original Rust dynamic writer or native projected values. Actual native
region/view/field-layout adapters, parent defaults, complete backward ABI and
original source/heap/loan adequacy remain required. No primitive operation,
ordinary callback result, original root/body or pure refusal is replaced.

## Actual native fields and value/view transport (§13.216)

`borrow_projection.make_expander` now supplies the same declaration/argument/
predicate/field logic to candidate and native type expressions. It checks the
complete scope at every recursive type. The native expression scope comes only
from the port's actual alpha-instance footprint; it is not a rewritten function
signature or an assumed native lifetime validity result.

`native_borrow_transport.ml` independently expands the actual native port type
from native declarations and complete arguments. Its result must equal the
candidate shape renamed by the exact per-port map. All tags, field positions/
names, Box structure, reference kinds and nominal/dictionary trees remain.
Instantiated native nominal requirements stay recorded. An opaque atom must
have its identical complete type after renaming, including phantom lifetime
arguments. Otherwise construction refuses and requires an explicit reviewed
adapter; no erased atom/result or callback fallback is supplied.

`Auths.Support.BorrowTransport` defines structural value and selected-view
transports, inverses and plan transport. Independent metadata scripts check
the exact injective map, complete nominal renaming and unchanged field/variant
identities. Authored laws cover both value/view round trips and commutation of
extraction and restoration, including refusal paths. Actual generated cases
bind these functions to every concrete native port shape and region selection.
All Lean scripts and added shape/atom mutation regressions remain unrun.

The constructor seals `OUTPUT.json.backward-transport-source-node-ID.json`
and `.lean` before the original pure translator. These are typed pure-data
field adapters. They do not prove native projector execution, reference
permissions/lifetime validity, original Rust heap/loan/layout adequacy, current
parent defaults or the complete backward ABI. Those remain required, together
with all original whole-program and qualification gates. No pure guard is
removed and no new qualified claim follows from source generation.


### Current-carrier reconstruction (§13.217 source work)

`current_borrow_carrier.ml` locates every actual boundary port origin in the
native returned value retained by `native_capture_value.ml`. It traverses
actual nominal field spines, Box and exclusive-reference wrappers; missing,
repeated, reordered or differently shaped origins refuse. It never chooses
an enum alternative or searches only by an erased type. The resulting indexed
focus ties each native port adapter to its exact candidate subtree in the
returned carrier.

`Auths.Support.CurrentBorrowCarrier` supplies typed read/write, plan lifting
and partial-view restoration. Every update takes the current complete carrier;
siblings are retained from that value. Authored focus laws, successful-update
laws and disjoint-focus frame laws connect local restoration to a whole-carrier
put. Actual generated cases cover all ten native ports and recover the original
inputs from their actual moved fields. Source-input round trips and preservation
of the separate current input are authored. Parent-region pure views are
extracted from the same current carrier, never a stored forward snapshot.

This component does not yet lower native parent/default continuations, the
level-1 dependent continuation ABI, heap/loan endings or the original Rust
interface. A complete pure-data carrier is an explicit component input, not
proof that pending native loans can be materialized that way. The pinned pure
translator guard remains unchanged. New scripts/regressions remain
unelaborated/unrun until final checks.


### Immediate current-version defaults (§13.218 source work)

`native_borrow_defaults.ml` reconstructs the default expressions of every
actual given-back producer in both abstraction and continuation observations.
The immediate source is retained. In the deepest branch, symbol 14 requires
current symbol 13; its provenance through symbol 6 is not a license to read a
forward snapshot. Repeated level observations retain the original producer and
complete type. Native field layouts are independently expanded and matched
against exact injective region maps; opaque atom types must remain unchanged.

`Auths.Support.NativeBorrowDefaults` supplies a typed current-version view store,
default evaluation, and explicit registration of an actually supplied native
view. `BorrowViewRestriction` requires structural evidence that the available
current view can supply the selected one; enum tags and missing fields cannot
be invented. The deepest default restricts symbol 13's region-2 view to region 3. Missing or differently shaped immediate sources refuse. Evaluation
never falls back to an ancestor and never installs a given-back result. Separate
versions remain separate when a current binding is registered. Source scripts
state exact current reads, missing-source refusal and version preservation.
These operations prepare native default expressions; they do not execute
parent calls, level-1 dependent continuations or native heap/loan semantics.
All new proof/regression sources remain unelaborated/unrun.


### Selected-level ending execution (§13.219 source work)

`native_borrow_execution.ml` lowers every actual ending port to a typed view
operation: receive an incoming backward-interface parameter, select a foreign
level-zero synthesis-return default, emit an owned result, or observe a parent
consumption. All eighteen ending events remain ordered; both owned and foreign
ports have independently expanded native field adapters. Unsupported foreign
higher-level effects refuse. Incoming binders cannot be replaced by defaults.

`Auths.Support.NativeBorrowExecution` executes these operations against exact
current/incoming view stores, checking event roles, complete native root types,
normalized payload types and injective structural field transports. Consumed
parent views are read even when absent from the output tuple. Symbolic versions
remain distinct. The generated four curried interfaces have authored statements
normalizing execution of all actual endings to those interfaces for arbitrary
counter, writer and incoming view values. These scripts await final Lean checks.

The pure machine's foreign synthesis-default selection is an explicit proposed
lowering rule, not a proof of native continuation/default adequacy. Native ADT
ABI, original source, heap/loan/alias/ownership/lifetime and conditional-writer
relations remain required. The pinned pure guard is unchanged; no ordinary
Rust function-result fallback is introduced.


### Full native field-value adapters (§13.220 source work)

`native_borrow_full_abi.ml` wraps every actual incoming/outgoing channel with
full Data values in the independently expanded native field shapes. Incoming
values supply only their selected view. Partial updates restore into explicit
current outgoing carriers; unselected incoming fields cannot overwrite current
state. Whole-pointee updates need no current default. The two deepest current
carriers retain their distinct immediate origins, symbols 13 and 6.

`Auths.Support.FullBorrowABI` provides selected-update/frame/noninterference
scripts and accepted matching-input witnesses constructed from existing current
data. The generated four full-value interfaces have authored correspondence
statements against execution of every actual ending. Native physical/pure-type
ABI, current-state materialization, source/heap/loan and writer adequacy remain
required; all new scripts/regressions remain unelaborated/unrun.

The region selector now uses an uninhabited `Plan.empty` for the nonexistent
enum tail. Transport, restriction and frame operations preserve that empty view;
it cannot be supplied with unit or made into an invented enum alternative. This
corrects the unfinished formal representation, not shipping Rust semantics.


Current native fields can be materialized from exact available current views
only with `BorrowViewMaterialize.Rebuilder` evidence. Every field must be
accounted for; no skipped atom can be supplied. The actual symbol-13 region-2
view has this evidence, while its selected region-3 child view does not.
Generated `FullFromEndingState` functions run all actual endings, read their
native output views and materialize partial-update bases from the resulting
current-version store. They never substitute source 6 for absent source 13.
The native current-store correspondence and physical/pure-type ABI remain open.

### Source writer input lifetime interface (§13.221 source work)

`writer_input_bound.ml` retains every actual writer Box producer, replays its
original getter and prepared frame, and enumerates actual regular getter calls
from the complete source graph. It reads the returned Box's object annotation
from the exact dynamic predicate, retaining the complete native signature and
input/result typing requirements. It requires the parent writer input at its
original position to be exactly `&'object mut W`; mismatched positions, pointees
or lifetime annotations refuse. It never guesses a static lifetime.

`Auths.Support.WriterInputBound` reflects complete supported input types and
their exact writer pointee. Its checker rejects erased or escaped object
regions. Authored scripts derive pointee liveness from the explicit lifetime
component of a well-formed source reference input, independently of which
writer case was selected. That representation premise is not complete Rust
reference typing or a native fact supplied by the producer. The full dynamic
output predicate is replayed in the construction AST but is not independently
reflected in this component's Lean view.

The actual getter return/capture value path, source-input validity and native
heap/loan/ownership relation are still required before the added native W:object
bound is earned for reachable captures. All new scripts and source mutations
remain unelaborated/unrun. No ordinary Rust result is supplied, no root is
removed and the nested-mutable-ADT pure guard remains unchanged.

The component also retains the exact owner-315 capture route from the existing
source value-flow graph: getter call 1427639 in node 760, exclusive borrow
1427903, then field 0 of aggregate 1427904. Both original Box return branches
and their separate caller/callee scope environments must replay. The captured
parent writer type and object annotation must match the getter input interface
exactly after the recorded source equations; a different getter call, missing
origin, omitted producer or promoted static region refuses. Generated capture
scripts retain the source reference-input premise. This static origin/type
route does not prove intervening effect, alias, activation or native value
preservation; the full lexical effect obligations remain in the report.

### Pinned native pure payload fields (§13.222 source work)

`native_pure_payload.ml` calls the pinned `translate_fwd_ty` for each actual
incoming/outgoing port. Supported closed Pure.ty trees reconstruct their
complete original AST; unrepresented builtins, variables, constants or
dictionaries refuse instead of becoming opaque metadata. Borrowed nominal
fields are derived independently: translate the original generic field kind,
instantiate with complete native arguments, and require equality with
translation of the actual source-instantiated kind. Variant row positions must
preserve actual source IDs. The construction retains fields, names, attributes
and discriminants. The report prints native field kinds; opaque attribute
printing is diagnostic metadata, not an independent attribute reflection.

The native field layout is expanded from those Pure.ty schemas, independently
of the regionful source shape. A codec must account for every original atom,
nominal, enum alternative and field. Only source reference and Box wrappers
are transparent. The actual higher-level-first port order determines the
curried payload arrow, with same-level values grouped as native tuples; this
does not claim reconstruction of the complete original function signature.

`Auths.Support.NativePurePayload` has indexed native field values and total
encode/decode codecs with authored round-trip scripts. Missing atom typings
have an empty representation. The native field-value adapters compose those
codecs with the existing selected-view channel; matching existing current
values give accepted inputs, and authored frame/noninterference scripts keep
unselected current fields authoritative. They create no absent atom or enum
alternative. All new Lean and regression scripts remain unelaborated/unrun.

These native field values are a logical representation of the actual Pure.ty
schemas, not original Rust addresses or already extracted native ADT terms.
Complete expression/default/current-state/continuation correspondence and
source heap/loan/alias/ownership/layout adequacy remain required. The original
`translate_type_decl` nested-mutable guard is neither removed nor called through
a permissive substitute; no complete native program is emitted by this component.

### Actual closed native helper expressions (§13.223 source work)

`native_pure_expressions.ml` compiles every actual full-value channel's field
ownership into real pinned Pure.texpr helpers. Whole-pointee helpers have one
incoming argument. Partial helpers take current and incoming values, match all
actual enum variants, reconstruct every field and retain current values for
unowned fields. Incompatible partial alternatives produce a represented native
Result failure. The helper Result is a representation-domain adapter interface,
not a claim that the original Rust function panics or has that effect/signature.

The complete supported typed AST round-trips, including constructor generics,
all applications, pattern variables/names, bound scopes/slots, lambdas and
ordered matches. Open/free/place-bearing or unrepresented metadata/effect/error
nodes refuse; pretty output and opaque environment equality supply no semantics.
Native Result/Error types are reflected explicitly. A represented Result failure
constructor remains distinct from an expression-error placeholder.

`Auths.Support.NativePureExpressions` supplies an independent scoped type checker
and fuel-bounded first-order evaluator over the reflected fragment. It checks
constructor fields, application types, binder scopes and exhaustive ordered
variant branches. Native field packing creates no atom and no missing variant.
Internal interpreter refusal is `none`; represented Result failure remains a
constructor value. Source scripts check each actual closed helper and state its
evaluation equals the preceding selected native-field adapter for every typed
current/incoming value. Negative scripts reject escaped scopes and omitted
variants. All scripts/regressions remain unelaborated/unrun.

These are real helper expressions, not a replacement for the original backward
functions. Actual current environments, immediate versions 13/6, synthesis
defaults, lambda/continuation composition, input representation validity and
original Rust/loan/heap adequacy remain required. The original nested-mutable
guard, public roots, ordinary bodies and installed toolchain are unchanged.

### Native SSA ending-model programs (§13.224 source work)

`native_current_wiring.ml` lowers every operation of the explicit selected-view
ending machine into real pinned Pure expressions. Current versions have unique
SSA binders and exact candidate types, shapes and available views. Initial
arguments are admitted only through existing forward symbolic bindings or an
actual forward mutable-borrow expansion; lookup never chases a missing version
to its producer's earlier origin. Receive binds only the incoming selected
view, foreignDefault binds a distinct version, observe reads without updating
the current table, and emit applies the exact owned symbol/level helper.
Received unselected fields are never promoted to available authority. Reading a
complete current carrier requires the prior exact field materializer; an absent
atom cannot be supplied. Whole-pointee emission has no current requirement.

Programs retain source event/port order and higher-level-first incoming order.
They take only required post-forward current seeds and actual incoming values,
use closed non-monadic lets, and propagate represented helper errors through
explicit Result matches. Outputs are separate SSA values; emitting does not
silently update a received current version. Supported syntax reflection now
also retains non-monadic let patterns, annotations, values and bodies exactly.
The independent interpreter explicitly evaluates these binders and applies the
complete packed argument list. Unsupported monadic lets still refuse.

Generated source scripts state scope/type acceptance and evaluation agreement
with `NativeBorrowFullABI.*FullFromEndingState`, using the existing independent
ending machine, current-view restrictions and selective field updates. They
quantify over arbitrary typed atom interpretations and every finite actual enum
layout. Malformed interpreter execution remains distinct from represented
Result refusal. Source mutation regressions reject omitted seeds, branches,
inputs, operations and altered immediate keys, including substituting version
6 for version 13. All scripts and regressions remain unelaborated/unrun.

This is lowering of the **explicit ending model**. Its foreignDefault rule is
still proposed: the pinned native foreign SynthRet translator currently ignores
that return, while other pinned guards reject nested cases. Native symbolic
metadata origins do not establish original native execution semantics. These
programs do not replace original functions, emit their complete ABI, prove a
forward-environment projection or qualify defaults/activation/continuations.
Original reference/heap/loan/alias/ownership/layout/drop/unwind adequacy and every
remaining full-spec obligation remain required; no guard or root is removed.

### Current seeds bound to the same forward capture (§13.225 source work)

`native_current_seeds.ml` derives the global initial-current roster from all
four actual SSA programs. A borrow key resolves through its unique actual
mutable expansion to the existing pointee symbolic value; a symbolic key names
its exact existing forward binding. Every branch must agree on that key's
complete source type, shape, native type and whole available view. No missing
version is followed through a default origin or supplied as an unrelated input.

Each seed must occur exactly once in the actual forward result. Its path keeps
ordered record indices, original exclusive borrow identities and real Box
unwrapping. The reader replays that path against the actual stored native
ForwardEnd value, checks the complete symbolic identity/type and executable
leaf type, and selects an existing exact whole field codec. A one-field record
cannot impersonate a Box. The return context's ended-region set is recorded
explicitly; no full opaque context or menv equality supplies a value relation.
This focused returned-value check is not an environment/permission theorem.

`NativeCaptureValue.runWithState` retains the state from the same forward
execution that produced the returned value; `run` projects that value. The
independent seed reader requires the actual borrow-expansion instruction,
expanded source, exclusive borrow shape and exact pointee binding. Returned
paths are a second independent data projection. They preserve complete record
spines and reject missing fields/wrong carriers; their data borrow nodes have
no native address identity, which the source path constructor checks separately.

The generated typed preparation function reads and encodes both current seeds
from that forward state, together with the original capture. A second
preparation function reads them from the returned capture. Authored source
scripts equate both preparations and recover the original source capture for
every typed input, without a forward-success/result premise. Four composed
backward interfaces accept only original forward inputs and actual backward
updates; they expose no unrelated current-seed arguments. Their correspondence
scripts reuse the complete ending-model programs from §13.224. Regressions
reject omitted seeds, absent fields, changed symbols and changed native borrow
identities. All Lean and regression scripts remain unelaborated/unrun.

This closes the authored component's separate-seed interface, not original
native environment/default/activation/continuation adequacy or source heap/
loan/alias/ownership/lifetime/layout/drop semantics. The foreign-default rule is
still proposed, representation validity and complete original native signatures/
effects remain required, and no pinned guard/root/body/toolchain is replaced.

### Native lexical closure bundle (§13.226 source work)

`native_capture_closures.ml` constructs one actual closed pinned Pure expression
which takes the two prepared native seeds and returns all four backward
functions as a tuple. Each member partially applies only its exact required
current seeds to the preceding actual native state program. Seed types and
arrows are checked explicitly before the pinned application builder is called.
The tuple retains the original region-group order, without omitted or duplicate
members. Complete supported AST reflection includes all nested lambdas,
applications, tuple-constructor arguments, bound scopes/slots and annotations.

The pinned backend's rule is higher-level-first inputs followed by collected
outputs at return (`compute_back_tys_with_info` and the backward ForwardEnd
translation). This is not an early-output/staged-continuation ABI. Member types
are checked against the actual port-level grouping. Original raw backward
effects are observed through the pinned function-info computation, separately
from the adapters' representation-domain Result interfaces. The latter are not
silently substituted for an original infallible function signature; no original
decomposed signature is fabricated to initialize a translation context.

The dynamic fragment has an explicit lexical closure constructor containing its
type, pattern, body and complete data environment. `NativePureClosures` evaluates
nested lambdas/applications with fuel, restores the captured environment upon
application, checks argument/result types, and selects tuple members by their
actual index. No host-language function or opaque native environment supplies
a result. The preceding first-order evaluator remains the independent restricted
semantics. Internal failure remains distinct from a represented Result refusal.

Generated scripts state that construction produces exactly the four member
types and that invoking each actual closure agrees with the preceding complete
state program for arbitrary typed atoms/current/update values. A composed
capture first uses the same actual forward-state preparation as §13.225,
builds the native lexical closures from those encoded values, and retains the
original source captured value. Its four methods expose no unrelated seed or
host-function input. Authored scripts connect this capture to the preceding
same-forward interfaces and original source value. Source regressions reject
omitted/reordered members, changed indices and changed original effects;
support scripts reject absent tuple members, non-function application and fuel
exhaustion. All new Lean and regression scripts remain unelaborated/unrun.

This is actual Pure-expression closure construction and model interpretation,
not complete extraction of the original Rust closure or its source heap/loan/
lifetime semantics. Legitimate partial-input validity, original full signatures/
effects, default/activation/continuation adequacy and every remaining spec gate
remain open. The original nested-mutable guard and complete root/dependency
inventory are unchanged; no qualified result is inferred from construction.

### Shared native default-registry primitives (§13.227 source work)

`native-default-bindings-v1.patch` factors the actual Core/Values/Abs variable
and default operations into `SymbolicToPureBindings`. Both original AV/EV
wrappers use this implementation through an exact minimal binding-context
projection; complete signature/effect/return-callback fields are not invented
or changed. Original unit lookup, missing-symbol diagnostics, optional loop
borrow defaults, translation/allocation/lookup order and immediate symbolic
lookup remain. Original type/level/projection-loan/dispatch guards remain in
place. Registration does not activate an ignored foreign SynthRet default.

The new isolated API library is source construction only, with its exact parent,
five-file patch, source identities and outcome under
`target/formal/aeneas-default-bindings-construction`. Installed tools, old
libraries, toolchain locks and the qualified reproducer are unchanged.

`native_default_bindings.ml` derives consumed-borrow aliases through actual
mutable/Box forward expansions and existing complete source/native codecs.
Exact abstract/continuation paths locate the actual selected typed leaves;
both complete projection types and loan counts remain visible. Shared native
primitives allocate/register each given-back value in a minimal focused context.
Actual generator counters and all finite variable/type/borrow/default maps are
reflected after each step; opaque context and generator-function equality are
never used. Both native paths must produce identical finite projections.

The independent Lean registry model checks initialization and every snapshot,
including direct immediate-variable defaults and the original missing-borrow/
unit rules. Separate alias scripts compare consumed pointee and focused seed
encodings from the same actual forward execution. Registration neither supplies
a given-back runtime value nor proves activation or complete native dispatch.
Source mutations reject missing branches/aliases/registrations and altered maps.
All scripts and regressions remain unelaborated/unrun. Original source/native
heap/loan/lifetime, signature/effect, default/continuation and full-spec gates
remain open; no qualification is inferred from constructing this API.

The §13.227 construction uses explicit candidate-to-native outgoing field
transport when encoding a consumed Box pointee: canonical/output region names
are not equated. Its nine actual registry projections agree between both paths;
symbol 14 retains immediate symbol 13. The retained symbol-15 leaves each have
one nested loan, so the original empty-loan leaf guard remains unsatisfied.
This primitive registration trace is not complete leaf dispatch. Both source
construction runs and the isolated library build are terminal; no Lean or
regression suite has run. See §13.227 for immutable identities and outcomes.


## Complete nested projector levels and native consumed references

`native_projector_levels.ml` retains the complete original typed AV/EV
projector trees, including meta-symbol identities/types and all consumed,
borrow and loan reprojection edges. Exact selected-level ports must agree with
the actual native tree paths. `native_default_bindings.ml` retains each ending's
finite state and calls the actual shared native symbolic lookup for its
consumed ports; missing or mistyped bindings and diagnostic placeholders refuse.
These reads name immediate variables and never chase registered defaults.

A nested ended outer borrow requires its inner consumed results to have unique
reads at earlier, higher-level endings of the same abstraction. The actual
branch-3 symbol-15 tree retains loan 13 and consumed result 14: symbol 14 reads
native variable 4 at ending 5 before symbol 15 is bound at ending 6.
`Auths.Support.NativeProjectorLevels` defines independent fuel-bounded typed-tree
selection, typed immediate reads and ordering receipts. Exhausted fuel and
active selected projectors refuse; all scripts and mutations await final checks.

AP-SPEC-069 §13.228 records the completed 168-source construction, eight actual
projector roots, nine consumed reads and exact emitted case/report identities.
The run emits `.projector-levels-source-node-1162.{json,lean}` before the original
nested-mutable-ADT guard refuses full translation. Original leaf/level/loan
guards remain intact. These artifacts do not execute full EndAbs dispatch,
activate defaults, establish complete source-environment/ABI/effect adequacy,
or prove Rust heap/loan/lifetime/layout behavior. They never qualify an ordinary
Rust result or replace any public root. Both inventories and Model.lean include
the support/emitter/case; installed tools, locks and qualified evidence remain
unchanged.


## Registry-driven closed backward programs

`native_binding_closures.ml` uses actual focused registry names and immediate
default/consumed expressions to construct complete closed Pure branch programs
and their higher-order bundle. Every native operation must match exactly one
existing selected-view operation. Injective typed names check every actual
source expression against the existing variable; no default chain is chased.
The real pinned allocator reserves the actual registry namespace before helper
and argument allocation. Both exact forward roots are captured, including a
root unused by one member; the complete original environment is not fabricated.

Partial outputs use the existing full field-reconstruction helpers and immediate
current versions. The 171-source construction in AP-SPEC-069 §13.229 emits four
programs, 33 typed name pairs and 21 immediate expression uses, plus complete
closed syntax and scripts for typing, agreement, bundle invocation and capture
from the same actual forward value. `.binding-closures-source-node-1162` has
JSON/Lean outputs. Original guard 295 still refuses full translation afterward.
Foreign default activation remains a proposed lowering rule; original complete
environment, infallible signature, native dispatch and Rust permission/heap
adequacy remain unproved. All new scripts and mutations await final checks.

The separately authored `Auths.Support.BorrowViewCompatibility` defines the
structural partial-input condition independently of adapter success, plus total
reconstruction, exact selected fields and current frame under that condition.
Partial sums retain the current tag; whole ownership can replace it. Native
codec transport and matching-current witnesses are explicit. The subsequent
four-source snapshot is separate from the native executable freeze. These
scripts do not prove actual Rust inputs meet the condition and do not eliminate
the helper Result layer or qualify the original native program.


## Structural input conditions for actual native programs

`native_compatible_programs.ml` derives complete native packing witnesses,
explicit fuel bounds and typed actual let-reference flow from every helper and
registry-driven program. Unsupported layouts, missing fields/alternatives,
insufficient fuel, missing earlier values and unsupported dependent-current
witnesses refuse. A reference follows an actual let assignment, never default
metadata. Distinct symbolic names, regions and authority stay distinct.

`Auths.Support.NativeValuePacking` computes full typed packed values and states
agreement with the original fallible packer under the derived fuel bound.
`Auths.Support.NativeInputCompatibility` independently scans all value-flow
snapshots and composes structural compatibility with computed successes.
The `.compatible-programs-source-node-1162` JSON/Lean output retains five
helpers and all 18 operations. Scripts state helper/branch/bundle/own-forward
success under the independent condition, explicit incompatible-domain failures
and useful matching inputs from each actual forward capture. No successful
Rust result, successful preparation premise or unrelated current is supplied.
The Result layer and all original native guards remain unchanged.

AP-SPEC-069 §13.230 records the terminal 176-source full-input construction,
case/report identities and remaining gates. Full translation still exits 2 at
the original nested-mutable-ADT guard after emitting these artifacts. No Lean,
regression, test, qualification or clean reproduction ran.

The later `Auths.Support.BorrowTagTopology` support has its own four-source
snapshot. It states that the compatibility condition is exactly equality of
partial tag topology, not payload equality, and that total compatible restore
preserves it. It neither narrows the domain nor proves actual Rust calls,
carrier writes, loops or loans satisfy that invariant. Original source/heap/
loan, complete environment and native dispatch/signature adequacy stay open.


### §13.231: nested native level API and permission-directed field stores

The isolated `native-borrow-levels-v1.patch` extends the actual backend counter
only for complete checked finite nested source fields. `native_borrow_levels`
compares every root/group and original complete-signature maximum, complete
source shape, actual symbolic maximum and owned levels. Disagreements stay in
the report; they never become fabricated events/signatures. Original forward,
backward-type, expression, loan and full dispatch guards remain. The 181-source
borrow-level constructor emitted/installed its case then exited 2 at the
unchanged original forward declaration guard. Complete native maxima 1/1/2/3
and symbolic maxima 1/1/1/2 disagree for two groups; those comparisons remain
false. Source wellformedness/hierarchy and ending-level adequacy must reconcile
the actual nested paths. See AP-SPEC-069 §13.231 for exact identities.

`BorrowTagTopology` adds typed permission-directed field stores, their finite
composition, exact frame/tag preservation and complete final-value/native-codec
reconstruction. The compatible-program emitter authors actual-helper statements
using those derivations. Arbitrary ordinary calls are not assigned store effects;
the source heap/loan/call interpretation remains open. The separately frozen
181-source field-store successor builds and was launched after the predecessor
became terminal; its own outcome and new installed helper statements have not
yet been observed. Preserve its actual handle and immutable source archive. All new Lean and regression scripts
remain unelaborated/unrun; these source constructions are not qualification.


### §13.232: conditional writer object/Box-borrow lifetime edge

`writer_runtime` retains the actual source Box borrow and adds the required
object-outlives-borrow edge to the conditional lifted owner's native predicates.
Existing source predicates/cases/fields and W/object bound remain. The generic
source-reference/object-liveness rule exposes the semantic premise needed to
justify this edge; original source heap/loan/Box/dynamic-object/call/capture
validity for all legitimate inputs remains unproved. Source TDyn field reflection
is unsupported and no complete source-field type is fabricated. Mutation scripts
remove/reverse the edge and remain unrun.

The 181-source writer-edge successor constructor builds and is prepared, not
launched. Wait for the active field-store constructor's authoritative outcome
before launching it and installing successor cases. The writer-edge driver also
installs its emitted writer certificate atomically. See AP-SPEC-069 §13.232 for
exact source/executable identities and the complete remaining scope. All new
Lean/regression scripts remain unelaborated/unrun; no qualification is claimed.


### §13.233: exact dynamic source field and ended-ignored borrow origins

The field-store run emitted all ten helper statements and terminated at the
original nested forward-declaration guard. The writer-edge successor completed
actual symbolic synthesis with group-2 parents [0,1] and transitive group-3
ancestry through 2, then explicitly refused an ended-ignored mutable borrow.
Both outcomes are terminal and recorded in AP-SPEC-069 §13.233.

The dynamic source codec now retains/reconstructs the original existential
binder, generic/region/type predicates, clause origins and all source metadata.
Unsupported const/associated predicates refuse. The writer names its exact
original Box field, independently checks the actual self/object annotation,
and exposes the remaining source heap/object/reference/call/capture semantics.
No opaque source type or narrower legitimate input domain is substituted.

Ended-ignored headers use an existing parent symbol; they own/define no header
port. Complete AV/EV metadata matches, child remains at current level,
given-back subtree moves to the next level, and original root/port/default
paths remain. The combined 182-source source constructor builds and is active;
observe its actual handle/outcome without restarting on a timeout. The
reflection-only intermediate was prepared but never run and is superseded.
All new Lean and mutations remain unelaborated/unrun; full original native and
all-source qualification remain open.


### §13.234: actual active-level receipts for empty descending gaps

The combined source constructor emitted/installed the exact original dynamic
field writer case, passed explicit ignored-borrow origin/header handling, then
terminated at the consecutive-level assumption. The actual native trace
contains a 2-to-0 descent, and no missing event was supplied.

Scope events now retain all AV/EV active owned borrow/loan/projector levels and
the original native live-borrow/loan query result. Nonconsecutive descent must
be clear above the selected level according to every receipt; mismatches refuse.
Strict identity/descent, original level-zero completion and paired endings stay.
The model/emitter use new required event fields and must regenerate the scope
case before final elaboration. Source mutation scripts alter each receipt and
remain unrun. Full native loan/source/heap/ending/signature adequacy is still open.

The 182-source empty-level successor builds and is active through its existing
handle. Preserve its source archive and observe that exact process/outcome;
do not restart on observation expiry. AP-SPEC-069 §13.234 records identities and
the complete remaining objective. No new Lean/test/qualification gate has run.


### §13.235: actual terminal context and native sub-abstraction corrections

The completed native terminal receipt shows return abstraction 79 still owns a
live level-1 loan at group 3's terminal context. Scope completion correctly
refuses; missing events or empty contexts are not supplied. All actual ending
identities/levels and remaining abstraction ASTs/native queries are retained.

The isolated `native-subabstraction-levels-v1.patch` corrects projector visited
level selection, drains all strict higher levels with checked decreasing
maximum, excludes already-ended levels from pending maxima, and increments
continuation borrow-reprojection child levels. Original assertions/guards and
ended metadata remain. Both inventories include the patch. The new isolated
library and source constructor build; original installed tools/pins are unchanged.

The 183-source full-input source construction is active through its existing
handle. Observe its exact outcome/terminal state without restarting on a timeout.
Actual source/native loan/heap/signature/effect and the entire remaining
qualification scope remain open. All new Lean and source mutation cases remain
unelaborated/unrun. AP-SPEC-069 §13.235 records exact sources/artifacts and resume
order; no complete original program or qualified result is claimed.


### §13.236: closed target terminal context and explicit terminal scope rows

The corrected backend emits the actual missing intermediate endings. Input 3
and return 79 now end through levels 2/1/0, disappear from the final context,
and pass original scope completion. The scope artifact is emitted/installed;
its Lean statement remains unelaborated. The run then terminates at an internal
port polarity not covered by external-only wiring; no port/result/default or
extra caller input is fabricated.

Scope now retains every actual terminal synthesis row and checks no live
owned target/ancestor borrow/loan in AV, EV or original native queries, while
preserving all unselected/empty rows and original completion/pairing guards.
New required model fields need regenerated cases before final elaboration.
Mutations remove a row or insert a live target loan and remain unrun. Exact
internal-port identities are retained in refusal diagnostics.

The 183-source terminal-scope generator builds and is active through its actual
handle. Observe its authoritative outcome without restarting on timeout. All
source/native internal flow, heap/loan/ABI/signature/effect and full remaining
qualification obligations stay open. AP-SPEC-069 §13.236 records identities and
resume order; no complete original native program or qualification is claimed.


AP-SPEC-069 §13.237: the terminal-scope source construction has terminated
(exit 2) after preserving the complete required terminal rows and passing
actual target/ancestor closure. Its next refusal was internal symbol 18 at
return abstraction 79, group 3, level 2. No constructor remains running.
Wiring source/model now require full events and explicit internal links,
source-order/type/identity checks and exact once-only owned-port coverage.
The new edits have not been built/generated/elaborated; regenerate the required
wiring case from the same original full 21-root input next. Internal payload
execution and higher-level parent flow still refuse and require actual native
semantics. Authored mutations remain unrun. No full ABI, program or qualification
is claimed; all full-spec obligations and final gates remain open.


AP-SPEC-069 §13.238: full 21-root source construction now emits complete
internal wiring through default preparation, including actual internal 18 at
events 8/9, level 2. Static level analysis runs from exact source/protocol/wiring
without requiring later runtime helpers; native and target depths agree at
1/1/2/3. Group 3 keeps external levels 0/1 and internal level 2 distinct.
Both completed source runs retain the foreign higher-level execution refusal.
The source-backed current initializer uses actual forward state and unique
borrow/pointee expansions instead of fixed seed keys. Its constructor builds;
the immutable `native-recipe-21-native-forward-current-source-construction`
is active through its actual handle. Observe without restarting on timeout.
New source-link, coverage, preparation/entry and composed-restriction scripts
are unelaborated; runtime parent/internal semantics and all full-spec/final
gates remain open. No complete native ABI/program/qualification is claimed.


AP-SPEC-069 §13.239: the actual whole-root native backward signature now emits
with every source associated-type constraint and complete translated predicates.
Native type reflection retains dictionaries/constants/binders/parameters and
round-trips the original native AST; its independent Lean syntax/row scripts
remain unelaborated. Group 3 has whole carrier rows at levels 2/1/0; individual
event payload types are not the original ABI. The signature run is terminal
at the retained parent-higher-level execution refusal. Root-origin generation
now follows all original expansion/capture moves for owned and foreign ports,
with typed current-carrier/source-forward laws rather than runtime default
chasing. Its 191-source constructor builds and is active through its existing
handle in `native-recipe-21-native-root-origins-source-construction`; observe
without restarting on timeout. Whole-root codecs, actual continuation/ending
execution and all original source/heap/loan/qualification obligations remain.
No tests/Lean elaboration or complete native program qualification is claimed.


AP-SPEC-069 §13.240: whole-root logical codecs now emit for all three roots,
14 candidate native signature slots, four field schemas and four predicate
contexts. Root-origin and payload source runs are terminal at the retained
higher-parent execution refusal. Static storage origins do not prove current
value equality: branch-3 fresh 19/20 retain immediate 15/17. Proposed argument
bindings now require separate source-version correspondence proofs; no closed
witness is generated. Same-slot overlapping versions retain a joint obligation.
Original AV/EV typed projector contexts and selected metadata ports are emitted
before execution lowering. The 199-source correspondence constructor builds and
its source run is active through the actual handle. No new Lean/test/qualification
checks have run. Native/source value, parent/internal continuation, heap/loan,
original-input and every other full-spec obligation remain open. The nested
whole-nominal backward type rule is a candidate requiring adequacy, not a proved
complete representation. Preserve all original roots, fields and current versions.


§13.240 continuation: the 199-source correspondence run is terminal and the
conditional case is installed (SHA-256
`27ae9916cc8fae5125d5ce69eae288d475ea849a8594ea96c3a2d51a4782b0b4`).
It retains all 30 ports/28 endings, exactly the 20-from-17 / 19-from-15 overlap,
and original nested projector trees. The 200-source nested-return successor
now links each selected outer given-back header to its actual nested current
returns and exact earlier same-abstraction consumed ports. Its constructor
builds; its full-root source run is active through the existing handle in
`native-recipe-21-native-root-nested-returns-source-construction`. Preserve
original current/prior projector trees, names, paths and levels. This is
continuation dependency metadata, not permission to replace 19 with 18,
chase defaults, assume payload equality or close source/native adequacy.


The §13.240 200-source nested-return run is now terminal (exit 2). It installed
the updated case SHA-256
`e26b1ea3faa3a4f7b380a9158d8c6037c7756fc5a7993d72afda7204b4021938`.
Exactly two original dependencies are retained: fresh 19 includes nested return
18 consumed at event 9 before event 10 in input abstraction 3; fresh 21 includes
nested return 20 consumed at event 11 before event 12 in return abstraction 79.
All 30 ports/28 endings remain. The higher-parent execution refusal remains;
no source job is outstanding. Next implement context-preserving actual ending/
continuation reconstruction and prove each source-value correspondence. Metadata
membership/order scripts and all other new Lean/regressions remain unchecked.


AP-SPEC-069 §13.241: complete native expression syntax and closed default-frame
reconstruction now retain dictionary/constant arguments, ignored patterns and
all exact value scopes. The original native pattern-decomposition primitive
constructs ordered matched/captured-default branches; the original public
native APIs retain their declaration-map lookup and every declaration/EndAbs
guard. The isolated pattern-context library builds (SHA-256
`dfacd6251dfa59d226e13ab3f3c88ee29c8c3f23fe02790790d05b6414de5505`).
The 204-source run is terminal and installed two closed helpers plus eight
universal native-row scripts (case SHA-256
`bac3ac365014132657917318a306a30ab8448e834d6190b5e4bd5eb9b2162368`).
The 205-source codec-bridge successor builds and its full-root run is active
through the actual handle in `native-recipe-21-native-reconstruction-codec-source-construction`.
All scripts and mutations remain unrun. These are reconstructed *default*
frames, not fresh given-back results. Keep independent backward arguments and
fresh versions; original environment/default activation/EndAbs/heap/loan/ABI
adequacy remains open, along with the full spec and final gates.


AP-SPEC-069 §13.242: native reconstruction's codec-bridge run is terminal and
installed eight native-row/eight source-codec scripts (case SHA-256
`1409fa91aa0955de0e5caf580d1fb337de61515afd9f50b7b6c9150ce84b9906`).
New native checked default registration stores an algebraic expression over
exact current variables without rebinding/evaluating a fresh given-back value.
The current-scope integration retains 19's captures 15/18 and 21's 6/20,
complete types/scopes and before/after allocation/declaration state. No default
chain is followed, no runtime result is supplied and no complete bs_ctx is
fabricated. The isolated library builds (SHA-256
`47303fa51b6ee5b329dc8e93e6a785b50aaec25cc691812360301caed32af47f`).
The 208-source constructor builds; its full-root source run is active through
the existing handle in `native-recipe-21-native-scoped-defaults-source-construction`.
Original higher-parent/internal/mixed ending rules, fresh backward bindings,
source/heap/loan/ABI adequacy and every full-spec/final gate remain open. New
Lean/model/metadata/codec scripts and mutations remain unrun.


The §13.242 208-source run is now terminal (exit 2), with scoped case SHA-256
`c9bc32833a8236e0720870157e4abdbf13205b034ec17de3e0204f13d2559a4e`.
It records fifteen actual native registrations (1/2/4/8), including default 19
capturing source/native pairs 15/8 and 18/11 and default 21 capturing 6/6 and
20/12. Fresh symbol/declaration maps and allocation counters remain unchanged.
Fifteen registration/fifteen preservation scripts are generated, unelaborated.
The higher-parent execution refusal remains; no whole program/runtime default
activation is supplied. No source job is outstanding. The later independent
model adds unique-map/declaration/allocation validation, outside that frozen
source input. Continue original ending/fresh-argument/source-value adequacy;
do not turn stored reconstructed defaults into assigned fresh results.


AP-SPEC-069 §13.243 adds the isolated `native-foreign-defaults-v1.patch`,
`native_foreign_defaults.ml` and `NativeForeignDefaults` finite runtime model.
Shared native materialization retains current binders/default dependencies,
rejects missing/duplicate/cyclic defaults and creates no caller parameters.
Complete source ancestry includes transitive parents; the previous refusal
was group 3 event 2 / group 1 level 0, before the later higher-level event.
The immutable 212-source full-21-root construction is terminal: seven native
lets and fourteen foreign ports are retained in the installed foreign-default
case; the next refusal is the owned-internal argument/continuation binding.
No source job remains from this checkpoint.
All Lean/scripts/mutations remain unrun. Full owned/source/ABI/heap/loan and
whole-spec/final gates remain open; see the spec for exact source identities.


AP-SPEC-069 §13.244 adds actual closed full-type argument projection expressions
to `native_root_bindings.ml`, exhaustive source-carrier/native-codec execution
scripts, and unconditional actual-current-value success scripts for the foreign
runtime. A native projection is not a source-version correspondence proof;
all individual/joint `Represents` obligations remain. No fresh owned value or
extra public caller argument is supplied. The 213-source full-21-root construction
is terminal: eight native projection helpers and 24 typing/carrier/codec scripts
are installed, along with four new foreign-runtime success scripts. The next
refusal is owned internal symbol 18 / return abstraction 79 / group 3 / level 2
(original event 8). Its existing level-2 input slot 0 projection is constructed;
source-version/continuation correspondence remains open. No source job remains.
Lean, mutations, qualification and all remaining whole-spec/final gates are open.


AP-SPEC-069 §13.245 adds `native_owned_bindings.ml` and `NativeOwnedBindings`.
Actual native lets apply complete projections to the existing whole-argument
roster, preserving exact fresh declarations and default maps. Neither lazy
defaults nor ordinary results supply owned given values. The finite runtime
refuses missing/extra original arguments and overwrites; carrier/slot scripts
and mutations remain unrun. This is not complete original EndAbs/continuation/
ABI or source-version/heap/loan adequacy. The 215-source full-21-root construction
is terminal: seven whole arguments, eight given lets and 23 unelaborated scripts
are installed in the actual generated case. The execution constructor still
refuses owned internal 18 / abstraction 79 / group 3 / level 2 afterward.
No source job remains. Stronger working-model argument validity/level/disjointness
guards were authored after the freeze and also remain unelaborated; see §13.245.


AP-SPEC-069 §13.246 adds `native_root_updates.ml`, `native_root_programs.ml`
and `NativeRootPrograms`: complete actual ending rosters, typed SSA availability,
whole arguments, selected current-frame writes and complete saved outputs. The
candidate capture body and each backward factory must have the actual native
signature API's complete type; original parameters/predicates remain explicit.
The independent source-carrier specification uses focus reads/writes and selected
reconstruction, not a host/native expected-result evaluator. Universal native/
runtime bridge scripts and source mutations are authored and unrun.
The earlier flat endpoint chain is no longer invoked by `native_capture_plan`;
its modules/cases remain independent references. The original guarded native
pure translator/extractor still follows the candidate source case. Nothing
qualifies the candidate ABI, original continuation or Rust heap/loan semantics.
The first immutable 219-source construction is terminal; its refusal is recorded below.

The first §13.246 run is terminal: all backward factory API comparisons passed,
but the full arrow refused because the original forward signature conservatively
returns Result and the constructor omitted its success wrapper. No root-program
case/report was emitted, and no original backend guard had been reached. The
successor preserves the effect, uses the original success constructor and
retains complete intrinsic Result/Error rows in the reflected semantics. Its
immutable 219-source result-preserving construction is terminal.

The result-preserving 219-source construction is terminal (exit 2, wall
470.356370542082 seconds, CPU 408.567352 + 5.860526 seconds). The complete
candidate body and every backward factory passed the strict actual native API
type comparison. It emitted and installed `NativeRootPrograms.lean`, SHA-256
`fa99533a9c9808547c71acc393b2bf3a9d73db0f414ed2745b051f01aa848438`;
the full candidate report SHA-256 is
`0793e19ebacc0113cb8327b7d5b1794b2b14375bcfa32701d94f427724cbbade`.
Original pure translation then refused: "ADTs containing nested mutable borrows
are not supported yet", at `SymbolicToPureTypes.ml:295`, for original
`serde_json_canonicalizer-0.3.2/src/jcs.rs:371:26-371:43`. The candidate body is
constructed, not qualified; the complete original program was not emitted.
No source job remains active. New Lean/regressions remain unrun, and this
translator limitation does not establish a production Rust defect.


Latest implementation checkpoint: AP-SPEC-069 §13.247 (24 October 2026).
Full E1–E5/M6, §13.5 and §10 remain incomplete. Only the historical 917 claims
at their original revision are qualified. New Lean/regressions remain unchecked.

The complete candidate now has scripts invoking its actual returned closures
through captured scopes, plus exact forward capture and failure/type-refusal
scripts. The isolated native declaration guard has a checked complete-field
extension that retains all fields/variants/types/generics/predicates; original
backward/ending/environment/loan checks remain. The library and constructor
build successfully. Mutation cases are authored, unrun. The frozen next full-
21-root source construction still needs an observed generated case/declaration
report/backend outcome. No candidate ABI, original source/heap/loan adequacy or
new qualification is inferred. See §13.247 for identities and remaining scope.


Latest implementation checkpoint: AP-SPEC-069 §13.248 (24 October 2026).
Full E1–E5/M6, §13.5 and §10 remain incomplete. Only the historical 917 claims
at their original revision are qualified. All new Lean/regressions are unrun.

The preceding 221-source run emitted the actual returned-closure candidate
case (`dae8f9c3531d7a5162d9522ceaf839a11bbed1bfe43f671369b6bdce2c4cf8f0`),
then refused the report prepass's scan of unanalyzed lookup-only declarations.
Working code now uses exactly the original native extraction registry while
retaining the full lookup map. Transparent shared native syntax reduces source
repetition without omitting metadata. New generic scripts preserve earlier SSA
versions and saved output snapshots. The original joint-version/whole-ABI gate
remains explicit, including the actual identical level-1 projections of distinct
source versions 20 and 19. Source reachability/coherence is not inferred.

The final constructor builds; its frozen 221-source successor is
`target/formal/native-recipe-21-native-forward-extraction-registry-source-construction`.
Observe its existing handle/outcome for actual regenerated size, declaration
certificate and next original backend refusal. No source/heap/loan qualification
or full milestone completion is claimed. See §13.248 for exact identities.


Latest implementation checkpoint: AP-SPEC-069 §13.249 (24 October 2026).
Full E1–E5/M6, §13.5 and §10 remain incomplete. Only the historical 917 claims
at their original revision are qualified. All new Lean/regressions are unrun.

The §13.248 run actually emitted the returned-closure candidate case
`211dca44116eea57010d4050ecb988b1b7bed9b8a3d93ef4f0c9e685dc5a8f78`
and complete forward declaration certificate for original type 315. The native
component extraction registry has nine entries, with 461 retained component
lookup declarations. Original body translation then refused nested symbolic
projector classification. Transparent native syntax sharing reduces the actual
Lean case from 18,111,087 to 1,904,700 bytes; this is not a proof/timing result.

A new exact per-level classification path retains immediate typed reprojection
edges, original non-nested result rules and the mixed-polarity refusal. Its
finite source-linked case/model and level/type/port mutations are authored.
The library and constructor build; the immutable next source construction is
`target/formal/native-recipe-21-native-projector-kind-levels-source-construction`.
Its actual new classification case and next original body/ending outcome remain
to be observed. All source/current-version/whole-ABI/heap/loan and final gates
remain open. See §13.249 for exact identities and resume order.


Latest implementation checkpoint: AP-SPEC-069 §13.250 (24 October 2026).
Full E1–E5/M6, §13.5 and §10 remain incomplete. Only the historical 917 claims
at their original revision are qualified. All new Lean/regressions are unrun.

The §13.249 224-source run refused a real native-classification/source-port
mismatch before the new case or original pure backend. No new case, root body
or qualification is inferred. The strict prepass now records every original
root/ending's full AV, typed observations, native kind and exact agreement flags
before refusing, keeping the source evidence for repair. Admission/replay/case/
body gates still require every cell to agree; no failed cell is excluded.

Universal classifier and mutable-port-contract scripts are authored, unchecked.
The diagnostic constructor builds. Its immutable 224-source successor is
`target/formal/native-recipe-21-native-projector-kind-diagnostics-source-construction`.
Observe the existing source handle/refusal report, then repair the actual
mismatch. All source/current-version/whole-ABI/heap/loan, remaining five-part
spec requirements and final gates remain open. See §13.250 for exact identities.


Latest implementation checkpoint: AP-SPEC-069 §13.251 (24 October 2026).
Full E1–E5/M6, §13.5 and §10 remain incomplete. Only historical 917 claims at
their original revision are qualified. All new Lean/regressions remain unrun.

The retained §13.250 report covers all four branches/28 endings/42 AV roots,
54 header observations and 30 actual ports. One genuine current-type mismatch
is isolated: target 3/event 8/level 2/root 0, fresh symbol 18, owned region 79;
its old edge has regions 2/3 while its actual current type has regions 78/79.
The new classifier uses the actual fresh type while preserving both exact types
and enforcing complete lifetime-only shape agreement. Actual source port
polarity/full-roster admission stays strict; context-only empty rosters can keep
a container origin. No source/current-value equality is inferred.

The library and constructor build. The frozen 225-source successor is
`target/formal/native-recipe-21-native-projector-kind-current-types-source-construction`.
Observe its actual new case/report and next original body/ending result.
Separately authored E4 durable-claim/lost-ack suffix scripts remain unelaborated;
actual storage and driver correspondence remain open. All remaining full-spec
and final gates remain required. See §13.251 for identities and resume order.

### 13.252 Selected-level given-back materialization (24 October 2026)

The §13.251 immutable 225-source construction is terminal: exit 2 after
487.05767579202075 seconds. It emits the actual classification report
`5efd389fb613b38ab83e1cf0bab94c788cf429795655fc745fae5f2880efe934`
and installed `NativeProjectorKinds.lean` case
`4d6a7b9e0f7d91c3b118f66d8a9cc85b0eb1e61b98afda848ddea9315b8e4c20`.
All four branches, 28 endings, 42 AV-root cells and 30 actual mutable ports
satisfy that selected classification/roster gate. The complete candidate body
is constructed, with the retained root-program case `211dca44116eea57010d4050ecb988b1b7bed9b8a3d93ef4f0c9e685dc5a8f78`.
No new qualification is earned. The original body translator subsequently
refuses `SymbolicToPureValues.ml:982`: `aproj_to_given_back_aux` assumes an
ended borrow projector has no nested loan reprojections and ignores both
ending-level parameters. This is an observed translator limitation, not a
production Rust defect or evidence that the nested source value is invalid.

The successor source patch selects the actual ended borrow headers at the
exact requested level. Immediate reprojection edges advance exactly one level
and retain their own type. Selecting an outer fresh value does not materialize
its descendant loans early; selecting a deeper level follows the actual child
edges. The selected fresh symbolic identity/type is used to create the pattern;
the consumed identity remains only the original lazy-default registration.
Complete lifetime-erased shape agreement is required. No default is used as a
fresh runtime value. Active selected projectors still refuse, and multiple
selected headers under one symbolic root require explicit nominal
reconstruction rather than silently choosing one or inventing caller arguments.
Original consumed-value and ending guards remain unchanged.

The tool independently compares each actual symbolic subtree's selected fresh
identity/type list against the complete original source-event port roster,
filtered by its exact AV path. All original roots/events/ports stay in scope.
Finite Lean roster scripts retain order, duplicate identities, and current types;
mutations cover omitted headers, changed edge/current types and shifted paths.
These scripts and mutations are authored, unelaborated/unrun. The selected
source/current-value/whole-ABI, heap/loan and continuation adequacy gates remain
separate; matching lists is not a proof of those gates.

Patch: `formal/qualification/aeneas/toolchain/native-projector-given-back-levels-v1.patch`,
SHA-256 `fd7a74005de12f42bd516c37888b779b8a69e3036579074904aa63945db475b3`.
The isolated library builds with exit 0, wall 44.767696582945064 seconds;
`aeneas.cmxa` SHA-256 `da1a2b2b77c8c9aa8bd1488750cb2905af9f17c78f5de846610e27c7fee6d0cc`.
Constructor/source artifact construction follows; observe its authoritative
outcome and next original body/ending result before claiming further progress.
No Lean elaboration, regression, qualification, local verification or CI ran.

The full E1–E5/M6 objective, §13.5 and §10 remain incomplete. Only historical
917 claims at their original revision are qualified. Exact serde/JCS/hash/URL
bytes, source/backend/runtime correspondence, all original roots/shims/types/
calls/leaves/drop/unwind/primitive contracts, bounds and useful witnesses, final
Lean/regression/axiom/qualification checks, two independent clean reproductions,
and exact-revision hosted/release gates remain required.

### 13.253 Exact own-ending phases and complete selection trees (24 October 2026)

The immutable selected-given-back 226-source construction is terminal: exit 2,
wall 428.50873841601424 seconds, CPU 396.38413 + 5.783999 seconds, peak child
RSS 9,906,487,296 platform units. Its source classification/selection report is
`873bd93311a7dfc01dca26873b703dcb6f17642c1846f999bf456e66ee74e099`;
the actual installed classification/roster case is
`8817ea36ac9f7cfb47c9d3003cbd988bf7bf424e3e3bf32e5cd9f68de464057e`.
All four branches/28 endings/42 AV-root cells/30 actual mutable ports remain
admitted. The new library selector agrees with the independent exact source
identity/type roster for all 28 symbolic subtree observations, including eight
selected fresh headers. The complete candidate body is again constructed;
its retained root-program case is `211dca44116eea57010d4050ecb988b1b7bed9b8a3d93ef4f0c9e685dc5a8f78`.
No Lean or qualification checks ran, and no shipping closure is certified.

Original native body translation gets past the preceding nested given-back
guard, then refuses `SymbolicToPureExpressions.ml:1213`: the own `SynthRet`
path requires `abs_level = 0`. Actual source events show why an origin/zero-level
rule is insufficient: target 2's own input ending at level 1 gives symbol 12,
and its own return ending at level 1 consumes symbol 12. Target 3's own input
ending at level 2 consumes symbol 18, while its own level-1 input ending gives
symbols 20/19 and its own level-1 return ending consumes them. These source
roles are retained, not replaced with guessed parity or fabricated events.

The new library patch handles own input/return endings through their actual
consumed/given values and exact declared native signature rows. Each nonempty
consumed row must match complete declared arity/types before one-time output
capture. Given patterns bind an unused original input row with strict arity/
type checks; scheduling removal leaves the ordinary SSA values/defaults intact.
The actual return iterates original signature output order and refuses missing,
extra, repeated or mistyped output levels. No per-port caller arguments or
ordinary callback result are supplied. Foreign ancestor, consumed-projector,
nominal reconstruction, default and heap/loan/whole-ABI obligations remain.

Patch: `formal/qualification/aeneas/toolchain/native-own-synthesis-phases-v1.patch`,
SHA-256 `aea09bc6a5f8aee5ab1ae73631147d77524930d310081fe9ec9125c3760b5e55`.
The isolated library builds with exit 0, wall 41.90339908399619 seconds, CPU
139.183067 + 17.691491 seconds, peak child RSS 689,766,400 platform units;
`aeneas.cmxa` SHA-256 `2e8f954d49ff638b9d8a8d6de70f54b68159c57c7a23d89abd9b00d505184572`.
The constructor is building; this is artifact construction, not verification.

The selector now also has a complete typed source-projector tree model, rather
than only a flattened selection list. Fuel exhaustion/active selected headers/
changed non-lifetime shape refuse; future trees stay for their own ending;
multiple selected headers require reconstruction. The writer emits a finite
native-selection/source-tree/independent-roster equality chain. All scripts and
same-type/different-version, redirected-default, exact-level and retained-child
mutations remain unelaborated/unrun. A tree-only 226-source archive/executable
`ec2a52077e3fd7674d60f0ac10bd9630867b8f11f95560c0be3d3af785695478`
is preserved but unrun; construct the composite own-phase successor instead of
rerunning the already known level-zero refusal just to emit the tree case.

Separate working E3/E4 scripts now compose actual source capture, empty, arm
and permit-history primitives, preserving the first command/evaluation time/
selected requirements with a useful first-send witness. Aggregate claim history
adds durable-owner preservation and non-recharge under every suffix after a
lost acknowledgement, and capacity preservation under every post-collection
suffix regardless of later arrival facts. Thirty-two newly authored scripts,
including the preceding checkpoint's history facts, are registered for the final
theorem/axiom audit. None is newly qualified. Actual storage acknowledgement,
reservation/backend, connection/authority and physical async-driver refinement
remain distinct requirements. The latest collection scripts postdate the
preserved tree-only archive's separate working-source snapshot.

Full E1–E5/M6, §13.5 and §10 remain incomplete. Only historical 917 claims at
their original revision are qualified. All new Lean and regressions are unrun;
all original roots/shims/types/calls/leaves/drop/unwind/primitive contracts,
source/current-version/environment/reference/alias/ownership/loan/layout and
whole-ABI adequacy, exact serde/JCS/hash/URL bytes, total bounds/useful witnesses,
final elaboration/regressions/axioms/qualification, two independent clean
reproductions and exact-revision hosted/release gates remain required.

§13.253 construction handoff: the final constructor links the actual own-phase
library (above), exits 0 in 30.260999624966644 seconds, CPU 71.281304 + 6.934589,
peak child RSS 846,790,656 platform units, executable SHA-256
`5c1ae691b8c06ea9ab3b2ee12d75d80264defae58e4f20b6b0c3be7487103834`.
The first link accidentally used the preceding library and reproduced the
preceding `ec2a5207…` executable; that unused attempt is preserved separately
and is not evidence for the own-phase patch. The corrected construction command
records the actual own-phase OCAMLPATH. No source run used the wrong link.

Immutable composite successor, 227 source inputs:
`target/formal/native-recipe-21-native-own-synthesis-phases-source-construction`.
It retains the complete original 21-root input/argument identities, actual
selection-tree writer, own-phase patch and separately hashed current working
proof sources. Its original exec handle is 18407. Observe that handle or its
authoritative outcome before starting another full source construction. The
preserved tree-only 226-source archive remains unrun. The source driver prints
compact metadata but retains its full outcome; its exact source hash is stored
in the construction identity. Construction is not qualification. All remaining
full-spec and final verification gates above are still required.

### 13.254 Selected consumption branches and durable lost-batch evidence (24 October 2026)

The §13.253 composite 227-source construction is terminal: exit 2, wall
440.69122887495905 seconds, CPU 396.041847 + 5.444818 seconds, peak child RSS
9,178,628,096 platform units. The real complete selection-tree/source-roster
report is `12c9b7d7bc9084957d27d810fbfb9b4f25b4cb74d14a85414aba715edddfcad3`;
the installed `NativeProjectorKinds.lean` case is 148,925 bytes, SHA-256
`ec52ae7c3ab80d78e5db0cd9c575d2319f7addc3e94026e9ca2916167a4aa0e9`.
All four branches/28 endings/42 AV-root cells/30 actual mutable ports and all
28 symbolic subtree identity/type selections remain admitted. The case now
contains the actual complete source-tree selection equality as well as the
independent roster equality. These are unelaborated scripts, not new qualified
claims. The complete candidate body is retained with the same root-program
case `211dca44116eea57010d4050ecb988b1b7bed9b8a3d93ef4f0c9e685dc5a8f78`.

Original body translation gets past the own-return level-zero refusal, then
refuses the active/empty consumed-projector alternative at
`SymbolicToPureValues.ml:746`. The retained target-2/event-5 source contains an
active level-zero borrow projector for symbol 6 in the child of an ended
ignored mutable borrow, with the actual consumed loan in the given-back branch
at level 1. Both branches were traversed with the nominal container's unfiltered
flag. The first branch has no selected mutable loan but still reaches an active
header. It is not an owned consumed value at that ending level.

The successor patch uses the exact native selected-level classifier before
consuming either child of an ended ignored mutable loan/borrow. It preserves
the existing filter inside the selected branch, including complete nominal
fields, while leaving the other ending's branch alone. It does not substitute
a default, supply runtime values or choose between multiple consumed results.
The existing ambiguous-result, projector, nominal reconstruction, complete-type,
foreign/default and source/heap/loan/whole-ABI guards remain. Remaining refused
active/empty headers now include their actual kind and selected/current levels
in the diagnostic, without printing runtime payloads or huge AV dumps.

Patch: `formal/qualification/aeneas/toolchain/native-selected-consumed-branches-v1.patch`,
SHA-256 `3f58eba186c88a6b7ad2edbcb3c690ada4bc621794fd11a0dba1fe3159c44c3d`.
The isolated library builds with exit 0, wall 41.45557849993929 seconds, CPU
138.839329 + 15.745573 seconds, peak child RSS 688,848,896 platform units;
`aeneas.cmxa` SHA-256 `29c7d7f7a7051d08c664147c02cbf96e3c448ed3e73eff9f2371ca42d941a5c4`.
Constructor construction follows. No Lean/tests/qualification/CI checks ran.

The shared actual-backend conformance suite now includes
`conformance_lost_batch_acknowledgement_retains_capacity` in
`product/runtime/auths-gateway/src/scenario_tests.rs`. It loses acknowledgement
after a real claim/count/sum batch commit, reopens durable state, checks exact
retained bytes, and attempts four retries with the same claim and different
slot keys. It checks atomic refusal without partial second charges, then
collection retaining the claim and an older collection sample failing to reopen
the expired window. A fresh claim with old-window count/sum slots must also be
refused atomically. Both File and PostgreSQL suites call this case; it is written
but unrun. Existing submission-level lost-acknowledgement tests separately cover
no new execution handle/provider write. The raw backend case does not pretend
to construct valid attempt records or establish actual counter derivation.

`docs/assurance/ADMISSION_HISTORY_BOUNDARY.md` maps these scripts/source calls/
backend tests and the residual correspondence obligations. The transport
boundary links it. Actual reservation/backend linearization, complete prepared
batch membership, claim/connection/authority/driver and physical I/O composition
remain open. Full E1–E5/M6, §13.5 and §10 remain incomplete; only historical 917
claims at their original revision are qualified. All original roots/shims/types/
calls/leaves/drop/unwind/primitive contracts, source/current/whole-ABI/heap/loan
adequacy, exact bytes, bounds/useful witnesses, final Lean/regression/axiom/
qualification, two independent clean reproductions and exact-revision hosted/
release gates remain required.

§13.254 construction handoff: the constructor links the selected-branch
library and exits 0 in 58.64940666698385 seconds, CPU 133.336387 + 12.425728,
peak child RSS 846,249,984 platform units. Executable SHA-256:
`82522ff36f7bf2fec17c5112145f11afe5ff15e674ff8db4bb60578973e8198f`.
Immutable successor, 228 constructor inputs:
`target/formal/native-recipe-21-native-selected-consumed-branches-source-construction`.
The original full 21-root input/argument identities remain unchanged. The
current Rust backend regression and admission/history boundary are separately
hashed working evidence, not constructor/Lean qualification evidence. Its
original exec handle is 87683. Observe that handle or its authoritative outcome
before another full source construction; an observation timeout is not a stop.
Original consumed-projector, nested nominal reconstruction, whole ABI and
source/current/heap/loan requirements remain, followed by all final gates.

### 13.255 Actual incoming projection receipts and coverage (24 October 2026)

The selected-consumption 228-source construction is terminal: exit 2, wall
410.44804145907983 seconds, CPU 395.647772 + 4.70276 seconds, peak child RSS
10,024,566,784 platform units. It retains the actual complete selection-tree
case `ec52ae7c3ab80d78e5db0cd9c575d2319f7addc3e94026e9ca2916167a4aa0e9`
and complete candidate root-program case `211dca44116eea57010d4050ecb988b1b7bed9b8a3d93ef4f0c9e685dc5a8f78`.
The ignored-wrapper correction gets past the preceding active-projector
failure. Original translation now refuses the nested-borrow coverage guard in
`SymbolicToPureValues.ml:739`, on a single consumed symbolic update with an
empty child and no separate borrow reprojections. That guard remains intact.

The original symbolic give-back code retains the receiving loan's projection
type in `mconsumed_symb`, but discards the incoming borrow's projection type
and ended-region set. Consequently the old metadata cannot by itself show
which receiving fields the incoming value owns. The new metadata records the
real incoming symbolic identity, incoming projection type, original ended
regions and actual fresh type at all six abstract/continuation receipt creation
sites in `end_aproj_borrows` and `give_back_symbolic_value`. Existing edge types
are unchanged. Metadata equality and the original ordering key are preserved;
the existing opaque metadata visitors retain their original treatment. No
fresh value, coverage summary, lifetime renaming or source context is invented.

Patch: `formal/qualification/aeneas/toolchain/native-consumed-origin-receipts-v1.patch`,
SHA-256 `fe43d8d297b3c55145d9ca030c681add83ba4812284cb34c24e82aa12ae05505`.
The library builds with exit 0, wall 34.51323979196604 seconds, CPU 129.403436 +
12.585135 seconds, peak child RSS 691,044,352 platform units; library SHA-256
`e5002eb9ad99449ecf8785a019e3443d637848ecac73b44cdeeef256c6437729`.
The first attempt used a nonexistent ID comparison spelling; that failed
artifact/log is retained, and the correction uses the original generated
symbolic-ID comparison. This is source-artifact construction, not verification.

`native_consumed_coverage.ml` retains the actual evaluation context from every
original `EndAbs`, visits every selected consumed symbolic edge, and compares
its exact original source port, incoming origin and complete non-lifetime
shapes. It invokes the existing native `projection_contains` with the real
incoming region/type and receiver region/type pairs. Both partial and total
coverage are reported as outcomes; neither is a trusted input bit. The finite
Lean model `NativeConsumedCoverage.lean` conservatively compares complete source
syntax and source-region membership, refusing erased/bound/hole/shape mismatch
rather than guessing. Its emitted case must compare that result to the actual
native comparison and retain each update's original source-event membership.
Actual model/case imports and qualification inventories are registered; the
case remains a required actual output, never a stub. Origin/type/scope/coverage
mutations are authored, unrun. Source/heap/value and full ABI adequacy are not
consequences of projection coverage.

The constructor builds with exit 0, wall 48.542575458064675 seconds, CPU
128.424421 + 11.828895 seconds, peak child RSS 863,305,728 platform units;
executable SHA-256 `ffbd6924b1d67045b8619d955b58828991771bdfbf305e8ed29b77ed8c337c18`.
The immutable 231-source successor is
`target/formal/native-recipe-21-native-consumed-origin-receipts-source-construction`.
It uses the unchanged complete original 21-root input/argument identities and
the actual receipt library. Original exec handle: 29924. Observe that handle or
its authoritative outcome before another full source run. The driver installs
an actually emitted coverage case atomically even when later original body
translation refuses. No nested consumption guard is relaxed in this successor.

The next lowering must use the actual incoming coverage and current native
frame to preserve every unselected field and relevant enum/default branch.
An existing lazy-default helper is not a fresh runtime value. Keep immediate
source versions distinct; source coordinates or a matching signature do not
establish their joint representability. In particular, the existing identical
native projections for source versions 19/20 do not prove their source views
equal. The exact original EndAbs/heap/alias/loan/whole-ABI relation remains.

The pinned canonicalizer's owned-writer serializer constructor is private; the
shipping application cannot directly select it through the existing public API.
No production serialization, dependency, accepted domain, wire bytes or error
precedence is changed to avoid this proof obligation.

All new Lean/regressions/qualification/CI remain unrun. Full E1–E5/M6, §13.5 and
§10 remain incomplete; only historical 917 claims at their original revision are
qualified. Every original root/shim/type/call/leaf/drop/unwind/primitive contract,
source/current/whole-ABI/heap/loan adequacy, exact serde/JCS/hash/URL bytes, bounds
and useful witnesses, source/backend/driver composition, final elaboration/
regressions/axioms/qualification, two independent clean reproductions and
exact-revision hosted/release gates remain required.

### 13.256 Source-derived consumed-current reconstruction (24 October 2026)

The incoming-receipt 231-source construction is terminal: exit 2, wall
399.8451340419706 seconds, CPU 389.128539 + 4.441859 seconds, peak child RSS
9,876,668,416 platform units. Its actual consumed-coverage report is
`16257fb1b0f1fc97e4d75e0885d3c84b5cb6934db9920a1f50b36b019058cde3`;
the installed `NativeConsumedCoverage.lean` case is
`4765333cfe4dfdc3110e25da631f81ee40a655f6b70c27b197a2fc7e4e1dde41`.
All eight selected consumed symbolic receipts have matching incoming origins
and complete non-lifetime shapes. The real native comparison reports total
receiver-owned projection coverage for all eight. None has multiple sibling
consumed updates; two still retain separate borrow reprojections. The emitted
Lean comparison scripts remain unelaborated. Coverage alone is not total-value,
current-state, pointer/loan or whole-ABI adequacy. The original body still
refuses its old single-update nested guard at `SymbolicToPureValues.ml:739`.

The new library operation compiles a closed, typed current/incoming
reconstruction from `SymbolicToPureBorrowLevels.describe`, retaining the actual
complete instantiated fields, enum rows and source requirements. Owned mutable
references select their incoming referent; shared/unselected fields retain the
current value. Reference/Box wrapper erasure requires exact complete native-type
agreement. Structures reconstruct every field. Partial enum mismatch propagates
as explicit internal Result data to the root, which retains the entire current
frame, matching the independent `put/get` reconstruction with current fallback.
A wholly owned referent can still replace its own enum tag. No host callback,
ordinary function result, effectful let or new caller argument is supplied.
The resulting helper is closed with exactly `current → incoming → value` types.

The original nested single-consumed rule now requires the real incoming origin,
complete lifetime-erased type agreement and actual native projection coverage.
It reads the receiving source symbol and actual fresh symbol through existing,
same-typed native bindings before applying reconstruction. It never substitutes
a default or an older source version for either operand. A binding-map entry
is not by itself a proof of actual runtime availability; full original native
scope/closed-body and source-state adequacy remain required. Missing current
bindings fail explicitly. Partial incoming coverage, multiple consumed updates,
nonempty consumed children and separate borrow-reprojection cases retain their
remaining guards. Source versions 19/20 and joint representability remain open.

Patch: `formal/qualification/aeneas/toolchain/native-consumed-current-reconstruction-v1.patch`,
SHA-256 `4ae5e2bf3f299a0fd0e52f05991498c26a0dd6270f10df9a2ebfa5ac718f95de`.
The library builds with exit 0, wall 10.485476874979213 seconds, CPU 15.442918 +
1.566837 seconds, peak child RSS 554,598,400 platform units;
`aeneas.cmxa` SHA-256 `555e5855e90b3bdb4af035c2cab5fd940c3bcdb036987cf2c41dde12ccdfc907`.
Two earlier construction failures from ambiguous OCaml `.ty` record inference
are retained separately; explicit expression annotations resolve them. This is
artifact construction, not a Lean/regression/qualification check.

`native_consumed_reconstruction.ml` calls that actual library operation for
every actual consumed receipt. It independently expands the complete source
shape, native schemas/constraints and logical codec, links the exact source
coverage receipt, reflects the actual closed library code, and emits typed/
source-view reconstruction scripts for arbitrary source carrier values and
every sum branch. It supplies no actual current/fresh runtime payload or dummy
full native context. Source-provenance mutations are authored, unrun. The new
case is registered as an actual required output; no stub is supplied. These
helper scripts do not discharge the original ending's operand availability or
Rust heap/loan/whole-ABI relation.

The constructor builds with exit 0, wall 52.28414829191752 seconds, CPU
133.038817 + 12.802742 seconds, peak child RSS 868,876,288 platform units;
executable SHA-256 `e65a79e08ecd449adc43e2c9275fc22165c11260ac2ec7c4b1d1401e73797375`.
Immutable successor, 233 source inputs:
`target/formal/native-recipe-21-native-consumed-current-reconstruction-source-construction`.
Its original exec handle is 86677. It retains the unchanged original full
21-root input/argument identities and actual source coverage pipeline. Observe
its actual helper case and next original binding/ending outcome before another
full source construction. Its driver installs a genuinely emitted helper case
atomically even if later original body translation refuses.

Full E1–E5/M6, §13.5 and §10 remain incomplete; only historical 917 claims at
their original revision are qualified. All new Lean and regressions remain
unrun. Keep all original roots/shims/types/calls/leaves/drop/unwind/primitive
contracts and source/current/alias/reference/ownership/layout/loan/whole-ABI
obligations, exact serde/JCS/hash/URL bytes, bounds/useful witnesses, actual
backend/driver and final composition, final Lean/regression/axiom/qualification,
two independent clean reproductions and exact-revision hosted/release gates.


### 13.257 Paused after consumed-current construction (24 October 2026)

The 233-source construction from §13.256 is terminal (original handle 86677,
exit 2). Its actual eight-helper report SHA-256 is
`974e9e5c82ef5252e83b52b64261710cfe7baf0fb0505692743dc0c797b0179d`;
its emitted/installed reconstruction case SHA-256 is
`16164ed02868e434f1d9449793c0839736060aa85ec88a1128fa115073c9eb88`.
Original pure translation next refuses the exact own-ending input-type guard
at `SymbolicToPureExpressions.ml:939`; expected/actual types and source
abstraction/group/level must be obtained before a justified repair. The original
native program is not emitted or qualified. Full scope and final gates remain
open. A separate post-freeze declarative coverage proof draft is authored,
unelaborated and not yet registered in the public theorem ledger.

Work is paused at the user's request, with no successor job started. See
AP-SPEC-069 §13.257 for the full terminal evidence and exact resume order.
Only historical 917 claims at their original revision are qualified. No local
checks or hosted CI polling ran for the pause checkpoint.
