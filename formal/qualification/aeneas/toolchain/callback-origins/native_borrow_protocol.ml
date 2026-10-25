(* Scope/provenance projection of every actual backward EndAbs. This is not
   execution of loan endings or lowering to the final native backward ABI. *)
open Charon
open Types
module V = Aeneas.Values
module S = Aeneas.SymbolicAst
module F = Native_capture_value
module P = Borrow_projection

type origin = Borrow of V.borrow_id | Symbolic of V.symbolic_value_id
type observation = Use of V.symbolic_value_id * ty | BorrowUse of V.borrow_id * ty
  | Define of V.symbolic_value * origin | Control of bool * region_group_id
type event = {
  abstraction : V.abs_id; input : bool; group : region_group_id; level : int;
  can_end : bool; parents : V.abs_id list; owned_regions : region_id list;
  abstract_values : observation list; continuation : observation list;
  abstract_types : ty list; continuation_types : ty list;
  active_abstract_levels : int list; active_continuation_levels : int list;
  native_no_live_above : bool;
}
type terminal = {
  terminal_abstraction : V.abs_id; terminal_input : bool; terminal_group : region_group_id;
  terminal_active_abstract_levels : int list; terminal_active_continuation_levels : int list;
  terminal_has_live_borrows : bool; terminal_has_live_loans : bool;
}
type branch = { target : region_group_id; allowed : region_group_id list; events : event list;
  terminal : terminal list }
type binding = { value : V.symbolic_value; owner : V.abs_id option; origin : origin option }
type t = { initial : V.symbolic_value list; borrows : (V.borrow_id * ty) list; branches : branch list }

let marker = function V.PNone -> () | _ -> invalid_arg "native backward join markers need explicit scope handling"

(* Record every still-active owned borrow/loan/projector, following the actual
   native level visitor on both representations. A completed higher level can
   leave an empty intermediate level; no event is fabricated for that gap. *)
let active_levels (abs : V.abs) =
  let abstract = ref [] and continuation = ref [] in
  let save levels level = levels := level :: !levels in
  let visitor = object
    inherit [_] Aeneas.InterpBorrowsCore.iter_abs_with_levels as super
    method incr_level level = level + 1
    method! visit_aborrow_content level borrow =
      (match borrow with V.AMutBorrow _ | V.ASharedBorrow _ | V.AProjSharedBorrow _ -> save abstract level | _ -> ());
      super#visit_aborrow_content level borrow
    method! visit_aloan_content level loan =
      (match loan with V.AMutLoan _ | V.ASharedLoan _ -> save abstract level | _ -> ());
      super#visit_aloan_content level loan
    method! visit_aproj level projector =
      (match projector with V.AProjLoans _ | V.AProjBorrows _ -> save abstract level | _ -> ());
      super#visit_aproj level projector
    method! visit_eborrow_content level borrow =
      (match borrow with V.EMutBorrow _ -> save continuation level | _ -> ());
      super#visit_eborrow_content level borrow
    method! visit_eloan_content level loan =
      (match loan with V.EMutLoan _ -> save continuation level | _ -> ());
      super#visit_eloan_content level loan
    method! visit_eproj level projector =
      (match projector with V.EProjLoans _ | V.EProjBorrows _ -> save continuation level | _ -> ());
      super#visit_eproj level projector
  end in
  visitor#visit_abs 0 abs;
  List.sort_uniq Int.compare !abstract, List.sort_uniq Int.compare !continuation

let clear_above event = event.native_no_live_above &&
  List.for_all (fun level -> level <= event.level) event.active_abstract_levels &&
  List.for_all (fun level -> level <= event.level) event.active_continuation_levels

let terminal (context : Aeneas.Contexts.eval_ctx) =
  Aeneas.Contexts.ctx_get_abs context |> V.AbsId.Map.bindings |> List.map (fun (identity, (abs : V.abs)) ->
    let terminal_input, terminal_group = match abs.kind with
      | V.SynthInput group -> true, group | V.SynthRet group -> false, group
      | _ -> invalid_arg "native constructor terminal scope requires an explicit called/loop/other abstraction contract" in
    let terminal_active_abstract_levels, terminal_active_continuation_levels = active_levels abs in
    { terminal_abstraction = identity; terminal_input; terminal_group;
      terminal_active_abstract_levels; terminal_active_continuation_levels;
      terminal_has_live_borrows = Aeneas.InterpBorrowsCore.abs_has_non_ended_eborrows abs 0;
      terminal_has_live_loans = Aeneas.InterpBorrowsCore.abs_has_non_ended_eloans abs 0 })

let observations (abs : V.abs) =
  let abstract_types = ref [] and continuation_types = ref [] in
  let abstract_ignored = ref [] and continuation_ignored = ref [] in
  let rec regular (value : V.tvalue) = match value.value with
    | V.VSymbolic symbolic -> [Use (symbolic.sv_id, symbolic.sv_ty)]
    | V.VAdt aggregate -> List.concat_map regular aggregate.fields
    | V.VBorrow (V.VMutBorrow (identity, contents)) -> BorrowUse (identity, value.ty) :: regular contents
    | V.VLiteral _ | V.VBottom -> []
    | _ -> invalid_arg "native backward shared/loan value requires explicit provenance handling"
  and abstract (value : V.tavalue) =
    abstract_types := value.ty :: !abstract_types;
    match value.value with
    | V.AIgnored _ -> []
    | V.AAdt aggregate -> List.concat_map abstract aggregate.fields
    | V.ALoan loan ->
        (match loan with
         | V.AMutLoan (pm, identity, contents) -> marker pm; BorrowUse (identity, value.ty) :: abstract contents
         | V.AIgnoredMutLoan (identity, contents) ->
             Option.fold ~none:[] ~some:(fun identity -> [BorrowUse (identity, value.ty)]) identity @ abstract contents
         | V.AEndedMutLoan ended -> regular ended.given_back_meta @ abstract ended.child @ abstract ended.given_back
         | V.AEndedIgnoredMutLoan ended -> regular ended.given_back_meta @ abstract ended.child @ abstract ended.given_back
         | _ -> invalid_arg "native backward shared loan needs its own provenance rules")
    | V.ABorrow borrow ->
        (match borrow with
         | V.AMutBorrow (pm, identity, contents) -> marker pm; BorrowUse (identity, value.ty) :: abstract contents
         | V.AIgnoredMutBorrow (identity, contents) ->
             Option.fold ~none:[] ~some:(fun identity -> [BorrowUse (identity, value.ty)]) identity @ abstract contents
         | V.AEndedMutBorrow (meta, contents) ->
             BorrowUse (meta.bid, value.ty) :: abstract contents @ [Define (meta.given_back, Borrow meta.bid)]
         | V.AEndedIgnoredMutBorrow ended ->
             (* This header is an already-produced parent's value. It does not
                own a borrow or introduce a new symbol in this abstraction.
                Retain its exact use and both actual subtrees; their contained
                projectors carry the real definitions/consumed uses. *)
             abstract_ignored := (value.ty, ended.given_back_meta, ended.child.ty, ended.given_back.ty) :: !abstract_ignored;
             Use (ended.given_back_meta.sv_id, ended.given_back_meta.sv_ty) ::
               abstract ended.child @ abstract ended.given_back
         | _ -> invalid_arg "native backward shared borrow needs its own provenance rules")
    | V.ASymbolic (pm, projector) -> marker pm; aproj value.ty projector
  and aproj sort = function
    | V.AEmpty -> []
    | V.AProjLoans node -> Use (node.proj.sv_id, node.proj.proj_ty) :: apairs node.consumed @ apairs node.borrows
    | V.AProjBorrows node -> Use (node.proj.sv_id, node.proj.proj_ty) :: apairs node.loans
    | V.AEndedProjLoans node -> Use (node.proj, sort) :: apairs node.consumed @ apairs node.borrows
    | V.AEndedProjBorrows node ->
        Use (node.mvalues.consumed, sort) :: apairs node.loans @
          [Define (node.mvalues.given_back, Symbolic node.mvalues.consumed)]
  and apairs pairs = List.concat_map (fun ((consumed : V.mconsumed_symb), projector) ->
    Use (consumed.sv_id, consumed.proj_ty) :: aproj consumed.proj_ty projector) pairs
  and continuation (value : V.tevalue) =
    continuation_types := value.ty :: !continuation_types;
    match value.value with
    | V.EIgnored _ -> []
    | V.EAdt aggregate -> List.concat_map continuation aggregate.fields
    | V.EMutBorrowInput contents -> continuation contents
    | V.EValue (_, value) -> regular value
    | V.EApp (V.EInputAbs group, args) -> Control (true, group) :: List.concat_map (List.concat_map continuation) args
    | V.EApp (V.EOutputAbs group, args) -> Control (false, group) :: List.concat_map (List.concat_map continuation) args
    | V.ELoan loan ->
        (match loan with
         | V.EMutLoan (pm, identity, contents) -> marker pm; BorrowUse (identity, value.ty) :: continuation contents
         | V.EIgnoredMutLoan (identity, contents) ->
             Option.fold ~none:[] ~some:(fun identity -> [BorrowUse (identity, value.ty)]) identity @ continuation contents
         | V.EEndedMutLoan ended -> regular ended.given_back_meta @ continuation ended.child @ continuation ended.given_back
         | V.EEndedIgnoredMutLoan ended -> regular ended.given_back_meta @ continuation ended.child @ continuation ended.given_back)
    | V.EBorrow borrow ->
        (match borrow with
         | V.EMutBorrow (pm, identity, contents) -> marker pm; BorrowUse (identity, value.ty) :: continuation contents
         | V.EIgnoredMutBorrow (identity, contents) ->
             Option.fold ~none:[] ~some:(fun identity -> [BorrowUse (identity, value.ty)]) identity @ continuation contents
         | V.EEndedMutBorrow (meta, contents) ->
             BorrowUse (meta.bid, value.ty) :: continuation contents @ [Define (meta.given_back, Borrow meta.bid)]
         | V.EEndedIgnoredMutBorrow ended ->
             continuation_ignored := (value.ty, ended.given_back_meta, ended.child.ty, ended.given_back.ty) :: !continuation_ignored;
             Use (ended.given_back_meta.sv_id, ended.given_back_meta.sv_ty) ::
               continuation ended.child @ continuation ended.given_back)
    | V.ESymbolic (pm, projector) -> marker pm; eproj value.ty projector
    | _ -> invalid_arg "native backward let/join/free/bound/function control needs explicit scope lowering"
  and eproj sort = function
    | V.EEmpty -> []
    | V.EProjLoans node -> Use (node.proj.sv_id, node.proj.proj_ty) :: epairs node.consumed @ epairs node.borrows
    | V.EProjBorrows node -> Use (node.proj.sv_id, node.proj.proj_ty) :: epairs node.loans
    | V.EEndedProjLoans node -> Use (node.proj, sort) :: epairs node.consumed @ epairs node.borrows
    | V.EEndedProjBorrows node ->
        Use (node.mvalues.consumed, sort) :: epairs node.loans @
          [Define (node.mvalues.given_back, Symbolic node.mvalues.consumed)]
  and epairs pairs = List.concat_map (fun ((consumed : V.mconsumed_symb), projector) ->
    Use (consumed.sv_id, consumed.proj_ty) :: eproj consumed.proj_ty projector) pairs in
  let abstract_values = List.concat_map abstract abs.avalues in
  let cont = match abs.cont with Some value -> value
    | None -> invalid_arg "an actual ended constructor abstraction must retain its continuation" in
  let continuation = Option.fold ~none:[] ~some:continuation cont.input @
    Option.fold ~none:[] ~some:continuation cont.output in
  if List.rev !abstract_ignored <> List.rev !continuation_ignored then
    invalid_arg "actual ended-ignored AV/EV headers differ in complete metadata, original producer or child/given-back types";
  abstract_values, continuation, List.rev !abstract_types, List.rev !continuation_types

let validate witness (branch : branch) =
  let identities = List.map (fun entry -> entry.terminal_abstraction) branch.terminal in
  if List.length identities <> List.length (List.sort_uniq compare identities) then
    invalid_arg "native terminal abstraction scope repeats an original identity";
  List.iter (fun entry ->
    if List.mem entry.terminal_group branch.allowed &&
       (entry.terminal_active_abstract_levels <> [] || entry.terminal_active_continuation_levels <> [] ||
        entry.terminal_has_live_borrows || entry.terminal_has_live_loans) then
      invalid_arg "native terminal context retains a live target/ancestor borrow or loan"
  ) branch.terminal;
  let initial = List.map (fun value -> { value; owner = None; origin = None }) witness.initial in
  let lookup bindings identity = match List.filter (fun binding -> binding.value.sv_id = identity) bindings with
    | [binding] -> binding | _ -> invalid_arg ("native backward observation has no unique preceding symbolic producer: " ^
        string_of_int (V.SymbolicValueId.to_int identity)) in
  let same_shape left right = Region_equations.type_shape left = Region_equations.type_shape right in
  let process event bindings observations = List.fold_left (fun bindings -> function
    | Use (identity, sort) ->
        let binding = lookup bindings identity in
        if not (same_shape binding.value.sv_ty sort) then
          invalid_arg "native backward symbolic projection changed non-region type/dictionary structure";
        bindings
    | BorrowUse (identity, sort) ->
        (match List.assoc_opt identity witness.borrows with
         | Some original when same_shape original sort -> bindings
         | _ -> invalid_arg "native backward borrow has no matching actual forward origin")
    | Define (value, origin) ->
        let original = match origin with
          | Symbolic identity -> (lookup bindings identity).value.sv_ty
          | Borrow identity ->
              (match List.assoc_opt identity witness.borrows with
               | Some (TRef (_, inner, RMut)) -> inner
               | _ -> invalid_arg "native backward update has no exclusive-borrow producer") in
        if not (same_shape original value.sv_ty) then
          invalid_arg "native backward producer changed its complete non-region payload type";
        let introduced = { value; owner = Some event.abstraction; origin = Some origin } in
        (match List.find_opt (fun binding -> binding.value.sv_id = value.sv_id) bindings with
         | None -> introduced :: bindings
         | Some previous when previous = introduced -> bindings
         | Some _ -> invalid_arg "native backward producer conflicts with a prior name, owner, origin or complete type")
    | Control (input, group) ->
        if input <> event.input || group <> event.group then
          invalid_arg "native continuation invokes a different input/output region abstraction";
        bindings) bindings observations in
  let _, endings = List.fold_left (fun (bindings, endings) (event : event) ->
    if event.level < 0 || not event.can_end || event.parents <> [] || not (List.mem event.group branch.allowed) then
      invalid_arg "native backward ending is not endable or leaves its actual target/ancestor scope";
    let count values = List.length (List.filter (function Control _ -> true | _ -> false) values) in
    if count event.abstract_values <> 0 || count event.continuation <> 1 then
      invalid_arg "native ending needs exactly its actual input/output continuation call";
    (match List.assoc_opt event.abstraction endings with
     | None -> ()
     | Some (input, group, previous) when input = event.input && group = event.group &&
         previous > event.level && (previous = event.level + 1 || clear_above event) -> ()
     | Some _ -> invalid_arg "native abstraction endings must descend without repeating completion, changing identity or skipping live levels");
    let apply side observations = try process event bindings observations with Invalid_argument message ->
      invalid_arg (Printf.sprintf "native backward group=%d abstraction=%d level=%d %s: %s"
        (RegionGroupId.to_int branch.target) (V.AbsId.to_int event.abstraction) event.level side message) in
    let from_abstract = apply "abstract values" event.abstract_values in
    let from_continuation = apply "continuation" event.continuation in
    if from_abstract <> from_continuation then
      invalid_arg "native abstraction and continuation do not produce the same complete symbolic scope";
    let endings = (event.abstraction, (event.input, event.group, event.level)) ::
      List.remove_assoc event.abstraction endings in
    from_abstract, endings) (initial, []) branch.events in
  if not (List.for_all (fun (_, (input, group, level)) -> level = 0 &&
      List.exists (fun (_, (other_input, other_group, _)) -> group = other_group && input <> other_input) endings &&
      List.length (List.filter (fun (_, (other_input, other_group, _)) -> group = other_group && input = other_input) endings) = 1) endings) ||
      not (List.exists (fun (_, (input, group, _)) -> input && group = branch.target) endings) ||
      not (List.exists (fun (_, (input, group, _)) -> not input && group = branch.target) endings) then
    invalid_arg "native backward branch left a level unfinished or omitted its input/output pair"

(* Reusable source traversal. Consumers retain the original EndAbs values;
   no lowered execution, default result or guessed continuation is required. *)
let rec backward_expressions = function
  | S.Meta (_, next) | S.Expansion (_, _, S.ExpandNoBranch (_, next)) -> backward_expressions next
  | S.Expansion (_, _, S.ExpandAdt [None, _, next]) -> backward_expressions next
  | S.ForwardEnd (_, _, _, backward) -> backward
  | _ -> invalid_arg "native backward protocol cannot omit an intervening symbolic effect"

let rec ending_abstractions = function
  | S.Meta (_, next) -> ending_abstractions next
  | S.Return (context, None) -> [], context
  | S.EndAbs (_, abs, level, next) ->
      let endings, terminal = ending_abstractions next in
      (abs, level) :: endings, terminal
  | _ -> invalid_arg "native backward protocol requires explicit implementation of every effect before its void return"

let derive component (projection : P.t) inputs expression (forward : F.t) =
  if not (F.replay component projection inputs expression forward) then
    invalid_arg "native backward protocol requires the complete actual forward witness";
  let initial = forward.inputs @ List.concat_map (function
    | F.MutableExpansion (_, _, value) | F.BoxExpansion (_, value) -> [value]
    | F.RecordExpansion (_, values) -> values) forward.steps in
  let symbols = List.map (fun (value : V.symbolic_value) -> value.sv_id) initial in
  if List.length symbols <> List.length (List.sort_uniq compare symbols) then
    invalid_arg "native backward initial symbolic scope contains duplicate identities";
  let borrows = List.filter_map (function F.MutableExpansion (source, identity, _) ->
    let source = List.find (fun (value : V.symbolic_value) -> value.sv_id = source) initial in
    Some (identity, source.sv_ty) | _ -> None) forward.steps in
  let allowed target =
    let rec visit seen group =
      if List.mem group seen then invalid_arg "cyclic actual native region ancestry";
      let entry = match List.filter (fun (entry : region_var_group) -> entry.id = group) projection.hierarchy with
        | [entry] -> entry | _ -> invalid_arg "native region ancestry references an absent or ambiguous group" in
      group :: List.concat_map (visit (group :: seen)) entry.parents in
    List.sort_uniq compare (visit [] target) in
  let event ((abs : V.abs), level) =
        if level < 0 || level = Int.max_int then invalid_arg "native ending level is outside its exact finite range";
        let input, group = match abs.kind with V.SynthInput group -> true, group | V.SynthRet group -> false, group
          | _ -> invalid_arg "native backward constructor has an unsupported called/joined/loop abstraction" in
        let abstract_values, continuation, abstract_types, continuation_types = observations abs in
        let active_abstract_levels, active_continuation_levels = active_levels abs in
        let native_no_live_above =
          not (Aeneas.InterpBorrowsCore.abs_has_non_ended_eborrows abs (level + 1)) &&
          not (Aeneas.InterpBorrowsCore.abs_has_non_ended_eloans abs (level + 1)) in
        { abstraction = abs.abs_id; input; group; level; can_end = abs.can_end;
          parents = V.AbsId.Set.elements abs.parents; owned_regions = RegionId.Set.elements abs.regions.owned;
          abstract_values; continuation; abstract_types; continuation_types;
          active_abstract_levels; active_continuation_levels; native_no_live_above } in
  let branches = RegionGroupId.Map.bindings (backward_expressions expression) |> List.map (fun (target, expression) ->
    let endings, context = ending_abstractions expression in
    { target; allowed = allowed target; events = List.map event endings; terminal = terminal context }) in
  let witness = { initial; borrows; branches } in
  List.iter (validate witness) branches;
  witness

let replay component projection inputs expression forward witness =
  try derive component projection inputs expression forward = witness with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward =
  let witness = derive component projection inputs expression forward in
  if not (replay component projection inputs expression forward witness) then
    invalid_arg "the actual native backward scope protocol did not replay";
  witness

let nat value = if value < 0 then invalid_arg "a native backward certificate identity cannot be negative" else string_of_int value
let sid id = nat (V.SymbolicValueId.to_int id)
let bid id = nat (V.BorrowId.to_int id)
let aid id = nat (V.AbsId.to_int id)
let gid id = nat (RegionGroupId.to_int id)
let bool value = if value then "true" else "false"
let lean_origin = function Borrow id -> ".borrow " ^ bid id | Symbolic id -> ".symbolic " ^ sid id
let ty sort = P.reflect sort
let lean_observation = function
  | Use (id, sort) -> ".use " ^ sid id ^ " (" ^ ty sort ^ ")"
  | BorrowUse (id, sort) -> ".borrow " ^ bid id ^ " (" ^ ty sort ^ ")"
  | Define (value, origin) -> ".define " ^ sid value.sv_id ^ " (" ^ ty value.sv_ty ^ ") (" ^ lean_origin origin ^ ")"
  | Control (input, group) -> ".control " ^ bool input ^ " " ^ gid group
let list f values = "[" ^ String.concat ", " (List.map f values) ^ "]"
let lean_terminal entry =
  "{ abstraction := " ^ aid entry.terminal_abstraction ^ ", input := " ^ bool entry.terminal_input ^
  ", group := " ^ gid entry.terminal_group ^ ", activeAbstractLevels := " ^ list nat entry.terminal_active_abstract_levels ^
  ", activeContinuationLevels := " ^ list nat entry.terminal_active_continuation_levels ^
  ", nativeHasLiveBorrows := " ^ bool entry.terminal_has_live_borrows ^
  ", nativeHasLiveLoans := " ^ bool entry.terminal_has_live_loans ^ " }"
let rec expression_depth = function
  | Return_region_certificate.Binder (_, contents) -> 1 + expression_depth contents
  | Return_region_certificate.Node (_, contents) -> 1 + List.fold_left (fun n value -> max n (expression_depth value)) 0 contents
  | _ -> 1
let fuel witness =
  let sorts = List.map (fun (value : V.symbolic_value) -> value.sv_ty) witness.initial @ List.map snd witness.borrows @
    List.concat_map (fun branch -> List.concat_map (fun event -> event.abstract_types @ event.continuation_types @
      List.filter_map (function Use (_, sort) | BorrowUse (_, sort) -> Some sort | Define (value, _) -> Some value.sv_ty | Control _ -> None)
        (event.abstract_values @ event.continuation)) branch.events) witness.branches in
  1 + List.fold_left (fun n sort -> max n (expression_depth (Return_region_certificate.reflect_type ~holes:[] sort))) 0 sorts

let report component projection inputs expression forward witness =
  if not (replay component projection inputs expression forward witness) then
    invalid_arg "the native backward report requires its exact actual-source protocol witness";
  `Assoc ["schema", `String "actual-native-backward-scope-protocol/v1";
    "scope_construction_replayed", `Bool true;
    "type_shape_fuel", `Int (fuel witness);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "allowed_groups", `List (List.map (fun group -> `Int (RegionGroupId.to_int group)) branch.allowed);
      "complete_original_terminal_scope", `List (List.map (fun entry -> `String (lean_terminal entry)) branch.terminal);
      "events", `List (List.map (fun event -> `Assoc ["abstraction", `Int (V.AbsId.to_int event.abstraction);
        "input", `Bool event.input; "group", `Int (RegionGroupId.to_int event.group); "level", `Int event.level;
        "owned_native_regions", `List (List.map (fun region -> `Int (RegionId.to_int region)) event.owned_regions);
        "active_abstract_levels", `List (List.map (fun level -> `Int level) event.active_abstract_levels);
        "active_continuation_levels", `List (List.map (fun level -> `Int level) event.active_continuation_levels);
        "actual_native_no_live_above", `Bool event.native_no_live_above;
        "abstract_observations", `List (List.map (fun value -> `String (lean_observation value)) event.abstract_values);
        "continuation_observations", `List (List.map (fun value -> `String (lean_observation value)) event.continuation);
        "complete_abstract_type_trees", `List (List.map (fun sort -> `String (ty sort)) event.abstract_types);
        "complete_continuation_type_trees", `List (List.map (fun sort -> `String (ty sort)) event.continuation_types)]) branch.events)]) witness.branches);
    "observation_only_not_native_execution", `Bool true;
    "native_region_and_projection_value_adequacy_proved", `Bool false;
    "native_backward_abi_lowered", `Bool false;
    "native_heap_loan_layout_refinement_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let output = Buffer.create 32768 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.NativeBorrowProtocol";
  line "/- Actual native ordered name/type-shape protocol only; unelaborated/unqualified.";
  line "   No native value, region, heap/loan or backward-ABI adequacy follows. -/";
  line "namespace Auths.Qualification.NativeBorrowProtocol";
  line "open Auths.Support.SourceClosureRegions Auths.Support.NativeBorrowProtocol";
  List.iter (fun branch ->
    let name = "branch" ^ gid branch.target in
    line ("def " ^ name ^ " : Program := {");
    line ("  target := " ^ gid branch.target);
    line ("  allowedGroups := " ^ list gid branch.allowed);
    line ("  terminal := " ^ list lean_terminal branch.terminal);
    line ("  initial := " ^ list (fun (value : V.symbolic_value) ->
      "⟨" ^ sid value.sv_id ^ ", " ^ ty value.sv_ty ^ ", none, none⟩") witness.initial);
    line ("  borrows := " ^ list (fun (identity, sort) -> "(" ^ bid identity ^ ", " ^ ty sort ^ ")") witness.borrows);
    line ("  typeFuel := " ^ string_of_int (fuel witness));
    line "  events := [";
    List.iteri (fun index event ->
      line ("    { abstraction := " ^ aid event.abstraction ^ ", input := " ^ bool event.input ^
        ", group := " ^ gid event.group ^ ", level := " ^ nat event.level ^ ", canEnd := " ^ bool event.can_end ^
        ", parents := " ^ list aid event.parents ^ ",");
      line ("      abstractValues := " ^ list lean_observation event.abstract_values ^ ",");
      line ("      continuation := " ^ list lean_observation event.continuation ^ ",");
      line ("      activeAbstractLevels := " ^ list nat event.active_abstract_levels ^
        ", activeContinuationLevels := " ^ list nat event.active_continuation_levels ^
        ", nativeNoLiveAbove := " ^ bool event.native_no_live_above ^ " }" ^
        (if index + 1 = List.length branch.events then "" else ","))) branch.events;
    line "  ] }";
    line ("theorem " ^ name ^ "_has_ordered_producer_scope : check " ^ name ^ " = true := by");
    line "  rfl"
  ) witness.branches;
  line "end Auths.Qualification.NativeBorrowProtocol";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
