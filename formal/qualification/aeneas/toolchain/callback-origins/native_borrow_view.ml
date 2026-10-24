(* Bind routed payload families to actual candidate-regionful carrier views.
   Candidate fields include the conditional writer overlay; original Rust/
   native projected-value/region/heap/loan adequacy is not supplied here. *)
open Charon
open Types
module V = Aeneas.Values
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol
module W = Native_borrow_wiring

type root = BorrowPayload of V.borrow_id | ForwardSymbol of V.symbolic_value_id
type selection = Whole | Regions of region list
type schema = { payload_type : ty; candidate_type : ty; shape : P.shape; selection : selection }
type type_instance = { pattern : ty; candidate_arguments : region list; native_arguments : region list }
type port = { native : W.port; root : root; chain : V.symbolic_value_id list; schema : int; type_instance : type_instance }
type branch = { target : region_group_id; schemas : schema list; inputs : port list; outputs : port list; routes : int list }
type t = { public_parameters : region_id list; branches : branch list }

let rec root_type = function
  | P.Atom sort -> sort
  | P.Named (P.Nominal reference, _) -> TAdt reference
  | P.Named (P.Boxed, contents) ->
      TAdt { id = TBuiltin TBox; generics = { TypesUtils.empty_generic_args with types = [root_type contents] } }
  | P.Borrow (kind, region, contents) -> TRef (region, root_type contents, kind)
  | _ -> invalid_arg "this native payload carrier needs explicit candidate root-type reconstruction"

let rec contains_selected regions = function
  | P.Atom _ | P.Empty | P.Unit -> false
  | P.Product (first, second) | P.Sum (first, second) -> contains_selected regions first || contains_selected regions second
  | P.Named (_, contents) -> contains_selected regions contents
  | P.Borrow (RShared, _, _) -> false
  | P.Borrow (RMut, region, contents) -> List.mem region regions || contains_selected regions contents

let type_instance candidate native =
  let wrap sort = { TypesUtils.empty_generic_args with types = [sort] } in
  let candidate_factor = Region_shape.factor (wrap candidate) in
  let native_factor = Region_shape.factor (wrap native) in
  if candidate_factor.pattern <> native_factor.pattern then
    invalid_arg "native payload type changed complete structure, known static/bound regions or the candidate alias partition";
  let free = function RVar (Free id) when RegionId.to_int id >= 0 -> ()
    | _ -> invalid_arg "native payload alpha instances require actual free region names; body/captured binder scopes need explicit support" in
  List.iter free candidate_factor.arguments; List.iter free native_factor.arguments;
  let pattern = match candidate_factor.pattern.types with [sort] -> sort
    | _ -> invalid_arg "native payload type factorization changed its original root arity" in
  { pattern; candidate_arguments = candidate_factor.arguments; native_arguments = native_factor.arguments }

let validate (wiring : W.branch) (branch : branch) =
  if branch.target <> wiring.target || branch.routes <> wiring.routes ||
      List.map (fun port -> port.native) branch.inputs <> wiring.inputs ||
      List.map (fun port -> port.native) branch.outputs <> wiring.outputs then
    invalid_arg "native concrete views must retain every actual boundary port and route";
  let keys = List.map (fun schema -> schema.payload_type) branch.schemas in
  if List.length keys <> List.length (List.sort_uniq compare keys) then
    invalid_arg "a native payload family cannot contain ambiguous normalized keys";
  List.iter (fun schema ->
    if root_type schema.shape <> schema.candidate_type ||
        Region_equations.type_shape schema.candidate_type <> schema.payload_type then
      invalid_arg "native concrete view lost its complete candidate root type or normalized payload key";
    match schema.selection with
    | Whole -> ()
    | Regions regions ->
        if regions = [] || not (contains_selected regions schema.shape) then
          invalid_arg "a symbolic native view needs an actual selected mutable region") branch.schemas;
  List.iter (fun port ->
    let schema = match List.nth_opt branch.schemas port.schema with Some schema -> schema
      | None -> invalid_arg "a concrete native port has no view-family schema" in
    if schema.payload_type <> port.native.payload_type then
      invalid_arg "a concrete native port changed its normalized payload key";
    if port.type_instance <> type_instance schema.candidate_type port.native.value.sv_ty then
      invalid_arg "a concrete native port lost its exact alias-preserving candidate/native type instance") (branch.inputs @ branch.outputs);
  List.iter2 (fun output input ->
    let input = match List.nth_opt branch.inputs input with Some input -> input
      | None -> invalid_arg "a concrete native view route has no original input" in
    if output.schema <> input.schema then
      invalid_arg "a native route cannot silently reinterpret different candidate projection contexts") branch.outputs branch.routes

let derive component (projection : P.t) inputs expression (forward : F.t) (protocol : B.t) (wiring : W.t) =
  if not (W.replay component projection inputs expression forward protocol wiring) then
    invalid_arg "concrete native views require the complete actual level-aware wiring witness";
  let public_parameters = List.map (fun (parameter : region_param) -> parameter.index) projection.candidate.generics.regions in
  let scope = new Region_scope.check projection.candidate.generics.regions in
  let source identity = match List.filter (fun (binding : F.binding) -> binding.native.sv_id = identity) forward.source_bindings with
    | [binding] -> binding | _ -> invalid_arg "a native view root needs one exact forward candidate binding" in
  let borrow identity =
    match List.filter_map (function F.MutableExpansion (original, actual, _) when actual = identity -> Some original | _ -> None) forward.steps with
    | [original] ->
        let binding = source original in
        (match binding.source_type, binding.shape with
         | TRef (region, inner, RMut), P.Borrow (RMut, actual, shape) when region = actual -> region, inner, shape
         | _ -> invalid_arg "a native whole-pointee schema requires its actual exclusive forward borrow")
    | _ -> invalid_arg "a native payload origin names an absent or ambiguous forward borrow" in
  let branches = List.map (fun (wiring : W.branch) ->
    let protocol_branch = match List.filter (fun (branch : B.branch) -> branch.target = wiring.target) protocol.branches with
      | [branch] -> branch | _ -> invalid_arg "native payload view lacks its exact actual backward scope" in
    let definitions = List.concat_map (fun (event : B.event) -> List.filter_map (function
      | B.Define (value, origin) -> Some (value, origin, event.abstraction)
      | _ -> None) event.abstract_values) protocol_branch.events in
    let definition identity =
      match List.filter (fun ((value : V.symbolic_value), _, _) -> value.sv_id = identity) definitions |> List.sort_uniq compare with
      | [(_, origin, _)] -> origin
      | _ -> invalid_arg "native payload needs one consistent actual metadata producer" in
    let rec trace seen identity =
      if List.mem identity seen then invalid_arg "cyclic native payload origin chain";
      match List.filter (fun (binding : F.binding) -> binding.native.sv_id = identity) forward.source_bindings with
      | [_] -> ForwardSymbol identity, [identity]
      | [] ->
          (match definition identity with
           | B.Borrow borrow -> BorrowPayload borrow, [identity]
           | B.Symbolic original -> let root, chain = trace (identity :: seen) original in root, identity :: chain)
      | _ -> invalid_arg "ambiguous native forward candidate carrier" in
    let regions = match List.filter (fun (group : region_var_group) -> group.id = wiring.target) projection.hierarchy with
      | [group] -> List.map (fun id -> RVar (Free id)) group.regions
      | _ -> invalid_arg "a symbolic payload view needs the exact actual candidate region group" in
    let schemas = ref [] in
    let port (native : W.port) =
      let direct = definition native.value.sv_id in
      let root, chain = trace [] native.value.sv_id in
      let candidate_type, shape, root_region = match root with
        | ForwardSymbol identity -> let binding = source identity in binding.source_type, binding.shape, None
        | BorrowPayload identity -> let region, sort, shape = borrow identity in sort, shape, Some region in
      let selection = match direct with
        | B.Borrow _ ->
            if native.level <> 0 || not (Option.fold ~none:false ~some:(fun region -> List.mem region regions) root_region) then
              invalid_arg "a whole-pointee native port needs its actual owned level-zero region";
            Whole
        | B.Symbolic _ -> Regions regions in
      scope#visit_ty [] candidate_type;
      if root_type shape <> candidate_type || Region_equations.type_shape candidate_type <> native.payload_type then
        invalid_arg "native port origin changed its complete candidate carrier or payload type shape";
      (match selection with Regions regions when not (contains_selected regions shape) ->
        invalid_arg "native symbolic carrier has no selected mutable component" | _ -> ());
      let schema = { payload_type = native.payload_type; candidate_type; shape; selection } in
      let index = match List.mapi (fun index original -> index, original) !schemas |>
          List.filter (fun (_, original) -> original.payload_type = schema.payload_type) with
        | [] -> let index = List.length !schemas in schemas := !schemas @ [schema]; index
        | [index, original] when original = schema -> index
        | _ -> invalid_arg "equal normalized native payload types have incompatible complete candidate carriers or projection plans" in
      { native; root; chain; schema = index; type_instance = type_instance candidate_type native.value.sv_ty } in
    let inputs = List.map port wiring.inputs and outputs = List.map port wiring.outputs in
    let branch = { target = wiring.target; schemas = !schemas; inputs; outputs; routes = wiring.routes } in
    validate wiring branch; branch) wiring.branches in
  { public_parameters; branches }

let replay component projection inputs expression forward protocol wiring witness =
  try derive component projection inputs expression forward protocol wiring = witness with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring =
  let witness = derive component projection inputs expression forward protocol wiring in
  if not (replay component projection inputs expression forward protocol wiring witness) then
    invalid_arg "the actual native candidate view-family adapter did not replay";
  witness

let selection = function Whole -> ".whole" | Regions regions ->
  ".regions " ^ B.list Return_region_certificate.lean_region regions
let lean_schema schema = "{ payloadKey := " ^ P.reflect schema.payload_type ^ ", candidateType := " ^ P.reflect schema.candidate_type ^
  ", shape := " ^ P.lean schema.shape ^ ", selection := " ^ selection schema.selection ^ " }"
let lean_type_instance schema (port : port) =
  let witness = port.type_instance in
  let holes = List.mapi (fun index _ -> index, RVar (Free (RegionId.of_int index))) witness.candidate_arguments in
  let pattern = Return_region_certificate.reflect_type ~holes witness.pattern |> Return_region_certificate.lean in
  let parameters regions = B.list (function RVar (Free id) -> B.nat (RegionId.to_int id)
    | _ -> invalid_arg "a reflected native type instance has an unsupported region scope") regions in
  let bindings regions = B.list (fun (index, region) -> "⟨" ^ B.nat index ^ ", " ^ Return_region_certificate.lean_region region ^ "⟩")
    (List.mapi (fun index region -> index, region) regions) in
  "{ pattern := " ^ pattern ^ ", candidate := " ^ P.reflect schema.candidate_type ^ ", native := " ^ P.reflect port.native.value.sv_ty ^
  ", candidateParameters := " ^ parameters witness.candidate_arguments ^ ", nativeParameters := " ^ parameters witness.native_arguments ^
  ", candidateBindings := " ^ bindings witness.candidate_arguments ^ ", nativeBindings := " ^ bindings witness.native_arguments ^ " }"
let rec shape_depth = function
  | P.Atom sort -> 1 + B.expression_depth (Return_region_certificate.reflect_type ~holes:[] sort)
  | P.Named (P.Nominal reference, contents) -> 1 + max (shape_depth contents)
      (B.expression_depth (Return_region_certificate.reflect_type ~holes:[] (TAdt reference)))
  | P.Named (_, contents) | P.Borrow (_, _, contents) -> 1 + shape_depth contents
  | P.Product (first, second) | P.Sum (first, second) -> 1 + max (shape_depth first) (shape_depth second)
  | P.Empty | P.Unit -> 1
let fuel witness =
  1 + List.fold_left (fun n branch -> List.fold_left (fun n schema ->
    max n (max (shape_depth schema.shape) (B.expression_depth (Return_region_certificate.reflect_type ~holes:[] schema.candidate_type))))
    n branch.schemas) 0 witness.branches

let report component projection inputs expression forward protocol wiring witness =
  if not (replay component projection inputs expression forward protocol wiring witness) then
    invalid_arg "native view-family report requires the exact actual-source witness";
  let port schemas port = `Assoc ["native_symbol", `Int (V.SymbolicValueId.to_int port.native.value.sv_id);
    "level", `Int port.native.level; "schema", `Int port.schema;
    "actual_origin_chain", `List (List.map (fun id -> `Int (V.SymbolicValueId.to_int id)) port.chain);
    "root", (match port.root with BorrowPayload identity -> `Assoc ["borrow_payload", `Int (V.BorrowId.to_int identity)]
      | ForwardSymbol identity -> `Assoc ["forward_symbol", `Int (V.SymbolicValueId.to_int identity)]);
    "exact_alias_preserving_type_instance", `String (lean_type_instance (List.nth schemas port.schema) port)] in
  `Assoc ["schema", `String "actual-native-candidate-regionful-payload-views/v1";
    "actual_candidate_view_families_replay", `Bool true; "schema_fuel", `Int (fuel witness);
    "public_candidate_parameters", `List (List.map (fun id -> `Int (RegionId.to_int id)) witness.public_parameters);
    "retained_candidate_requirements", `String (show_generic_params projection.candidate.generics);
    "retained_conditional_nominal_requirements", `List (List.map (fun (nominal : P.nominal) -> `Assoc [
      "reference", `String (P.reflect (TAdt nominal.reference));
      "requirements", `String (show_generic_params nominal.inherited_requirements)]) projection.nominals);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "coherent_view_schemas", `List (List.map (fun schema -> `String (lean_schema schema)) branch.schemas);
      "input_ports", `List (List.map (port branch.schemas) branch.inputs); "output_ports", `List (List.map (port branch.schemas) branch.outputs);
      "routes", `List (List.map (fun index -> `Int index) branch.routes)]) witness.branches);
    "unmatched_payload_keys_are_empty", `Bool true;
    "candidate_views_include_conditional_writer_overlay", `Bool true;
    "native_projected_value_region_layout_adapter_proved", `Bool false;
    "original_rust_candidate_heap_loan_relation_proved", `Bool false;
    "parent_default_values_lowered", `Bool false; "complete_native_backward_abi_lowered", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let output = Buffer.create 32768 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.NativeBorrowView";
  line "import qualification.aeneas.cases.NativeBorrowWiring";
  line "/- Actual candidate-regionful payload views; unelaborated/unqualified.";
  line "   Native projection/region/layout, conditional writer and original Rust/heap/loan adequacy remain required. -/";
  line "namespace Auths.Qualification.NativeBorrowView";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.NativeBorrowView";
  line "universe u";
  line ("def publicParameters : List Nat := " ^ B.list (fun id -> B.nat (RegionId.to_int id)) witness.public_parameters);
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.target in
    let schema_name index = name ^ "Schema" ^ B.nat index in
    List.iteri (fun index schema ->
      let name = schema_name index in
      line ("def " ^ name ^ " : Schema := " ^ lean_schema schema);
      line ("theorem " ^ name ^ "_has_scoped_candidate_shape : check publicParameters " ^ B.nat (fuel witness) ^ " " ^ name ^ " = true := by");
      line "  rfl";
      line ("theorem " ^ name ^ "_extract_restore (Atom : Expr → Type u) (value : Data Atom " ^ name ^ ".shape) :");
      line ("    restore " ^ name ^ " value (extract " ^ name ^ " value) = some value :=");
      line "  extract_then_restore_keeps_carrier _ _"
    ) branch.schemas;
    line ("def " ^ name ^ "Schemas : List Schema := " ^ B.list (fun (index, _) -> schema_name index) (List.mapi (fun index schema -> index, schema) branch.schemas));
    List.iteri (fun index port ->
      let instance_name = name ^ "TypeInstance" ^ B.nat index in
      line ("def " ^ instance_name ^ " : TypeInstance := " ^ lean_type_instance (List.nth branch.schemas port.schema) port);
      line ("theorem " ^ instance_name ^ "_preserves_complete_type_and_aliases : checkTypeInstance " ^ instance_name ^ " = true := by");
      line "  rfl"
    ) (branch.inputs @ branch.outputs);
    line ("def " ^ name ^ "Payload (Atom : Expr → Type u) : Expr → Type u := Family " ^ name ^ "Schemas Atom");
    let actual = "Auths.Qualification.NativeBorrowWiring." ^ name in
    line ("def " ^ name ^ "ConcreteBackward (Atom : Expr → Type u)");
    line ("    (inputs : Auths.Support.NativeBorrowWiring.Values (" ^ name ^ "Payload Atom) (" ^ actual ^ ".inputs.map Auths.Support.NativeBorrowWiring.Port.payloadType)) :");
    line ("    Auths.Support.NativeBorrowWiring.Values (" ^ name ^ "Payload Atom) (" ^ actual ^ ".outputs.map Auths.Support.NativeBorrowWiring.Port.payloadType) :=");
    line ("  " ^ actual ^ "Backward (" ^ name ^ "Payload Atom) inputs");
    let names = List.mapi (fun index _ -> "view" ^ B.nat index) branch.inputs in
    let arguments = List.map2 (fun name port -> "(" ^ name ^ " : " ^ schema_name port.schema ^ ".Payload Atom)") names branch.inputs in
    let values = List.fold_right (fun value tail -> ".cons " ^ value ^ " (" ^ tail ^ ")") in
    line ("theorem " ^ name ^ "_routes_actual_candidate_views (Atom : Expr → Type u) " ^ String.concat " " arguments ^ " :");
    line ("    " ^ name ^ "ConcreteBackward Atom (" ^ values names ".nil" ^ ") =");
    line ("      " ^ values (List.map (List.nth names) branch.routes) ".nil" ^ " := by"); line "  rfl"
  ) witness.branches;
  line "end Auths.Qualification.NativeBorrowView";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
