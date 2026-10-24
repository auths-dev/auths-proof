(* Forward value lowering from the actual native symbolic tree. No backward
   expression, native loan event, ordinary result or pure-translation refusal
   is replaced by this component. The independent Lean program consumes the
   actual native input/expansion/borrow identities and reconstructs all fields. *)
open Charon
open Types
module V = Aeneas.Values
module S = Aeneas.SymbolicAst
module P = Borrow_projection

type value = Symbolic of V.symbolic_value_id | MutableBorrow of V.borrow_id * value
  | Record of P.shape * value list | Boxed of value
type step = MutableExpansion of V.symbolic_value_id * V.borrow_id * V.symbolic_value
  | RecordExpansion of V.symbolic_value_id * V.symbolic_value list
  | BoxExpansion of V.symbolic_value_id * V.symbolic_value
type binding = { native : V.symbolic_value; source_type : ty; shape : P.shape }
type t = {
  inputs : V.symbolic_value list;
  source_bindings : binding list;
  region_instantiation : (region_id * region) list;
  steps : step list;
  result : value;
  backward_groups : region_group_id list;
}

let symbolic_id id = V.SymbolicValueId.to_int id
let borrow_id id = V.BorrowId.to_int id

let derive component (projection : P.t) inputs expression =
  if not (P.replay component projection) then
    invalid_arg "native forward lowering requires the complete actual projection witness";
  if List.length inputs <> List.length projection.inputs then
    invalid_arg "native forward inputs differ from the complete actual function arity";
  let declared = List.map (fun (parameter : region_param) -> parameter.index)
    projection.candidate.generics.regions in
  let instantiation = ref [] in
  List.iter2 (fun (root : P.root) (native : V.symbolic_value) ->
    if Region_equations.type_shape root.source_type <> Region_equations.type_shape native.sv_ty then
      invalid_arg "native forward input changed its complete non-region type or dictionary";
    List.iter2 (fun source actual -> match source with
      | RVar (Free id) when List.mem id declared ->
          (match actual with RVar (Free _) | RBody _ -> ()
           | _ -> invalid_arg "native public region instantiation cannot guess erased, bound or static regions");
          (match List.assoc_opt id !instantiation with
           | Some previous when previous <> actual ->
               invalid_arg "one public region has conflicting native instantiations"
           | Some _ -> ()
           | None ->
               if List.exists (fun (_, previous) -> previous = actual) !instantiation then
                 invalid_arg "native region instantiation merged distinct public regions";
               instantiation := !instantiation @ [id, actual])
      | RErased -> invalid_arg "an erased source region is not native input provenance"
      | _ when source = actual -> ()
      | _ -> invalid_arg "native input changed a known static or quantified source region")
      (Region_equations.type_occurrences root.source_type)
      (Region_equations.type_occurrences native.sv_ty)
  ) projection.inputs inputs;
  if List.sort compare (List.map fst !instantiation) <> List.sort compare declared then
    invalid_arg "every public region needs an actual native input instantiation";
  let instantiate source =
    let visitor = object inherit [_] map_ty
      method! visit_region _ = function
        | RVar (Free id) as original ->
            (match List.assoc_opt id !instantiation with Some value -> value | None -> original)
        | original -> original
    end in visitor#visit_ty () source in
  let bindings = ref V.SymbolicValueId.Map.empty in
  let insert source_type shape (native : V.symbolic_value) =
    if native.sv_ty <> instantiate source_type then
      invalid_arg "native symbolic value disagrees with its complete instantiated source type";
    if V.SymbolicValueId.Map.mem native.sv_id !bindings then
      invalid_arg "native forward symbolic identifiers must be fresh";
    bindings := V.SymbolicValueId.Map.add native.sv_id { native; source_type; shape } !bindings in
  List.iter2 (fun (root : P.root) native -> insert root.source_type root.shape native)
    projection.inputs inputs;
  let lookup (native : V.symbolic_value) =
    match V.SymbolicValueId.Map.find_opt native.sv_id !bindings with
    | Some binding when binding.native = native -> binding
    | _ -> invalid_arg "native forward uses an unknown or retyped symbolic value" in
  let expanded = ref V.SymbolicValueId.Set.empty in
  let borrows = ref V.BorrowId.Map.empty in
  let steps = ref [] in
  let record_fields source_type shape =
    match source_type, shape with
    | TAdt ({ id = TAdtId _; _ } as reference), P.Named (P.Nominal actual, fields)
        when actual = reference ->
        let nominal = match List.filter (fun (nominal : P.nominal) -> nominal.reference = reference) projection.nominals with
          | [nominal] -> nominal
          | _ -> invalid_arg "native record expansion lacks its complete instantiated declaration" in
        let types = match nominal.instantiated_kind with
          | Struct fields -> List.map (fun (field : field) -> field.field_ty) fields
          | _ -> invalid_arg "native enum/opaque expansion needs explicit branch lowering" in
        let rec shapes index fields = function
          | [] when fields = P.Unit -> []
          | source_type :: rest ->
              (match fields with
               | P.Product (P.Named (P.Field (actual, _), shape), tail) when actual = index ->
                   (source_type, shape) :: shapes (index + 1) tail rest
               | _ -> invalid_arg "native record expansion cannot reorder or omit fields")
          | [] -> invalid_arg "native record expansion left unexplained fields" in
        shapes 0 fields types
    | _ -> invalid_arg "native record expansion needs the original borrowed nominal representation" in
  let expand (source : V.symbolic_value) expansion =
    let binding = lookup source in
    if V.SymbolicValueId.Set.mem source.sv_id !expanded then
      invalid_arg "native forward expands the same symbolic value more than once";
    expanded := V.SymbolicValueId.Set.add source.sv_id !expanded;
    let instruction = match expansion with
      | V.SeMutRef (identity, contents) ->
          (match binding.source_type, binding.shape with
           | TRef (_, inner, RMut), P.Borrow (RMut, _, shape) ->
               if V.BorrowId.Map.mem identity !borrows then
                 invalid_arg "native mutable borrow names must be fresh";
               borrows := V.BorrowId.Map.add identity binding !borrows;
               insert inner shape contents;
               MutableExpansion (source.sv_id, identity, contents)
           | _ -> invalid_arg "native mutable expansion changed the actual reference kind")
      | V.SeAdt (None, children) ->
          (match binding.source_type, binding.shape, children with
           | TAdt { id = TBuiltin TBox; generics = { types = [inner]; _ } },
               P.Named (P.Boxed, shape), [contents] ->
               insert inner shape contents; BoxExpansion (source.sv_id, contents)
           | _ ->
               let fields = record_fields binding.source_type binding.shape in
               if List.length fields <> List.length children then
                 invalid_arg "native record expansion changed its full field arity";
               List.iter2 (fun (source_type, shape) native -> insert source_type shape native) fields children;
               RecordExpansion (source.sv_id, children))
      | _ -> invalid_arg "this native expansion requires explicit literal/shared/enum branch semantics" in
    steps := !steps @ [instruction] in
  let rec lower expected_type expected_shape (native : V.tvalue) =
    if Aeneas.TypesUtils.ty_erase_regions native.ty <>
        Aeneas.TypesUtils.ty_erase_regions (instantiate expected_type) then
      invalid_arg "native return value changed its complete executable type";
    match native.value with
    | V.VSymbolic symbolic ->
        let binding = lookup symbolic in
        if binding.source_type <> expected_type || binding.shape <> expected_shape then
          invalid_arg "native return symbolic changed its exact source shape";
        Symbolic symbolic.sv_id
    | V.VBorrow (V.VMutBorrow (identity, contents)) ->
        let origin = match V.BorrowId.Map.find_opt identity !borrows with
          | Some origin -> origin
          | None -> invalid_arg "native return contains a mutable borrow with no actual expansion origin" in
        if origin.source_type <> expected_type || origin.shape <> expected_shape then
          invalid_arg "native return borrow changed its original regionful type";
        (match expected_type, expected_shape with
         | TRef (_, inner, RMut), P.Borrow (RMut, _, shape) ->
             MutableBorrow (identity, lower inner shape contents)
         | _ -> invalid_arg "native mutable reconstruction changed the source reference kind")
    | V.VAdt { variant_id = None; fields } ->
        (match expected_type, expected_shape, fields with
         | TAdt { id = TBuiltin TBox; generics = { types = [inner]; _ } }, P.Named (P.Boxed, shape), [contents] ->
             Boxed (lower inner shape contents)
         | _ ->
             let declarations = record_fields expected_type expected_shape in
             if List.length declarations <> List.length fields then
               invalid_arg "native return aggregate omitted or added a source field";
             Record (expected_shape, List.map2 (fun (ty, shape) value -> lower ty shape value) declarations fields))
    | _ -> invalid_arg "native return requires explicit semantics for this value; no opaque value fallback is allowed" in
  let rec finish expression = match expression with
    | S.Meta (_, next) -> finish next
    | S.Return (_, Some value) -> value
    | _ -> invalid_arg "the supported native forward tail must return its actual value without additional effects" in
  let rec walk expression = match expression with
    | S.Meta (_, next) -> walk next
    | S.Expansion (_, source, S.ExpandNoBranch (expansion, next)) -> expand source expansion; walk next
    | S.Expansion (_, source, S.ExpandAdt [None, fields, next]) ->
        expand source (V.SeAdt (None, fields)); walk next
    | S.ForwardEnd (Some (_, stored), _, forward, backward) ->
        let returned = finish forward in
        if stored <> returned then invalid_arg "native delimiter and actual return values disagree";
        let backward_groups = List.map fst (RegionGroupId.Map.bindings backward) in
        if List.sort compare backward_groups <>
            List.sort compare (List.map (fun (group : region_var_group) -> group.id) projection.hierarchy) then
          invalid_arg "native backward branches do not match the complete actual region hierarchy";
        let result = lower projection.output.source_type projection.output.shape returned in
        { inputs; source_bindings = List.map snd (V.SymbolicValueId.Map.bindings !bindings);
          region_instantiation = !instantiation; steps = !steps; result; backward_groups }
    | _ -> invalid_arg "native forward lowering requires explicit handling of every actual effect and branch" in
  walk expression

let replay component projection inputs expression witness =
  try derive component projection inputs expression = witness with Invalid_argument _ | Not_found -> false

let create component projection inputs expression =
  let witness = derive component projection inputs expression in
  if not (replay component projection inputs expression witness) then
    invalid_arg "the actual native forward value lowering did not replay";
  witness

let rec lean_value = function
  | Symbolic identity -> ".symbolic " ^ string_of_int (symbolic_id identity)
  | MutableBorrow (identity, contents) -> ".mutableBorrow " ^ string_of_int (borrow_id identity) ^ " (" ^ lean_value contents ^ ")"
  | Record (shape, fields) -> ".record (" ^ P.lean shape ^ ") [" ^ String.concat ", " (List.map lean_value fields) ^ "]"
  | Boxed contents -> ".boxed (" ^ lean_value contents ^ ")"
let lean_step = function
  | MutableExpansion (source, identity, contents) -> ".mutableBorrow " ^ string_of_int (symbolic_id source) ^ " " ^
      string_of_int (borrow_id identity) ^ " " ^ string_of_int (symbolic_id contents.sv_id)
  | RecordExpansion (source, fields) -> ".record " ^ string_of_int (symbolic_id source) ^ " [" ^
      String.concat ", " (List.map (fun (value : V.symbolic_value) -> string_of_int (symbolic_id value.sv_id)) fields) ^ "]"
  | BoxExpansion (source, contents) -> ".boxed " ^ string_of_int (symbolic_id source) ^ " " ^ string_of_int (symbolic_id contents.sv_id)
let rec fuel = function Symbolic _ -> 1 | MutableBorrow (_, contents) | Boxed contents -> 1 + fuel contents
  | Record (_, fields) -> 1 + List.fold_left (fun n value -> max n (fuel value)) 0 fields

let report component projection inputs expression witness =
  `Assoc ["schema", `String "actual-native-forward-capture-value/v1";
    "actual_native_trace_replays", `Bool (replay component projection inputs expression witness);
    "native_inputs", `List (List.map (fun (value : V.symbolic_value) -> `Assoc [
      "identity", `Int (symbolic_id value.sv_id); "complete_type", `String (show_ty value.sv_ty)]) witness.inputs);
    "complete_candidate_source_bindings", `List (List.map (fun (binding : binding) -> `Assoc [
      "native_identity", `Int (symbolic_id binding.native.sv_id);
      "complete_native_type", `String (P.reflect binding.native.sv_ty);
      "candidate_regionful_type", `String (P.reflect binding.source_type);
      "candidate_shape", `String (P.lean binding.shape)]) witness.source_bindings);
    "region_instantiation", `List (List.map (fun (id, region) -> `Assoc [
      "public_parameter", `Int (RegionId.to_int id); "native_region", `String (show_region region)]) witness.region_instantiation);
    "steps", `List (List.map (fun step -> `String (lean_step step)) witness.steps);
    "result", `String (lean_value witness.result); "value_fuel", `Int (fuel witness.result);
    "retained_native_backward_groups", `List (List.map (fun id -> `Int (RegionGroupId.to_int id)) witness.backward_groups);
    "native_backward_continuations_lowered", `Bool false;
    "native_and_source_heap_loan_layout_adequacy_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "native_pure_program_emitted", `Bool false;
    "lean_elaboration_run", `Bool false; "tests_run", `Bool false; "qualified", `Bool false]

(* Expand only the single-constructor preparation spine. Opaque atoms and
   enum alternatives remain arbitrary data; no source branch is guessed. *)
let rec case_depth = function
  | P.Named (_, inner) | P.Borrow (_, _, inner) -> 1 + case_depth inner
  | P.Product (left, right) -> 1 + case_depth left + case_depth right
  | P.Unit -> 1 | P.Atom _ | P.Empty | P.Sum _ -> 0

let rec emit_cases line indent name = function
  | P.Named (_, contents) ->
      line (indent ^ "cases " ^ name ^ " with");
      line (indent ^ "| named " ^ name ^ "Body =>");
      emit_cases line (indent ^ "    ") (name ^ "Body") contents
  | P.Borrow (_, _, contents) ->
      line (indent ^ "cases " ^ name ^ " with");
      line (indent ^ "| borrow " ^ name ^ "Body =>");
      emit_cases line (indent ^ "    ") (name ^ "Body") contents
  | P.Product (first, second) ->
      line (indent ^ "cases " ^ name ^ " with");
      line (indent ^ "| product " ^ name ^ "First " ^ name ^ "Rest =>");
      emit_cases line (indent ^ "    ") (name ^ "First") first;
      emit_cases line (indent ^ "    " ^ String.make (4 * case_depth first) ' ') (name ^ "Rest") second
  | P.Unit -> line (indent ^ "cases " ^ name ^ " with"); line (indent ^ "| unit =>")
  | P.Atom _ | P.Empty | P.Sum _ -> ()

let emit_input_cases line indent names roots =
  let indent = ref indent in
  List.iter2 (fun name (root : P.root) -> emit_cases line !indent name root.shape;
    indent := !indent ^ String.make (4 * case_depth root.shape) ' ') names roots;
  !indent

let write_lean path (projection : P.t) witness =
  let output = Buffer.create 16384 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.NativeCaptureValue";
  line "import Auths.Support.NativeBorrowDefaults";
  line "import qualification.aeneas.cases.BorrowProjection";
  line "/- Actual native forward value trace; unelaborated/unqualified.";
  line "   Native backward, heap/loan and source-interface adequacy remain required. -/";
  line "namespace Auths.Qualification.NativeCaptureValue";
  line ("open Auths.Qualification.BorrowProjection.Candidate" ^ string_of_int (FunDeclId.to_int projection.candidate.def_id));
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.NativeCaptureValue";
  line "universe u";
  line "def actualProgram : Program := {";
  line ("  inputs := [" ^ String.concat ", " (List.map (fun (value : V.symbolic_value) -> string_of_int (symbolic_id value.sv_id)) witness.inputs) ^ "]");
  line ("  steps := [" ^ String.concat ", " (List.map lean_step witness.steps) ^ "]");
  line ("  result := " ^ lean_value witness.result);
  line ("  valueFuel := " ^ string_of_int (fuel witness.result) ^ " }");
  let names = List.map (fun (root : P.root) -> "input" ^ string_of_int root.index) projection.inputs in
  line ("theorem native_forward_value_matches_source_capture (Atom : Expr → Type u) " ^
    String.concat " " (List.map (fun name -> "(" ^ name ^ " : Data Atom " ^ name ^ "Shape)") names) ^ " :");
  line ("    run actualProgram [" ^ String.concat ", " (List.map (fun name -> "⟨" ^ name ^ "Shape, " ^ name ^ "⟩") names) ^ "] =");
  line ("      some ⟨outputShape, construct Atom " ^ String.concat " " names ^ "⟩ := by");
  let indent = emit_input_cases line "  " names projection.inputs in
  line (indent ^ "rfl");
  let arguments = String.concat " " (List.map (fun name -> "(" ^ name ^ " : Data Atom " ^ name ^ "Shape)") names) in
  let values = "[" ^ String.concat ", " (List.map (fun name -> "⟨" ^ name ^ "Shape, " ^ name ^ "⟩") names) ^ "]" in
  line ("def preparedCurrent (Atom : Expr → Type u) " ^ arguments ^ " : Option (Auths.Support.NativeBorrowDefaults.Current Atom) :=");
  line ("  Auths.Support.NativeBorrowDefaults.prepareCurrent actualProgram " ^ values);
  line ("theorem actual_forward_prepares_current_for_every_input (Atom : Expr → Type u) " ^ arguments ^ " :");
  line ("    ∃ current, preparedCurrent Atom " ^ String.concat " " names ^ " = some current := by");
  line ("  exact Auths.Support.NativeBorrowDefaults.successful_forward_has_prepared_current actualProgram " ^ values ^ " _");
  line ("    (native_forward_value_matches_source_capture Atom " ^ String.concat " " names ^ ")");
  line "end Auths.Qualification.NativeCaptureValue";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
