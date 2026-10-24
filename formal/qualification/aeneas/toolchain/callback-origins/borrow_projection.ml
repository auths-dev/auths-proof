(* Pure projection schemas from complete actual native component types.
   No native guard is removed. In particular, these schemas are not yet the
   SymbolicToPure lowering or a source/loan/continuation refinement. *)
open Charon
open Types
open Expressions
open LlbcAst

type label = Nominal of type_decl_ref | Variant of variant_id
  | Field of int * string option | Boxed
type shape = Atom of ty | Empty | Unit | Product of shape * shape
  | Sum of shape * shape | Named of label * shape | Borrow of ref_kind * region * shape
type nominal = {
  reference : type_decl_ref;
  declaration : type_decl;
  instantiated_kind : type_decl_kind;
  inherited_requirements : generic_params;
}
type root = { index : int; source_type : ty; shape : shape }
type capture = {
  nominal : type_decl_ref;
  aggregate : statement_id;
  returned : statement_id;
  moved_inputs : int list;
  statements : (statement_id * string) list;
}
type t = {
  candidate : fun_decl;
  hierarchy : region_var_groups;
  inputs : root list;
  output : root;
  nominals : nominal list;
  capture : capture;
}

let rec product = function [] -> Unit | first :: rest -> Product (first, product rest)
let rec sum = function [] -> Empty | first :: rest -> Sum (first, sum rest)

let capture_constructor (candidate : fun_decl) inputs (output : root) =
  let body = match candidate.body with StructuredBody body -> body
    | _ -> invalid_arg "a projected capture constructor requires its complete actual body" in
  if body.locals.arg_count <> List.length inputs then
    invalid_arg "a projected constructor cannot change its declared input count";
  ignore (Source_path.unique_ids body.body);
  let captured = ref None and returned = ref None and opened = ref false in
  let ended = ref LocalId.Set.empty in
  let statements = List.map (fun (statement : statement) ->
    if Option.is_some !returned then invalid_arg "a projected constructor cannot continue after returning";
    let syntax = match statement.kind with
      | StorageLive id when LocalId.to_int id = 0 && not !opened && Option.is_none !captured ->
          opened := true; ".storageLive 0"
      | Assign (({ kind = PlaceLocal id; _ } as destination), Aggregate (AggregatedAdt (nominal, None, None), operands))
          when LocalId.to_int id = 0 && !opened && Option.is_none !captured ->
          if Aeneas.TypesUtils.ty_erase_regions (TAdt nominal) <>
              Aeneas.TypesUtils.ty_erase_regions output.source_type ||
              Aeneas.TypesUtils.ty_erase_regions destination.ty <>
              Aeneas.TypesUtils.ty_erase_regions output.source_type then
            invalid_arg "the projected constructor aggregate changed its complete output type";
          let moved_inputs = List.map (function
            | Move ({ kind = PlaceLocal local; _ } as place) when LocalId.to_int local > 0 &&
                LocalId.to_int local <= List.length inputs ->
                let index = LocalId.to_int local - 1 in
                let input = List.nth inputs index in
                let erased = Aeneas.TypesUtils.ty_erase_regions in
                let declared = match List.filter (fun (declaration : local) -> declaration.index = local) body.locals.locals with
                  | [declaration] -> declaration
                  | _ -> invalid_arg "an actual moved source input has ambiguous local declarations" in
                if erased place.ty <> erased input.source_type || erased declared.local_ty <> erased input.source_type then
                  invalid_arg "an actual source move changed its declared complete executable type";
                index
            | _ -> invalid_arg "a projected constructor must move whole declared inputs, never copy/project a value") operands in
          if List.length moved_inputs <> List.length inputs ||
              List.length moved_inputs <> List.length (List.sort_uniq Int.compare moved_inputs) then
            invalid_arg "the projected constructor must consume every original input exactly once";
          captured := Some (nominal, statement.statement_id, moved_inputs);
          let id = match nominal.id with TAdtId id -> TypeDeclId.to_int id
            | _ -> invalid_arg "the projected return cannot substitute a tuple for the original nominal" in
          ".assignClosure (.local 0) " ^ string_of_int id ^ " [" ^
            String.concat ", " (List.map (fun input -> ".move (.local " ^ string_of_int (input + 1) ^ ")") moved_inputs) ^ "]"
      | StorageDead id when Option.is_some !captured && LocalId.to_int id > 0 &&
          LocalId.to_int id <= List.length inputs && not (LocalId.Set.mem id !ended) ->
          ended := LocalId.Set.add id !ended;
          ".storageDead " ^ string_of_int (LocalId.to_int id)
      | Return when Option.is_some !captured -> returned := Some statement.statement_id; ".returnValue"
      | Nop -> ".nop"
      | _ -> invalid_arg "a projected constructor requires an explicit implementation for this source effect"
    in statement.statement_id, syntax) body.body.statements in
  let nominal, aggregate, moved_inputs = match !captured with Some value -> value
    | None -> invalid_arg "the projected source constructor has no aggregate" in
  let returned = match !returned with Some value -> value
    | None -> invalid_arg "the projected source constructor has no return" in
  if LocalId.Set.cardinal !ended <> List.length inputs then
    invalid_arg "the projected source constructor must end every consumed input's original storage";
  let fields = match output.shape with
    | Named (Nominal reference, contents) when
        Aeneas.TypesUtils.ty_erase_regions (TAdt reference) = Aeneas.TypesUtils.ty_erase_regions (TAdt nominal) -> contents
    | _ -> invalid_arg "the projected source return lost its original nominal field structure" in
  let rec require_fields index fields = function
    | [] when fields = Unit -> ()
    | input :: rest ->
        (match fields with
         | Product (Named (Field (field_index, _), field_shape), tail) when field_index = index ->
             let parameter = List.nth inputs input in
             if field_shape <> parameter.shape then
               invalid_arg "an original moved input and projected return field differ in complete regionful shape";
             require_fields (index + 1) tail rest
         | _ -> invalid_arg "the projected constructor reordered or omitted an actual output field")
    | [] -> invalid_arg "the projected constructor left an unexplained return field" in
  require_fields 0 fields moved_inputs;
  { nominal; aggregate; returned; moved_inputs; statements }

let make_expander component ~span ~type_infos ~parameters =
  let scope = new Region_scope.check parameters in
  let nominals = ref [] in
  let rec expand stack source =
    scope#visit_ty [] source;
    (* Opaque values are never a fallback for unresolved lifetime/type forms.
       Borrow-free atoms are existing values carried through unchanged, not
       an ordinary function contract or an invented result. *)
    (match source with
     | TDynTrait _ | TFnPtr _ | TFnDef _ | TError _ | TTraitType _ | TVar _ ->
         invalid_arg "a projection schema cannot hide an unresolved dynamic/function/associated/type-variable value"
     | _ -> ());
    let info = Aeneas.TypesAnalysis.analyze_ty (Some span)
      type_infos source in
    if not info.contains_borrow then (
      ignore (Return_region_certificate.reflect_type ~holes:[] source);
      Atom source)
    else match source with
    | TRef (region, inner, kind) ->
        scope#visit_region [] region;
        Borrow (kind, region, expand stack inner)
    | TAdt ({ id = TBuiltin TBox; generics = { regions = []; types = [inner];
          const_generics = []; trait_refs = [] } }) -> Named (Boxed, expand stack inner)
    | TAdt { id = TTuple; generics = { regions = []; types; const_generics = []; trait_refs = [] } } ->
        product (List.mapi (fun index ty -> Named (Field (index, None), expand stack ty)) types)
    | TAdt ({ id = TAdtId id; _ } as reference) ->
        if List.mem id stack then
          invalid_arg "a recursive borrowed nominal needs an inductive projection datatype, not finite unrolling";
        let declaration = match TypeDeclId.Map.find_opt id component.type_decls with
          | Some declaration -> declaration
          | None -> invalid_arg "an actual borrowed nominal declaration is absent" in
        let substitution = Type_view.source_substitution declaration reference.generics None in
        let substitute = object inherit [_] map_type_decl
          method! visit_ty _ ty = Substitute.ty_substitute substitution ty
        end in
        let instantiated_kind = substitute#visit_type_decl_kind () declaration.kind in
        let inherited_requirements = Substitute.predicates_substitute substitution declaration.generics in
        let witness = { reference; declaration; instantiated_kind; inherited_requirements } in
        if not (List.mem witness !nominals) then nominals := witness :: !nominals;
        let fields values = product (List.mapi (fun index (field : field) ->
          Named (Field (index, field.field_name), expand (id :: stack) field.field_ty)) values) in
        let contents = match instantiated_kind with
          | Struct values -> fields values
          | Enum variants ->
              let ids = List.map (fun (variant : variant) -> VariantId.to_int variant.id) variants in
              if List.exists (fun id -> id < 0) ids ||
                  List.length ids <> List.length (List.sort_uniq Int.compare ids) then
                invalid_arg "an enum projection cannot merge missing or duplicate original variant identities";
              sum (List.map (fun (variant : variant) -> Named (Variant variant.id, fields variant.fields)) variants)
          | Alias _ | Union _ | Opaque | TDeclError _ ->
              invalid_arg "a borrowed alias/union/opaque/error nominal needs its complete representation semantics" in
        (* The original full nominal argument tree is retained and round-trips
           through the structural reflector, including dictionary arguments. *)
        ignore (Return_region_certificate.reflect_type ~holes:[] source);
        Named (Nominal reference, contents)
    | _ -> invalid_arg "this borrowed source container needs an explicit projection shape" in
  (fun source -> expand [] source), (fun () -> List.rev !nominals)

let derive component (candidate : fun_decl) =
  if FunDeclId.Map.find_opt candidate.def_id component.fun_decls <> Some candidate then
    invalid_arg "borrow projection requires the complete actual component declaration";
  if candidate.generics.types <> [] || candidate.generics.const_generics <> [] then
    invalid_arg "this projection constructor requires fully instantiated type/constant parameters";
  let scope = new Region_scope.check candidate.generics.regions in
  scope#visit_fun_sig [] candidate.signature;
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then
    invalid_arg "native projection type context contains unresolved errors";
  let hierarchy = Aeneas.RegionsHierarchy.compute_regions_hierarchy_for_sig
    (Some candidate.item_meta.span) component {
      item_binder_params = candidate.generics; item_binder_value = candidate.signature } in
  let groups = List.map (fun (group : region_var_group) -> RegionGroupId.to_int group.id) hierarchy in
  let regions = List.concat_map (fun (group : region_var_group) -> group.regions) hierarchy
    |> List.map RegionId.to_int in
  let declared = List.map (fun (parameter : region_param) -> RegionId.to_int parameter.index) candidate.generics.regions in
  if List.exists (fun id -> id < 0) groups ||
      List.length groups <> List.length (List.sort_uniq Int.compare groups) ||
      List.sort Int.compare regions <> List.sort_uniq Int.compare declared then
    invalid_arg "native projection hierarchy must partition all actual declared regions exactly once";
  List.iter (fun (group : region_var_group) ->
    if group.regions = [] || List.mem group.id group.parents ||
        List.exists (fun id -> not (List.mem (RegionGroupId.to_int id) groups)) group.parents then
      invalid_arg "native projection hierarchy has an empty or unbound/self-parent group") hierarchy;
  let expand, nominal_witnesses = make_expander component ~span:candidate.item_meta.span
    ~type_infos:context.type_ctx.type_infos ~parameters:candidate.generics.regions in
  let inputs = List.mapi (fun index source_type ->
    { index; source_type; shape = expand source_type }) candidate.signature.inputs in
  let output = { index = 0; source_type = candidate.signature.output;
    shape = expand candidate.signature.output } in
  (match output.source_type with
   | TAdt { id = TAdtId id; _ } ->
       (match (TypeDeclId.Map.find id component.type_decls).src with
        | ClosureItem _ -> ()
        | _ -> invalid_arg "a capture projection cannot reclassify an ordinary nominal as a source closure")
   | _ -> invalid_arg "the actual projected closure return must retain its nominal source identity");
  let capture = capture_constructor candidate inputs output in
  { candidate; hierarchy; inputs; output; nominals = nominal_witnesses (); capture }

let replay component witness =
  try derive component witness.candidate = witness with Invalid_argument _ | Not_found -> false

let create component candidate =
  let witness = derive component candidate in
  if not (replay component witness) then invalid_arg "the complete actual projection schema did not replay";
  witness

let reflect ty = Return_region_certificate.reflect_type ~holes:[] ty |> Return_region_certificate.lean
let naturals values = "[" ^ String.concat ", " (List.map string_of_int values) ^ "]"
let field_name = function None -> "none" | Some text ->
  "some " ^ naturals (List.init (String.length text) (fun index -> Char.code text.[index]))
let label = function
  | Nominal reference -> ".nominal (" ^ reflect (TAdt reference) ^ ")"
  | Variant id -> ".variant " ^ string_of_int (VariantId.to_int id)
  | Field (index, name) -> ".field " ^ string_of_int index ^ " (" ^ field_name name ^ ")"
  | Boxed -> ".boxed"
let rec lean = function
  | Atom ty -> ".atom (" ^ reflect ty ^ ")"
  | Empty -> ".empty" | Unit -> ".unit"
  | Product (first, second) -> ".product (" ^ lean first ^ ") (" ^ lean second ^ ")"
  | Sum (first, second) -> ".sum (" ^ lean first ^ ") (" ^ lean second ^ ")"
  | Named (identity, body) -> ".named (" ^ label identity ^ ") (" ^ lean body ^ ")"
  | Borrow (kind, region, body) ->
      ".borrow " ^ (match kind with RMut -> "true" | RShared -> "false") ^ " (" ^
      Return_region_certificate.lean_region region ^ ") (" ^ lean body ^ ")"

let report component witness =
  `Assoc ["schema", `String "actual-native-borrow-projection-shapes/v1";
    "candidate", `Int (FunDeclId.to_int witness.candidate.def_id);
    "candidate_signature", `String (show_fun_sig witness.candidate.signature);
    "complete_shape_replays", `Bool (replay component witness);
    "checked_capture_constructor", `Assoc [
      "source_aggregate", `Int (StatementId.to_int witness.capture.aggregate);
      "source_return", `Int (StatementId.to_int witness.capture.returned);
      "moved_inputs", `List (List.map (fun input -> `Int input) witness.capture.moved_inputs);
      "complete_regionful_field_input_shapes_equal", `Bool true;
      "source_syntax", `List (List.map (fun (id, instruction) -> `Assoc [
        "statement", `Int (StatementId.to_int id); "instruction", `String instruction]) witness.capture.statements)];
    "region_hierarchy", `List (List.map (fun (group : region_var_group) -> `Assoc [
      "id", `Int (RegionGroupId.to_int group.id);
      "regions", `List (List.map (fun id -> `Int (RegionId.to_int id)) group.regions);
      "parents", `List (List.map (fun id -> `Int (RegionGroupId.to_int id)) group.parents)]) witness.hierarchy);
    "inputs", `List (List.map (fun (root : root) -> `Assoc ["index", `Int root.index;
      "original_type", `String (show_ty root.source_type); "pure_projection_shape", `String (lean root.shape)]) witness.inputs);
    "output", `Assoc ["original_type", `String (show_ty witness.output.source_type);
      "pure_projection_shape", `String (lean witness.output.shape)];
    "expanded_nominals", `List (List.map (fun (nominal : nominal) -> `Assoc [
      "reference", `String (show_type_decl_ref nominal.reference);
      "native_component_declared_kind", `String (show_type_decl_kind nominal.declaration.kind);
      "instantiated_kind", `String (show_type_decl_kind nominal.instantiated_kind);
      "retained_native_component_requirements", `String (show_generic_params nominal.inherited_requirements);
      "source_and_native_wellformedness_loan_layout_relation_proved", `Bool false]) witness.nominals);
    "symbolic_to_projection_value_and_continuation_refinement_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "native_pure_component_constructed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false;
    "whole_program_emitted", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let output = Buffer.create 16384 in
  let line text = Buffer.add_string output (text ^ "\n") in
  line "import Auths.Support.BorrowProjection";
  line "import Auths.Support.SourceClosureSyntax";
  line "/- Actual native component shape expansion; unelaborated/unqualified.";
  line "   Source/native loans, projection lowering and continuation refinement remain required. -/";
  line "namespace Auths.Qualification.BorrowProjection";
  line ("namespace Candidate" ^ string_of_int (FunDeclId.to_int witness.candidate.def_id));
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection";
  line "universe u";
  line ("def candidateFunction : Nat := " ^ string_of_int (FunDeclId.to_int witness.candidate.def_id));
  List.iter (fun (group : region_var_group) ->
    line ("def regions" ^ string_of_int (RegionGroupId.to_int group.id) ^ " : List Region := [" ^
      String.concat ", " (List.map (fun id -> ".parameter " ^ string_of_int (RegionId.to_int id)) group.regions) ^ "]");
    line ("def parents" ^ string_of_int (RegionGroupId.to_int group.id) ^ " : List Nat := " ^
      naturals (List.map RegionGroupId.to_int group.parents))) witness.hierarchy;
  let root prefix root =
    line ("def " ^ prefix ^ "Type : Expr := " ^ reflect root.source_type);
    line ("def " ^ prefix ^ "Shape : Shape := " ^ lean root.shape);
    List.iter (fun (group : region_var_group) ->
      let suffix = string_of_int (RegionGroupId.to_int group.id) in
      line ("def " ^ prefix ^ "Plan" ^ suffix ^ " : Plan " ^ prefix ^ "Shape := select regions" ^ suffix ^ " " ^ prefix ^ "Shape");
      line ("theorem " ^ prefix ^ "_round_trip_" ^ suffix ^ " (Atom : Expr → Type u)");
      line ("    (value : Data Atom " ^ prefix ^ "Shape) :");
      line ("    put " ^ prefix ^ "Plan" ^ suffix ^ " value (get " ^ prefix ^ "Plan" ^ suffix ^ " value) = some value :=");
      line "  get_then_put _ _"
    ) witness.hierarchy in
  List.iter (fun (input : root) -> root ("input" ^ string_of_int input.index) input) witness.inputs;
  root "output" witness.output;
  let input_names = List.map (fun (input : root) -> "input" ^ string_of_int input.index) witness.inputs in
  let names = String.concat " " input_names in
  let arguments = String.concat " " (List.map (fun name -> "(" ^ name ^ " : Data Atom " ^ name ^ "Shape)") input_names) in
  let nominal = match witness.capture.nominal.id with TAdtId id -> TypeDeclId.to_int id
    | _ -> invalid_arg "a pure capture constructor requires its actual nominal" in
  let field_values = List.fold_right (fun input tail ->
    ".product (.named " ^ List.nth input_names input ^ ") (" ^ tail ^ ")") witness.capture.moved_inputs ".unit" in
  line ("def sourceSyntax : List Auths.Support.SourceClosureSyntax.Statement := [" ^
    String.concat ", " (List.map (fun (id, instruction) -> "⟨" ^ string_of_int (StatementId.to_int id) ^ ", " ^ instruction ^ "⟩") witness.capture.statements) ^ "]");
  line ("def construct (Atom : Expr → Type u) " ^ arguments ^ " : Data Atom outputShape :=");
  line ("  .named (" ^ field_values ^ ")");
  let datum input = "(⟨input" ^ string_of_int input ^ "Shape, input" ^ string_of_int input ^ "⟩ : Datum Atom)" in
  let input_list = "[" ^ String.concat ", " (List.map (fun (input : root) -> datum input.index) witness.inputs) ^ "]" in
  line ("theorem constructed_fields_match_actual_source_moves (Atom : Expr → Type u) " ^ arguments ^ " :");
  line ("    capturedFields (construct Atom " ^ names ^ ") =");
  line ("      (Auths.Support.SourceClosureSyntax.sourceResult sourceSyntax " ^ input_list ^ ").bind");
  line ("        (Auths.Support.SourceClosureSyntax.observedFields " ^ string_of_int nominal ^ ") := by");
  line "  rfl";
  List.iter (fun (group : region_var_group) ->
    let suffix = string_of_int (RegionGroupId.to_int group.id) in
    let parameters = String.concat " " (List.map (fun name ->
      "(" ^ name ^ " : View Atom " ^ name ^ "Plan" ^ suffix ^ ")") input_names) in
    let fields = List.fold_right (fun input tail ->
      "(" ^ List.nth input_names input ^ ", " ^ tail ^ ")") witness.capture.moved_inputs "PUnit.unit" in
    line ("def constructView" ^ suffix ^ " (Atom : Expr → Type u) " ^ parameters ^ " : View Atom outputPlan" ^ suffix ^ " :=");
    line ("  " ^ fields);
    line ("theorem constructor_commutes_with_region_view_" ^ suffix ^ " (Atom : Expr → Type u) " ^ arguments ^ " :");
    line ("    get outputPlan" ^ suffix ^ " (construct Atom " ^ names ^ ") =");
    line ("      constructView" ^ suffix ^ " Atom " ^ String.concat " " (List.map (fun name -> "(get " ^ name ^ "Plan" ^ suffix ^ " " ^ name ^ ")") input_names) ^ " := by");
    line "  rfl";
    let tuple_type projection = List.fold_right (fun name tail ->
      "(" ^ projection name ^ " × " ^ tail ^ ")") input_names "PUnit" in
    let tuple values = List.fold_right (fun value tail -> "(" ^ value ^ ", " ^ tail ^ ")") values "PUnit.unit" in
    let nth value index = value ^ String.concat "" (List.init index (fun _ -> ".2")) ^ ".1" in
    let positions = List.mapi (fun position input -> input, position) witness.capture.moved_inputs in
    let restored_views = List.mapi (fun input _ -> nth "value" (List.assoc input positions)) input_names in
    line ("def unpackView" ^ suffix ^ " (Atom : Expr → Type u) (value : View Atom outputPlan" ^ suffix ^ ") :");
    line ("    " ^ tuple_type (fun name -> "View Atom " ^ name ^ "Plan" ^ suffix) ^ " :=");
    line ("  " ^ tuple restored_views);
    line ("theorem unpack_constructed_view_" ^ suffix ^ " (Atom : Expr → Type u) " ^ parameters ^ " :");
    line ("    unpackView" ^ suffix ^ " Atom (constructView" ^ suffix ^ " Atom " ^ names ^ ") = " ^ tuple input_names ^ " := by");
    line "  rfl";
    line ("theorem reconstruct_unpacked_view_" ^ suffix ^ " (Atom : Expr → Type u)");
    line ("    (value : View Atom outputPlan" ^ suffix ^ ") :");
    line ("    constructView" ^ suffix ^ " Atom " ^ String.concat " " (List.mapi (fun input _ ->
      "(" ^ nth ("(unpackView" ^ suffix ^ " Atom value)") input ^ ")") input_names) ^ " = value := by");
    let fields = List.mapi (fun field _ -> "field" ^ string_of_int field) witness.capture.moved_inputs in
    line ("  rcases value with ⟨" ^ String.concat ", " (fields @ ["tail"]) ^ "⟩");
    line "  cases tail";
    line "  rfl";
    line ("def restoreInputs" ^ suffix ^ " (Atom : Expr → Type u) " ^ arguments);
    line ("    (update : View Atom outputPlan" ^ suffix ^ ") : Option " ^ tuple_type (fun name -> "Data Atom " ^ name ^ "Shape") ^ " := do");
    line ("  let views := unpackView" ^ suffix ^ " Atom update");
    List.iteri (fun input name -> line ("  let " ^ name ^ " ← put " ^ name ^ "Plan" ^ suffix ^ " " ^ name ^ " " ^ nth "views" input)) input_names;
    line ("  pure " ^ tuple input_names);
    line ("theorem restoring_original_capture_view_keeps_inputs_" ^ suffix ^ " (Atom : Expr → Type u) " ^ arguments ^ " :");
    line ("    restoreInputs" ^ suffix ^ " Atom " ^ names ^ " (get outputPlan" ^ suffix ^ " (construct Atom " ^ names ^ ")) =");
    line ("      some " ^ tuple input_names ^ " := by");
    line ("  simp [restoreInputs" ^ suffix ^ ", constructor_commutes_with_region_view_" ^ suffix ^ ",");
    line ("    unpack_constructed_view_" ^ suffix ^ ", get_then_put]");
    line ("theorem restoring_capture_view_is_exact_" ^ suffix ^ " (Atom : Expr → Type u) " ^ arguments);
    line ("    (update : View Atom outputPlan" ^ suffix ^ ")");
    line ("    (after : " ^ tuple_type (fun name -> "Data Atom " ^ name ^ "Shape") ^ ")");
    line ("    (accepted : restoreInputs" ^ suffix ^ " Atom " ^ names ^ " update = some after) :");
    line ("    get outputPlan" ^ suffix ^ " (construct Atom " ^ String.concat " " (List.mapi
      (fun input _ -> "(" ^ nth "after" input ^ ")") input_names) ^ ") = update := by");
    let rec split_results index indent equations next_values =
      if index = List.length input_names then (
        line (indent ^ "have same : " ^ tuple next_values ^ " = after := by");
        line (indent ^ "  simpa [restoreInputs" ^ suffix ^ ", " ^ String.concat ", " equations ^ "] using accepted");
        line (indent ^ "subst after");
        line (indent ^ "rw [constructor_commutes_with_region_view_" ^ suffix ^ "]");
        List.iteri (fun input name ->
          line (indent ^ "have inputExact" ^ string_of_int input ^ " := put_then_get " ^ name ^ "Plan" ^ suffix ^ " " ^ name ^
            " " ^ List.nth next_values input ^ " (" ^ nth ("(unpackView" ^ suffix ^ " Atom update)") input ^ ") " ^ List.nth equations input)
        ) input_names;
        line (indent ^ "rw [" ^ String.concat ", " (List.mapi (fun input _ -> "inputExact" ^ string_of_int input) input_names) ^ "]");
        line (indent ^ "exact reconstruct_unpacked_view_" ^ suffix ^ " Atom update")
      ) else (
        let name = List.nth input_names index in
        let equation = "inputResult" ^ string_of_int index in
        let next = "nextInput" ^ string_of_int index in
        line (indent ^ "cases " ^ equation ^ " : put " ^ name ^ "Plan" ^ suffix ^ " " ^ name ^ " " ^
          nth ("(unpackView" ^ suffix ^ " Atom update)") index ^ " with");
        line (indent ^ "| none => simp [restoreInputs" ^ suffix ^ ", " ^ String.concat ", " (equations @ [equation]) ^ "] at accepted");
        line (indent ^ "| some " ^ next ^ " =>");
        split_results (index + 1) (indent ^ "    ") (equations @ [equation]) (next_values @ [next])
      ) in
    split_results 0 "  " [] []
  ) witness.hierarchy;
  line ("end Candidate" ^ string_of_int (FunDeclId.to_int witness.candidate.def_id));
  line "end Auths.Qualification.BorrowProjection";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
