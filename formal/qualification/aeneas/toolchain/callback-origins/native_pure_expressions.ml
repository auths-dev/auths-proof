(* Real pinned Pure expressions for complete field-value adapter helpers.
   Every closed syntax node round-trips; unknown syntax/metadata refuses.
   These helpers do not replace the original component or its pinned guards. *)
open Charon
open Types
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module P = Native_pure_payload
module D = Native_borrow_defaults
module C = Native_borrow_view
module T = Native_borrow_transport

type mask = Keep | Skip | Empty | Product of mask * mask | Sum of mask * mask | Named of mask
let rec erase_plan codec plan = match plan, codec with
  | D.Keep, _ -> Keep | D.Skip, _ -> Skip
  | D.Empty, P.CEmpty -> Empty
  | D.Product (left, right), P.CProduct (first, second) -> Product (erase_plan first left, erase_plan second right)
  | D.Sum (left, right), P.CSum (first, second) -> Sum (erase_plan first left, erase_plan second right)
  | D.Named body, (P.CNominal (_, _, contents) | P.CVariant (_, contents) | P.CField (_, _, contents)) -> Named (erase_plan contents body)
  | D.Named body, P.CBoxed contents | D.Borrow body, P.CBorrow (_, _, contents) -> erase_plan contents body
  | _ -> invalid_arg "a native expression cannot erase ownership of an unaccounted source field"

let selection (endpoint : P.endpoint) =
  let selected = match endpoint.access.producer.selected with C.Whole -> C.Whole
    | C.Regions regions -> C.Regions (List.map (T.rename_region endpoint.access.mapping) regions) in
  erase_plan endpoint.codec (D.selection_plan endpoint.access.native_shape selected)

type constructor = Nominal of int | Tuple | Result | Error
type pattern = BoundPattern of Q.ty * string option | ConstructorPattern of Q.ty * variant_id option * pattern list
type term = Bound of Q.ty * int * int | Constructor of Q.ty * constructor * variant_id option * Q.ty list
  | Application of Q.ty * term * term | Lambda of Q.ty * pattern * term
  | Switch of Q.ty * term * (pattern * term) list | Binding of Q.ty * pattern * term * term

let constructor = function Q.TAdtId id -> Nominal (TypeDeclId.to_int id)
  | Q.TTuple -> Tuple | Q.TBuiltin Q.TResult -> Result | Q.TBuiltin Q.TError -> Error
  | _ -> invalid_arg "native expression reflection needs an explicit constructor identity"
let native_constructor = function Nominal id when id >= 0 -> Q.TAdtId (TypeDeclId.of_int id)
  | Tuple -> Q.TTuple | Result -> Q.TBuiltin Q.TResult | Error -> Q.TBuiltin Q.TError
  | _ -> invalid_arg "native constructor identities cannot be negative"

let rec reflect_pattern (source : Q.tpat) =
  ignore (P.reflect source.ty);
  match source.pat with
  | Q.PBound (variable, None) when variable.ty = source.ty -> BoundPattern (source.ty, variable.basename)
  | Q.PAdt value -> ConstructorPattern (source.ty, value.variant_id, List.map reflect_pattern value.fields)
  | _ -> invalid_arg "native patterns cannot omit an open/ignored/constant/place-bearing binder"
let rec decode_pattern = function
  | BoundPattern (ty, basename) -> Q.{ pat = PBound ({ basename; ty }, None); ty }
  | ConstructorPattern (ty, variant_id, fields) -> Q.{ pat = PAdt { variant_id; fields = List.map decode_pattern fields }; ty }

let rec reflect_unchecked (source : Q.texpr) =
  ignore (P.reflect source.ty);
  match source.e with
  | Q.BVar value when value.scope >= 0 && Q.BVarId.to_int value.id >= 0 -> Bound (source.ty, value.scope, Q.BVarId.to_int value.id)
  | Q.Qualif { id = Q.AdtCons id; generics } ->
      if generics.const_generics <> [] || generics.trait_refs <> [] then
        invalid_arg "native constructor reflection cannot omit constant/dictionary arguments";
      List.iter (fun ty -> ignore (P.reflect ty)) generics.types;
      Constructor (source.ty, constructor id.adt_id, id.variant_id, generics.types)
  | Q.App (function_, argument) -> Application (source.ty, reflect_unchecked function_, reflect_unchecked argument)
  | Q.Lambda (pattern, body) -> Lambda (source.ty, reflect_pattern pattern, reflect_unchecked body)
  | Q.Let (false, pattern, value, body) -> Binding (source.ty, reflect_pattern pattern, reflect_unchecked value, reflect_unchecked body)
  | Q.Switch (scrutinee, Q.Match branches) -> Switch (source.ty, reflect_unchecked scrutinee,
      List.map (fun (branch : Q.match_branch) -> reflect_pattern branch.pat, reflect_unchecked branch.branch) branches)
  | _ -> invalid_arg "a native helper contains an unrepresented free variable, call, effect, error, loop, metadata or control node"

let rec decode = function
  | Bound (ty, scope, slot) when scope >= 0 && slot >= 0 -> Q.{ e = BVar { scope; id = BVarId.of_int slot }; ty }
  | Constructor (ty, id, variant_id, types) -> Q.{ e = Qualif { id = AdtCons { adt_id = native_constructor id; variant_id };
      generics = { U.empty_generic_args with types } }; ty }
  | Application (ty, function_, argument) -> Q.{ e = App (decode function_, decode argument); ty }
  | Lambda (ty, pattern, body) -> Q.{ e = Lambda (decode_pattern pattern, decode body); ty }
  | Binding (ty, pattern, value, body) -> Q.{ e = Let (false, decode_pattern pattern, decode value, decode body); ty }
  | Switch (ty, scrutinee, branches) -> Q.{ e = Switch (decode scrutinee, Match (List.map (fun (pattern, body) ->
      { pat = decode_pattern pattern; branch = decode body }) branches)); ty }
  | _ -> invalid_arg "native reflected variables must retain nonnegative exact binder positions"

let reflect source =
  let term = reflect_unchecked source in
  if Q.compare_texpr (decode term) source <> 0 then
    invalid_arg "native helper syntax reflection failed to reconstruct the entire original typed Pure expression";
  term

let rec depth = function
  | Bound _ | Constructor _ -> 1
  | Application (_, left, right) -> 1 + max (depth left) (depth right)
  | Lambda (_, _, body) -> 1 + depth body
  | Binding (_, _, value, body) -> 1 + max (depth value) (depth body)
  | Switch (_, scrutinee, branches) -> 1 + List.fold_left (fun n (_, body) -> max n (depth body)) (depth scrutinee) branches

type row = { variant : int; fields : (Q.ty * bool) list }
type strategy = Incoming | Current | Enumeration of row list
let strategy layout mask = match mask with Keep -> Incoming | Skip -> Current | _ ->
  let rec fields index layout mask = match layout, mask with
    | P.Unit, (Skip | Keep) -> []
    | P.Product (P.Named (P.NativeField (actual, _), P.Atom ty), rest), Product (Named selected, tail) when index = actual ->
        let owned = match selected with Keep -> true | Skip -> false
          | _ -> invalid_arg "a partially selected native field needs its own expression compiler" in
        (ty, owned) :: fields (index + 1) rest tail
    | _ -> invalid_arg "native adapter fields must retain every actual atomic field and ordered tail" in
  let rec rows = function
    | P.Empty, Empty -> []
    | P.Sum (P.Named (P.NativeVariant variant, body), rest), Sum (Named selected, tail) ->
        { variant; fields = fields 0 body selected } :: rows (rest, tail)
    | _ -> invalid_arg "native enum expression compilation cannot invent or omit an actual variant" in
  match layout, mask with
  | P.Named (P.NativeNominal _, body), Named selected -> Enumeration (rows (body, selected))
  | _ -> invalid_arg "this partial native payload needs an explicit complete expression compiler"

let compile_body span native_type strategy fresh current incoming =
  let variable = U.mk_texpr_from_fvar in
  let success value = U.mk_result_ok_texpr span value in
  let failure () = U.mk_result_fail_texpr_with_error_id span Q.error_failure_id native_type in
  let switch scrutinee branches : Q.texpr = { e = Q.Switch (scrutinee, Q.Match branches); ty = U.mk_result_ty native_type } in
  match strategy with
    | Incoming -> success (variable incoming)
    | Current -> success (variable current)
    | Enumeration rows ->
        switch (variable current) (List.map (fun current_row ->
          let current_fields = List.map (fun (ty, _) -> fresh ty) current_row.fields in
          let current_pattern = U.mk_adt_pat native_type (Some (VariantId.of_int current_row.variant))
            (List.map (U.mk_tpat_from_fvar None) current_fields) in
          let inner = switch (variable incoming) (List.map (fun incoming_row ->
            let incoming_fields = List.map (fun (ty, _) -> fresh ty) incoming_row.fields in
            let pattern = U.mk_adt_pat native_type (Some (VariantId.of_int incoming_row.variant))
              (List.map (U.mk_tpat_from_fvar None) incoming_fields) in
            let body = if current_row.variant <> incoming_row.variant then failure () else (
              if List.map fst current_row.fields <> List.map fst incoming_row.fields then
                invalid_arg "matching native enum rows disagree on complete field types";
              let values = List.mapi (fun index (_, owned) ->
                variable (List.nth (if owned then incoming_fields else current_fields) index)) current_row.fields in
              success (U.mk_adt_texpr span native_type (Some (VariantId.of_int current_row.variant)) values)) in
            U.close_branch span pattern body) rows) in
          U.close_branch span current_pattern inner) rows)

let compile span native_type strategy =
  let next = ref 0 in
  let fresh ty =
    if !next = Int.max_int then invalid_arg "native helper variables exceed the identifier space";
    let variable : Q.fvar = { id = Q.FVarId.of_int !next; basename = None; ty } in
    incr next; variable in
  let current = fresh native_type and incoming = fresh native_type in
  let body = compile_body span native_type strategy fresh current incoming in
  let arguments = match strategy with Incoming -> [incoming] | Current | Enumeration _ -> [current; incoming] in
  let term = U.mk_closed_lambdas span (List.map (U.mk_tpat_from_fvar None) arguments) body in
  if term.ty <> U.mk_arrows (List.map (fun (variable : Q.fvar) -> variable.ty) arguments) (U.mk_result_ty native_type) then
    invalid_arg "the complete native helper changed its current/input/output interface";
  term

type helper = { group : region_group_id; index : int; source : P.channel; mask : mask;
  strategy : strategy; native : Q.texpr; reflected : term; fuel : int }
type t = { payload : P.t; helpers : helper list }

let derive component projection inputs expression forward protocol wiring defaults execution full_abi (payload : P.t) =
  if not (P.replay component projection inputs expression forward protocol wiring defaults execution full_abi payload) then
    invalid_arg "native helpers need every complete actual type/field/codec witness";
  let helpers = List.concat_map (fun (branch : P.branch) -> List.mapi (fun index (source : P.channel) ->
    let mask = selection source.incoming in
    if selection source.outgoing <> mask then
      invalid_arg "the native incoming/outgoing channel has different actual field ownership";
    let strategy = strategy source.incoming.layout mask in
    if (match strategy with Incoming -> true | Current | Enumeration _ -> false) <> source.source.whole then
      invalid_arg "native helper current arguments disagree with actual whole-pointee ownership";
    let native = compile projection.Borrow_projection.candidate.item_meta.span source.incoming.native_type strategy in
    let reflected = reflect native in
    let fuel = 32 + 4 * depth reflected in
    { group = branch.target; index; source; mask; strategy; native; reflected; fuel }) branch.channels) payload.branches in
  { payload; helpers }

let replay component projection inputs expression forward protocol wiring defaults execution full_abi payload witness =
  try derive component projection inputs expression forward protocol wiring defaults execution full_abi payload = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring defaults execution full_abi payload =
  let witness = derive component projection inputs expression forward protocol wiring defaults execution full_abi payload in
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi payload witness) then
    invalid_arg "the actual closed native helper AST did not replay";
  witness

let optional number = function None -> "none" | Some value -> "some " ^ string_of_int (number value)
let text = function None -> "none" | Some value -> "some " ^ Return_region_certificate.numbers (List.init (String.length value) (fun i -> Char.code value.[i]))
let rec lean_pattern = function
  | BoundPattern (ty, name) -> ".bound (" ^ P.pure ty ^ ") (" ^ text name ^ ")"
  | ConstructorPattern (ty, variant, fields) -> ".constructor (" ^ P.pure ty ^ ") (" ^ optional VariantId.to_int variant ^ ") [" ^ String.concat ", " (List.map lean_pattern fields) ^ "]"
let lean_constructor = function Nominal id -> ".nominal " ^ string_of_int id | Tuple -> ".tuple" | Result -> ".result" | Error -> ".error"
let rec lean_term = function
  | Bound (ty, scope, slot) -> ".bound (" ^ P.pure ty ^ ") " ^ string_of_int scope ^ " " ^ string_of_int slot
  | Constructor (ty, id, variant, arguments) -> ".constructor (" ^ P.pure ty ^ ") (" ^ lean_constructor id ^ ") (" ^ optional VariantId.to_int variant ^ ") [" ^ String.concat ", " (List.map P.pure arguments) ^ "]"
  | Application (ty, function_, argument) -> ".application (" ^ P.pure ty ^ ") (" ^ lean_term function_ ^ ") (" ^ lean_term argument ^ ")"
  | Lambda (ty, pattern, body) -> ".lambda (" ^ P.pure ty ^ ") (" ^ lean_pattern pattern ^ ") (" ^ lean_term body ^ ")"
  | Binding (ty, pattern, value, body) -> ".binding (" ^ P.pure ty ^ ") (" ^ lean_pattern pattern ^ ") (" ^ lean_term value ^ ") (" ^ lean_term body ^ ")"
  | Switch (ty, scrutinee, branches) -> ".switch (" ^ P.pure ty ^ ") (" ^ lean_term scrutinee ^ ") [" ^
      String.concat ", " (List.map (fun (pattern, body) -> "(" ^ lean_pattern pattern ^ ", " ^ lean_term body ^ ")") branches) ^ "]"

let report component projection inputs expression forward protocol wiring defaults execution full_abi payload witness =
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi payload witness) then
    invalid_arg "native helper report lost the exact actual source/type/ownership/expression witness";
  `Assoc ["schema", `String "actual-native-pure-field-adapter-expressions/v1";
    "closed_native_helper_terms", `List (List.map (fun helper -> `Assoc [
      "group", `Int (RegionGroupId.to_int helper.group); "channel", `Int helper.index;
      "symbol", `Int (Aeneas.Values.SymbolicValueId.to_int helper.source.incoming.access.port.value.sv_id);
      "level", `Int helper.source.incoming.access.port.level;
      "current_argument_required", `Bool (match helper.strategy with Incoming -> false | _ -> true);
      "current_origin", `String (D.lean_origin helper.source.outgoing.access.producer.origin);
      "native_type", `String (Q.show_ty helper.native.ty);
      "complete_native_expression", `String (Q.show_texpr helper.native);
      "complete_reflected_expression", `String (lean_term helper.reflected);
      "interpreter_fuel", `Int helper.fuel;
      "native_ast_roundtrip_reconstructs_all_supported_nodes", `Bool true]) witness.helpers);
    "represented_result_failure_is_internal_interpreter_failure", `Bool false;
    "helpers_replace_original_backward_functions", `Bool false;
    "current_environment_default_and_continuation_adequacy_proved", `Bool false;
    "original_source_heap_loan_and_ownership_adequacy_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "native_complete_program_emitted", `Bool false; "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let buffer = Buffer.create 32768 in
  let line text = Buffer.add_string buffer (text ^ "\n") in
  line "import Auths.Support.NativePureExpressions";
  line "import qualification.aeneas.cases.NativePurePayload";
  line "/- Actual closed native Pure helper expressions. Unelaborated/unqualified.";
  line "   These helpers do not replace the original functions or prove current/default/loan adequacy. -/";
  line "namespace Auths.Qualification.NativePureExpressions";
  line "open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions";
  line "universe u";
  line ("def builtins : Builtins := { resultOk := " ^ string_of_int (VariantId.to_int Q.result_ok_id) ^
    ", resultFail := " ^ string_of_int (VariantId.to_int Q.result_fail_id) ^
    ", errorFailure := " ^ string_of_int (VariantId.to_int Q.error_failure_id) ^
    ", errorOutOfFuel := " ^ string_of_int (VariantId.to_int Q.error_out_of_fuel_id) ^ " }");
  line "theorem actual_builtin_tags_are_distinct : builtins.resultOk ≠ builtins.resultFail ∧ builtins.errorFailure ≠ builtins.errorOutOfFuel := by decide";
  let schemas = List.sort_uniq (fun (left : P.schema) right -> Q.compare_ty left.native_type right.native_type) witness.payload.schemas in
  line "def schemas : List Schema := [";
  List.iteri (fun index (schema : P.schema) ->
    let rows = match schema.native_kind with Q.Enum variants -> List.mapi (fun index (variant : Q.variant) -> Some (VariantId.of_int index), variant.fields) variants
      | Q.Struct fields -> [None, fields] | Q.Opaque -> invalid_arg "native helper schemas cannot be opaque" in
    line ("  { type := " ^ P.pure schema.native_type ^ ", variants := [" ^ String.concat ", " (List.map (fun (variant, fields) ->
      "(" ^ optional VariantId.to_int variant ^ ", [" ^ String.concat ", " (List.map (fun (field : Q.field) -> P.pure field.field_ty) fields) ^ "])") rows) ^ "] }" ^
      (if index + 1 = List.length schemas then "" else ","))) schemas;
  line "]";
  let fresh = ref 0 in
  let variable () = let name = "v" ^ string_of_int !fresh in incr fresh; name in
  let rec cases indent name layout finish =
    let add text = line (String.make indent ' ' ^ text) in
    match layout with
    | P.Empty -> add ("cases " ^ name)
    | P.Atom _ -> let value = variable () in add ("cases " ^ name ^ " with"); add ("| atom " ^ value ^ " =>"); finish (indent + 2)
    | P.Unit -> add ("cases " ^ name ^ " with"); add "| unit =>"; finish (indent + 2)
    | P.Named (_, body) -> let value = variable () in add ("cases " ^ name ^ " with"); add ("| named " ^ value ^ " =>"); cases (indent + 2) value body finish
    | P.Product (left, right) -> let first = variable () and second = variable () in
        add ("cases " ^ name ^ " with"); add ("| product " ^ first ^ " " ^ second ^ " =>");
        cases (indent + 2) first left (fun indent -> cases indent second right finish)
    | P.Sum (left, right) -> let first = variable () and second = variable () in
        add ("cases " ^ name ^ " with"); add ("| left " ^ first ^ " =>"); cases (indent + 2) first left finish;
        add ("| right " ^ second ^ " =>"); cases (indent + 2) second right finish in
  List.iter (fun helper ->
    let name = "branch" ^ string_of_int (RegionGroupId.to_int helper.group) ^ "Channel" ^ string_of_int helper.index in
    let source = "Auths.Qualification.NativePurePayload." ^ name in
    line ("def " ^ name ^ " : Term := " ^ lean_term helper.reflected);
    line ("def " ^ name ^ "Fuel : Nat := " ^ string_of_int helper.fuel);
    line ("theorem " ^ name ^ "_well_typed : check builtins schemas " ^ name ^ "Fuel [] " ^ name ^ " = true := by decide");
    let rec escaped = function
      | Lambda (ty, pattern, body) -> Lambda (ty, pattern, escaped body)
      | body -> let ty = match body with Bound (ty, _, _) | Constructor (ty, _, _, _) | Application (ty, _, _) | Switch (ty, _, _) | Binding (ty, _, _, _) -> ty
          | Lambda _ -> assert false in Bound (ty, 999, 0) in
    line ("def " ^ name ^ "Escaped : Term := " ^ lean_term (escaped helper.reflected));
    line ("theorem " ^ name ^ "_escaped_scope_refused : check builtins schemas " ^ name ^ "Fuel [] " ^ name ^ "Escaped = false := by decide");
    let rec missing = function
      | Lambda (ty, pattern, body) -> Option.map (fun body -> Lambda (ty, pattern, body)) (missing body)
      | Switch (ty, scrutinee, _ :: rest) -> Some (Switch (ty, scrutinee, rest))
      | _ -> None in
    Option.iter (fun missing ->
      line ("def " ^ name ^ "MissingVariant : Term := " ^ lean_term missing);
      line ("theorem " ^ name ^ "_missing_variant_refused : check builtins schemas " ^ name ^ "Fuel [] " ^ name ^ "MissingVariant = false := by decide")
    ) (missing helper.reflected);
    line ("theorem " ^ name ^ "_evaluates_as_selected_adapter (Atom : Ty → Type u)");
    line ("    (current incoming : Value Atom " ^ source ^ "Layout) :");
    line ("    execute builtins schemas " ^ name ^ "Fuel " ^ name ^ " current incoming =");
    line ("      expected builtins " ^ name ^ "Fuel (" ^ P.pure helper.source.outgoing.native_type ^ ") (" ^ source ^ "Native Atom current incoming) := by");
    line ("  rw [checked_runs_body builtins schemas " ^ name ^ "Fuel " ^ name ^ " " ^ name ^ "_well_typed]");
    cases 2 "current" helper.source.outgoing.layout (fun indent ->
      cases indent "incoming" helper.source.incoming.layout (fun indent -> line (String.make indent ' ' ^ "rfl")))
  ) witness.helpers;
  line "end Auths.Qualification.NativePureExpressions";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
