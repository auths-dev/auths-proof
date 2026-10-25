(* Closed Pure syntax preserving complete native type/generic arguments.
   Unknown effects, open variables, metadata and unsupported patterns refuse. *)
open Charon
module Q = Aeneas.Pure
module T = Native_type_syntax
module B = Native_borrow_protocol
module U = Aeneas.PureUtils

type pattern = BoundPattern of Q.ty * string option | IgnoredPattern of Q.ty
  | ConstructorPattern of Q.ty * Types.variant_id option * pattern list
type term = Bound of Q.ty * int * int | Constructor of Q.ty * Q.ty * Types.variant_id option
  | Application of Q.ty * term * term | Lambda of Q.ty * pattern * term
  | Binding of Q.ty * pattern * term * term | Switch of Q.ty * term * (pattern * term) list

let validate ty =
  let visitor = object inherit [_] Q.iter_ty as super
    method! visit_ty env ty =
      if ty = Q.TError then invalid_arg "a type-error placeholder cannot supply native context reconstruction";
      super#visit_ty env ty
    method! visit_UnknownTrait _ _ = invalid_arg "an unresolved dictionary cannot supply native context reconstruction"
  end in visitor#visit_ty () ty; ignore (T.reflect ty)

let rec reflect_pattern (pattern : Q.tpat) =
  validate pattern.ty;
  match pattern.pat with
  | Q.PBound (variable, None) when variable.ty = pattern.ty -> BoundPattern (pattern.ty, variable.basename)
  | Q.PIgnored -> IgnoredPattern pattern.ty
  | Q.PAdt value -> ConstructorPattern (pattern.ty, value.variant_id, List.map reflect_pattern value.fields)
  | _ -> invalid_arg "native context patterns must retain exact closed binders, ignored fields and constructor positions"
let rec decode_pattern = function
  | BoundPattern (ty, basename) -> Q.{ pat = PBound ({ basename; ty }, None); ty }
  | IgnoredPattern ty -> Q.{ pat = PIgnored; ty }
  | ConstructorPattern (ty, variant_id, fields) -> Q.{ pat = PAdt { variant_id; fields = List.map decode_pattern fields }; ty }
let rec reflect_unchecked (source : Q.texpr) =
  validate source.ty;
  match source.e with
  | Q.BVar variable when variable.scope >= 0 && Q.BVarId.to_int variable.id >= 0 ->
      Bound (source.ty, variable.scope, Q.BVarId.to_int variable.id)
  | Q.Qualif { id = Q.AdtCons id; generics } ->
      let owner = Q.TAdt (id.adt_id, generics) in validate owner;
      Constructor (source.ty, owner, id.variant_id)
  | Q.App (function_, argument) -> Application (source.ty, reflect_unchecked function_, reflect_unchecked argument)
  | Q.Lambda (pattern, body) -> Lambda (source.ty, reflect_pattern pattern, reflect_unchecked body)
  | Q.Let (false, pattern, value, body) -> Binding (source.ty, reflect_pattern pattern, reflect_unchecked value, reflect_unchecked body)
  | Q.Switch (value, Q.Match branches) -> Switch (source.ty, reflect_unchecked value,
      List.map (fun (branch : Q.match_branch) -> reflect_pattern branch.pat, reflect_unchecked branch.branch) branches)
  | _ -> invalid_arg "native context expression contains an unrepresented free variable, call, effect, loop, error or control node"
let rec decode = function
  | Bound (ty, scope, slot) when scope >= 0 && slot >= 0 -> Q.{ e = BVar { scope; id = BVarId.of_int slot }; ty }
  | Constructor (ty, Q.TAdt (adt_id, generics), variant_id) -> Q.{ e = Qualif { id = AdtCons { adt_id; variant_id }; generics }; ty }
  | Application (ty, function_, argument) -> Q.{ e = App (decode function_, decode argument); ty }
  | Lambda (ty, pattern, body) -> Q.{ e = Lambda (decode_pattern pattern, decode body); ty }
  | Binding (ty, pattern, value, body) -> Q.{ e = Let (false, decode_pattern pattern, decode value, decode body); ty }
  | Switch (ty, value, branches) -> Q.{ e = Switch (decode value, Match (List.map (fun (pattern, body) ->
      { pat = decode_pattern pattern; branch = decode body }) branches)); ty }
  | _ -> invalid_arg "a native context constructor or variable lost its exact type or binder identity"
let reflect source =
  let term = reflect_unchecked source in
  if Q.compare_texpr (decode term) source <> 0 then
    invalid_arg "complete native context syntax failed exact original typed-expression reconstruction";
  term
let type_depth ty = T.depth (T.reflect ty)
let rec pattern_depth = function
  | BoundPattern (ty, _) | IgnoredPattern ty -> 1 + type_depth ty
  | ConstructorPattern (ty, _, fields) -> 1 + List.fold_left (fun depth field -> max depth (pattern_depth field)) (type_depth ty) fields
let rec depth = function
  | Bound (ty, _, _) -> 1 + type_depth ty
  | Constructor (ty, owner, _) -> 1 + max (type_depth ty) (type_depth owner)
  | Application (ty, first, second) -> 1 + max (type_depth ty) (max (depth first) (depth second))
  | Lambda (ty, pattern, body) -> 1 + max (type_depth ty) (max (pattern_depth pattern) (depth body))
  | Binding (ty, pattern, value, body) -> 1 + max (type_depth ty) (max (pattern_depth pattern) (max (depth value) (depth body)))
  | Switch (ty, value, branches) -> 1 + List.fold_left (fun size (pattern, body) -> max size (max (pattern_depth pattern) (depth body)))
      (max (type_depth ty) (depth value)) branches
let variant = function None -> "none" | Some value -> "some " ^ B.nat (Types.VariantId.to_int value)
let rec iter_pattern_types visit = function
  | BoundPattern (ty, _) | IgnoredPattern ty -> visit ty
  | ConstructorPattern (ty, _, fields) -> visit ty; List.iter (iter_pattern_types visit) fields
let rec iter_types visit = function
  | Bound (ty, _, _) -> visit ty
  | Constructor (ty, owner, _) -> visit ty; visit owner
  | Application (ty, function_, argument) -> visit ty; iter_types visit function_; iter_types visit argument
  | Lambda (ty, pattern, body) -> visit ty; iter_pattern_types visit pattern; iter_types visit body
  | Binding (ty, pattern, value, body) ->
      visit ty; iter_pattern_types visit pattern; iter_types visit value; iter_types visit body
  | Switch (ty, value, branches) -> visit ty; iter_types visit value;
      List.iter (fun (pattern, body) -> iter_pattern_types visit pattern; iter_types visit body) branches

let rec lean_pattern_with_type print_type = function
  | BoundPattern (ty, name) -> ".bound (" ^ print_type ty ^ ") (" ^ Native_pure_expressions.text name ^ ")"
  | IgnoredPattern ty -> ".ignored (" ^ print_type ty ^ ")"
  | ConstructorPattern (ty, tag, fields) -> ".constructor (" ^ print_type ty ^ ") (" ^ variant tag ^ ") " ^ B.list (lean_pattern_with_type print_type) fields
let rec lean_with_type print_type = function
  | Bound (ty, scope, slot) -> ".bound (" ^ print_type ty ^ ") " ^ B.nat scope ^ " " ^ B.nat slot
  | Constructor (ty, owner, tag) -> ".constructor (" ^ print_type ty ^ ") (" ^ print_type owner ^ ") (" ^ variant tag ^ ")"
  | Application (ty, function_, argument) -> ".application (" ^ print_type ty ^ ") (" ^ lean_with_type print_type function_ ^ ") (" ^ lean_with_type print_type argument ^ ")"
  | Lambda (ty, pattern, body) -> ".lambda (" ^ print_type ty ^ ") (" ^ lean_pattern_with_type print_type pattern ^ ") (" ^ lean_with_type print_type body ^ ")"
  | Binding (ty, pattern, value, body) -> ".binding (" ^ print_type ty ^ ") (" ^ lean_pattern_with_type print_type pattern ^ ") (" ^ lean_with_type print_type value ^ ") (" ^ lean_with_type print_type body ^ ")"
  | Switch (ty, value, branches) -> ".switch (" ^ print_type ty ^ ") (" ^ lean_with_type print_type value ^ ") " ^
      B.list (fun (pattern, body) -> "(" ^ lean_pattern_with_type print_type pattern ^ ", " ^ lean_with_type print_type body ^ ")") branches

let lean_pattern = lean_pattern_with_type T.pure
let lean = lean_with_type T.pure
