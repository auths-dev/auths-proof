(* Authored source-flow regressions; execution is deferred to the final batch.
   These synthetic bodies are not native initializer or borrow qualification. *)
open Charon
open Types
open Expressions
open LlbcAst
open Vtable_initializer

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let location : Meta.loc = { line = 1; col = 0 }
let span : Meta.span = { data = {
  file = { name = Meta.NotReal "source-vtable-initializer-fixture";
    crate_name = "construction_fixture"; contents = None };
  beg_loc = location; end_loc = location }; generated_from_span = None }
let id = LocalId.of_int
let table = { id = TAdtId (TypeDeclId.of_int 7); generics = TypesUtils.empty_generic_args }
let table_ty = TAdt table
let boolean = TLiteral Charon.Values.TBool
let local index ty : local = { index = id index; name = None; span; local_ty = ty }
let place index ty : place = { kind = PlaceLocal (id index); ty }
let ret = place 0 table_ty
let first = place 1 Vtable_shape.usize
let second = place 2 Vtable_shape.usize
let statement index kind : statement = { span; statement_id = StatementId.of_int index;
  kind; comments_before = [] }
let body statements : expr_body = { span; bound_body_regions = 0;
  locals = { arg_count = 0; locals = [local 0 table_ty;
    local 1 Vtable_shape.usize; local 2 Vtable_shape.usize] };
  body = { span; statements = List.mapi statement statements } }
let prefix = [StorageLive (id 0); StorageLive (id 1); StorageLive (id 2);
  Assign (first, NullaryOp (SizeOf, boolean)); Assign (second, NullaryOp (AlignOf, boolean))]
let aggregate operands = Assign (ret, Aggregate (AggregatedAdt (table, None, None), operands))
let complete operands = body (prefix @ [aggregate operands; Return])

let () =
  let source = complete [Move first; Move second] in
  let actual = Vtable_initializer.trace source in
  require "initializer fields must keep their exact source operand order and layout operations"
    (match actual.node with
     | AggregateValue (reference, [first; second]) ->
         reference = table && first.node = LayoutValue (SizeOf, boolean) && second.node = LayoutValue (AlignOf, boolean)
     | _ -> false);
  require "a source layout operation cannot be replaced by a fabricated size/alignment literal"
    (match actual.node with AggregateValue (_, values) ->
      List.for_all (fun (value : Vtable_initializer.value) -> match value.node with LayoutValue _ -> true | _ -> false) values
     | _ -> false);
  require "the same moved source local cannot populate two vtable slots"
    (refuses (fun () -> ignore (Vtable_initializer.trace (complete [Move first; Move first]))));
  require "a dead source local cannot supply a field"
    (refuses (fun () -> ignore (Vtable_initializer.trace
      (body (prefix @ [StorageDead (id 1); aggregate [Copy first; Move second]; Return])))));
  require "source place types cannot be relabelled to match an expected slot"
    (refuses (fun () -> ignore (Vtable_initializer.trace
      (body (prefix @ [aggregate [Move (place 1 boolean); Move second]; Return])))));
  require "an incomplete initializer cannot invent its return aggregate"
    (refuses (fun () -> ignore (Vtable_initializer.trace (body prefix))));
  require "statements following a return cannot be ignored"
    (refuses (fun () -> ignore (Vtable_initializer.trace
      (body (prefix @ [aggregate [Move first; Move second]; Return; StorageDead (id 1)])))));
  let duplicate = { source with body = { source.body with statements =
    (match source.body.statements with
     | first :: second :: rest -> first :: { second with statement_id = first.statement_id } :: rest
     | _ -> source.body.statements) } } in
  require "duplicate statement IDs cannot disguise a different source assignment"
    (refuses (fun () -> ignore (Vtable_initializer.trace duplicate)));
  let opaque = Constant { kind = COpaque "unmodeled source value"; ty = Vtable_shape.usize } in
  let unused = body (prefix @ [StorageLive (id 3);
    Assign (place 3 Vtable_shape.usize, Use (opaque, NoRetag));
    aggregate [Move first; Move second]; Return]) in
  let unused = { unused with locals = { unused.locals with
    locals = unused.locals.locals @ [local 3 Vtable_shape.usize] } } in
  require "even an unused opaque source value must stay an explicit unsupported boundary"
    (refuses (fun () -> ignore (Vtable_initializer.trace unused)));
  let pointer : fn_ptr = { kind = FunId (FRegular (FunDeclId.of_int 12));
    generics = TypesUtils.empty_generic_args } in
  let wrong : value = { ty = boolean; source_statement = None;
    node = ConstantValue { kind = CFnPtr pointer; ty = boolean } } in
  require "an integer/boolean slot cannot be relabelled as a source function pointer"
    (refuses (fun () -> ignore (function_pointer wrong)))
