(* Lexical prefix at a source point within a particular loop iteration. This
   is deliberately separate from Source_path's normal dominance interface.
   Entering a loop adds a required loop-head value invariant; it does not claim
   the first-entry parameter value survives any preceding iteration. Original
   branch conditions, calls, exits and loop statements remain untouched. *)
open Charon
open LlbcAst

type step = Source of Source_path.step | Iteration of statement

let rec falls_through (block : block) = List.for_all (fun (statement : statement) -> match statement.kind with
  | Return | Abort _ | UnwindResume | Break _ | Continue _ -> false
  | Switch switch -> let _, targets = Source_path.branches switch in List.exists falls_through targets
  | _ -> true) block.statements

let before (body : block) target =
  ignore (Source_path.unique_ids body);
  ignore (Prepared_injection.unique_statement body target);
  let rec continuation (statement : statement) = match statement.kind with
    | Return | Abort _ | UnwindResume | Break _ | Continue _ -> raise Source_path.Not_dominating
    | Switch switch ->
        let selector, targets = Source_path.branches switch in
        let continuing = List.mapi (fun index source -> index, source) targets |> List.filter (fun (_, source) -> falls_through source) in
        (match continuing with
         | [] -> raise Source_path.Not_dominating
         | [index, source] -> Source (Source_path.Branch { statement; index; selector }) :: List.concat_map continuation source.statements
         | _ -> [Source (Source_path.Execute statement)])
    | _ -> [Source (Source_path.Execute statement)]
  and path (block : block) =
    let rec statements prefix = function
      | [] -> invalid_arg "the exact iteration source point is absent from its lexical block"
      | statement :: _ when statement.statement_id = target -> List.rev prefix
      | statement :: rest ->
          let nested = match statement.kind with
            | Switch switch -> let _, targets = Source_path.branches switch in List.exists (fun source -> Source_path.contains source target) targets
            | Loop source -> Source_path.contains source target
            | _ -> false in
          if nested then (
            match statement.kind with
            | Loop source -> List.rev prefix @ (Iteration statement :: path source)
            | Switch switch ->
                let selector, targets = Source_path.branches switch in
                let matching = List.mapi (fun index source -> index, source) targets |> List.filter (fun (_, source) -> Source_path.contains source target) in
                (match matching with [index, source] -> List.rev prefix @ (Source (Source_path.Branch { statement; index; selector }) :: path source)
                 | _ -> invalid_arg "the actual iteration point has ambiguous source branch membership")
            | _ -> invalid_arg "the actual iteration path lost its original control structure"
          ) else (
            let hidden = ref false in
            let scan = object inherit [_] iter_statement as super
              method! visit_statement env statement = if statement.statement_id = target then hidden := true; super#visit_statement env statement
            end in scan#visit_statement () statement;
            if !hidden then invalid_arg "a source value point in an unwind/other control structure needs its actual exit semantics";
            statements (List.rev_append (continuation statement) prefix) rest)
    in statements [] block.statements in
  path body

let loops steps = List.filter_map (function Iteration statement -> Some statement | _ -> None) steps

let report steps = `List (List.map (function
  | Source source -> `Assoc ["source_step", Source_path.report [source]]
  | Iteration statement -> `Assoc ["kind", `String "original_loop_iteration";
      "source_statement", `Int (StatementId.to_int statement.statement_id);
      "loop_head_value_provenance_and_native_invariant_proved", `Bool false]) steps)
