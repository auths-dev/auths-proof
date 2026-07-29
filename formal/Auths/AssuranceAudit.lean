import Auths
import Lean.Elab.Command
import Lean.PrettyPrinter
import Lean.Util.CollectAxioms

open Lean Lean.Elab Lean.Elab.Command

private def declarationKind : ConstantInfo → String
  | .thmInfo _ => "theorem"
  | .axiomInfo _ => "axiom"
  | .opaqueInfo _ => "opaque"
  | .defnInfo _ => "definition"
  | .quotInfo _ => "quotient"
  | .inductInfo _ => "inductive"
  | .ctorInfo _ => "constructor"
  | .recInfo _ => "recursor"

private def declarationName (shortName : String) : Name :=
  Name.str `Auths shortName

run_cmd do
  let environment ← getEnv
  let mut declarations : Array Json := #[]
  for shortName in Auths.theoremInventory do
    let name := declarationName shortName
    let some info := environment.find? name
      | throwError "assurance inventory names missing declaration '{name}'"
    let statementFormat ← liftTermElabM <| Meta.ppExpr info.type
    let axioms ← collectAxioms name
    declarations := declarations.push <| Json.mkObj [
      ("name", name.toString),
      ("kind", declarationKind info),
      ("statement", statementFormat.pretty 120),
      ("axioms", Json.arr <| axioms.qsort Name.lt |>.map (toJson ·.toString))
    ]
  IO.println <| (Json.mkObj [
    ("schema", "auths-proof-lean-assurance-audit/v1"),
    ("declarations", Json.arr declarations)
  ]).compress
