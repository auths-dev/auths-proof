/- Resolve repository source imports with the pinned Lean parser and search
path in one process. This is the same parser/resolver used by `lean --src-deps`.
The Rust caller independently checks ownership, uniqueness and the entry root.
No proof, theorem statement, axiom or compiled module is created here. -/
import Lean.Elab.Import
open Lean System

def isOwned (root path : FilePath) : Bool :=
  root.components.isPrefixOf path.components &&
    !(root / ".lake").components.isPrefixOf path.components &&
    path.extension == some "lean"

partial def collectSources (root : FilePath) (search : Lean.SearchPath)
    (pending : List FilePath) (visited : Std.TreeSet String) : IO (Std.TreeSet String) := do
  match pending with
  | [] => pure visited
  | path :: pending =>
    let path ← IO.FS.realPath path
    if visited.contains path.toString then
      collectSources root search pending visited
    else
      let text ← IO.FS.readFile path
      let (imports, _, messages) ← Lean.Elab.parseImports text (some path.toString)
      if messages.hasErrors then
        throw (IO.userError s!"invalid Lean header: {path}")
      let mut pending := pending
      for item in imports do
        let resolved ← IO.FS.realPath (← Lean.findLean search item.module)
        if isOwned root resolved then pending := resolved :: pending
      collectSources root search pending (visited.insert path.toString)

def main (args : List String) : IO Unit := do
  unless args.length == 2 do throw (IO.userError "expected formal root and entry source")
  let root ← IO.FS.realPath args[0]!
  let entry ← IO.FS.realPath args[1]!
  unless isOwned root entry do throw (IO.userError "entry is outside formal root")
  let sources ← collectSources root (← Lean.getSrcSearchPath) [entry] {}
  IO.println (toJson sources.toList).compress
