import Auths.Support.BorrowProjection

/-!
A reversible field codec parameterized by the complete native type-label family.
All field/variant/nominal identities remain explicit. Borrow and Box wrappers
are transparent at this logical native-value boundary. No value, dictionary,
heap address or permission is synthesized by the codec. Native declaration and
source heap/loan adequacy remain separate requirements. Scripts await final
elaboration.
-/
namespace Auths.Support.NativePayloadCodec
open SourceClosureRegions BorrowProjection
universe u
variable {NativeSort : Type}

inductive Label (NativeSort : Type) where
  | nominal (type : NativeSort)
  | variant (identity : Nat)
  | field (index : Nat) (name : Option (List Nat))
  deriving DecidableEq, Repr

inductive Layout (NativeSort : Type) where
  | atom (type : NativeSort)
  | empty
  | unit
  | product (left right : Layout NativeSort)
  | sum (left right : Layout NativeSort)
  | named (identity : Label NativeSort) (body : Layout NativeSort)
  deriving DecidableEq, Repr

inductive Value {NativeSort : Type} (Atom : NativeSort → Type u) : Layout NativeSort → Type u where
  | atom {sort} (value : Atom sort) : Value Atom (.atom sort)
  | unit : Value Atom .unit
  | product {left right} (first : Value Atom left) (second : Value Atom right) :
      Value Atom (.product left right)
  | left {left right} (value : Value Atom left) : Value Atom (.sum left right)
  | right {left right} (value : Value Atom right) : Value Atom (.sum left right)
  | named {identity body} (value : Value Atom body) : Value Atom (.named identity body)

abbrev AtomTyping (NativeSort : Type) := Expr → Option NativeSort

/-- An unrecognized source atom has no representation and supplies no value. -/
def SourceAtom (typing : AtomTyping NativeSort) (Atom : NativeSort → Type u) (sort : Expr) : Type u :=
  match typing sort with
  | none => PEmpty
  | some type => Atom type

def atomForward {typing : AtomTyping NativeSort} {Atom : NativeSort → Type u} {sort : Expr} {type : NativeSort}
    (known : typing sort = some type) (value : SourceAtom typing Atom sort) : Atom type :=
  cast (by simp only [SourceAtom, known]) value

def atomBackward {typing : AtomTyping NativeSort} {Atom : NativeSort → Type u} {sort : Expr} {type : NativeSort}
    (known : typing sort = some type) (value : Atom type) : SourceAtom typing Atom sort :=
  cast (by simp only [SourceAtom, known]) value

inductive Codec {NativeSort : Type} (typing : AtomTyping NativeSort) : Shape → Layout NativeSort → Type where
  | atom (sort : Expr) (type : NativeSort) (known : typing sort = some type) :
      Codec typing (.atom sort) (.atom type)
  | empty : Codec typing .empty .empty
  | unit : Codec typing .unit .unit
  | product {left right first second} (a : Codec typing left first) (b : Codec typing right second) :
      Codec typing (.product left right) (.product first second)
  | sum {left right first second} (a : Codec typing left first) (b : Codec typing right second) :
      Codec typing (.sum left right) (.sum first second)
  | nominal (source : Expr) (native : NativeSort) {body layout} (contents : Codec typing body layout) :
      Codec typing (.named (.nominal source) body) (.named (.nominal native) layout)
  | variant (identity : Nat) {body layout} (contents : Codec typing body layout) :
      Codec typing (.named (.variant identity) body) (.named (.variant identity) layout)
  | field (index : Nat) (name : Option (List Nat)) {body layout} (contents : Codec typing body layout) :
      Codec typing (.named (.field index name) body) (.named (.field index name) layout)
  | boxed {body layout} (contents : Codec typing body layout) :
      Codec typing (.named .boxed body) layout
  | borrow (mutable : Bool) (region : Region) {body layout} (contents : Codec typing body layout) :
      Codec typing (.borrow mutable region body) layout

def encode {typing : AtomTyping NativeSort} {Atom : NativeSort → Type u} :
    {shape : Shape} → {layout : Layout NativeSort} → Codec typing shape layout →
      Data (SourceAtom typing Atom) shape → Value Atom layout
  | _, _, .atom _ _ known, .atom value => .atom (atomForward known value)
  | _, _, .empty, value => nomatch value
  | _, _, .unit, .unit => .unit
  | _, _, .product a b, .product first second => .product (encode a first) (encode b second)
  | _, _, .sum a _, .left value => .left (encode a value)
  | _, _, .sum _ b, .right value => .right (encode b value)
  | _, _, .nominal _ _ contents, .named value => .named (encode contents value)
  | _, _, .variant _ contents, .named value => .named (encode contents value)
  | _, _, .field _ _ contents, .named value => .named (encode contents value)
  | _, _, .boxed contents, .named value => encode contents value
  | _, _, .borrow _ _ contents, .borrow value => encode contents value

def decode {typing : AtomTyping NativeSort} {Atom : NativeSort → Type u} :
    {shape : Shape} → {layout : Layout NativeSort} → Codec typing shape layout →
      Value Atom layout → Data (SourceAtom typing Atom) shape
  | _, _, .atom _ _ known, .atom value => .atom (atomBackward known value)
  | _, _, .empty, value => nomatch value
  | _, _, .unit, .unit => .unit
  | _, _, .product a b, .product first second => .product (decode a first) (decode b second)
  | _, _, .sum a _, .left value => .left (decode a value)
  | _, _, .sum _ b, .right value => .right (decode b value)
  | _, _, .nominal _ _ contents, .named value => .named (decode contents value)
  | _, _, .variant _ contents, .named value => .named (decode contents value)
  | _, _, .field _ _ contents, .named value => .named (decode contents value)
  | _, _, .boxed contents, value => .named (decode contents value)
  | _, _, .borrow _ _ contents, value => .borrow (decode contents value)

theorem decode_encode {typing : AtomTyping NativeSort} {Atom : NativeSort → Type u} {shape layout}
    (codec : Codec typing shape layout) (value : Data (SourceAtom typing Atom) shape) :
    decode codec (encode codec value) = value := by
  induction codec with
  | atom sort type known => cases value; simp [encode, decode, atomForward, atomBackward]
  | empty => cases value
  | unit => cases value; rfl
  | product a b first second => cases value; simp [encode, decode, first, second]
  | sum a b first second => cases value <;> simp [encode, decode, first, second]
  | nominal source native contents ih => cases value; simp [encode, decode, ih]
  | variant identity contents ih => cases value; simp [encode, decode, ih]
  | field index name contents ih => cases value; simp [encode, decode, ih]
  | boxed contents ih => cases value; simp [encode, decode, ih]
  | borrow mutable region contents ih => cases value; simp [encode, decode, ih]

theorem encode_decode {typing : AtomTyping NativeSort} {Atom : NativeSort → Type u} {shape layout}
    (codec : Codec typing shape layout) (value : Value Atom layout) :
    encode codec (decode codec value) = value := by
  induction codec with
  | atom sort type known => cases value; simp [encode, decode, atomForward, atomBackward]
  | empty => cases value
  | unit => cases value; rfl
  | product a b first second => cases value; simp [encode, decode, first, second]
  | sum a b first second => cases value <;> simp [encode, decode, first, second]
  | nominal source native contents ih => cases value; simp [encode, decode, ih]
  | variant identity contents ih => cases value; simp [encode, decode, ih]
  | field index name contents ih => cases value; simp [encode, decode, ih]
  | boxed contents ih => simp [encode, decode, ih]
  | borrow mutable region contents ih => simp [encode, decode, ih]

theorem missing_atom_has_no_value {typing : AtomTyping NativeSort} {Atom : NativeSort → Type u} {sort : Expr}
    (missing : typing sort = none) (value : SourceAtom typing Atom sort) : False := by
  simp only [SourceAtom, missing] at value
  exact PEmpty.elim value

end Auths.Support.NativePayloadCodec
