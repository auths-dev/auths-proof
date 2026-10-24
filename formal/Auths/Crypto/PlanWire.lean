import Auths.Crypto.UnsignedWire

namespace Auths.Crypto.PlanWire

/- Independent tree syntax and canonical bytes. The grammar keeps every
child, its position and multiplicity. It contains no source encoder, parser,
validation result, registry callback or hash. Threshold validity and deployment
node/depth/branching limits are separate from serialization. -/
inductive Plan where
  | proof (reference : List Nat)
  | allOf (members : List Plan)
  | anyOf (members : List Plan)
  | kOfN (required : Nat) (members : List Plan)

mutual
  def encode (plan : Plan) : List Nat :=
    match plan with
    | .proof reference => UnsignedWire.map [(0, UnsignedWire.uint 0), (1, UnsignedWire.bytes reference)]
    | .allOf members => UnsignedWire.map [(0, UnsignedWire.uint 1), (1, UnsignedWire.array (encodeChildren members))]
    | .anyOf members => UnsignedWire.map [(0, UnsignedWire.uint 2), (1, UnsignedWire.array (encodeChildren members))]
    | .kOfN required members => UnsignedWire.map [(0, UnsignedWire.uint 3),
        (1, UnsignedWire.uint required), (2, UnsignedWire.array (encodeChildren members))]
  termination_by sizeOf plan

  def encodeChildren (members : List Plan) : List (List Nat) :=
    match members with
    | [] => []
    | first :: rest => encode first :: encodeChildren rest
  termination_by sizeOf members
end

mutual
  def cost (plan : Plan) : Nat :=
    match plan with
    | .proof reference => 45 + reference.length
    | .allOf members => 45 + childrenCost members
    | .anyOf members => 45 + childrenCost members
    | .kOfN _ members => 63 + childrenCost members
  termination_by sizeOf plan

  def childrenCost (members : List Plan) : Nat :=
    match members with
    | [] => 0
    | first :: rest => cost first + childrenCost rest
  termination_by sizeOf members
end

theorem children_count (members : List Plan) : (encodeChildren members).length = members.length := by
  induction members with
  | nil => rfl
  | cons first rest ih => simpa only [encodeChildren, List.length_cons] using congrArg Nat.succ ih

mutual
  theorem encode_length (plan : Plan) : (encode plan).length ≤ cost plan := by
    cases plan with
    | proof reference =>
      have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 0), (1, UnsignedWire.bytes reference)]
      have tag := UnsignedWire.uint_length 0
      have payload := UnsignedWire.bytes_length reference
      simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
      simp only [encode, cost]
      omega
    | allOf members =>
      have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 1), (1, UnsignedWire.array (encodeChildren members))]
      have tag := UnsignedWire.uint_length 1
      have array := UnsignedWire.array_length (encodeChildren members)
      have contents := children_lengths members
      simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
      simp only [encode, cost]
      omega
    | anyOf members =>
      have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 2), (1, UnsignedWire.array (encodeChildren members))]
      have tag := UnsignedWire.uint_length 2
      have array := UnsignedWire.array_length (encodeChildren members)
      have contents := children_lengths members
      simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
      simp only [encode, cost]
      omega
    | kOfN required members =>
      have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 3),
        (1, UnsignedWire.uint required), (2, UnsignedWire.array (encodeChildren members))]
      have tag := UnsignedWire.uint_length 3
      have threshold := UnsignedWire.uint_length required
      have array := UnsignedWire.array_length (encodeChildren members)
      have contents := children_lengths members
      simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
      simp only [encode, cost]
      omega
  termination_by sizeOf plan

  theorem children_lengths (members : List Plan) :
      ((encodeChildren members).map List.length).sum ≤ childrenCost members := by
    cases members with
    | nil => simp [encodeChildren, childrenCost]
    | cons first rest =>
      have head := encode_length first
      have tail := children_lengths rest
      simp only [encodeChildren, childrenCost, List.map_cons, List.sum_cons]
      omega
  termination_by sizeOf members
end

theorem children_flatten_length (members : List Plan) :
    (encodeChildren members).flatten.length ≤ childrenCost members := by
  simpa only [List.length_flatten] using children_lengths members

end Auths.Crypto.PlanWire
