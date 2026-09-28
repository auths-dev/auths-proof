import qualification.aeneas.generated.connections.Funs

open Aeneas Aeneas.Std Result

namespace qualification.aeneas.cases

open auths_connections

-- A state change keeps the credential generation; a rotation sets both.
example :
    kernel.state_change { generation := 3#u64, credential_generation := 1#u64 } =
      ok (some { generation := 4#u64, credential_generation := 1#u64 }) := by
  rfl

example :
    kernel.rotation { generation := 3#u64, credential_generation := 1#u64 } =
      ok (some { generation := 4#u64, credential_generation := 4#u64 }) := by
  rfl

-- The last generation never wraps.
example : kernel.next_generation 18446744073709551615#u64 = ok none := by rfl

end qualification.aeneas.cases
