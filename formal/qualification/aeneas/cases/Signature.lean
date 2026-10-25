import Auths.Crypto.NativeExamples
import Auths.Crypto.Strict.Examples
import Auths.Crypto.Encoding.Examples

-- The actual public Ed25519 wrapper and its guards are proved with explicit
-- foreign primitive parameters. Mock witnesses check call binding only;
-- published authentic tuples are checked by native cross-language evidence.
