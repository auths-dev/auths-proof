# Recipe canonical JSON boundary

Status: source-inspected specification work, 23 October 2026. New mathematical
models and native cases remain unelaborated, unqualified and unrun. This is
not actual canonicalizer/derive adequacy or a completed AP-SPEC-069 gate.

The shipping CanonicalRecipeInputs::from_decoded uses
serde_json_canonicalizer 0.3.2 on the complete typed RecipeSource and separately
on lock.command_schema. The lock metadata is not a fictitious whole-lock
serialization input. Actual Auths Serialize derives must stay transparent in
the selected full public extraction.

## Distinct data and formatting stages

FullJsonValue and RecipeSerdeSource retain complete decoded/native data and
typed serialization inputs BEFORE numeric formatting. They preserve integer
values and float bits; they are not proofs that distinct inputs have distinct
canonical bytes. Generic JSON Number carriers and serialize_i64 event inputs
also need not use the same positive-integer representation.

Pinned src/jcs.rs casts every signed/unsigned integer formatter input to f64,
then writes the ryu-js finite representation. Large integer inputs can round
to the same binary64 value. Positive and negative float zero print as the same
canonical zero. Non-finite floats fail. Neither exact integer decimal printing
nor raw float-bit identity is a valid whole-library model.

JcsIntegerRounding now specifies integer rounding on the native i64/u64 input
domains using 53-bit precision and ties to an even significand. Its total
arithmetic functions do not specify native floating overflow for larger input
domains. The result is the exact integral value of the rounded binary64 number,
not necessarily the integer denoted by its shortest printed decimal string.
Actual native cast/bit and ryu-js adequacy remain required.

RecipeLiteralRounding connects the existing safe literal range to this model,
including nested JSON in form bodies. It covers source integer literals only.
It does not cover every recipe counter, command-schema annotation, floating
input, decimal formatter or verified argument substituted for a field reference.
Those remain separate obligations; no global canonical-injectivity claim is
introduced.

The authored native source case distinguishes typed integers 2^53 and 2^53+1,
checks that actual canonicalization aliases them, then requires the public
compiler to refuse both through its existing unsafe-literal rule. Canonical
inputs are computed before source validation, so the claim is refusal before
successful compilation, not refusal before canonicalization. Additional unrun
native cases specify signed-zero normalization and escaped property sorting.

## Keys, strings and object buffering

JsonProperty::new reparses the serialized key to recover its decoded String,
then compares its encode_utf16 vector. It retains the serialized key bytes for
output. Sorting serialized escape spellings or using the body compiler's
scalar/UTF-8 key order would describe a different algorithm. The U+E000 versus
U+10000 native case and the newline/quote/backslash key case separate these
orders.

String fragments retain UTF-8. Quote, reverse solidus and controls use the
formatter's prescribed escapes; solidus is unescaped; remaining control bytes
use lowercase hexadecimal. This formatting still needs complete original
String/escape provenance, including parser refusal of invalid UTF-8/surrogates.

Objects are buffered and inserted into a BTreeSet keyed by decoded UTF-16 names.
Repeated names do not create a second property. The proof must therefore earn
uniqueness of EVERY serialized object from strict input preflight, actual map
construction and the complete fixed Auths field/tag declarations. A library
set insertion cannot silently stand in for that proof. Nested object and value
buffers, complete writer state/error behavior and byte/resource bounds must
also be preserved.

## Evidence still required

The §13.168 authored admission consequences connect the existing shipping
counter/probe/scalar-schema safe ranges to mathematical integer conversion.
Complete closed schema key sets account for every original numeric occurrence,
including enum/field children, and lift that safety back to the full original
JSON value. Floats cannot be made safe integers by the schema view; unknown
annotations are refused. The source inspection found existing restrictions
and introduced no new production policy. Actual native cast/ryu/decimal bytes,
all recipe-serialization numeric occurrences and authenticated argument
projection/rendering remain separate obligations.

Native safe-endpoint/unsafe-alias/float/closed-key cases are authored but unrun.
Canonical inputs precede source validation; refusal applies before successful
compilation, not before a canonicalization attempt. These new mathematical
and model statements remain unelaborated and unqualified and do not establish
global canonical injectivity or a whole-canonicalizer claim.

The §13.167 reference retains the full pinned 256-byte ESCAPE table and gives
closed dispatch into formatter escapes. Authored finite statements check
every slot and handled code; initializer/checksum binding to the actual
reviewed native source is still required. Escape triggers are ASCII and
cannot split a non-ASCII UTF-8 scalar. Concrete begin-string/fragment/escape/
end-string reference schedules now earn full quoted bytes and the property
producer consumes them. Fragment merge/chunk statements retain complete
original bytes, without claiming arbitrary raw fragments are admitted string
content. Actual native span partition and transparent serde/Serialize event
correspondence remain open.

Native whole-string-versus-collect_str fragmentation cases cover controls,
Unicode, empty runs and original outer Vec prefixes. They are unrun; all
new statements are unelaborated and unqualified. Numeric/ryu, complete child
serialization, native set/reader/String/Vec/formatter adequacy, physical
resources and canonical source/schema/hash provenance remain required.

The §13.166 authored roundtrip statements connect every Unicode UTF-8 scalar
and complete canonical string escaping to the concrete key reader, including
arbitrary following bytes and all controls. The complete document reader earns
the original name from its quoted bytes; property construction therefore
earns its sorting key without a supplied parsed-name or success premise.
String quoting is injective, separately from the non-injective numeric
formatting boundary. Complete named object schedules restore parent frames,
retain original property columns for unique names and are invariant under
permuted unique property events. These remain unelaborated model results.

The schedules use complete quoted key/child bytes as primitive writes; actual
serde fragment/escape/number dispatch and transparent Auths Serialize traces
still have to earn them. Native reader/String/set/Vec/formatter adequacy,
numeric/ryu/source/schema/hash bytes, physical resources and real useful
native/compiler witnesses remain open. The new append/Unicode/payload/prefix
native cases remain unrun. No whole-canonicalizer or release claim is earned.

The §13.165 reference adds concrete UTF-8/hex/escape readers and a complete
quoted-string document reader for key reparsing. Successful results retain
an exact consumed prefix/suffix and strict original-byte progress; only JSON
whitespace may surround a key. Invalid UTF-8, overlong encodings, surrogate
scalars/incorrect escape pairs and out-of-range values are refused. Char
construction requires validity. The property constructor derives its key
from those original bytes, preserving complete serialized key/value buffers.
No parsed-name callback or parser-success flag supplies the result.

The new formatter reference owns the actual object/key/value stacks and
routes bytes to their original parent buffer or outer Vec. End-value errors
preserve completed pops in source order, and successful property schedules
restore parent frames. Array/string/escape/null/Boolean mechanics, nested empty
objects, raw-fragment refusal and finite event composition are authored.
This is not yet actual formatter/key/serde adequacy, quoted-string roundtrip,
numeric/ryu dispatch, arbitrary io::Write partial-error behavior or physical
resource evidence. Native malformed-event and key-language cases are unrun;
all new lemmas are unelaborated and unqualified.

The §13.164 JcsObjectBuffer reference now retains every actual property data
column and models duplicate-key insertion as retaining the first property.
Unique decoded names earn fresh insertions, complete property permutation,
count and sorted/permutation-invariant output, including payload bytes.
JcsObjectBytes emits complete braces/commas/colons/key/value buffers and has
authored compositional byte/length bounds. These are unelaborated model
derivations, not BTreeSet tree/iteration adequacy, full nested writer state,
key reparsing, child serialization, numeric formatting, actual I/O or aggregate
resource proofs. No whole-canonicalizer claim is introduced.

The added test-only ordered Serialize map can emit repeated names without
first collapsing them in a Value map. Its native cases specify actual first
property retention and strict raw duplicate refusal; unique event permutations
must retain complete nested child bytes and exact outer framing. All cases
remain unrun. The actual Auths source serializer still has to earn the unique
serialization relation before these unique-input properties can be consumed.

The §13.162 JcsUtf16Keys mathematical reference now describes full UTF-16
keys and an independent inverse that rejects isolated/incorrect surrogates
and out-of-range units. Authored roundtrip lemmas earn String injectivity and
transfer original-name uniqueness to sorting-key uniqueness. Original names
and payloads are retained in the projection. These do not yet prove actual
key reparsing, Rust encode_utf16, BTreeSet insertion or original serialized
object uniqueness. Full Unicode names are retained without normalization.

The §13.163 reference derivations now earn serialized-object uniqueness from
the same full original decoded source/lock meaning. They preserve uniqueness
through field/default/positional/internal-content handling, actual native field
columns, body/header/probe maps and all fixed source serde declarations. The
existence statements construct recursively unique source/schema values without
a supplied serialization-uniqueness premise. Every object's original unique
names then transfer to distinct sorting keys. This is authored, unelaborated
model work: actual strict/serde/Serialize construction and native key/set/writer
adequacy remain required. The earlier statement about missing original
serialized uniqueness refers to actual implementation evidence, not a missing
independent propagation rule.

JcsStringEncoding now describes all exact string escapes and Unicode UTF-8
bytes. Authored lemmas bound bytes and a quoted string's output by six times
its original UTF-8 byte length plus two. This is not a whole-source or aggregate
allocation/time bound. Native scalar-reference/property and boundary tests
for these operations are authored but unrun; the new mathematical lemmas are
unelaborated and unqualified. Actual serde dispatch and writer/key parsing
correspondence remain required.

Source inspection uses Cargo.lock and the pinned canonicalizer src/jcs.rs,
src/util.rs, serde_json serializer, serde 1.0.229 derives and ryu-js 1.0.3 dependency.
Final qualification must bind their exact reviewed source/checksums. No
generator, compiler, solver, native test or audit ran for this work.

The remaining chain is actual bytes → complete strict traversal/EOF → native
decoded fields → transparent Auths Serialize calls → full canonical writer and
numeric/key behavior → exact bytes consumed by the actual domain-separated
hash. Source limits alone do not establish canonical output length or aggregate
allocation/time; positional/tag aliases can expand when serialized as objects.
Real library/compiler useful witnesses, two clean reproductions and all
AP-SPEC-069 §13.5/§10 and E1–E5/M6 gates remain mandatory.

The §13.169 written independent numeric chain now extends from complete
original source-rule success to every numeric occurrence in the full typed
source serialization. Complete original body maps/arrays/form children,
paths, reads, statuses, retention, relative ceilings and probe literals are
retained. Original decoded provenance constructs unique full serialization
before its admission-derived safety/rounding consequences; no serialization
or safe-number flag is a caller premise. The full original command schema
has the corresponding constructed-value statement. This replaces the earlier
missing independent whole-source numeric propagation step, while actual
native Serialize/cast/ryu/decimal/byte/hash adequacy remains open.

The same §13.169 chain is also consumed by actual native constructor and
decoded-compiler success consequences. Those calls earn the schema/source
rule admission; full decoded provenance earns the original body and numeric
representation domains. These partial roots require no separate rule success
or safe-number record. They do not establish actual source-byte decoding,
Serialize/JCS adequacy, canonical-input provenance or useful native execution.

Native full-source/fixture/corpus and arbitrary safe nested body/probe test
bodies inspect original numeric leaves before JCS, then require exact complete
roundtrips after public compilation. All new proof code and cases remain
unelaborated/unqualified/unrun. No production policy or generated evidence
changed. Actual library/byte-entry adequacy, physical bounds, useful witnesses,
two clean reproductions and every E1–E5/M6/§13.5/§10 gate remain mandatory.

The §13.170 expected numeric-byte reference now constructs canonical plain
decimal bytes for every original admitted integer. Its closed reader earns
the existing DecimalProjection positional meaning; inverses give injectivity
in original integer meaning, including across signed/unsigned carrier tags.
The admitted unsigned/signed bounds give at most 16/17 bytes. Every original
numeric occurrence of the complete source and schema consumes this result,
and actual decoded compiler success earns the necessary admission/provenance.

This does not identify actual native cast/ryu/formatter output with the
reference. In particular, the admitted reference refuses unsupported/unsafe
numbers, while native JCS may round those before recipe admission. The pinned
write_i64/write_u64 → f64 → finite check → ryu format_finite → current sink
chain and d2d/pretty layout remain implementation obligations. Native integer
Display differential, boundary, property and append-prefix cases are authored
but unrun. All new proofs are unelaborated/unqualified. Complete child/tree
canonical bytes, transparent Auths Serialize, native library adequacy,
physical bounds, actual hash provenance and all final gates remain required.

The §13.171 reference no longer requires caller-supplied canonical child
buffers. Complete recursive encodings and nested formatter traces construct
every original array/object child byte sequence. Arrays retain original
order/count; objects retain original names and full encoded values before
UTF-16 sorting. Earned uniqueness prevents property loss, while duplicate
reference objects retain the existing first-property behavior. Complete
schedules restore parent object/key/value buffers and append to the original
current sink. Byte values below 256 are earned for the whole tree; aggregate
allocation/work/stack and output-size bounds are separate.

Actual decoded compiler success now constructs full original source/schema
values, expected complete bytes and useful reference schedules. This is not
native Serialize/cast/ryu/key/set/Vec/formatter adequacy or actual canonical/
hash provenance. Numeric primitive sink writes use closed expected bytes;
actual numeric dispatch must still earn them. New native recursive oracle
cases use no JCS call for expected child bytes and cover nested state/Unicode/
integers/prefixes. All new proofs/cases remain unelaborated/unqualified/unrun.
Full raw strict/EOF/Decode, native libraries, physical bounds, useful native
witnesses and every final gate remain mandatory.

The §13.172 written tree envelope now counts every original child, UTF-8 key/
value byte, quote expansion and collection separator. Complete recursive
encoding earns its expected output length and current-sink growth. The envelope
is at most seventeen times decoded tree weight, counting every value node,
collection edge and original key/value byte. Actual decoded compiler success
constructs source/schema writers with these bounds, not supplied child lengths
or capacity flags. Native control-expansion/nested-child/append/property and
fixture/corpus size assertions are authored but unrun.

This is not an allocator/work/stack or raw input-to-output bound and does not
discharge NativeCanonicalFits. Actual parser-to-tree accounting, typed positional/
default expansion, transparent Auths Serialize, native cast/ryu/formatter and
library adequacy, actual canonical/hash provenance, physical bounds, useful
witnesses and all final gates remain open. All new proof code is unelaborated/
unqualified; no generation or qualification evidence changed.

The §13.173 raw numeric-token reader now keeps original -0, fractional and
exponent syntax before any native conversion or canonical normalization.
Lexical acceptance, original byte decomposition, progress, stopping and
complete-document whitespace/EOF are earned by the closed reference. Numeric
kind, binary64 bits, finite/range refusal and ryu normalization remain separate
native obligations; lexical 1e309 does not promise a native finite value.
New native kind/negative-zero/range/grammar cases are authored but unrun,
and all new proofs remain unelaborated/unqualified. Full parser/strict/Decode,
canonical/hash provenance, physical resources and all final gates remain.

The §13.174 raw syntax reference now preserves full original numeric tokens,
quoted String spellings, decoded Unicode keys and every ordered array/object
child before any map collapse. Strict syntax checking earns decoded-name
uniqueness of the same full raw value and complete original whitespace/EOF
traces. The uniqueness shape is not a canonical preimage. Actual numeric
conversion, native recursion/visitor/error behavior and typed Decode remain
separate obligations; lexical overflow/deeper syntax can be recognized before
native conversion/resource refusal. New hidden/escaped-duplicate and nested
syntax cases are unrun, and all proof code remains unelaborated/unqualified.
Actual Serialize/cast/ryu/formatter/JCS/hash and physical/final gates remain.

The §13.175 lossless numeric preparation retains original token spelling and
complete raw structure while recording exact expected u64/i64 routing or an
unresolved floating conversion. Negative zero and fractional/exponent forms
remain floating paths even when canonical formatting may print an integer.
Word overflow is not confused with the separate admitted-safe-integer bound.
No floating bits or finite result are fabricated; original-token retention
does not assert ideal native float parsing or actual canonical bytes. New
native dispatch visitor/boundary/property cases are unrun; all proof code is
unelaborated/unqualified. Exact parser/feature/cast/float/visitor, full Decode,
canonical/hash, resource/usefulness and final gates remain mandatory.

The §13.176 signed-word reference now establishes the exact cast/wrapping
branch and preserves the original unsigned magnitude for negative-zero or
signed-underflow floating fallback. This avoids treating a wrapped signed
residue as the numeric conversion input. Native dispatch/fallback-bit cases
are authored but unrun; all mathematical lemmas are unelaborated/unqualified.
No native f64 cast/number parser/ryu/formatter/JCS/hash adequacy is inferred.
All original-source, resource/usefulness and final gates remain open.

The §13.177 raw-number digit loop now preserves the original partial word
and first unconsumed overflowing digit, with exact checked-update and every-
prefix u64 bounds. Nondigit stop retains fraction/exponent syntax for the next
native numeric stage. These are original-input arithmetic/slice laws, not
floating conversion, native cursor/read/loop or canonical byte adequacy.
New checked-arithmetic/dispatch cases are unrun; all proofs are unelaborated/
unqualified. Full parser/feature/conversion, Serialize/cast/ryu/formatter/JCS/
hash/resource/usefulness and final gates remain mandatory.

The §13.178 initial number stage now retains original error snapshots and
partial/remainder data through exact word, negative-cast, decimal, exponent
and long-integer continuations. Leading-zero refusal occurs before a later
float suffix is considered; peek-error position is distinct from consumed
position. No floating helper success, bits or canonical result is assumed.
New native category/position cases are unrun and mathematical code remains
unelaborated/unqualified. Actual parser/feature/cursor/conversion/Decode,
Serialize/cast/ryu/formatter/JCS/hash/resource/usefulness and final gates remain.

The §13.179 decimal stage now preserves original input, loop provenance and
all helper arguments, with exact negative fractional counts and every-prefix
i32 bounds from original input size. First-digit overflow is distinguished
from a missing fraction and reaches its helper before empty-fraction refusal.
No float-helper success or arbitrary correctly rounded bit result is assumed.
New native zero/sign/underflow/overflow/fraction cases are unrun; all proof
code is unelaborated/unqualified. Exact native feature/parser/primitive/float/
visitor, Serialize/cast/ryu/formatter/JCS/hash/resource/usefulness and final
gates remain mandatory.


The §13.180 exponent reference now preserves original optional signs, mandatory
first bytes, committed digits, consumed overflow trigger and remaining suffix.
It composes exact saturation and source overflow-helper paths with actual model
integer/decimal callers. Range refusal and signed-zero suffix consumption are
distinct; native cases target their public columns/zero signs but are unrun.
Normal from-parts continuation is not a native float result or JCS number
preimage. All five Lean inputs/thirty-two roots/forty-six cases are unelaborated/
unqualified. Exact native parser/feature/cursor/i32/float/helper/visitor and
long-number adequacy, Serialize/cast/ryu/formatter/JCS/hash/resources/usefulness
and all final gates remain open. No checks/generation/replay/CI poll ran.


The §13.181 long-number scratch reference now retains expected partial-word
bytes, all remaining integer digits, fractional zero padding and the entire
integer/fraction split. Source-derived counts earn mathematical scratch/slice
bounds. Native exact-2^64 scaling cases are unrun; all model roots/cases are
unelaborated/unqualified. The enabled float_roundtrip feature is explicit.
These expected conversion arguments are not native float or JCS byte results.
Long-decimal/exponent handoffs, native formatting/usize/scratch/parser/float/
visitor, Serialize/cast/ryu/formatter/JCS/hash/resource/usefulness and all final
gates remain. No checks/generation/replay/CI poll ran.


The §13.182 reference now composes complete ordinary/long number-helper routes,
including fractional append, long exponent and the original signed word/cast
choices. Every buffer/split/argument and input remainder is retained. Actual
overflow callers earn nonzero original scratch even when the unscaled value
would round to zero; appended digits cannot erase that fact. Pending concise/
truncated conversion arguments are not native float bits or JCS preimages.
Twenty-nine roots/fifty-five Lean cases and native unit/property cases are
unelaborated/unqualified/unrun. Native parser/precision/float/visitor, typed
Decode, Serialize/cast/ryu/formatter/JCS/hash/resource/usefulness and all final
gates remain; no checks/generation/replay/CI poll ran.


The §13.183 full original JSON preparation now carries each actual numeric
stage call, including partial refusal and pending float arguments, through
every original member/array in order. Numeric occurrence count and exact full-
tree restoration are preserved. Eight roots/eleven cases are authored,
unelaborated/unqualified/unrun. Syntax/annotation success is not native finite
conversion, visitor/Decode success or canonical numeric preimage evidence.
Native parser/precision/float/Serialize/cast/ryu/JCS/hash/resource/usefulness and
all final gates remain; no checks/generation/replay/CI poll ran.


The §13.184 actual source construction exposed recursive Auths serde trait
cycles. ValueExpr Deserialize now uses explicit AST frames while its Serialize
derive stays authoritative. Strict uniqueness comes from original raw child
slices, never the discarded Value validation map. The public source/canonical
contract must retain direct/buffered tags, maps/sequences, defaults, all children
and unit behavior; new frozen-oracle tests are authored, unrun. Complete native
Lean emission still fails on source loop/field-byte-visitor constructs; the
last loop normalization is unregenerated. No opaque Auths callback or gate
relaxation was used. Pending native ABI/parser/conversion/Serialize/JCS/hash/
physical bounds/usefulness and all final gates remain; staged Rust intermediates
are qualified=false, not passing proof or release evidence.


The §13.185 decoder field/default/variant tables preserve the required complete
source JSON contract; existing Serialize implementations remain authoritative.
Original derives and new normalization matrix tests are test-only and unrun.
Actual twenty-one-root source construction still fails in Aeneas, with a traced
static-reference mismatch at serialize_struct and related/residual paths.
No serializer callback was hidden or warning/type gate relaxed. A future
emission/projection change must preserve the complete authoritative source,
original command schema and canonical preimage against the actual frozen
serializer. Native conversion/Serialize/JCS/hash, semantic/physical bounds,
usefulness and all final gates remain; no verification/replay evidence exists
for this source cutover. See qualified=false snapshot §13.185.
