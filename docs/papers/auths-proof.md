---
title: "Auths-Proof: Mechanically Linking Authorization Algebra to Shipping Rust"
author: "bordumb · bordumbb@gmail.com"
date: 27 July 2026
abstract: |
  Authorization systems are often verified at the wrong boundary. A proof
  assistant may establish elegant properties of a model while production code
  independently reimplements the model, leaving semantic correspondence to
  review and testing. We present the formal core of **Auths-Proof**, a
  deterministic proof-carrying authorization kernel, and a refinement boundary
  designed to make that gap explicit and mechanically difficult to cross.

  Auths-Proof models delegation as a product order over ten authority
  dimensions and composition as a three-valued algebra over authorized,
  denied, and indeterminate branch outcomes. Lean 4 proves transitivity,
  antisymmetry, downward-closed action coverage, strict delegation depth,
  threshold soundness, monotonicity, permutation invariance, termination, and
  linear structural cost. A versioned declarative contract generates both the
  shipping `no_std` Rust algebra kernel and the corresponding Lean definitions.
  Production authority and composition code call that generated Rust kernel.
  Lean exports all 1,024 Boolean attenuation projections and 2,448 threshold
  states through the default 16-leaf deployment bound; Rust replays those
  vectors against both the generated functions and the shipping composition
  path. Kani additionally checks the two production functions over symbolic
  bounded inputs.

  This is not a proof of the complete verifier. The Lean theorems are
  unbounded, but the cross-language threshold enumeration is bounded; the
  contract generator, Rust compiler, cryptographic and codec layers, and the
  projection from rich protocol values to ten Boolean predicates remain in the
  trusted computing base. The result is a precise middle ground between an
  unlinked formal model and whole-program verification: small enough to audit,
  executable in production, reproducible by one command, and honest about the
  obligations that remain.
---

# 1. Introduction

An authorization verifier answers a deceptively small question:

\begin{thesisbox}
\centering
\textbf{Does authority trusted by this verifier authorize this exact action
under this exact context?}
\end{thesisbox}

The answer is security-critical because identity is not authority. A valid
signature establishes control of a key. A WebAuthn ceremony establishes
control of a credential under ceremony conditions. A certificate establishes
a path to a trust root. None of those facts alone grants permission to deploy
software, spend a budget, invoke a tool, or mutate a repository. Authentication
logics and authorization logics have long treated these as different
judgments [@burrows1990logic; @abadi1993calculus]. Capability and
trust-management systems likewise make authority and delegation explicit
[@dennis1966capabilities; @blaze1996trust; @keynote1999].

Auths-Proof implements this separation as an offline kernel:

$$
\operatorname{verify}(P,A,C)
\rightarrow
\operatorname{Authorized}(S)
\mid \operatorname{Denied}(d)
\mid \operatorname{Indeterminate}(q).
$$

$P$ is a portable proof graph, $A$ is a profile-canonical action, and $C$ is
verifier-trusted context. The kernel performs no network, clock, filesystem,
database, or key-custody I/O. Only `Authorized` contains a sealed action value
eligible for execution. `Denied` records a stable permanent failure.
`Indeterminate` records a stable missing trustworthy fact. The latter two
outcomes never permit execution.

This paper is about a narrower problem than the full protocol: how do we know
that the algebra proved in Lean is the algebra executed by shipping Rust?

Writing the same function twice does not answer that question. Tests over a few
examples do not answer it. A shared trait name does not answer it. Even a
machine-checked proof can create false confidence when its definitions are
detached from production. Experience from verified compilers and kernels shows
that useful assurance depends on an explicit refinement chain and an explicit
trusted computing base [@leroy2009compcert; @klein2009sel4].

Auths-Proof therefore treats linkage as a first-class artifact. A small
versioned contract generates the finite algebra surface in both languages.
Lean proves unbounded mathematical properties over those generated
definitions. Production Rust calls the generated Rust functions. Lean emits
semantic vectors; Rust consumes them. Kani analyzes the same Rust functions
with symbolic inputs. Figure 1 summarizes the chain.

\begin{figure}[H]
\centering
\resizebox{0.97\linewidth}{!}{%
\begin{tikzpicture}[node distance=7mm and 10mm]
  \node[axisbox=purple, minimum width=45mm, minimum height=18mm] (contract) {
    \textbf{Versioned algebra contract}\\[-1pt]
    truth order · 10 dimensions · threshold partition
  };

  \node[card, minimum width=42mm, below left=11mm and 13mm of contract] (lean) {
    \textcolor{purple}{\faCheckCircle}\quad\textbf{Generated Lean surface}\\
    \texttt{Truth} · projection · functions
  };
  \node[card, minimum width=42mm, below right=11mm and 13mm of contract] (rust) {
    \textcolor{blue}{\faCogs}\quad\textbf{Generated Rust kernel}\\
    \texttt{no\_std} · trait · functions
  };

  \node[axisbox=purple, minimum width=42mm, below=9mm of lean] (proofs) {
    \textbf{Lean theorems}\\
    unbounded algebraic obligations
  };
  \node[axisbox=blue, minimum width=42mm, below=9mm of rust] (shipping) {
    \textbf{Shipping Rust}\\
    authority + composition call kernel
  };

  \node[axisbox=green, minimum width=42mm, below=9mm of proofs] (vectors) {
    \textbf{Lean vector exporter}\\
    1,024 attenuation + 2,448 threshold
  };
  \node[axisbox=amber, minimum width=42mm, below=9mm of shipping] (kani) {
    \textbf{Kani harnesses}\\
    symbolic bounded production checks
  };

  \node[kernel, minimum width=99mm, below=12mm of $(vectors)!0.5!(kani)$] (gate) {
    \faLock\quad \texttt{cargo xtask formal}\\[2pt]
    \normalfont\footnotesize source drift · theorem inventory · vector drift ·
    Rust replay · Kani
  };

  \draw[flow=purple] (contract) -- (lean);
  \draw[flow=blue] (contract) -- (rust);
  \draw[flow=purple] (lean) -- (proofs);
  \draw[flow=blue] (rust) -- (shipping);
  \draw[flow=green] (proofs) -- (vectors);
  \draw[flow=amber] (shipping) -- (kani);
  \draw[flow=green] (vectors) -- (gate);
  \draw[flow=amber] (kani) -- (gate);
  \draw[thinflow=blue,dashed] (shipping.south) |- (gate.east);
\end{tikzpicture}}
\caption{\textbf{The mechanical refinement boundary.} One contract generates
the definitions used by Lean and production Rust. The proof, exhaustive finite
replay, and bounded model-checking paths converge in one reproducible gate.}
\end{figure}

## 1.1 Contributions

This paper makes five contributions.

**A closed authorization algebra.** Delegation is a product order over root,
depth, profile, permissions, validity, audiences, action constraint, budget,
status, and assurance. Composition is a three-valued algebra that preserves
trustworthy uncertainty.

**An unbounded Lean model.** The Lean development proves the order-theoretic,
coverage, threshold, determinism, termination, and cost properties needed by
the V1 algebra. The checked source contains no `sorry`, `admit`, or new axioms.

**A generated language boundary.** A declarative TOML contract generates the
Rust trait and functions and the corresponding Lean structure and functions.
Changing a dimension is a cross-language schema change rather than two
independent edits.

**Production refinement evidence.** Shipping authority and composition code
execute the generated Rust kernel. Lean-originated vectors cover the entire
finite Boolean attenuation space and the entire threshold count space through
the default deployment bound. Kani checks the same functions symbolically.

**An explicit assurance ledger.** We distinguish what is proved, what is
exhaustively checked under a bound, what is tested, and what remains trusted.
The artifact does not claim whole-verifier formal verification.

## 1.2 Scope and terminology

The paper uses *proof* in three different senses:

- an **authorization proof** is untrusted protocol input;
- a **Lean proof** is a kernel-checked theorem;
- a **Kani proof harness** is a bounded symbolic program check.

These are not interchangeable. The formal model excludes parsing,
cryptography, principal adapters, graph resolution, clocks, status evidence,
and complete verifier control flow. Those components are relevant to the
system, but the formal claim in this paper is confined to authority
attenuation and branch composition.

# 2. Authorization semantics

## 2.1 Trusted context and portable evidence

The portable proof carries signed grants, signed actions, evidence objects,
bindings, and an authorization plan. It does not carry verifier trust. Trust
anchors, accepted registries, evaluation time, expected challenge and audience,
status and assurance policy, composition floors, and resource limits enter
through $C$.

\begin{figure}[H]
\centering
\resizebox{0.93\linewidth}{!}{%
\begin{tikzpicture}[node distance=7mm and 14mm]
  \node[card, minimum width=43mm, minimum height=24mm] (portable) {
    \textcolor{blue}{\faFileSignature}\quad\textbf{Portable proof}\\[2pt]
    signed grants + actions\\
    evidence + bindings + plan
  };
  \node[card, minimum width=43mm, minimum height=24mm, below=of portable] (action) {
    \textcolor{amber}{\faFingerprint}\quad\textbf{Canonical action}\\[2pt]
    profile meaning + exact bytes\\
    permission + digest + budget
  };
  \node[card, minimum width=43mm, minimum height=24mm, below=of action] (context) {
    \textcolor{purple}{\faLock}\quad\textbf{Trusted context}\\[2pt]
    roots + time + status + policy\\
    registries + limits + challenge
  };

  \node[kernel, minimum width=52mm, minimum height=39mm,
        right=20mm of action] (kernel) {
    AUTHS-PROOF CORE\\[5pt]
    \normalfont\footnotesize
    resolve · verify control\\
    attenuate · compose\\
    seal
  };

  \node[verdict=green, minimum width=39mm, right=17mm of kernel, yshift=14mm] (yes) {
    AUTHORIZED\\[-1pt]\normalfont\scriptsize sealed action
  };
  \node[verdict=red, minimum width=39mm, right=17mm of kernel] (no) {
    DENIED\\[-1pt]\normalfont\scriptsize stable reason
  };
  \node[verdict=amber, minimum width=39mm, right=17mm of kernel, yshift=-14mm] (maybe) {
    INDETERMINATE\\[-1pt]\normalfont\scriptsize stable requirement
  };

  \draw[flow=blue] (portable.east) -- (kernel.west);
  \draw[flow=amber] (action.east) -- (kernel.west);
  \draw[flow=purple] (context.east) -- (kernel.west);
  \draw[flow=green] (kernel.east) -- (yes.west);
  \draw[flow=red] (kernel.east) -- (no.west);
  \draw[flow=amber] (kernel.east) -- (maybe.west);
\end{tikzpicture}}
\caption{\textbf{The verifier's narrow waist.} Identity evidence contributes
facts, but only the local authority computation can produce a sealed action.}
\end{figure}

This partition instantiates verifier sovereignty. A proof can demonstrate a
chain from a root, but it cannot choose the local root. It can carry a status
statement, but it cannot choose the accepted status method or freshness limit.
It can request a composition plan, but the verifier can impose additional
branch, actor, and root diversity floors.

## 2.2 Three-valued truth

Each proof branch produces one value in

$$
\mathbb{T} = \{\bot,\ ?,\ \top\},
\qquad
\bot \preceq ? \preceq \top,
$$

where $\top$ is authorized, $\bot$ is denied, and $?$ is indeterminate.
Indeterminate is not an error code disguised as authority. It means that a
recognized trustworthy fact is absent or unavailable and that authorization
would still be reachable if that fact were supplied.

For conjunction and disjunction:

$$
x \wedge y = \min_{\preceq}(x,y),
\qquad
x \vee y = \max_{\preceq}(x,y).
$$

The implementation evaluates all members in canonical order so diagnostic
selection remains deterministic even when the truth algebra is permutation
invariant.

For a threshold requiring $k$ successes, let $a$ be the number of authorized
branches and $u$ the number of indeterminate branches:

$$
\operatorname{threshold}(k,a,u)=
\begin{cases}
\top & a \ge k,\\
? & a < k \land a+u \ge k,\\
\bot & a+u < k.
\end{cases}
$$

\begin{figure}[H]
\centering
\begin{tikzpicture}[x=0.72cm,y=0.72cm]
  \draw[->,draw=muted] (0,0) -- (10.8,0)
    node[note,below=3pt] {authorized count \(a\)};
  \draw[->,draw=muted] (0,0) -- (0,7.8)
    node[note,rotate=90,above=4pt] {indeterminate count \(u\)};

  \fill[redwash] (0,0) -- (6,0) -- (0,6) -- cycle;
  \fill[amberwash] (0,6) -- (6,0) -- (6,7) -- (0,7) -- cycle;
  \fill[greenwash] (6,0) rectangle (10,7);

  \draw[red,line width=1.1pt] (0,6) -- (6,0);
  \draw[green,line width=1.1pt] (6,0) -- (6,7);

  \node[font=\sffamily\small\bfseries,text=red] at (2.0,1.6) {DENIED};
  \node[font=\sffamily\small\bfseries,text=amber] at (2.7,5.3) {INDETERMINATE};
  \node[font=\sffamily\small\bfseries,text=green] at (8.0,3.5) {AUTHORIZED};

  \node[note,anchor=west] at (10.25,6.7) {\(k=6\)};
  \foreach \x in {0,2,4,6,8,10}
    \draw[muted] (\x,0.08) -- (\x,-0.08) node[note,below=2pt] {\x};
  \foreach \y in {0,2,4,6}
    \draw[muted] (0.08,\y) -- (-0.08,\y) node[note,left=2pt] {\y};
\end{tikzpicture}
\caption{\textbf{Threshold partition for \(k=6\).} The three regions are total
and mutually exclusive. Increasing \(k\) moves the authorization boundary
rightward and cannot create authority.}
\end{figure}

Preserving $?$ matters operationally. Collapsing it into $\bot$ loses the
difference between "the statement is invalid" and "a required status snapshot
is unavailable." Collapsing it into $\top$ fails open.

## 2.3 Delegation as a product order

An effective authority value is modeled in Lean as:

$$
E =
(r,s,p,\pi,v,a,c,b,t,h,d),
$$

where $r$ is the root, $s$ the current subject, $p$ profile authority,
$\pi$ permissions, $v$ validity, $a$ audiences, $c$ action constraint,
$b$ budget, $t$ status, $h$ assurance, and $d$ remaining delegation depth.
The subject changes when authority is delegated; the other coordinates form
the attenuation relation.

For child $E'$ and parent $E$:

$$
\begin{aligned}
E' \sqsubseteq E \iff {}&
r'=r
\land p'\le p
\land \pi'\le\pi
\land v'\le v
\land a'\le a\\
&\land c'\le c
\land b'\le b
\land t'\le t
\land h'\le h
\land d'\le d.
\end{aligned}
$$

A valid delegation is stricter:

$$
\operatorname{delegates}(E,E')
\iff E'\sqsubseteq E \land d' < d.
$$

The production protocol has rich domain-specific orders. Permission and
audience sets use subset. Validity uses interval containment. Action
constraints order `AnyBody`, allowed digest sets, and exact digests. Bounded
budgets use their selected algebra. Snapshot policy preserves the method and
can only reduce accepted age. Assurance policy cannot weaken.

\begin{figure}[H]
\centering
\resizebox{0.94\linewidth}{!}{%
\begin{tikzpicture}[node distance=7mm]
  \node[kernel, minimum width=101mm] (root) {
    LOCAL ROOT AUTHORITY \quad \(E_0\)
  };
  \node[card, minimum width=101mm, below=of root] (g1) {
    \textbf{Delegation edge 1}\\
    \(r_1=r_0\) · \(\pi_1\subseteq\pi_0\) · \(v_1\subseteq v_0\) ·
    \(a_1\subseteq a_0\) · \(d_1<d_0\)
  };
  \node[card, minimum width=101mm, below=of g1] (g2) {
    \textbf{Delegation edge 2}\\
    profile · action constraint · budget · status · assurance do not widen
  };
  \node[axisbox=green, minimum width=101mm, below=of g2] (action) {
    \textbf{Covered canonical action}\\
    exact permission · valid interval · audience · body digest · requested budget
  };
  \draw[flow=blue] (root) -- node[note,right]{product order} (g1);
  \draw[flow=blue] (g1) -- node[note,right]{strict depth} (g2);
  \draw[flow=green] (g2) -- node[note,right]{downward-closed coverage} (action);
\end{tikzpicture}}
\caption{\textbf{Authority narrows along a chain.} If the terminal authority
covers an action, every ancestor also covers it; the converse is intentionally
false. Strictly decreasing depth bounds chain length.}
\end{figure}

# 3. Lean specification

## 3.1 Why Lean

Lean 4 combines an interactive theorem prover with an executable functional
language and a small proof-checking kernel [@demoura2021lean4]. The Auths-Proof
model uses ordinary inductive types, structures, recursive functions, and
theorems. `omega` discharges Presburger arithmetic obligations; finite truth
tables are proved by case analysis.

The formal project is intentionally small. It does not model Rust memory,
cryptographic primitives, CBOR, or dynamic adapter behavior. Instead it defines
the semantic center that is both security-critical and stable enough to merit
an unbounded mathematical treatment.

The generated truth type is:

```lean
inductive Truth where
  | denied
  | indeterminate
  | authorized
  deriving BEq, DecidableEq, Repr
```

The generated attenuation surface is ten named Booleans. The abstract model
then interprets those names as order relations over natural-number coordinates.
This separation lets Lean prove order properties while the generated surface
remains isomorphic to production's finite decision boundary.

## 3.2 Attenuation theorems

The attenuation development proves:

1. reflexivity and transitivity of $\sqsubseteq$;
2. antisymmetry when subjects agree;
3. downward-closed action coverage;
4. root preservation and strict depth for delegation;
5. transitive non-widening across delegation chains;
6. coverage of an authorized child action by its parent;
7. equivalence between the generated Boolean kernel and abstract delegation.

The central refinement theorem is executable documentation:

```lean
theorem attenuation_kernel_refines
    (parent child : EffectiveAuthority) :
    Generated.attenuationAccepts
        (delegationProjection parent child) = true
      ↔ delegates parent child := by
  simp [Generated.attenuationAccepts,
        delegationProjection, delegates, attenuates]
  omega
```

This theorem is stronger than separately proving the conjunction function and
the abstract order. It states that the generated acceptance result is true
exactly when the abstract delegation judgment holds.

The theorem `coverage_downward_closed` establishes:

$$
E' \sqsubseteq E \land \operatorname{covers}(E',A)
\Longrightarrow
\operatorname{covers}(E,A).
$$

This is the safety direction required for attenuation. Delegating narrower
authority cannot make the descendant authorize an action that the ancestor
could not authorize.

## 3.3 Composition theorems

For both `all` and `any`, Lean proves commutativity, associativity, and
idempotence. It proves that one-of-two is `any`, two-of-two is `all`, and that
tightening a threshold cannot increase truth:

$$
\operatorname{thresholdTwo}(2,x,y)
\preceq
\operatorname{thresholdTwo}(1,x,y).
$$

The unbounded count classifier has three soundness theorems:

$$
\begin{aligned}
\operatorname{threshold}(k,a,u)=\top &\Rightarrow k\le a,\\
\operatorname{threshold}(k,a,u)=\bot &\Rightarrow a+u<k,\\
\operatorname{threshold}(k,a,u)=? &\Rightarrow a<k\le a+u.
\end{aligned}
$$

Plan traversal is modeled structurally. Lean proves that the defined visit list
is exactly the leaf list, that every finite plan has a node count, and that the
declared structural cost equals that count. These are algebra-level results,
not a cost proof for cryptography or allocation.

Composition floors are ordered componentwise over authorized branches,
distinct actors, and distinct roots. The model proves that a tighter satisfied
floor implies every looser floor is also satisfied. Thus raising local
diversity requirements cannot create authorization.

## 3.4 Proof inventory

Table 1 groups the checked obligations. The formal source currently contains
32 named theorems; the release manifest inventories 29 public
algebra/refinement obligations, while three local helper/diversity declarations
remain outside that release list.

\begin{table}[H]
\centering
\small
\begin{tabular}{@{}p{31mm}p{82mm}r@{}}
\toprule
\textbf{Family} & \textbf{Representative obligations} & \textbf{Count}\\
\midrule
Attenuation &
reflexive, transitive, antisymmetric, coverage closure, root, depth,
chain attenuation, generated-kernel refinement & 12\\
Composition &
semilattice laws, threshold identities and monotonicity, permutation-stable
truth and diagnostics, plan traversal, termination, structural cost,
three threshold soundness directions & 17\\
Helpers and diversity &
truth-rank injectivity, canonical-code commutativity, tighter-floor monotonicity
& 3\\
\midrule
\textbf{Lean source total} & & \textbf{32}\\
\bottomrule
\end{tabular}
\caption{\textbf{Lean theorem inventory.} Counts describe named declarations,
not proof difficulty or whole-system coverage.}
\end{table}

# 4. From model to shipping code

## 4.1 The correspondence problem

A traditional refinement approach can prove that an implementation simulates
an abstract specification. CompCert and seL4 demonstrate the strength of such
end-to-end refinement arguments [@leroy2009compcert; @klein2009sel4].
Translation validation instead validates the result of a particular
translation rather than proving a translator correct for all inputs
[@pnueli1998translation].

Auths-Proof currently occupies a smaller point in this design space. It does
not extract the full Rust verifier into Lean, and it does not verify the
contract generator. It generates the small common algebra surface, proves the
Lean interpretation, executes the generated Rust surface in production, and
checks finite semantic agreement.

Tools such as Aeneas translate safe Rust into functional models for proof
assistants [@ho2022aeneas], while Verus verifies rich properties directly over
Rust-like programs [@lattuada2024verus]. Those approaches are promising future
routes for reducing the remaining projection and generator trust. The present
design was chosen because its boundary is smaller than the toolchain required
to translate the complete verifier.

## 4.2 One declarative contract

The source of the shared surface is
`formal/algebra-contract-v1.toml`. Its essential shape is:

```toml
schema = "auths-proof-algebra-contract/v1"
exhaustive_threshold_bound = 16
truth_order = ["denied", "indeterminate", "authorized"]
attenuation_acceptance = "all"

[[attenuation_dimensions]]
rust = "root_preserved"
lean = "rootPreserved"

[[attenuation_dimensions]]
rust = "depth_decreases"
lean = "depthDecreases"

[threshold]
authorized = "authorized >= required"
indeterminate =
  "authorized < required &&
   authorized + indeterminate >= required"
denied = "authorized + indeterminate < required"
```

The real contract lists all ten dimensions. The generator parses a closed
typed TOML schema, rejects unknown fields, checks unique names, and accepts only
the declared V1 truth order and formulas. It then deterministically renders:

- `core/crates/auths-algebra-kernel/src/generated.rs`;
- `formal/Auths/Generated/Algebra.lean`.

Normal verification compares both files byte-for-byte with fresh renderings.
Intentional changes require `cargo xtask formal --update`.

\begin{figure}[H]
\centering
\resizebox{0.96\linewidth}{!}{%
\begin{tikzpicture}[node distance=8mm and 11mm]
  \node[axisbox=purple, minimum width=40mm] (source) {
    \textbf{Contract V1}\\
    names + formulas + bound
  };
  \node[card, minimum width=43mm, below left=12mm and 12mm of source] (leansurface) {
    \textbf{Lean structure}\\
    camelCase fields\\
    Bool conjunction + Nat threshold
  };
  \node[card, minimum width=43mm, below right=12mm and 12mm of source] (rustsurface) {
    \textbf{Rust trait}\\
    snake\_case methods\\
    bool conjunction + count threshold
  };
  \node[axisbox=purple, minimum width=43mm, below=of leansurface] (abstract) {
    \textbf{Abstract Lean order}\\
    rich coordinates mapped to predicates
  };
  \node[axisbox=blue, minimum width=43mm, below=of rustsurface] (domain) {
    \textbf{Rich Rust projection}\\
    sets + windows + policies mapped to predicates
  };
  \node[kernel, minimum width=97mm, below=12mm of $(abstract)!0.5!(domain)$] (same) {
    SAME FINITE ACCEPTANCE SURFACE
  };

  \draw[flow=purple] (source) -- (leansurface);
  \draw[flow=blue] (source) -- (rustsurface);
  \draw[flow=purple] (leansurface) -- (abstract);
  \draw[flow=blue] (rustsurface) -- (domain);
  \draw[flow=purple] (abstract) -- (same);
  \draw[flow=blue] (domain) -- (same);
\end{tikzpicture}}
\caption{\textbf{Generated structural correspondence.} The contract prevents
silent field drift. Semantic correctness of each rich Rust predicate remains a
separate obligation.}
\end{figure}

## 4.3 Shared traits, correctly understood

There is no runtime trait object shared between Lean and Rust. Instead, the
contract generates structurally corresponding interfaces:

```rust
pub trait AttenuationProjection {
    fn root_preserved(&self) -> bool;
    fn depth_decreases(&self) -> bool;
    // ... eight more named dimensions
}
```

```lean
structure AttenuationProjection where
  rootPreserved : Bool
  depthDecreases : Bool
  -- ... eight more named dimensions
```

This is stronger than manually duplicating traits because one source controls
the field set, ordering, names, and aggregation semantics. It is weaker than
proving a compiler from Rust to Lean. The distinction is central to the paper's
claim.

Adding an eleventh attenuation dimension causes deliberate breakage:

1. the generated Rust trait changes;
2. the generated Lean structure changes;
3. Rust projection implementations fail to compile until they supply it;
4. Lean projections fail to elaborate until they supply it;
5. vector cardinality and exporter logic must change;
6. the checked-in generated artifacts drift until explicitly regenerated.

That failure mode turns semantic expansion into an auditable repository-wide
event.

## 4.4 Production Rust routing

The generated kernel is a separate `no_std`, `unsafe`-free crate. Shipping
composition no longer owns a handwritten threshold classifier:

```rust
pub fn evaluate_threshold_counts(
    k: u16,
    authorized: usize,
    indeterminate: usize,
) -> ThresholdTruth {
    auths_algebra_kernel::threshold_counts(
        k, authorized, indeterminate
    )
}
```

Shipping authority constructs a `GrantAttenuation` from rich domain checks and
passes it to `attenuation_accepts`. The generated function accepts exactly the
conjunction of all trait methods.

Root preservation deserves special attention. In Rust, root is not supplied by
an untrusted child grant; `EffectiveAuthority::delegate` mutates the existing
state while retaining its private root field. The production projection
therefore returns `true` for `root_preserved`. Lean models root explicitly and
proves that an accepted abstract delegation preserves it. This is a legitimate
representation difference, but it belongs in the trusted mapping rather than
being hidden.

# 5. Executable refinement evidence

## 5.1 Lean-generated vectors

The Lean executable `Auths.VectorExport` is the semantic vector producer. It
does not call a Rust reference evaluator.

For attenuation, it enumerates all assignments in $\{0,1\}^{10}$:

$$
2^{10}=1{,}024 \text{ cases}.
$$

Exactly one vector, the all-true assignment, is accepted because V1 aggregation
is conjunction.

For threshold counts, the declared exhaustive bound is $B=16$. The exporter
enumerates:

$$
1\le k\le B,\quad 0\le a\le B,\quad 0\le u\le B-a.
$$

The case count is:

$$
B\sum_{a=0}^{B}(B-a+1)
=16\cdot153
=2{,}448.
$$

Rust checks every vector against `auths_algebra_kernel::threshold_counts`.
It also constructs a real 16-leaf `AuthorizationPlan::k_of_n`, feeds the
declared mix of branch outcomes to shipping `auths_composition::evaluate`, and
checks that the result and full leaf visitation agree.

\begin{figure}[H]
\centering
\begin{tikzpicture}[node distance=7mm and 9mm]
  \node[axisbox=purple, minimum width=41mm] (lean) {
    \textbf{Lean evaluation}\\
    unbounded definitions
  };
  \node[axisbox=green, minimum width=41mm, right=of lean] (json) {
    \textbf{Canonical JSON vectors}\\
    schema + bound + expected result
  };
  \node[axisbox=blue, minimum width=41mm, right=of json] (kernel) {
    \textbf{Generated Rust}\\
    direct function replay
  };
  \node[axisbox=blue, minimum width=41mm, below=of kernel] (shipping) {
    \textbf{Shipping composition}\\
    real bounded plan replay
  };
  \node[kernel, minimum width=91mm, below=of $(lean)!0.5!(json)$] (stable) {
    BYTE-STABLE CHECKED-IN ARTIFACTS
  };
  \draw[flow=purple] (lean) -- (json);
  \draw[flow=green] (json) -- (kernel);
  \draw[flow=blue] (kernel) -- (shipping);
  \draw[flow=purple] (lean) -- (stable);
  \draw[flow=green] (json) -- (stable);
  \draw[flow=blue] (shipping) -- (stable);
\end{tikzpicture}
\caption{\textbf{Semantic vector provenance.} Expected values originate in
Lean. Rust is a consumer, not a co-author of the oracle.}
\end{figure}

## 5.2 Kani over the shipping kernel

Kani lowers Rust MIR into CBMC's bit-precise model-checking pipeline and checks
assertions over symbolic inputs [@delmas2026kani; @kroening2023cbmc]. Two
harnesses target the generated production crate.

The threshold harness selects symbolic `u16` values, assumes the declared
default bound and a valid positive threshold, calls `threshold_counts`, and
asserts the three-way partition. Kani also checks arithmetic overflow and
runtime safety on reachable paths.

The attenuation harness selects ten symbolic Booleans and asserts:

```rust
attenuation_accepts(&checks)
    == checks.root_preserved
    && checks.depth_decreases
    && checks.profile_attenuates
    && checks.permissions_attenuate
    && checks.validity_attenuates
    && checks.audiences_attenuate
    && checks.action_constraint_attenuates
    && checks.budget_attenuates
    && checks.status_attenuates
    && checks.assurance_attenuates
```

Kani contributes implementation-level evidence: the actual compiled Rust
functions satisfy these assertions over the bounded harness domain. It does
not replace the unbounded Lean theorems, and the Lean theorems do not replace
Kani's check of Rust arithmetic and control flow.

## 5.3 One reproducible gate

`cargo xtask formal` performs, in order:

1. parse and validate the contract;
2. render both generated modules and reject byte drift;
3. build the Lean project;
4. execute the Lean vector exporter and reject vector drift;
5. scan selected formal source for `sorry`, `admit`, and `axiom`;
6. verify every release-inventory theorem name is declared;
7. run Rust refinement tests over all vectors;
8. run both Kani harnesses.

The update mode is explicit:

```text
cargo xtask formal --update
```

It regenerates both language modules and both vector files. A normal run never
silently updates proof evidence.

## 5.4 Evaluation results

\begin{table}[H]
\centering
\small
\begin{tabular}{@{}p{43mm}p{30mm}p{43mm}@{}}
\toprule
\textbf{Artifact} & \textbf{Observed result} & \textbf{Established scope}\\
\midrule
Lean source &
32 named theorems; 29 release-inventoried &
unbounded abstract attenuation, composition, traversal, and diversity facts\\
Attenuation vectors &
1,024 / 1,024 replayed &
all Boolean assignments over ten generated predicates\\
Threshold vectors &
2,448 / 2,448 replayed &
all valid count states through the default 16-leaf bound\\
Shipping plan replay &
2,448 / 2,448 agreed &
real `k-of-n` evaluation agrees with the Lean oracle at that bound\\
Kani &
2 / 2 harnesses; 0 failures &
symbolic bounded generated Rust functions and runtime checks\\
Generated drift &
no drift &
checked-in Rust, Lean, and vectors match deterministic generation\\
\bottomrule
\end{tabular}
\caption{\textbf{Formal artifact results at the evaluated revision.} These are
semantic checks, not performance measurements.}
\end{table}

# 6. Assurance boundary

## 6.1 What is proved

The Lean kernel checks the following model-level claims:

- attenuation is a partial order modulo subject identity;
- delegation preserves the root, never widens authority, and strictly reduces
  depth;
- terminal action coverage implies ancestor coverage;
- `all` and `any` have the expected semilattice laws;
- threshold results imply their defining count inequalities;
- tightening a two-branch threshold cannot increase truth;
- truth and canonical diagnostic selection are permutation invariant;
- finite plans terminate under the structural model and have linear declared
  node cost;
- tighter diversity floors cannot create authorization;
- generated attenuation acceptance is equivalent to abstract delegation.

These proofs quantify over natural numbers and finite inductive plans. They are
not limited to 16 leaves.

## 6.2 What is exhaustively checked under a bound

The cross-language threshold relation is exhaustive only through 16 leaves,
which equals `DEFAULT_MAX_PLAN_LEAVES` for target V1. The protocol model also
contains a separately configurable hard maximum of 128. The artifact does not
enumerate or model-check every threshold count through 128.

The attenuation projection space is genuinely complete for the generated
Boolean interface because it has exactly ten inputs. That completeness does not
prove that each rich Rust predicate computes the intended domain relation.

## 6.3 What remains trusted

\begin{figure}[H]
\centering
\resizebox{0.97\linewidth}{!}{%
\begin{tikzpicture}[node distance=7mm and 8mm]
  \node[kernel, minimum width=43mm, minimum height=24mm] (proved) {
    PROVED IN LEAN\\[2pt]
    \normalfont\footnotesize abstract algebra\\
    refinement theorem
  };
  \node[axisbox=green, minimum width=43mm, minimum height=24mm,
        right=of proved] (checked) {
    \textbf{Mechanically checked}\\
    generated drift · vectors\\
    Kani bounded Rust
  };
  \node[axisbox=amber, minimum width=43mm, minimum height=24mm,
        right=of checked] (trusted) {
    \textbf{Trusted mapping}\\
    rich predicates · generator\\
    compiler + tools
  };

  \node[card, minimum width=43mm, below=of proved] (outside) {
    \textbf{Outside this model}\\
    codecs · crypto · adapters\\
    graph + full verifier
  };
  \node[card, minimum width=43mm, below=of checked] (tests) {
    \textbf{Covered elsewhere}\\
    domain tests · corpus\\
    conformance + fuzzing
  };
  \node[card, minimum width=43mm, below=of trusted] (effects) {
    \textbf{Outer effects}\\
    replay · budgets · custody\\
    transport + execution
  };

  \draw[flow=green] (proved) -- (checked);
  \draw[flow=amber] (checked) -- (trusted);
  \draw[thinflow=muted,dashed] (outside) -- (tests);
  \draw[thinflow=muted,dashed] (tests) -- (effects);
\end{tikzpicture}}
\caption{\textbf{Claim and trust boundary.} Dark blue is theorem-proved;
green is mechanically cross-checked; amber remains trusted. The lower row is
outside the formal model.}
\end{figure}

The trusted computing base includes:

- the Lean kernel and imported tactics;
- the deterministic contract generator;
- the Rust compiler and Kani/CBMC toolchain;
- the mapping from rich Rust values to ten Boolean predicates;
- the model's adequacy as a specification of intended authorization;
- everything outside the algebra, including codecs and cryptography.

Rust's type system and `unsafe`-free core reduce memory-safety risk, but Rust
language safety is not itself a proof of functional authorization correctness.
RustBelt provides a machine-checked foundation for important Rust safety claims
and illustrates why language safety and application correctness must remain
separate statements [@jung2018rustbelt].

## 6.4 The projection gap

The largest remaining semantic gap is not the ten-input conjunction. It is the
construction of those inputs:

```rust
GrantAttenuation {
    permissions_attenuate:
        grant.permissions().is_subset_of(&self.permissions),
    validity_attenuates:
        self.validity.contains_window(grant.validity()),
    action_constraint_attenuates:
        grant.action_constraint().attenuates(
            &self.action_constraint
        ),
    // profile, audience, budget, status, assurance, depth
}
```

Each method has ordinary Rust tests, but the Lean model abstracts it to an
ordered natural-number coordinate. A future refinement should either:

1. translate this isolated safe-Rust projection into Lean with Aeneas;
2. model each rich domain type and prove its Rust relation against generated
   vectors;
3. use a Rust-native deductive verifier such as Verus for the projection;
4. combine these approaches for defense in depth.

Whole-verifier translation is not the immediate next step. The highest-value
work is to close this narrow projection gap first.

# 7. Security consequences

## 7.1 Delegation escalation

The product-order design makes widening explicit. A child must not:

- change the local root;
- keep or increase remaining depth;
- select a broader or different profile;
- add permissions or audiences;
- extend validity;
- broaden action-body discretion;
- remove or increase a bounded budget;
- weaken status freshness;
- weaken assurance.

The aggregate function cannot accidentally omit a declared dimension because
the generated trait and generated conjunction share the contract's field list.
The projection can still miscompute a dimension; that is the residual gap
described above.

## 7.2 Fail-closed uncertainty

Three-valued threshold semantics prevent unavailable evidence from being
treated as success. They also preserve enough information to distinguish a
permanent denial from a potentially satisfiable missing fact. The threshold
soundness theorems show:

- authorization requires at least $k$ established branches;
- denial means even every indeterminate branch cannot reach $k$;
- indeterminate means $k$ is not established but remains reachable.

No diagnostic ordering can change that truth result. Canonical reason selection
exists for deterministic reporting, not as an input to authorization.

## 7.3 Bounded work

Strictly decreasing depth gives a simple termination measure for delegation
chains. Structural plan recursion terminates because plans are finite
inductive values. Production additionally validates deployment limits before
evaluation and reserves work before variable-cost adapters and cryptography.

The Lean theorem `evaluation_cost_linear_in_nodes` concerns the declared
structural cost function. It should not be read as an empirical runtime
complexity proof for the full verifier. Allocation, hashing, signature
verification, adapter work, and codec behavior remain outside that theorem.

## 7.4 Change control as a security property

Authorization semantics evolve. The generated boundary is therefore valuable
even if no current theorem fails. It changes the review shape:

\begin{invariantbox}{SEMANTIC CHANGE RULE}
A new truth value, threshold rule, or attenuation dimension must appear as one
contract change whose generated Rust, generated Lean, proofs, vector
cardinality, production projection, and checked artifacts change together.
\end{invariantbox}

This is not merely build convenience. It prevents a class of silent
specification drift in which a production check is added without a formal
counterpart, or a formal obligation is strengthened without changing shipping
behavior.

# 8. What the core enables

The verified algebra is deliberately below transport and product policy. That
placement lets outer packages vary without redefining authority.

\begin{figure}[H]
\centering
\resizebox{0.96\linewidth}{!}{%
\begin{tikzpicture}[node distance=7mm and 10mm]
  \node[kernel, minimum width=55mm, minimum height=27mm] (core) {
    FORMAL CORE\\[3pt]
    \normalfont\footnotesize attenuation + composition\\
    canonical three-valued result
  };
  \node[axisbox=green, minimum width=42mm, above left=12mm and 16mm of core] (principal) {
    \textbf{Principal evidence}\\
    keys · DIDs · WebAuthn\\
    HSM · SPIFFE
  };
  \node[axisbox=amber, minimum width=42mm, above right=12mm and 16mm of core] (exchange) {
    \textbf{Exchange}\\
    memory · file · HTTPS\\
    Iroh · TCP · Unix
  };
  \node[axisbox=purple, minimum width=42mm, below left=12mm and 16mm of core] (product) {
    \textbf{Product policy}\\
    profiles · status · assurance\\
    replay · budgets · receipts
  };
  \node[axisbox=blue, minimum width=42mm, below right=12mm and 16mm of core] (bindings) {
    \textbf{Bindings and tools}\\
    WASM · Python · Go · TS\\
    explanations · benchmarks
  };

  \draw[flow=green] (principal) -- (core);
  \draw[flow=amber] (exchange) -- (core);
  \draw[flow=purple] (core) -- (product);
  \draw[flow=blue] (core) -- (bindings);
\end{tikzpicture}}
\caption{\textbf{The algebra as a narrow semantic center.} Outer components
supply evidence, carry bytes, enforce state, and expose APIs; they do not
redefine attenuation or composition.}
\end{figure}

Seven principal methods can produce typed control evidence for the same
verifier. Exchange transports carry opaque proof bytes but cannot upgrade an
invalid proof. Product packages can add atomic replay and budget stores,
receipts, custody, profiles, and enforcement. Native and WASM boundaries can
consume the same canonical result. Deployment explanations can report which
trusted-context facts caused or prevented authorization.

These packages demonstrate architectural leverage, not additional formal
coverage. A correct algebra cannot compensate for an adapter that overstates
control, a profile that assigns unsafe meaning, a stale status source, or an
executor that ignores the sealed action.

# 9. Related work

## 9.1 Authorization and attenuation

Capability systems made authority an explicit transferable object
[@dennis1966capabilities]. SPKI authorization certificates bind permissions to
keys and support delegation [@ellison1999spki]. SDSI emphasizes linked local
namespaces [@rivest1996sdsi]. Macaroons support efficient contextual
attenuation through caveats [@birgisson2014macaroons]. Trust-management
systems such as PolicyMaker, KeyNote, and RT separate assertions, local policy,
and compliance checking [@blaze1996trust; @keynote1999; @li2002rt].

Auths-Proof shares explicit delegation and local policy but uses a closed
multidimensional order rather than a general policy language. That restriction
makes the core algebra finite at its production projection boundary and
tractable for exhaustive cross-language checking.

Proof-carrying code shifts the burden of supplying safety evidence to the
producer [@necula1997pcc]. Proof-carrying authentication applies a related idea
to distributed authorization judgments [@appel1999pca; @bauer2002pcaweb].
Auths-Proof authorization proofs are protocol evidence, not Lean proof terms;
the receiver still executes a fixed verifier.

## 9.2 Formal refinement

CompCert proves semantic preservation through a realistic compiler
[@leroy2009compcert]. seL4 proves refinement from an abstract specification to
a C implementation [@klein2009sel4]. Translation validation checks a particular
translation result [@pnueli1998translation]. Auths-Proof's generated boundary
is closer in spirit to a small translation-validation artifact, but its
generator is not verified and the rich projection is not yet translated.

Lean 4 supplies the theorem-proving environment [@demoura2021lean4]. Aeneas
uses functional translation to make safe Rust amenable to proof assistants
[@ho2022aeneas]. Verus provides a practical Rust-centered systems-verification
environment [@lattuada2024verus]. These systems define credible paths toward a
stronger implementation refinement than the current generated correspondence.

## 9.3 Model checking and testing

Kani and CBMC provide bit-precise bounded model checking over the shipping Rust
function [@delmas2026kani; @kroening2023cbmc]. This complements, rather than
duplicates, Lean: Kani sees Rust control flow and machine arithmetic, while Lean
proves unbounded properties of the mathematical definition.

Property-based testing and fuzzing remain valuable at the richer boundaries
that the Lean model excludes [@claessen2000quickcheck; @miller1990fuzz]. They
search large input spaces and preserve counterexamples, but passing campaigns
do not establish universal properties. The artifact therefore labels theorem,
exhaustive enumeration, bounded model checking, conformance testing, and fuzzing
separately.

# 10. Limitations and future work

\begin{limitbox}
\textbf{This paper does not claim full functional correctness of the verifier.}
It establishes an unbounded abstract algebra, a generated structural
correspondence, exhaustive finite agreement for declared domains, and bounded
checks of two shipping Rust functions.
\end{limitbox}

The most important limitations are:

**Model adequacy.** A correct proof of the wrong model is still wrong. Review of
the chosen authority dimensions and their order remains essential.

**Rich projection.** Permission sets, intervals, action constraints, budgets,
status, and assurance are reduced to Booleans by unverified Rust relations.

**Generator trust.** The generator is deterministic and drift-checked but not
proved semantics-preserving.

**Bound asymmetry.** Lean threshold theorems are unbounded. Rust vector replay
and the Kani threshold harness stop at 16, not the configurable hard maximum of
128.

**Incomplete release inventory.** Three named Lean helper/diversity theorems
are not currently listed in the 29-entry release manifest. The source builds
them, but the inventory checker does not require their names.

**Whole-verifier exclusion.** Parsing, graph resolution, signature
verification, evidence adapters, status, assurance matching, and final sealing
are tested but not refined to Lean.

**Toolchain trust.** Lean, Rust, Kani, CBMC, the build environment, and their
dependencies remain part of the evidence pipeline.

The next work should proceed in decreasing order of semantic leverage:

1. model the rich authority types and close the Rust projection gap;
2. include every public theorem in a generated release inventory;
3. translate the isolated safe-Rust algebra/projection with Aeneas or verify it
   with Verus;
4. extend symbolic threshold checks to the hard bound or prove a Rust function
   contract independent of enumeration;
5. connect canonical codec and graph-state invariants to the formal model;
6. produce proof-carrying build attestations for generated artifacts.

# 11. Conclusion

Formalization is valuable only to the extent that its relationship to shipping
behavior is understood. Auths-Proof does not solve that relationship by
assertion. It makes the authorization algebra small, generates the finite
language boundary from one contract, routes production Rust through that
boundary, proves the abstract properties in Lean, exports expected behavior
from Lean, replays every declared finite state in Rust, and model-checks the
same Rust functions with Kani.

The resulting claim is intentionally precise:

\begin{thesisbox}
\centering
\textbf{Auths-Proof's generated attenuation and threshold kernels agree with
their Lean definitions over the declared finite boundary, while Lean proves
the central algebraic properties without that bound.}
\end{thesisbox}

That claim is narrower than whole-program verification and substantially
stronger than parallel handwritten models. More importantly, it exposes the
remaining work: rich-domain projection, generator correctness, codecs,
cryptography, adapters, and complete verifier control flow. The system can now
improve along a visible refinement ladder rather than accumulating informal
confidence around an isolated proof artifact.

# References
