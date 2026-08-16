---
title: "Order, Evidence, and Effects: The Formal Semantics of Auths-Proof"
author: "bordumb · bordumbb@gmail.com"
date: 16 August 2026
abstract: |
  Auths-Proof is a proof-carrying authorization system whose formal
  development spans algebra, denotational semantics, transition systems,
  bounded arithmetic, and refinement of shipping Rust. Its central safety
  idea is order-theoretic: delegation may preserve or reduce authority, but it
  may not enlarge the set of complete authorization facts admitted by a
  parent. This paper reconstructs that idea from the Lean 4 artifact under
  `formal/`, presents the model as mathematics rather than source-code
  commentary, and explains how the abstract relations connect to executable
  decisions.

  The authority scope is a heterogeneous product of profile state, finite
  permission and audience sets, inclusive time intervals, an action-constraint
  preorder, optional budget ceilings, freshness policies, exact assurance
  identities, and pinned critical extensions. Lean proves component order
  laws, semantic monotonicity, canonical antisymmetry, downward closure of
  action coverage and evidence requirements, preservation of trust roots and
  critical extensions, strict decrease of delegation depth, finiteness of
  chains, unique accepted transitions, and sound and complete decision
  procedures. A separate three-valued algebra treats denial, uncertainty, and
  authorization as an ordered chain and proves threshold-classification
  properties. Product and lifecycle modules formalize configuration equality,
  checked arithmetic, capacity conservation, replay classification,
  credential ordering, provider-call entry, and recovery from unknown
  outcomes.

  To connect specification with implementation, Charon and Aeneas translate
  selected pure safe Rust functions into Lean. Representation maps and
  weakest-precondition proofs relate translated strings, bounded vectors,
  sets, intervals, constraints, budgets, and state machines to the handwritten
  model. The current assurance inventory contains 121 compiled declarations:
  66 rich-authority claims, 4 production-refinement claims, 13 product claims,
  22 lifecycle claims, and 16 composition claims. The artifact also records
  its limits: canonical decoding, cryptography, external evidence, stores, and
  provider behavior are not proved; representation validity is a premise; and
  the checked-in translation has an explicitly proved stale optional-budget
  case. The result is not whole-program verification. It is a precise,
  inspectable refinement argument for the security-critical pure semantics.
---

\newpage
\begin{multicols}{2}
\footnotesize
\tableofcontents
\end{multicols}
\newpage

# Introduction

Authorization is often presented as a Boolean predicate over a subject, an
operation, and a resource. That abstraction is useful, but it is too coarse
for a system in which authority is delegated, narrowed, bound to exact action
bytes, evaluated under uncertain evidence, and ultimately converted into an
irreversible external effect.

Auths-Proof separates four questions:

1. **Authenticity:** who produced a signed statement?
2. **Authority:** which actions can be justified from a trust root?
3. **Eligibility:** does a domain-specific policy admit this action in this
   context?
4. **Effect:** was the authorized action reserved, attempted, observed, and
   settled without duplication?

The formal directory concentrates on the pure semantics that make these
questions composable. It does not model public-key cryptography, byte decoding,
networks, clocks, databases, or providers. Instead, it gives mathematically
precise meanings to attenuation, coverage, evidence, decision composition,
bounded product policy, and effect lifecycle. It then connects selected
shipping Rust predicates to those meanings by mechanical translation.

The organizing judgment of the paper is:

\begin{thesisbox}
\centering
If a child authority is structurally below its parent, every complete
authorization fact admitted by the child is admitted by the parent.
\end{thesisbox}

Writing $S_c \atten S_p$ for structural attenuation and
$\denote{S}$ for the set of complete authorization facts admitted by a scope,
the fundamental implication is

$$
S_c \atten S_p
\quad\Longrightarrow\quad
\denote{S_c} \subseteq \denote{S_p}.
\tag{1}
$$

Equation (1) is the semantic form of least authority. A delegate can keep the
same authority or move downward, but cannot create a fact that becomes
authorized only after delegation. This connects order theory to access
control: the order is not chosen for elegance alone; it is justified by set
containment of admitted behaviors.

The work belongs to several research traditions. Trust-management systems
make delegation and authority explicit [@abadi1993calculus; @blaze1996trust].
Capability systems and caveat-based tokens motivate monotone restriction
[@birgisson2014macaroons]. Proof-carrying systems motivate portable evidence
checked by a small verifier [@necula1997pcc; @appel1999pca]. Order theory
supplies preorders, partial orders, products, and monotone maps
[@davey2002lattices]. Program logic supplies preconditions, postconditions,
and refinement [@hoare1969axiomatic; @dijkstra1975guarded]. Lean 4 provides the
machine-checked foundation [@demoura2021lean4], while Aeneas provides a route
from safe Rust to functional Lean [@ho2022aeneas].

## Contributions of the formal artifact

The development makes six concrete contributions.

**A heterogeneous authority order.** Authority is not reduced to a scalar.
Finite sets use inclusion, intervals use containment, action constraints use a
constructor-sensitive preorder, optional budgets have an unbounded top,
freshness requirements order by method and age, assurance is invariant, and
critical extensions become exactly pinned after their first declaration.

**A denotational safety theorem.** Structural attenuation implies semantic
attenuation: admission is downward closed for both actions and evidence.

**A well-founded delegation semantics.** Accepted edges preserve one trust
root, preserve pinned critical extensions, link exact grant identifiers,
strictly reduce remaining depth, and determine a unique child state.

**A three-valued composition algebra.** Denial, indeterminacy, and
authorization form a finite chain. Conjunction, disjunction, and threshold
classification preserve uncertainty rather than collapsing missing evidence
into permission.

**A formal lifecycle for effects.** The model separates decision, reservation,
intent, credential authorization, attempt, provider entry, settlement,
unknown outcome, and reconciliation. It proves key ordering and capacity
invariants.

**A production refinement chain.** Pure shipping Rust is translated to Lean,
then proved against the readable specification under explicit representation
premises. The proof inventory, statement hashes, axiom dependencies, source
closure, generated vectors, and mutation operators are themselves checked
artifacts.

## Reading the claims correctly

The paper uses three labels.

- **Definition** means a mathematical reconstruction of a Lean definition.
- **Checked theorem** means the named proposition is compiled in the current
  theorem inventory.
- **Interpretation** means a consequence or explanatory view useful to a human
  reader; it should not be confused with a separately inventoried Lean theorem.

This distinction matters. For example, the three truth values form a finite
chain and the implementations of `all` and `any` coincide with minimum and
maximum on that chain. Lean directly inventories commutativity, associativity,
and idempotence; this paper may use lattice language to explain those facts,
but it does not pretend that every familiar lattice law has its own exported
theorem.

## The proof architecture

The artifact is not one monolithic proof. It is a graph of specifications,
implementations, representation maps, and audit evidence.

\begin{figure}[H]
\centering
\resizebox{0.98\linewidth}{!}{%
\begin{tikzpicture}[node distance=8mm and 11mm]
  \node[axisbox=purple, minimum width=43mm, minimum height=19mm] (rich) {
    \textbf{Rich mathematical model}\\
    sets, intervals, constraints, chains
  };
  \node[axisbox=blue, minimum width=43mm, right=14mm of rich] (rust) {
    \textbf{Pure shipping Rust}\\
    authority, policy, lifecycle kernels
  };
  \node[axisbox=green, minimum width=43mm, right=14mm of rust] (aeneas) {
    \textbf{Translated Lean}\\
    Charon LLBC and Aeneas output
  };

  \node[axisbox=purple, minimum width=43mm, below=12mm of rich] (algebra) {
    \textbf{Algebra contract}\\
    truth order and 11 dimensions
  };
  \node[kernel, minimum width=43mm, below=12mm of rust] (refine) {
    REFINEMENT\\[-1pt]
    \normalfont\footnotesize translated result = rich result
  };
  \node[axisbox=amber, minimum width=43mm, below=12mm of aeneas] (premises) {
    \textbf{Representation premises}\\
    bounded, canonical, validated values
  };

  \node[card, minimum width=43mm, below=12mm of algebra] (vectors) {
    \textbf{Generated evidence}\\
    vectors and mutation witnesses
  };
  \node[axisbox=green, minimum width=43mm, below=12mm of refine] (inventory) {
    \textbf{121 audited declarations}\\
    exact names, statements, axioms
  };
  \node[card, minimum width=43mm, below=12mm of premises] (closure) {
    \textbf{Qualified source closure}\\
    tools, Rust sources, generated Lean
  };

  \node[kernel, minimum width=142mm, below=13mm of inventory] (gate) {
    READ-ONLY FORMAL GATE\\[-1pt]
    \normalfont\footnotesize build + audit + closure + drift + conformance
  };

  \draw[flow=blue] (rust) -- (aeneas);
  \draw[flow=purple] (rich) -- (refine);
  \draw[flow=green] (aeneas) -- (refine);
  \draw[flow=amber] (premises) -- (refine);
  \draw[flow=purple] (algebra) -- (vectors);
  \draw[flow=green] (refine) -- (inventory);
  \draw[flow=amber] (closure) -- (inventory);
  \draw[flow=green] (vectors) -- (gate);
  \draw[flow=green] (inventory) -- (gate);
  \draw[flow=green] (closure) -- (gate);
\end{tikzpicture}}
\caption{\textbf{The evidence graph.} The readable mathematical model and the
mechanically translated production functions meet in refinement theorems. The
assurance layer audits both the propositions and the source closure on which
they depend.}
\end{figure}

# Artifact map and methodological boundary

The Lean project is organized by mathematical concern rather than by one
end-to-end verifier function.

| Layer | Principal modules | Mathematical role |
|---|---|---|
| Finite algebra | `Generated/Algebra`, `Base`, `Composition` | Truth chain, conjunction, disjunction, thresholds, plan measures |
| Rich authority | `Rich/Types`, `Rich/Semantics`, `Rich/Theorems` | Scope order, denotation, delegation, coverage, decisions |
| Focused authority claims | `Authority`, `Attenuation` | Trust-root and critical-extension consequences |
| Product policy | `Product/*` | Commitments, checked arithmetic, eligibility, tightening |
| Effect lifecycle | `Lifecycle/*` | State transitions, capacity, replay, reconciliation |
| Rust refinement | `Refinement/Production` | Representation maps and equivalence to translated authority Rust |
| Assurance | `Theorems`, `AssuranceAudit`, manifest | Public inventory, exact statements, axiom audit, source closure |
| Qualification | `qualification/aeneas/*` | Pinned translation outputs, external models, executable cases |

The top-level `Auths.lean` imports the model. `Auths.Theorems` enumerates the
public theorem declarations. `Auths.AssuranceAudit` queries Lean's compiled
environment, prints each declaration's actual type, and computes its
transitive axiom set. This avoids a common anti-pattern: treating the presence
of a theorem-like string in source code as evidence that the intended theorem
still exists.

## What the formal core intentionally excludes

The model receives already validated semantic values and explicit facts. It
does not prove:

- canonical CBOR decoding or byte-for-byte re-encoding;
- signature schemes, key custody, or trust-registry behavior;
- evidence acquisition, wall-clock truth, or network freshness;
- database atomicity, crash durability, or concurrency control;
- external provider determinism or the truth of provider observations;
- the Rust compiler's machine-code output; or
- complete verifier control flow.

These exclusions are not incidental. They preserve a pure kernel in which
definitions are total and explicit. The complete system claim is therefore a
composition of proof, translation, generated conformance, testing, and trusted
boundaries rather than a single universal theorem.

\begin{boundarybox}
\textbf{Claim boundary.} Lean proves the pure relations and selected translated
Rust functions under their premises. It does not prove that arbitrary bytes
are valid Auths objects, that external facts are true, or that a remote effect
occurred. Those propositions require distinct evidence.
\end{boundarybox}

## Snapshot of the audited theorem inventory

The current `theoremInventory` contains 121 declarations.

| Family | Count | Examples |
|---|---:|---|
| Rich authority | 66 | component laws, semantic containment, chains, diagnostics |
| Production refinement | 4 | author scope, terminal coverage, delegation, explicit budget gap |
| Product policy | 13 | commitments, eligibility, arithmetic, translated arithmetic |
| Lifecycle | 22 | capacity, replay, effect ordering, translated transition kernel |
| Composition | 16 | truth algebra, thresholds, plan measures |

Auxiliary definitions and lemmas may compile without appearing in this public
inventory. The manifest is therefore a claim surface, not a count of every
fact Lean knows.

# The three-valued decision algebra

Authorization under incomplete evidence is not naturally Boolean. A negative
result may be permanent, or it may mean that a trustworthy fact is not yet
available. Auths-Proof uses

$$
\mathbb{T}_3 = \{\Denied,\Unknown,\Authorized\},
\qquad
\Denied \sqsubset \Unknown \sqsubset \Authorized.
\tag{2}
$$

The Lean function `Truth.rank` embeds this chain into $\Nat$:

$$
\rho(\Denied)=0,
\qquad
\rho(\Unknown)=1,
\qquad
\rho(\Authorized)=2,
$$

and defines $x\sqsubseteq y$ by $\rho(x)\leq\rho(y)$. Injectivity of $\rho$
is proved, so rank equality recovers truth equality.

## Conjunctive and disjunctive composition

Define

$$
x \mathbin{\wedge_3} y = \min_{\sqsubseteq}(x,y),
\qquad
x \mathbin{\vee_3} y = \max_{\sqsubseteq}(x,y).
\tag{3}
$$

Operationally, `all` denies if either branch denies, otherwise remains
indeterminate if either branch is indeterminate, and authorizes only when both
authorize. `any` authorizes if either branch authorizes, otherwise remains
indeterminate if either is indeterminate, and denies only when both deny.

| $x$ | $y$ | $x\wedge_3y$ | $x\vee_3y$ |
|---|---|---|---|
| $\Denied$ | $\Denied$ | $\Denied$ | $\Denied$ |
| $\Denied$ | $\Unknown$ | $\Denied$ | $\Unknown$ |
| $\Denied$ | $\Authorized$ | $\Denied$ | $\Authorized$ |
| $\Unknown$ | $\Unknown$ | $\Unknown$ | $\Unknown$ |
| $\Unknown$ | $\Authorized$ | $\Unknown$ | $\Authorized$ |
| $\Authorized$ | $\Authorized$ | $\Authorized$ | $\Authorized$ |

\begin{claimbox}{Checked theorem family: binary composition}
Lean proves commutativity, associativity, and idempotence for both
\texttt{all} and \texttt{any}. It also proves that the two-branch threshold at
one equals \texttt{any}, the threshold at two equals \texttt{all}, and increasing the threshold from one to two
cannot raise the result in the truth order.
\end{claimbox}

\begin{figure}[H]
\centering
\begin{tikzpicture}[node distance=13mm]
  \node[state=red, minimum width=28mm] (d) {$\Denied$\\[-1pt]\normalfont rank 0};
  \node[state=amber, minimum width=28mm, above=of d] (u) {$\Unknown$\\[-1pt]\normalfont rank 1};
  \node[state=green, minimum width=28mm, above=of u] (a) {$\Authorized$\\[-1pt]\normalfont rank 2};
  \draw[flow=muted] (d) -- node[right,note]{more informative permission} (u);
  \draw[flow=muted] (u) -- (a);
  \node[axisbox=purple, minimum width=49mm, right=26mm of u] (meet) {
    \textbf{all} $=\min$\\
    one denial is decisive
  };
  \node[axisbox=blue, minimum width=49mm, below=8mm of meet] (join) {
    \textbf{any} $=\max$\\
    one authorization is decisive
  };
  \draw[thinflow=purple,dashed] (meet.west) -- (u.east);
  \draw[thinflow=blue,dashed] (join.west) -- (u.east);
\end{tikzpicture}
\caption{\textbf{The truth chain.} Indeterminacy is neither authorization nor
permanent denial. Conjunction takes the lower result; disjunction takes the
higher result.}
\end{figure}

## Threshold classification

Let $k$ be the number of authorizing branches required, $a$ the number already
authorized, and $u$ the number indeterminate. The generated classifier is

$$
\Theta(k,a,u)=
\begin{cases}
\Authorized, & a\geq k,\\
\Unknown, & a<k\leq a+u,\\
\Denied, & a+u<k.
\end{cases}
\tag{4}
$$

These regions are exhaustive and disjoint. The first says the threshold has
already been met. The second says authorization is not yet established but
remains reachable if enough unknown branches resolve positively. The third
says even the optimistic completion cannot meet the threshold.

\begin{claimbox}{Checked theorem family: threshold soundness}
\texttt{authorized\_implies\_threshold\_met} proves
$\Theta=\Authorized\Rightarrow k\leq a$.
\texttt{denied\_implies\_threshold\_impossible} proves
$\Theta=\Denied\Rightarrow a+u<k$.
\texttt{indeterminate\_implies\_threshold\_reachable} proves
$\Theta=\Unknown\Rightarrow a<k\land k\leq a+u$.
\end{claimbox}

\begin{figure}[H]
\centering
\resizebox{0.83\linewidth}{!}{%
\begin{tikzpicture}[x=9mm,y=9mm]
  \draw[->,line width=0.8pt] (0,0) -- (9.4,0) node[right] {$a$ authorized};
  \draw[->,line width=0.8pt] (0,0) -- (0,6.8) node[above] {$u$ indeterminate};
  \fill[redwash] (0,0) -- (4.9,0) -- (0,4.9) -- cycle;
  \fill[amberwash] (0,5) -- (5,0) -- (5,6.3) -- (0,6.3) -- cycle;
  \fill[greenwash] (5,0) rectangle (9,6.3);
  \draw[red,line width=1.1pt] (0,5) -- (5,0);
  \draw[green,line width=1.1pt] (5,0) -- (5,6.3);
  \node[text=red,font=\sffamily\bfseries,align=center] at (1.6,1.3) {$a+u<k$\\DENIED};
  \node[text=amber,font=\sffamily\bfseries,align=center] at (2.6,4.7) {$a<k\leq a+u$\\INDETERMINATE};
  \node[text=green,font=\sffamily\bfseries,align=center] at (7.0,3.2) {$a\geq k$\\AUTHORIZED};
  \node[note] at (5,-0.55) {$k$};
\end{tikzpicture}}
\caption{\textbf{Threshold regions for fixed $k$.} The classifier separates
proved success, reachable success, and impossible success without assuming how
unknown branches will resolve.}
\end{figure}

## Outcomes and diagnostics

`Outcome` enriches truth with stable numerical diagnostics:

$$
\mathsf{Outcome}
=\mathsf{Authorized}
\mid\mathsf{Denied}(c)
\mid\mathsf{Indeterminate}(c)
\mid\mathsf{StructurallyInvalid}(c).
$$

Projection to $\mathbb{T}_3$ maps structural invalidity to denial. The helper
`canonicalCode(c_1,c_2)=\min(c_1,c_2)` is commutative, which gives a canonical
binary diagnostic independent of operand order. This is a deliberately narrow
result: the formal `Plan` module defines leaf enumeration and node count, but
does not yet export a general recursive authorization-plan correctness theorem.
Its inventory claims about `visit` and `cost` are definitional equalities.

# Authority as a heterogeneous product order

The rich model is parameterized by a vocabulary $V$ of opaque carrier types:

$$
V=(\mathsf{Principal},\mathsf{Profile},\mathsf{Permission},
\mathsf{Audience},\mathsf{Digest},\mathsf{BudgetAlg},
\mathsf{StatusMethod},\mathsf{Assurance},\mathsf{GrantId},
\mathsf{ExtId},\mathsf{ExtBody}).
$$

Each carrier has decidable equality and no other assumed structure. In
particular, the mathematical model does not order principals, permissions, or
digests by an arbitrary numerical encoding. Production refinement later
instantiates these carriers with exact byte-oriented representations.

An authority scope is the tuple

$$
S=(\Phi,P,I,A,C,B,T,Q,X),
\tag{5}
$$

where

- $\Phi$ is profile-selection state;
- $P$ is a finite permission set;
- $I$ is a well-formed inclusive validity interval;
- $A$ is a finite audience set;
- $C$ is an action-body constraint;
- $B$ is an optional budget ceiling;
- $T$ is a status-evidence policy;
- $Q$ is an assurance-policy identity; and
- $X$ is an optional pinned critical-extension sequence.

The attenuation relation $S_c\atten S_p$ is the conjunction of a relation for
every coordinate. The coordinates are intentionally heterogeneous.

\begin{figure}[H]
\centering
\resizebox{0.98\linewidth}{!}{%
\begin{tikzpicture}[node distance=6mm and 6mm]
  \node[axisbox=purple, minimum width=27mm] (profile) {profile\\select once};
  \node[axisbox=purple, minimum width=27mm, right=of profile] (perm) {permissions\\subset};
  \node[axisbox=purple, minimum width=27mm, right=of perm] (valid) {validity\\contained interval};
  \node[axisbox=purple, minimum width=27mm, right=of valid] (aud) {audiences\\subset};
  \node[axisbox=purple, minimum width=27mm, right=of aud] (action) {action body\\preorder};

  \node[axisbox=blue, minimum width=27mm, below=8mm of profile] (budget) {budget\\optional ceiling};
  \node[axisbox=blue, minimum width=27mm, right=of budget] (status) {status\\fresher or exact};
  \node[axisbox=blue, minimum width=27mm, right=of status] (assure) {assurance\\exact identity};
  \node[axisbox=blue, minimum width=27mm, right=of assure] (ext) {extensions\\pin exactly};
  \node[axisbox=green, minimum width=27mm, right=of ext] (depth) {chain depth\\strict decrease};

  \node[kernel, minimum width=160mm, below=12mm of assure] (product) {
    $S_c \preccurlyeq S_p$ iff every scope coordinate attenuates\\[-1pt]
    \normalfont\footnotesize linkage and strict depth are checked at the chain transition
  };

  \foreach \n in {profile,perm,valid,aud,action,budget,status,assure,ext,depth}
    \draw[thinflow=muted] (\n.south) -- (product.north);
\end{tikzpicture}}
\caption{\textbf{The authority product.} The scope order is a conjunction of
relations chosen for each domain. Strict depth is not a partial-order
coordinate; it is a well-founded transition guard.}
\end{figure}

## Finite sets and validity intervals

Permissions and audiences use finite-set inclusion:

$$
P_c\atten P_p \iff P_c\subseteq P_p,
\qquad
A_c\atten A_p \iff A_c\subseteq A_p.
\tag{6}
$$

An inclusive window is $I=[s,f]$ with a constructor proof $s\leq f$.
Containment is

$$
[s_c,f_c]\atten[s_p,f_p]
\iff s_p\leq s_c\land f_c\leq f_p.
\tag{7}
$$

Lean proves reflexivity, transitivity, and antisymmetry for both finite-set
inclusion and interval containment. It also proves membership and interval
coverage monotone: an item or action window covered by a child remains covered
by a parent.

## Profile selection

A profile scope is $(R,s)$, where $R$ is the invariant root-allowed set and
$s\in\{\mathsf{none}\}\cup R$ is an optional selected profile. The type stores
the proof that every selected profile belongs to $R$. Its order preserves $R$
exactly and permits only

$$
\mathsf{none}\to\mathsf{none},
\qquad
\mathsf{none}\to\mathsf{some}(p),
\qquad
\mathsf{some}(p)\to\mathsf{some}(p).
\tag{8}
$$

Selection is therefore a one-way refinement. It cannot be cleared or changed
after it is fixed. Before selection, any $p\in R$ is covered; after selection,
only the selected profile is covered.

## Action constraints

The action-body language is closed:

$$
C ::= \mathsf{Any}
\mid \mathsf{Exact}(d)
\mid \mathsf{Allowed}(D),
$$

where $D$ is a finite digest set. Its denotation is

$$
\denote{\mathsf{Any}}=\mathcal{D},
\quad
\denote{\mathsf{Exact}(d)}=\{d\},
\quad
\denote{\mathsf{Allowed}(D)}=D.
\tag{9}
$$

The structural relation follows denotational inclusion but respects the
constructors explicitly:

$$
\begin{aligned}
C\atten\mathsf{Any} &\quad\text{always},\\
\mathsf{Exact}(x)\atten\mathsf{Exact}(y) &\iff x=y,\\
\mathsf{Exact}(x)\atten\mathsf{Allowed}(Y) &\iff x\in Y,\\
\mathsf{Allowed}(X)\atten\mathsf{Exact}(y) &\iff X\subseteq\{y\},\\
\mathsf{Allowed}(X)\atten\mathsf{Allowed}(Y) &\iff X\subseteq Y.
\end{aligned}
\tag{10}
$$

This relation is reflexive and transitive. It is not structurally
antisymmetric on raw syntax because `Exact(d)` and `Allowed({d})` admit the same
digest and attenuate each other. The model therefore proves two different
statements:

1. mutual attenuation implies extensional equivalence of allowed digests; and
2. if singleton allow-lists are excluded by a canonicality predicate, mutual
   attenuation implies constructor equality.

This is an important formal-methods lesson: quotient-like semantic equality
and representation equality should not be conflated.

## Optional budgets

A budget ceiling is a pair $(\alpha,n)$ of an opaque algebra identity and a
natural-number value. The optional order treats absence as unbounded top:

$$
B_c\atten B_p \iff
\begin{cases}
\mathsf{true}, & B_p=\mathsf{none},\\
\mathsf{false}, & B_c=\mathsf{none},\ B_p=\mathsf{some}(\alpha,n),\\
\alpha_c=\alpha_p\land n_c\leq n_p,
  & B_c=\mathsf{some}(\alpha_c,n_c),\ B_p=\mathsf{some}(\alpha_p,n_p).
\end{cases}
\tag{11}
$$

Terminal coverage has a different argument orientation. A ceiling covers a
request when

$$
\mathsf{budgetCovers}(B,R) \iff
\begin{cases}
\mathsf{true}, & B=\mathsf{none},\\
\mathsf{false}, & B=\mathsf{some}(-),\ R=\mathsf{none},\\
\alpha_R=\alpha_B\land n_R\leq n_B, & B=\mathsf{some}(\alpha_B,n_B),\ R=\mathsf{some}(\alpha_R,n_R).
\end{cases}
\tag{12}
$$

The second case is security-critical. An absent request states no action-level
bound, so it is not covered by a present ceiling. Lean proves budget-order
reflexivity, transitivity, antisymmetry, and monotonicity of coverage.

## Status, assurance, and critical extensions

A status policy is either

$$
\mathsf{ExpiryOnly}
\quad\text{or}\quad
\mathsf{SnapshotRequired}(m,\delta),
$$

where $m$ is an opaque method and $\delta>0$ is a maximum age. Every policy is
below `ExpiryOnly`. Two snapshot policies compare only when their methods are
equal, and the child maximum age is no greater than the parent's. Thus a
fresher requirement is narrower. Lean proves that satisfaction is monotone
from child to parent.

Assurance is not modeled as a lattice. It is preserved by exact identity:
$Q_c=Q_p$. This deliberately avoids inventing an ordering between assurance
schemes.

Critical extensions follow a lock-in relation. Let $X$ be either `none` or a
canonical ordered sequence of at most 32 identifier-payload pairs. Then

$$
X_c\atten X_p \iff
\begin{cases}
\mathsf{true}, & X_p=\mathsf{none},\\
\mathsf{false}, & X_c=\mathsf{none},\ X_p=\mathsf{some}(E),\\
E_c=E_p, & X_c=\mathsf{some}(E_c),\ X_p=\mathsf{some}(E_p).
\end{cases}
\tag{13}
$$

The first accepted edge may declare a critical-extension sequence. Every later
edge must preserve it exactly. Unlike permissions and audiences, extensions
are represented by an ordered list because the shipping predicate compares
canonical vectors positionally. Distinct identifiers and the cardinality
bound are stored as constructor obligations.

# Denotational authorization semantics

The product order becomes a security statement only after scopes are given a
meaning. Auths-Proof defines that meaning over actions and trusted evidence
facts.

## Actions and evidence

An action carries

$$
a=(\mathit{actor},\mathit{terminalGrant},\mathit{profile},
\mathit{permission},\mathit{window},\mathit{audience},
\mathit{bodyDigest},\mathit{requestedBudget}).
$$

Evidence facts carry an optional status method, a status age, and an assurance
identity. Complete authorization facts are a pair $F=(a,e)$.

Scope-level action coverage is

$$
\begin{aligned}
\mathsf{ActionCovers}(S,a) \iff {}&
\mathsf{profileAllows}(\Phi,a.profile)\\
&\land a.permission\in P\\
&\land a.window\subseteq I\\
&\land a.audience\in A\\
&\land \mathsf{constraintAllows}(C,a.bodyDigest)\\
&\land \mathsf{budgetCovers}(B,a.requestedBudget).
\end{aligned}
\tag{14}
$$

Evidence satisfaction is

$$
\mathsf{EvidenceSatisfied}(S,e)
\iff \mathsf{statusSatisfied}(T,e)\land e.assurance=Q.
\tag{15}
$$

Finally,

$$
\mathsf{Admits}(S,F)
\iff \mathsf{ActionCovers}(S,F.action)
\land \mathsf{EvidenceSatisfied}(S,F.evidence).
\tag{16}
$$

Define the denotation

$$
\denote{S}=\{F\mid\mathsf{Admits}(S,F)\}.
\tag{17}
$$

This is the bridge between access control and order theory.

## Structural soundness

The semantic attenuation relation is extensional:

$$
S_c\atten_{\mathrm{sem}}S_p
\iff \forall F.\ \mathsf{Admits}(S_c,F)\Rightarrow
\mathsf{Admits}(S_p,F).
\tag{18}
$$

Equivalently, $\denote{S_c}\subseteq\denote{S_p}$.

\begin{theorem}[Structural attenuation is semantically sound]
If $S_c\atten S_p$, then $S_c\atten_{\mathrm{sem}}S_p$.
\end{theorem}

The Lean proof factors by concern. `action_coverage_downward_closed` uses
profile monotonicity, set membership monotonicity, interval transitivity,
constraint allowance monotonicity, and budget coverage monotonicity.
`evidence_requirements_downward_closed` uses status-satisfaction monotonicity
and assurance equality. `complete_admission_downward_closed` combines them.
`structural_scope_le_implies_semantic_attenuation` packages the result as
Equation (18).

\begin{figure}[H]
\centering
\begin{tikzpicture}
  \fill[bluewash] (0,0) ellipse (65mm and 31mm);
  \draw[blue,line width=1pt] (0,0) ellipse (65mm and 31mm);
  \fill[purplewash] (0,0) ellipse (39mm and 19mm);
  \draw[purple,line width=1pt] (0,0) ellipse (39mm and 19mm);
  \node[text=blue2,font=\sffamily\bfseries] at (0,24mm)
    {$\denote{S_p}$ parent-admitted facts};
  \node[text=purple,font=\sffamily\bfseries,align=center] at (0,0)
    {$\denote{S_c}$\\child-admitted facts};
  \node[axisbox=green, minimum width=49mm] at (91mm,0) (law) {
    $S_c\preccurlyeq S_p$\\[2pt]
    $\Longrightarrow$\\[2pt]
    $\denote{S_c}\subseteq\denote{S_p}$
  };
  \draw[flow=green] (39mm,0) -- (law.west);
\end{tikzpicture}
\caption{\textbf{Denotational attenuation.} A narrower scope may remove
authorized facts, but cannot add a fact outside the parent's authorization
denotation.}
\end{figure}

## Preorder, canonical partial order, and equivalence

Semantic attenuation is reflexive and transitive because subset is reflexive
and transitive. Mutual semantic attenuation defines extensional equivalence.
The structural scope relation is also reflexive and transitive.

Raw action-constraint syntax prevents global structural antisymmetry, as noted
in Section 4.3. Under canonical action constraints, however, every component is
antisymmetric. Lean then proves

$$
S_1\atten S_2\land S_2\atten S_1
\quad\Longrightarrow\quad S_1=S_2.
\tag{19}
$$

Thus the development uses the correct algebraic level for each question:

- a preorder for raw representations;
- semantic equivalence for denotations; and
- a partial order for canonical representatives.

## Decidability

Every carrier supplies decidable equality, and every component relation is
decidable. `structuralScopeLeDecide` computes a Boolean, and Lean proves

$$
\mathsf{structuralScopeLeDecide}(S_c,S_p)=\mathsf{true}
\iff S_c\atten S_p.
\tag{20}
$$

This theorem is small but architecturally important. The mathematical relation
is not merely axiomatized; it has a decision procedure whose positive result
is exactly the declared V1 relation.

# Delegation as a well-founded transition system

Scope order alone does not express identity linkage, trust roots, grant
lineage, or chain termination. These live in `ChainState`:

$$
q=(r,s,S,d,g),
\tag{21}
$$

where $r$ is the root principal, $s$ the current subject, $S$ the authority
scope, $d\in\Nat$ the remaining depth, and $g$ an optional identifier of the
last applied grant.

## Rootedness and linkage

The local predicate

$$
\mathsf{rooted}(q)
\iff g\neq\mathsf{none}\ \lor\ r=s
\tag{22}
$$

states that either an accepted edge has already been applied or a fresh state
still speaks for its root. A proposed grant $h$ preserves the root when

$$
\mathsf{rootPreserved}(q,h)
\iff \mathsf{rooted}(q)\land h.issuer=s.
\tag{23}
$$

It is linked when, additionally, $h.parent=g$. These are local semantic facts;
the formal module does not reverify signatures or reconstruct a proof graph.

The first edge of a fresh chain must be issued by the root itself. Every
accepted edge is issued by the current subject and copies the root into its
child. An unrooted state delegates nothing and authorizes no terminal action.

## Accepted transition

A grant carries its issuer, new subject, selected profile, narrowed scope
coordinates, remaining depth, parent grant identifier, and critical
extensions. It passes scope and depth checks when

$$
d>0
\land h.depth<d
\land \mathsf{GrantScopeChecks}(S,h).
\tag{24}
$$

If linked and checked, `acceptedNextState` deterministically constructs

$$
q'=(r,h.subject,\mathsf{acceptedScope}(S,h),h.depth,
\mathsf{some}(h.id)).
\tag{25}
$$

The proposition `delegates(q,id,h,q')` says exactly that linkage holds and
$q'$ is this constructed state for some proof of the checks.

\begin{claimbox}{Checked theorem family: accepted delegation}
Lean proves that accepted evaluation is equivalent to \texttt{delegates}, that the
accepted state is unique, that the child scope is below the parent scope, that
subject and last-grant fields update exactly, and that remaining depth strictly
decreases.
\end{claimbox}

## Finiteness and transitive attenuation

The strict relation

$$
q'\prec_d q \iff q'.depth<q.depth
$$

is well-founded by the natural-number measure. For a delegation chain starting
at $q_0$ with successor list $L$, Lean proves

$$
|L|\leq q_0.depth.
\tag{26}
$$

Hence no accepted chain can be infinite, even if every scope coordinate stays
unchanged. Strict depth is a transition measure, not another reflexive
authority coordinate.

For two accepted edges $q_0\to q_1\to q_2$, transitivity of the product order
gives

$$
q_2.scope\atten q_0.scope.
\tag{27}
$$

More generally, every reachable state remains under the starting root, is
rooted, and preserves any critical-extension sequence pinned at the start.

\begin{figure}[H]
\centering
\resizebox{0.96\linewidth}{!}{%
\begin{tikzpicture}[node distance=14mm and 17mm]
  \node[state=blue, minimum width=33mm] (q0) {$q_0$\\root subject\\depth $d$};
  \node[state=purple, minimum width=33mm, right=of q0] (q1) {$q_1$\\delegate 1\\depth $d_1<d$};
  \node[state=purple, minimum width=33mm, right=of q1] (q2) {$q_2$\\delegate 2\\depth $d_2<d_1$};
  \node[state=purple, minimum width=33mm, right=of q2] (qn) {$q_n$\\terminal subject\\depth $d_n$};

  \draw[flow=blue] (q0) -- node[above,note]{linked grant} (q1);
  \draw[flow=blue] (q1) -- node[above,note]{linked grant} (q2);
  \draw[flow=blue,dashed] (q2) -- node[above,note]{$\cdots$} (qn);

  \node[note, below=11mm of q0] (r0) {same root $r$};
  \node[note, below=11mm of q1] (r1) {same root $r$};
  \node[note, below=11mm of q2] (r2) {same root $r$};
  \node[note, below=11mm of qn] (rn) {same root $r$};
  \draw[thinflow=green] (q0) -- (r0);
  \draw[thinflow=green] (q1) -- (r1);
  \draw[thinflow=green] (q2) -- (r2);
  \draw[thinflow=green] (qn) -- (rn);

  \draw[decorate,decoration={brace,mirror,amplitude=5pt},purple,line width=0.9pt]
    ($(q0.south west)+(0,-20mm)$) -- ($(qn.south east)+(0,-20mm)$)
    node[midway,below=7pt,note] {$n\leq d$ and $scope(q_n)\preccurlyeq scope(q_0)$};
\end{tikzpicture}}
\caption{\textbf{A delegation chain.} Root identity is invariant, scope moves
downward, and a natural-number variant makes the chain finite.}
\end{figure}

## Terminal coverage and lineage

Terminal coverage strengthens scope-level action coverage with chain facts:

$$
\begin{aligned}
\mathsf{TerminalCovers}(q,a)\iff {}&
\mathsf{rooted}(q)\\
&\land a.actor=q.subject\\
&\land a.terminalGrant=q.lastGrant\\
&\land \mathsf{ActionCovers}(q.scope,a).
\end{aligned}
\tag{28}
$$

The evaluator checks these predicates in a fixed first-failure order. Lean
proves

$$
\mathsf{evaluateCoverage}(q,a)=\mathsf{authorized}
\iff \mathsf{TerminalCovers}(q,a).
\tag{29}
$$

It also proves every returned denial is incompatible with terminal coverage.
If a child action is covered after an accepted edge, scope monotonicity implies
that the action was also within the parent's scope. The actor and terminal
grant naturally differ across the edge, so the theorem is stated for
`actionCovers`, not for full terminal linkage.

## Critical extensions and falsifiability

The generated attenuation projection contains eleven Booleans:

$$
(b_{root},b_{depth},b_{profile},b_{perm},b_{valid},b_{aud},
b_{action},b_{budget},b_{status},b_{assurance},b_{ext}).
$$

Acceptance is their conjunction. A Boolean dimension would be vacuous if the
projection filled it with the literal `true`. The formal development therefore
proves not only that accepted projection implies root and extension
requirements, but that each dimension is exact and falsifiable.

For root preservation,

$$
b_{root}=\mathsf{true}
\iff \mathsf{rootPreserved}(q,h),
\tag{30}
$$

and a foreign issuer forces $b_{root}=\mathsf{false}$. For critical
extensions,

$$
b_{ext}=\mathsf{true}
\iff \mathsf{extensionsLe}(\mathsf{some}(h.extensions),q.scope.extensions),
\tag{31}
$$

and an altered pinned sequence forces $b_{ext}=\mathsf{false}$. No other true
dimension can rescue either failure because the aggregator is conjunction.

\begin{figure}[H]
\centering
\begin{tikzpicture}[node distance=10mm and 15mm]
  \node[axisbox=amber, minimum width=45mm] (unbound) {
    parent extensions = none\\
    first edge may choose $E$
  };
  \node[kernel, minimum width=42mm, right=of unbound] (pin) {
    PIN $E$\\[-1pt]
    \normalfont\footnotesize accepted first edge
  };
  \node[axisbox=green, minimum width=45mm, right=of pin] (bound) {
    parent extensions = some $E$\\
    child must carry exact $E$
  };
  \node[axisbox=red, minimum width=45mm, below=13mm of bound] (reject) {
    none or $E'\neq E$\\
    delegation denied
  };
  \draw[flow=blue] (unbound) -- (pin);
  \draw[flow=green] (pin) -- (bound);
  \draw[flow=green,loop above] (bound) to node[above,note]{preserve $E$} (bound);
  \draw[flow=red] (bound) -- (reject);
\end{tikzpicture}
\caption{\textbf{Critical-extension lock-in.} The anchor is initially
uncommitted. Once an accepted edge selects a sequence, later edges may neither
remove nor alter it.}
\end{figure}

# Executable decisions and ordered diagnostics

The rich relations are propositions, but the system must return a stable
decision. The formal development defines three evaluators with explicit
first-failure order.

## Grant evaluation

`evaluateGrant(q,id,h)` returns either an accepted next state or one of two
diagnostics:

$$
\mathsf{BrokenGrantChain}
\quad\text{or}\quad
\mathsf{DelegationExpanded}.
$$

It tests linkage first. If linkage fails, the chain diagnostic is returned. If
linkage succeeds but scope or depth checks fail, expansion is returned. If both
hold, it constructs the unique accepted state.

Lean proves both extensional correctness and diagnostic partition:

$$
\exists q'.\ \mathsf{evaluateGrant}(q,id,h)=\mathsf{accepted}(q')
\iff \mathsf{linked}(q,h)\land\mathsf{scopeDepthChecks}(q,h),
\tag{32}
$$

$$
\begin{aligned}
\mathsf{BrokenGrantChain}
&\iff \neg\mathsf{linked}(q,h),\\
\mathsf{DelegationExpanded}
&\iff \mathsf{linked}(q,h)\land
\neg\mathsf{scopeDepthChecks}(q,h).
\end{aligned}
\tag{33}
$$

## Author-planning evaluation

Before signing or invoking custody, `evaluateAuthorScope` compares a proposed
child scope to a parent. It checks dimensions in this order:

$$
\mathsf{profile}prec
\mathsf{permissions}prec
\mathsf{validity}prec
\mathsf{audiences}prec
\mathsf{actionConstraint}prec
\mathsf{budget}prec
\mathsf{depth}prec
\mathsf{status}prec
\mathsf{assurance}prec
\mathsf{extensions}.
\tag{34}
$$

The theorem `author_planning_diagnostic_sound_complete` proves that acceptance
is equivalent to structural scope attenuation plus strict valid depth:

$$
\mathsf{evaluateAuthorScope}=\mathsf{accepted}
\iff S_c\atten S_p\land 0<d_p\land d_c<d_p.
\tag{35}
$$

The fixed order is functional determinism, not a timing-security claim. A
system may expose the first diagnostic for explainability while separately
considering whether timing and cache behavior reveal sensitive policy facts.

## Terminal coverage evaluation

`evaluateCoverage` checks root and lineage facts as one leading guard, then
permission membership, validity containment, audience membership, action-body
constraint, and budget coverage. The leading guard maps actor mismatch,
terminal-grant mismatch, invalid profile selection, and unrooted state to
`BrokenGrantChain`; later dimensions receive more specific diagnostics.

This design makes the success theorem strong and the diagnostic vocabulary
stable. It does not claim that every semantic falsehood has a unique reason;
when several checks fail, the evaluator intentionally selects the earliest.

\begin{figure}[H]
\centering
\resizebox{0.95\linewidth}{!}{%
\begin{tikzpicture}[node distance=7mm]
  \node[state=blue, minimum width=27mm] (link) {root + actor\\+ grant + profile};
  \node[state=purple, minimum width=25mm, right=of link] (perm) {permission\\member};
  \node[state=purple, minimum width=25mm, right=of perm] (time) {window\\contained};
  \node[state=purple, minimum width=25mm, right=of time] (aud) {audience\\member};
  \node[state=purple, minimum width=25mm, right=of aud] (body) {body digest\\allowed};
  \node[state=purple, minimum width=25mm, right=of body] (budget) {budget\\covered};
  \node[state=green, minimum width=27mm, right=of budget] (ok) {AUTHORIZED};
  \draw[flow=blue] (link) -- (perm);
  \draw[flow=blue] (perm) -- (time);
  \draw[flow=blue] (time) -- (aud);
  \draw[flow=blue] (aud) -- (body);
  \draw[flow=blue] (body) -- (budget);
  \draw[flow=green] (budget) -- (ok);
  \foreach \n/\lab in {link/broken chain,perm/permission,time/validity,aud/audience,body/body,budget/budget}
    \draw[thinflow=red] (\n.south) -- ++(0,-9mm) node[below,note,text=red]{\lab denial};
\end{tikzpicture}}
\caption{\textbf{Ordered terminal-coverage diagnostics.} Success means every
predicate holds. Failure reports the earliest false dimension in the specified
order.}
\end{figure}

# Product policy: commitments, eligibility, and arithmetic

The authority kernel answers whether delegated authority covers an action.
Product policy answers whether a closed, versioned domain evaluator admits it
under a fixed context. The formal modules keep that distinction explicit.

## Semantic and configuration commitments

A semantic identity is a nonempty byte sequence. A digest is exactly 32 bytes.
A policy commitment records

$$
(type,version,canonicalization,policyDigest,evaluatorSemantics),
$$

with a proof that the version is positive. A configuration commitment records

$$
(semantics,canonicalization,digest,implementation?),
\tag{36}
$$

where the implementation identity may be unpinned.

Required and executed configurations match in lexicographic diagnostic order:

1. semantic identity;
2. canonicalization identity;
3. digest; and
4. implementation identity, if the required commitment pins one.

Formally,

$$
\mathsf{match}(r,e)=
\begin{cases}
\mathsf{SemanticMismatch}, & r_s\neq e_s,\\
\mathsf{CanonicalizationMismatch}, & r_c\neq e_c,\\
\mathsf{DigestMismatch}, & r_d\neq e_d,\\
\mathsf{ImplementationMismatch}, & r_i=\mathsf{some}(x)\land e_i\neq\mathsf{some}(x),\\
\mathsf{Matches}, & \text{otherwise}.
\end{cases}
\tag{37}
$$

Reflexivity and functional determinism are checked. More importantly,
`gateConfiguration` turns any mismatch into denial before returning an
eligible result.

## Three-way eligibility

Product evaluation returns exactly one of

$$
\mathsf{Eligible}(O),
\quad
\mathsf{Denied}(code,stage),
\quad
\mathsf{Indeterminate}(code,stage).
\tag{38}
$$

Eligible output $O$ commits to reservation intents and obligations, carries
counts bounded by 32, and carries canonical bytes bounded by 65,536. Lean
proves the three-way partition and that any result classified as eligible has
complete output commitments.

\begin{claimbox}{Checked product-safety claims}
A configuration mismatch is never eligible. Every eligible value contains an
\texttt{OutputCommitments} record satisfying its construction bounds. These are
pure-contract properties; the truth of a domain's evidence and the durability
of its eventual reservation remain outside this module.
\end{claimbox}

## Closed evaluators and fixed-context tightening

Rather than invent a universal policy language, the Lean record
`ClosedEvaluator` packages a domain's own policy type $P$, context type $C$,
evaluator $E:P\to C\to Eligibility$, tightening relation $\atten_P$, and
output-refinement relation $\atten_O$.

Its central law is

$$
p_c\atten_P p_p
\land E(p_c,c)=\mathsf{Eligible}(o_c)
\Longrightarrow
\exists o_p.\ E(p_p,c)=\mathsf{Eligible}(o_p)
\land o_c\atten_O o_p.
\tag{39}
$$

The context $c$ is fixed. Tightening therefore cannot exploit a different
clock, evidence snapshot, configuration, or state value. The theorem
`fixed_context_tightening` simply exposes the law stored in the record; each
concrete domain must supply the proof when it instantiates the evaluator.

## Unit-aware checked arithmetic

A `UnitQuantity` stores a byte-exact unit, a natural amount, and a proof that
the amount is no greater than

$$
U_{64}=2^{64}-1=18{,}446{,}744{,}073{,}709{,}551{,}615.
$$

Addition rejects unequal units and overflow. Subtraction rejects unequal units
and underflow. Division rejects zero. Successful results preserve the unit and
the natural-number operation exactly.

\begin{align}
\mathsf{checkedAdd}(x,y)=\mathsf{ok}(z)
&\Rightarrow z.amount=x.amount+y.amount\leq U_{64},\tag{40}\\
\mathsf{checkedSub}(x,y)=\mathsf{ok}(z)
&\Rightarrow y.amount\leq x.amount,\tag{41}\\
\mathsf{checkedDiv}(x,0)=\mathsf{ok}(z)
&\Rightarrow \bot.\tag{42}
\end{align}

The production-refinement module separately proves that Aeneas-translated
Rust checked addition, subtraction, multiplication, and division agree with
natural-number specifications at the `u64` boundary.

# Effect lifecycle as a guarded transition system

Authorization is repeatable; an external effect may not be. The lifecycle
model begins after pure authority and product eligibility and describes when a
runtime may reserve capacity, obtain credentials, enter a provider call,
settle, or reconcile uncertainty.

## States, operations, and gates

The state set is

$$
\begin{aligned}
\mathcal{S}=\{&DecisionRecorded,Reserved,ExecutionIntentRecorded,Executing,\\
&Committed,Released,OutcomeUnknown,\\
&ReconciledCommitted,ReconciledReleased\}.
\end{aligned}
$$

The transition function is total:

$$
\delta:Option(\mathcal{S})\times\mathcal{O}\times\mathcal{G}
\to\mathcal{C},
\tag{43}
$$

where $\mathcal{O}$ is the operation code, $\mathcal{G}$ is a Boolean record of
gates, and $\mathcal{C}$ is either an applied state, observation-only result,
terminal response, illegal transition, or stable rejection code.

The gate record includes core authorization, policy eligibility,
configuration equality, revocation, expiry, capacity, execution intent,
credential authorization, attempt presence, provider entry, cancellation,
definite effect, definite non-effect, and reconciliation freshness and match.

\begin{figure}[H]
\centering
\resizebox{0.99\linewidth}{!}{%
\begin{tikzpicture}[node distance=12mm and 14mm]
  \node[state=blue, minimum width=29mm] (none) {no record};
  \node[state=blue, minimum width=31mm, right=of none] (decision) {decision\\recorded};
  \node[state=purple, minimum width=29mm, right=of decision] (reserved) {reserved};
  \node[state=purple, minimum width=35mm, right=of reserved] (intent) {execution intent\\recorded};
  \node[state=amber, minimum width=29mm, right=of intent] (executing) {executing};

  \node[state=green, minimum width=29mm, below=18mm of executing] (commit) {committed};
  \node[state=green, minimum width=29mm, below=18mm of reserved] (release) {released};
  \node[state=red, minimum width=33mm, right=17mm of executing] (unknown) {outcome\\unknown};
  \node[state=green, minimum width=36mm, below=15mm of unknown] (rcommit) {reconciled\\committed};
  \node[state=green, minimum width=36mm, right=11mm of rcommit] (rrelease) {reconciled\\released};

  \draw[flow=blue] (none) -- node[above,note]{record decision} (decision);
  \draw[flow=blue] (decision) -- node[above,note]{reserve} (reserved);
  \draw[flow=blue] (reserved) -- node[above,note]{record intent} (intent);
  \draw[flow=amber] (intent) -- node[above,note]{start attempt} (executing);
  \draw[flow=green] (executing) -- node[right,note]{proved effect} (commit);
  \draw[flow=green] (reserved) -- node[left,note]{safe release} (release);
  \draw[thinflow=green] (intent) -- (release);
  \draw[thinflow=green] (executing) -- node[above,note,sloped]{proved non-effect} (release);
  \draw[flow=red] (executing) -- node[above,note]{ambiguous result} (unknown);
  \draw[flow=green] (unknown) -- node[left,note]{fresh effect proof} (rcommit);
  \draw[flow=green] (unknown) -- node[right,note]{fresh non-effect proof} (rrelease);
  \draw[thinflow=amber,loop above] (intent) to node[above,note]{authorize credential} (intent);
  \draw[thinflow=amber,loop above] (executing) to node[above,note]{provider entered} (executing);

  \node[note,text=green, below=8mm of release] {terminal};
  \node[note,text=green, below=8mm of commit] {terminal};
  \node[note,text=green, below=8mm of rcommit] {terminal};
  \node[note,text=green, below=8mm of rrelease] {terminal};
\end{tikzpicture}}
\caption{\textbf{The effect lifecycle.} Unknown outcome is not equivalent to
release. It retains uncertainty until fresh reconciliation proves effect or
non-effect. Self-loops represent ordered side-condition updates that do not
change the lifecycle state value.}
\end{figure}

## Safety ordering

The transition function encodes several non-commuting requirements.

**Decision before reservation.** The first state is created only if core
authorization, product eligibility, configuration match, non-revocation, and
non-expiry all hold.

**Reservation before intent.** Capacity is claimed before the execution intent
is admitted.

**Intent before credentials.** Credential authorization is only defined at
`ExecutionIntentRecorded` and requires the same configuration, revocation,
expiry, and intent gates.

**Credentials before attempts.** Starting an attempt requires
`credentialAuthorized=true`.

**Attempt before provider entry.** Marking provider entry requires an existing
attempt and refuses duplicate entry.

**Provider entry and effect proof before commit.** Commit requires an attempt,
provider-call entry, and definite effect.

**Definite non-effect before risky release.** Once executing, release requires
both an attempt and definite non-effect.

**Reconciliation after ambiguity.** `OutcomeUnknown` cannot release directly.
Only effect or non-effect reconciliation can reach a terminal state, and both
require fresh matching reconciliation evidence.

\begin{claimbox}{Checked lifecycle ordering claims}
Lean proves that starting an attempt implies credential authorization;
provider-call entry implies an attempt; commit implies attempt, provider
entry, and definite effect; unknown outcome cannot release; and only effect or
non-effect reconciliation can terminate an unknown outcome. Configuration
mismatch blocks both reservation and credential authorization. Terminal states
never transition.
\end{claimbox}

## Capacity algebra

An additive ledger is $L=(c,m,a)$: ceiling, committed capacity, and active
reservation. Its invariant is

$$
\mathsf{Valid}(L)\iff 0<c\land m+a\leq c.
\tag{44}
$$

A request $r$ is available only if

$$
c\neq0\land r\neq0
\land m+a\leq U_{64}
\land m+a+r\leq U_{64}
\land m+a+r\leq c.
\tag{45}
$$

The ledger operations are

$$
\begin{aligned}
reserve_r(c,m,a)&=(c,m,a+r),\\
commit_x(c,m,a)&=(c,m+x,a-x) &&\text{when }x\leq a,\\
release_x(c,m,a)&=(c,m,a-x) &&\text{when }x\leq a.
\end{aligned}
\tag{46}
$$

Lean proves that every successful operation preserves Equation (44).
Successful availability also implies positive ceiling and request, capacity
containment, and absence of `u64` overflow.

\begin{figure}[H]
\centering
\begin{tikzpicture}[node distance=9mm and 12mm]
  \node[axisbox=blue, minimum width=42mm] (base) {$L=(c,m,a)$\\$m+a\leq c$};
  \node[axisbox=purple, minimum width=42mm, right=of base] (reserve) {$reserve_r$\\$(c,m,a+r)$};
  \node[axisbox=green, minimum width=42mm, above right=9mm and 12mm of reserve] (commit) {$commit_x$\\$(c,m+x,a+r-x)$};
  \node[axisbox=amber, minimum width=42mm, below right=9mm and 12mm of reserve] (release) {$release_x$\\$(c,m,a+r-x)$};
  \draw[flow=purple] (base) -- node[above,note]{$r>0$, bounded} (reserve);
  \draw[flow=green] (reserve) -- node[above,note]{$x\leq a+r$} (commit);
  \draw[flow=amber] (reserve) -- node[below,note]{$x\leq a+r$} (release);
  \node[note,text=green, right=6mm of commit] {$m'+a'\leq c$};
  \node[note,text=green, right=6mm of release] {$m'+a'\leq c$};
\end{tikzpicture}
\caption{\textbf{Capacity preservation.} Reserve increases active capacity,
commit moves active capacity into committed capacity, and release returns
active capacity. Every successful step preserves the ceiling invariant.}
\end{figure}

Exclusive capacity uses a separate predicate:

$$
\mathsf{exclusiveAvailable}(liveOwner,exactReplay)
=\neg liveOwner\lor exactReplay.
\tag{47}
$$

Thus the current owner may revisit the same exact operation, but a distinct
claim cannot coexist with a live owner.

## Replay classification

Replay is classified from record existence and commitment equality:

$$
\mathsf{replay}(exists,equal)=
\begin{cases}
\mathsf{Absent},&\neg exists,\\
\mathsf{ExactReplay},&exists\land equal,\\
\mathsf{Conflict},&exists\land\neg equal.
\end{cases}
\tag{48}
$$

Lean checks that exact replay is stable, conflicting replay is never exact,
and an absent record never claims an existing effect regardless of the
irrelevant equality Boolean.

# Refinement from shipping Rust to mathematical semantics

A proof about a handwritten model does not by itself prove a separately
written implementation. Auths-Proof addresses this correspondence problem by
isolating pure safe Rust functions, lowering them with Charon, translating
them with Aeneas, and proving the generated Lean functions equivalent to the
rich model. This resembles translation-validation thinking
[@pnueli1998translation], but the target theorem relates translated program
semantics to a domain specification rather than validating one compiler run.

## Three semantic levels

The proof chain has three levels:

$$
\text{validated Rust representation}
\xrightarrow{\alpha}
\text{rich semantic value}
\xrightarrow{\denote{-}}
\text{authorization meaning}.
\tag{49}
$$

The translated Rust function runs on the left. The readable specification runs
on the middle value. Refinement proves that decisions agree. The denotational
theorems then justify the security meaning of the rich relation.

\begin{figure}[H]
\centering
\resizebox{0.98\linewidth}{!}{%
\begin{tikzpicture}[node distance=10mm and 13mm]
  \node[axisbox=blue, minimum width=42mm] (bytes) {
    \textbf{Canonical bytes}\\
    outside this proof
  };
  \node[axisbox=amber, minimum width=42mm, right=of bytes] (rustval) {
    \textbf{Validated Rust values}\\
    constructor invariants
  };
  \node[axisbox=green, minimum width=42mm, right=of rustval] (translated) {
    \textbf{Aeneas evaluator}\\
    translated shipping Rust
  };
  \node[axisbox=purple, minimum width=42mm, right=of translated] (rich) {
    \textbf{Rich Lean value}\\
    extensional semantics
  };
  \node[kernel, minimum width=102mm, below=16mm of translated] (theorem) {
    REFINEMENT THEOREM\\[-1pt]
    \normalfont\footnotesize translated decision equals rich decision
  };
  \node[axisbox=purple, minimum width=42mm, right=13mm of theorem] (meaning) {
    \textbf{Denotation}\\
    admitted facts
  };

  \draw[flow=amber,dashed] (bytes) -- node[above,note]{tested decoder} (rustval);
  \draw[flow=blue] (rustval) -- node[above,note]{exact function} (translated);
  \draw[flow=purple] (rustval) to[bend left=22] node[above,note]{abstraction $\alpha$} (rich);
  \draw[flow=green] (translated) -- (theorem);
  \draw[flow=purple] (rich) -- (theorem);
  \draw[flow=purple] (rich) -- (meaning);
\end{tikzpicture}}
\caption{\textbf{Refinement layers.} Decoding is a separate boundary.
Validated Rust values feed both the translated evaluator and an abstraction
map into the rich model; the theorem equates their decisions.}
\end{figure}

## Aeneas weakest-precondition judgments

The production bridge uses Aeneas' functional translation and weakest-
precondition notation. Schematically,

$$
f(x)\ \{\!\!\{\ y\mid Q(y)\ \}\!\!\}
\tag{50}
$$

states that running translated function $f$ on $x$ returns a result satisfying
$Q$. Loop-bearing Rust functions are proved with decreasing natural measures
and prefix invariants. For example, a membership loop over a vector maintains
that every earlier index differs from the target; a subset loop maintains that
every earlier child element has a corresponding parent element.

This is classic program logic applied to extracted safe Rust. The proof does
not postulate that helper predicates behave semantically. It proves leaf
specifications for byte equality, string bytes, profile equality, permission
and audience membership and subset, digest membership, interval containment,
constraints, budgets, status, and critical extensions, then composes them
through the evaluator.

## Representation maps

The production vocabulary instantiates opaque carriers as exact byte-oriented
keys:

| Rich carrier | Production key |
|---|---|
| Principal | UTF-8 byte list |
| Profile | `(version, UTF-8 id bytes)` |
| Permission | `(capability bytes, resource bytes)` |
| Audience | UTF-8 byte list |
| Digest | fixed byte list |
| Budget algebra | UTF-8 byte list |
| Status method | UTF-8 byte list |
| Assurance | UTF-8 byte list |
| Grant id | digest bytes |
| Critical extension | `(id bytes, payload bytes)` |

Strings carry a premise that their UTF-8 byte size fits Aeneas' `u32`
carrier. Windows carry a well-formedness proof. Freshness limits are positive.
Selected profiles carry membership evidence. Sets carry boundedness and, where
the Rust constructor guarantees it, canonicality.

Permissions and audiences map lists to extensional finite sets. The refinement
therefore proves loop membership and subset against mapped keys. Critical
extensions deliberately map to an ordered rich list, not a finite set, so
positional equality remains exact. This is a good example of choosing the
abstraction by the decision being refined rather than by superficial data
shape.

## Authority refinement theorems

There are three principal production-evaluator theorems.

**Author scope.** For validated parent and child `ScopeAuthorityView` values,
the translated Rust pre-signing evaluator returns exactly
`richAuthorScopeDecision`, including the first failing dimension.

**Terminal coverage.** For validated authority and action views, an anchoring
premise, and a current optional-budget translation case, the translated Rust
coverage evaluator returns the mapped rich `evaluateCoverage` decision.

**Delegation.** For validated parent and grant views plus anchoring, the
translated Rust grant evaluator returns the mapped rich `evaluateGrant`
decision. An accepted production transition is the exact field projection of
the rich accepted next state.

In symbolic form, each has the shape

$$
\mathsf{Valid}(x)\land H(x)
\Longrightarrow
\mathsf{Aeneas}(f_{Rust})(x)=\gamma(f_{Rich}(\alpha(x))),
\tag{51}
$$

where $H$ records explicit bridge premises, $\alpha$ is the representation
map, and $\gamma$ maps rich decisions back to production decision codes.

## Lifecycle and bounded-policy refinement

The same pattern applies outside authority.

- Every rich lifecycle state, operation, and gate maps to its translated Rust
  counterpart. `translated_transition_refines_rich` proves equality for all
  combinations by exhaustive constructor analysis.
- Translated terminality, exclusive capacity, additive capacity, and replay
  classification agree with the rich functions.
- Translated configuration matching agrees with the pure product projection
  for all four input Booleans.
- Translated `u64` checked arithmetic refines natural-number arithmetic and
  correctly distinguishes successful results from overflow, underflow, or
  zero division.

These theorems turn fixed-width implementation concerns into explicit
mathematical cases. Aeneas' `U64.checked_*` specifications provide the bitvector
facts; Lean's arithmetic tactics discharge the natural-number consequences.

## The explicit stale-translation theorem

The checked-in Aeneas translation of `optional_budget_covers` predates a
shipping Rust correction. On one input class it returns the old, fail-open
answer:

$$
\mathsf{translatedBudgetCovers}(\mathsf{some}(b),\mathsf{none})
=\mathsf{true},
$$

while the current rich and shipping semantics require

$$
\neg\mathsf{budgetCovers}(\mathsf{some}(b),\mathsf{none}).
\tag{52}
$$

The development does not hand-edit generated Lean or conceal the mismatch.
It defines

$$
\mathsf{TranslatedBudgetCoverageCurrent}(B,R)
\iff B=\mathsf{none}\lor R\neq\mathsf{none}
\tag{53}
$$

and requires this premise in the coverage refinement. Separately,
`translated_budget_coverage_gap_is_the_absent_request` proves Equation (52) as
an audited claim.

\begin{boundarybox}
\textbf{Executable disclosure.} The coverage refinement intentionally excludes
the present-ceiling/absent-request pair until the translation is regenerated.
The mismatch is a theorem, not a comment. Once regenerated Lean matches the
shipping Rust, the mismatch theorem should stop compiling and the exclusion
premise should be removed atomically.
\end{boundarybox}

The authority bridge carries another explicit premise,
`AuthorityStateAnchored`, because the checked-in authority translation
predates a Rust root field. It states that a translated state either has a last
grant or its supplied root equals its subject. This lets the rich state satisfy
its local rootedness predicate without fabricating a translated field that is
not present.

# Assurance engineering around the proofs

Formal proof is only useful when the proposition, source closure, generated
artifacts, and trusted assumptions remain identifiable. The `formal/`
directory therefore contains an assurance system around Lean.

## Public theorem inventory

`Auths.Theorems.theoremInventory` is an explicit list of the 121 public
declarations discussed in Section 2.2. The compiled `AssuranceAudit` target
looks up each exact declaration name in Lean's environment. For each one it
records

$$
(name,kind,statement,transitive\ axioms).
$$

The manifest additionally stores a digest of the reviewed theorem statement.
Renaming, deleting, weakening, or changing a theorem changes the audit rather
than silently satisfying a source-text search.

The global reviewed axiom allowlist is

$$
\{\mathsf{Classical.choice},\mathsf{Quot.sound},\mathsf{propext}\}.
\tag{54}
$$

Individual theorems generally depend on subsets of this list. `sorryAx` is not
allowed. The distinction between compiled and uncompiled artifacts matters:
qualification templates contain placeholder axioms, but those templates are
inventoried as uncompiled and are not imported into the audited theorem
closure.

## Qualified mechanical translation

The Aeneas qualification pins a complete tool and source configuration:

| Component | Pinned value |
|---|---|
| Shipping Rust | 1.97.1 |
| Extraction Rust | nightly-2026-06-01 |
| Lean | 4.31.0 |
| Charon | 0.1.225 at commit `527ea8e...` |
| Aeneas | commit `3a8586f...` |
| Kani | 0.67.0 |

The translated crates cover model predicates, the generated algebra kernel,
the authority evaluators, bounded-policy primitives, and lifecycle primitives.
The qualification requires zero opaque local functions and zero required
compiled external axioms. External links are enumerated by exact Rust symbol.
The primary standard-library semantic bridge is `String::as_bytes`, modeled as
exact UTF-8 bytes within its carrier bound.

The pinned Aeneas runtime contains four general proof-support `sorry`
declarations in slice and string-iterator modules. They are explicitly
inventoried. The qualified Auths declarations do not transitively depend on
them, and the compiled assurance audit would reject their appearance in a
public claim's axiom set.

## Source closure

The qualification source-closure file hashes the Cargo manifests and lockfile,
shipping Rust sources, algebra contract, formal qualification configuration,
toolchain lock, and the repository code that drives the formal gate. Generated
Lean files are separately listed. Clean qualification translates twice and
requires byte-identical output before comparing with the committed artifacts.

This is not a proof that Charon or Aeneas is correct. It is a reproducibility
and drift argument:

$$
\text{same pinned sources + same pinned tools}
\Longrightarrow
\text{same generated evidence},
\tag{55}
$$

checked operationally rather than assumed informally.

## Generated vectors and mutation witnesses

The Lean vector exporter produces three portable corpora.

**All attenuation projections.** Eleven Booleans yield
$2^{11}=2{,}048$ assignments. The expected answer is the generated conjunction.

**Threshold states.** For each required count $1\leq k\leq16$, the exporter
enumerates every pair $0\leq a\leq16$ and
$0\leq u\leq16-a$, producing

$$
16\sum_{a=0}^{16}(17-a)=16\cdot153=2{,}448
\tag{56}
$$

cases.

**Rich semantic witnesses.** The current exporter contains 26 focused vectors
for interval boundaries, finite-set membership and inclusion, budget order and
coverage, status freshness, and action-constraint constructors.

The mutation manifest contains 23 security-relevant operators, including
reversing interval and subset directions, negating membership, accepting a
different exact digest, ignoring algebra or method identity, treating an
absent budget request as covered, accepting equal delegation depth, weakening
principal or grant-id equality, and ignoring critical-extension payload
changes.

The vectors are not substitutes for unbounded theorems. Their role is
cross-language conformance and mutation sensitivity: a binding or optimized
implementation must reproduce concrete consequences of the semantics.

\begin{figure}[H]
\centering
\resizebox{0.97\linewidth}{!}{%
\begin{tikzpicture}[node distance=9mm and 10mm]
  \node[axisbox=purple, minimum width=39mm] (decl) {theorem declaration\\exact compiled type};
  \node[axisbox=green, minimum width=39mm, right=of decl] (axiom) {axiom closure\\reviewed allowlist};
  \node[axisbox=amber, minimum width=39mm, right=of axiom] (source) {source closure\\pinned hashes};
  \node[axisbox=blue, minimum width=39mm, right=of source] (trans) {translation\\byte reproducibility};

  \node[card, minimum width=39mm, below=13mm of decl] (vectors) {4,522 generated cases\\plus 26 rich vectors};
  \node[card, minimum width=39mm, right=of vectors] (mut) {23 mutation\\operators};
  \node[card, minimum width=39mm, right=of mut] (cases) {qualification cases\\compiled closures};
  \node[card, minimum width=39mm, right=of cases] (bounds) {bounded Rust checks\\defense in depth};

  \node[kernel, minimum width=161mm, below=14mm of mut] (audit) {
    ASSURANCE CLAIM IS A TUPLE, NOT A SLOGAN\\[-1pt]
    \normalfont\footnotesize proposition + proof + source + tools + assumptions + conformance
  };

  \foreach \a/\b in {decl/axiom,axiom/source,source/trans,vectors/mut,mut/cases,cases/bounds}
    \draw[flow=muted] (\a) -- (\b);
  \foreach \n in {decl,axiom,source,trans,vectors,mut,cases,bounds}
    \draw[thinflow=green] (\n.south) -- (audit.north);
\end{tikzpicture}}
\caption{\textbf{Assurance closure.} A theorem is paired with its exact
statement, transitive axioms, production source closure, translation inputs,
and independent conformance evidence.}
\end{figure}

## Why proof and model checking coexist

The Lean theorems are unbounded where their statements quantify over natural
numbers, lists, scopes, or chain values. Bounded model checking remains useful
for fixed-width implementation properties, unsafe states that should be
unconstructible, panic freedom, and mutation killing. The two techniques answer
different questions. Proof supplies universal consequences of a model;
bounded checking explores the actual implementation within declared bounds
[@kroening2023cbmc].

# Trusted computing base and residual assumptions

The formal result is strongest when its boundary is stated precisely. The
trusted computing base and residual assumptions can be divided into five
classes.

## Logical foundation

The argument trusts the Lean kernel, the pinned Lean toolchain and libraries,
and the reviewed foundational axioms in Equation (54). This is the usual small
proof-checking base of an interactive theorem prover, not the whole IDE or
tactic implementation.

## Translation foundation

The argument trusts the pinned Rust, Charon, and Aeneas semantics and the
reviewed external models. Aeneas is selected because it translates ownership-
aware safe Rust into a functional representation suited to theorem proving
[@ho2022aeneas]. Auths-Proof does not claim to verify Aeneas itself.

The Rust compiler remains trusted for correspondence between extracted Rust
semantics and shipping machine code. This is narrower than a verified compiler
chain such as CompCert [@leroy2009compcert] and different from language-level
soundness work such as RustBelt [@jung2018rustbelt].

## Representation foundation

Aeneas exposes underlying carriers after erasing private Rust constructors.
Refinement theorems therefore assume the invariants established by production
constructors and validation:

- identifiers are canonical, nonempty, bounded byte sequences;
- counters and timestamps lie within fixed-width ranges;
- validity windows are well formed;
- collections are bounded and canonical where required;
- selected profiles are members of the allowed set;
- freshness limits are nonzero; and
- critical-extension identifiers are distinct and cardinality-bounded.

Many of these premises appear as Lean structures such as
`AuthorityStateViewValid`, `GrantAuthorityViewValid`,
`ActionAuthorityViewValid`, `ScopeAuthorityViewValid`, and
`CriticalExtensionsCanonical`. The refinement theorem does not apply to an
arbitrary malformed Lean value that safe Rust constructors could never create.

## Environmental foundation

The formal core receives explicit evidence facts and gate Booleans. It assumes
their interpretation is truthful. For example:

- `notRevoked=true` must come from a trustworthy revocation mechanism;
- `reconciliationFresh=true` must correspond to a domain-defined freshness
  policy;
- `definiteEffect=true` must be justified by provider-specific evidence;
- a configuration digest must be computed over the intended canonical bytes;
  and
- an assurance identifier must denote the policy the verifier believes it
  denotes.

The model proves what follows if these inputs are supplied. It does not prove
the external world supplied them honestly.

## Stateful implementation foundation

The lifecycle relation specifies legal transitions, but a concrete store must
provide atomic compare-and-swap, durable ordering, isolation, and restart
behavior. The capacity theorems apply to successful pure ledger steps. They do
not by themselves prove that two concurrent transactions cannot both observe
the same capacity or that a provider call and durable write are atomic.

Likewise, replay classification is pure. Exactly-once behavior requires the
runtime to claim and record one logical effect at an enforcement boundary.

\begin{boundarybox}
\textbf{No whole-system shortcut.} A proved transition relation does not make a
database atomic. A proved coverage predicate does not make a signature valid.
A proved refinement of pure Rust does not prove a network provider. The formal
artifact is designed to make these composition boundaries explicit.
\end{boundarybox}

## Claim matrix

| Claim | Status in this artifact |
|---|---|
| Truth algebra and thresholds | Lean-proved; finite contract generated into Rust and Lean |
| Rich authority order and denotational safety | Lean-proved |
| Delegation root, depth, extension, and uniqueness laws | Lean-proved |
| Pure Rust authority evaluators | Aeneas-translated and refined under representation premises, with explicit current gap premises |
| Product commitment and arithmetic primitives | Lean-proved; selected Rust functions refined |
| Pure lifecycle kernel | Lean-proved and translated-Rust refined |
| Canonical decoding and signatures | Outside these theorems; separate validation boundary |
| Concrete stores and concurrency | Outside these theorems; conformance obligation |
| External evidence and provider outcomes | Explicit environmental assumption plus reconciliation semantics |

# Cross-disciplinary interpretation

The value of the formal development is easier to see when its mathematical,
computer-science, and security readings are placed side by side.

## Order theory: authorization as a monotone semantics

The map

$$
\denote{-}:(\mathcal{S},\atten)\to
(\powerset(\mathcal{F}),\subseteq)
\tag{57}
$$

is monotone. Here $\mathcal{S}$ is the set of authority scopes and
$\mathcal{F}$ the set of complete authorization facts. Structural attenuation
is valuable because it is an efficiently decidable sufficient condition for
semantic inclusion.

The product is not a homogeneous lattice. Some coordinates are ordinary
orders, some are preorders, some use exact equality, and critical extensions
have an initially unpinned top followed by exact lock-in. The system therefore
uses a product of relations justified component by component rather than
forcing every concern into one numeric lattice.

## Denotational semantics: meaning before implementation

`Admits` gives scopes an extensional meaning independent of how Rust stores
them. This makes representation refinement possible. A sorted vector, a
finite set, and a canonical wire array may have different structures but can
be related by the behaviors they authorize.

The distinction between `Exact(d)` and `Allowed({d})` illustrates the point:
they are different syntax with equal denotation. Canonicalization chooses one
representative when structural equality matters.

## Type theory: invalid states as missing constructors

Several invariants are stored in types:

- inclusive windows contain a proof that start does not exceed finish;
- freshness limits contain a positivity proof;
- selected profiles contain membership evidence;
- unit quantities contain a `u64` bound;
- output commitments contain count and byte bounds; and
- critical-extension sequences contain distinctness and length proofs.

This moves obligations from repeated runtime conditions into construction.
The production bridge then explains which Rust constructors establish the
corresponding premises.

## Program logic: executable refinements

The weakest-precondition lemmas have the shape familiar from Hoare logic:

$$
\{P\}\ f\ \{Q\}.
\tag{58}
$$

Loop invariants connect imperative traversal to extensional membership and
subset. The large authority refinement proofs then compose these local
contracts through the translated evaluator. This is how the artifact advances
from "the model has good laws" to "the selected shipping predicate returns the
model's decision."

## Distributed systems: uncertainty is state

The truth value `Indeterminate` and lifecycle state `OutcomeUnknown` address
different uncertainties.

- `Indeterminate` means authorization evidence is insufficient but could
  resolve.
- `OutcomeUnknown` means an execution attempt may or may not have produced an
  effect.

Neither is permission. The first cannot become an authorized command without
new trustworthy evidence. The second cannot become released capacity without
fresh reconciliation. Preserving these distinctions prevents fail-open logic
at both decision and effect boundaries.

## Security engineering: negative-space theorems

Many of the strongest results state that a dangerous shortcut is impossible:

- an unrooted authority authorizes nothing;
- a foreign issuer falsifies the root dimension;
- a changed critical extension falsifies the extension dimension;
- a narrowed scope cannot admit a parent-rejected fact;
- a start attempt cannot succeed without credential authorization;
- a commit cannot succeed without provider entry and effect proof;
- an unknown outcome cannot be released; and
- an absent replay record cannot claim an existing effect.

These are negative-space theorems: they rule out classes of bad executions
rather than merely exhibiting a good example.

# Limitations and open proof obligations

The artifact is unusually explicit about its incomplete edges. Several are
important research and engineering directions.

## Regenerate the stale authority translation

The optional-budget and root-field bridge premises should disappear after the
checked-in Aeneas output is regenerated from current shipping Rust. The
existing mismatch theorem makes this a fail-loud change: successful
regeneration should invalidate the stale theorem rather than leave dead
documentation behind.

## Close constructor-to-view refinement

Representation-validity premises are reviewed and tested, but the strongest
chain would prove that every value produced by public safe Rust constructors
satisfies the corresponding Lean validity structure and that every lossless
view preserves the fields consumed by the evaluator.

## Strengthen plan semantics

The composition algebra has strong truth and threshold results, but the
current `Plan` theorems about leaf visits and cost are definitional. A richer
development could define an instrumented recursive evaluator and prove
occurrence-sensitive visitation, cost bounds, duplicate policy, arbitrary
permutation invariance, and diagnostic stability for complete plans.

## Connect state-machine relations to stores

The lifecycle kernel proves legal pure transitions. Concrete exactly-once
claims additionally need a refinement from transactional store operations and
crash histories to the pure state relation, including concurrent final
capacity, restart, and reconciliation.

## Separate information-flow properties

Deterministic first-failure diagnostics do not establish noninterference,
constant-time behavior, or resistance to policy probing. Those require a
separate observation model and attacker relation.

## Expand domain-specific evaluator proofs vertically

`ClosedEvaluator` defines the reusable proof obligation for policy tightening,
but each domain must instantiate it with its own exact action, evidence,
reservation, obligation, and output relations. Shared product mechanisms
should follow proven semantic identity across completed domains rather than
precede it.

# Related work

Auths-Proof sits between authorization logic, proof-carrying systems, and
systems verification.

Authorization logics distinguish authenticated statements from the authority
to act [@abadi1993calculus]. Trust-management systems make credentials and
policy composition explicit [@blaze1996trust]. Macaroons demonstrate
decentralized attenuation through contextual caveats
[@birgisson2014macaroons]. Auths-Proof shares the monotone-restriction goal but
formalizes a closed heterogeneous scope, exact terminal action coverage, and a
separate effect lifecycle.

Proof-carrying code asks a producer to supply machine-checkable evidence that a
consumer validates against a safety policy [@necula1997pcc]. Proof-carrying
authentication applies related ideas to authorization [@appel1999pca].
Auths-Proof is closer in spirit to proof-carrying authentication than to code
safety, but its shipped proof object is not a Lean proof term for every action.
Lean establishes the kernel laws; runtime objects carry signed authorization
evidence checked by that kernel.

Large verification projects such as CompCert and seL4 demonstrate the value
of explicit refinement chains and trusted computing bases
[@leroy2009compcert; @klein2009sel4]. Auths-Proof is narrower. It verifies
security-critical pure semantics and selected production functions, not an
operating system or compiler. Aeneas makes the production linkage practical
for ownership-aware safe Rust [@ho2022aeneas], while work such as RustBelt and
Verus attacks complementary language-soundness and deductive-verification
problems [@jung2018rustbelt; @lattuada2024verus].

# Conclusion

The formal work in Auths-Proof is best understood as a sequence of semantic
compressions.

1. A complex authorization scope is compressed into a decidable product
   relation without reducing every dimension to a scalar.
2. That structural relation is justified by a denotational theorem: child
   admission is a subset of parent admission.
3. Delegation adds trust-root linkage, exact lineage, deterministic state
   construction, critical-extension lock-in, and a well-founded depth measure.
4. Three-valued composition preserves the distinction between denial,
   unresolved evidence, and authorization.
5. Product and lifecycle models carry the result toward irreversible effects
   through commitments, checked arithmetic, reservations, credentials,
   attempts, provider entry, unknown outcomes, and reconciliation.
6. Mechanical Rust translation and refinement connect the readable model to
   selected shipping predicates under explicit representation assumptions.
7. The assurance manifest binds each public English claim to an exact compiled
   proposition, axiom set, toolchain, source closure, and evidence set.

The central theorem remains Equation (1): authority can move downward without
creating new admitted facts. Its practical power comes from the surrounding
work. Root preservation prevents re-anchoring. Strict depth prevents infinite
delegation. Pinned extensions prevent semantic stripping. Exact diagnostics
make decisions stable. Lifecycle invariants prevent authorization from being
mistaken for effect completion. Refinement prevents the mathematical model
from floating free of production Rust.

The result is neither a decorative proof nor a claim that the entire system is
verified. It is a disciplined formal boundary: small enough to audit, rich
enough to express the dangerous cases, mechanically connected to executable
semantics, and honest about what remains outside.

\newpage

# Appendix A. Complete scope relation {.unnumbered}

For reference, the complete scope order is

$$
\begin{aligned}
S_c\atten S_p \iff {}&
\Phi_c\atten\Phi_p\\
&\land P_c\subseteq P_p\\
&\land I_c\subseteq I_p\\
&\land A_c\subseteq A_p\\
&\land C_c\atten C_p\\
&\land B_c\atten B_p\\
&\land T_c\atten T_p\\
&\land Q_c=Q_p\\
&\land X_c\atten X_p.
\end{aligned}
\tag{A.1}
$$

| Dimension | Child below parent when | Coverage consequence |
|---|---|---|
| Profile | same root set; first selection or same selection | child-covered profile is parent-covered |
| Permissions | child set is a subset | child member is parent member |
| Validity | child interval is contained | child-contained action window is parent-contained |
| Audiences | child set is a subset | child member is parent member |
| Action body | allowed digest denotation is included | child-allowed digest is parent-allowed |
| Budget | parent unbounded, or same algebra with lower child ceiling | request covered by child is covered by parent |
| Status | parent expiry-only, or same method with no looser child age | evidence satisfying child satisfies parent |
| Assurance | exact identity equality | evidence assurance transfers by equality |
| Extensions | parent unpinned, or exact pinned sequence equality | chain cannot strip or alter pinned constraints |

# Appendix B. Delegation proof skeleton {.unnumbered}

Let $q_0$ be a parent, $h$ a grant, $i$ its identifier, and $q_1$ a proposed
child.

\begin{enumerate}
\item Prove $\mathsf{rooted}(q_0)$ and $h.issuer=q_0.subject$.
\item Prove $h.parent=q_0.lastGrant$.
\item Prove $0<q_0.depth$ and $h.depth<q_0.depth$.
\item Prove profile permission, window, audience, action, budget, status,
assurance, and extension checks.
\item Construct $q^*=\mathsf{acceptedNextState}(q_0,i,h)$.
\item Show $q_1=q^*$.
\end{enumerate}

Then

$$
\mathsf{delegates}(q_0,i,h,q_1)
$$

and the checked consequences include

$$
\begin{gathered}
q_1.root=q_0.root,
\qquad q_1.subject=h.subject,
\qquad q_1.lastGrant=\mathsf{some}(i),\\
q_1.depth<q_0.depth,
\qquad q_1.scope\atten q_0.scope,
\qquad \mathsf{rooted}(q_1).
\end{gathered}
\tag{B.1}
$$

# Appendix C. Lifecycle transition summary {.unnumbered}

| Current state | Operation | Essential success gates | Result |
|---|---|---|---|
| none | record decision | authorized, eligible, configuration match, live | decision recorded |
| decision recorded | reserve | configuration match, live, capacity | reserved |
| reserved | record intent | configuration match, live, intent present | intent recorded |
| intent recorded | authorize credential | configuration match, live, intent, not already authorized | intent recorded |
| intent recorded | start attempt | configuration match, live, intent, credential authorized | executing |
| executing | mark provider entered | attempt present, not already entered | executing |
| executing | commit | attempt, provider entered, definite effect | committed |
| reserved | release | no attempt; cancellation or definite non-effect | released |
| intent recorded | release | no attempt | released |
| executing | release | attempt and definite non-effect | released |
| executing | mark unknown | attempt present | outcome unknown |
| outcome unknown | reconcile effect | fresh matching reconciliation | reconciled committed |
| outcome unknown | reconcile non-effect | fresh matching reconciliation | reconciled released |
| outcome unknown | reconcile inconclusive | fresh matching reconciliation | observation only |

All terminal states return `terminal` for every later operation. All omitted
state-operation pairs return `illegalTransition` or a more specific failed
gate code according to the definition.

# Appendix D. Public theorem families {.unnumbered}

The table below maps mathematical claims to representative Lean declarations.
It is a guide, not a replacement for `formal/Auths/Theorems.lean` or the
assurance manifest.

| Mathematical claim | Representative declaration |
|---|---|
| Component orders are reflexive/transitive | `finiteSet_subset_*`, `window_contained_*`, `action_constraint_*`, `budget_*`, `status_*`, `profile_*`, `extensions_*` |
| Canonical scopes are antisymmetric | `scope_le_canonical_antisymmetry` |
| Structural attenuation is semantically sound | `structural_scope_le_implies_semantic_attenuation` |
| Complete admission is downward closed | `complete_admission_downward_closed` |
| Accepted edges never widen | `delegate_never_widens` |
| Accepted chains are finite | `remaining_depth_well_founded`, `finite_delegation_chain` |
| Root identity persists | `delegate_preserves_root`, `chain_preserves_root` |
| Pinned extensions persist | `delegate_preserves_pinned_extensions`, `chain_preserves_pinned_extensions` |
| Grant evaluation equals delegation relation | `apply_grant_success_iff_delegates` |
| Accepted child is unique | `apply_grant_success_unique` |
| Coverage decision equals terminal coverage | `coverage_decision_ok_iff_covers` |
| Shipping author evaluator matches rich semantics | `translated_rust_refines_rich_spec` |
| Shipping coverage evaluator matches rich semantics | `translated_coverage_refines_rich_spec` |
| Shipping delegation evaluator matches rich semantics | `translated_delegation_refines_rich_spec` |
| Configuration mismatch denies | `product_contract_configuration_safety` |
| Successful checked arithmetic is safe | `checked_add_never_wraps`, `checked_sub_never_underflows`, `checked_div_rejects_zero` |
| Capacity steps preserve validity | `reserve_preserves_capacity`, `commit_preserves_capacity`, `release_preserves_capacity` |
| Effect ordering is enforced | `start_attempt_requires_credential`, `provider_call_requires_attempt`, `commit_requires_provider_entry_and_effect` |
| Unknown outcome requires reconciliation | `outcome_unknown_cannot_release`, `outcome_unknown_only_reconciliation_can_terminate` |
| Translated lifecycle equals rich lifecycle | `translated_transition_refines_rich` |
| Threshold result matches count region | `authorized_implies_threshold_met`, `denied_implies_threshold_impossible`, `indeterminate_implies_threshold_reachable` |

# Appendix E. Module dependency guide {.unnumbered}

\begin{figure}[H]
\centering
\resizebox{0.98\linewidth}{!}{%
\begin{tikzpicture}[node distance=7mm and 10mm]
  \node[axisbox=purple, minimum width=38mm] (generated) {Generated.Algebra};
  \node[axisbox=purple, minimum width=38mm, right=of generated] (base) {Base};
  \node[axisbox=purple, minimum width=38mm, right=of base] (composition) {Composition};

  \node[axisbox=blue, minimum width=38mm, below=11mm of generated] (types) {Rich.Types};
  \node[axisbox=blue, minimum width=38mm, right=of types] (sem) {Rich.Semantics};
  \node[axisbox=blue, minimum width=38mm, right=of sem] (thm) {Rich.Theorems};

  \node[axisbox=green, minimum width=38mm, below=11mm of types] (prod) {Product.*};
  \node[axisbox=green, minimum width=38mm, right=of prod] (life) {Lifecycle.*};
  \node[axisbox=green, minimum width=38mm, right=of life] (refine) {Refinement.Production};

  \node[axisbox=amber, minimum width=38mm, below=11mm of prod] (aeneas) {qualification/aeneas};
  \node[kernel, minimum width=38mm, right=of aeneas] (inventory) {Theorems};
  \node[axisbox=amber, minimum width=38mm, right=of inventory] (audit) {AssuranceAudit};

  \draw[flow=muted] (generated) -- (base);
  \draw[flow=muted] (base) -- (composition);
  \draw[flow=muted] (base) -- (types);
  \draw[flow=muted] (types) -- (sem);
  \draw[flow=muted] (sem) -- (thm);
  \draw[flow=muted] (thm) -- (refine);
  \draw[flow=muted] (aeneas) -- (refine);
  \draw[flow=muted] (prod) -- (inventory);
  \draw[flow=muted] (life) -- (inventory);
  \draw[flow=muted] (refine) -- (inventory);
  \draw[flow=muted] (composition) to[bend left=18] (inventory);
  \draw[flow=muted] (inventory) -- (audit);
\end{tikzpicture}}
\caption{\textbf{A reader's dependency guide.} Arrows indicate conceptual
import flow toward the public theorem inventory and compiled assurance audit.}
\end{figure}

# References {.unnumbered}
