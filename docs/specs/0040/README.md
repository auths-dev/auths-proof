# AP-SPEC-040 Execution Map

AP-SPEC-040 has two coordinated implementation lanes and one release gate:

- **Platform epics (`P1`–`P11`)** build source truth, extraction, typed page
  models, rendering, executable examples, and qualification machinery.
- **Content epics (`C0`–`C9`)** choose reader journeys and author the public
  explanations, guidance, curation, and conceptual diagrams.
- **The verified page graph** is the only input to HTML, Markdown, search,
  navigation, and agent-readable output.

The lanes are not independent documentation systems. Content Epic 0 defines
their ownership contract and blocks all public-content implementation.

## Non-overlap rule

```text
auths-proof product facts       auths-docs editorial sources
signatures, routes, errors      explanations, choices, journeys
profiles, limits, evidence      conceptual diagrams, curation
tested scenario artifacts       references to scenario identities
             \                         /
              \                       /
               +-- strict compiler --+
                         |
                         v
                VerifiedPageGraph
              /      |      |      \
           HTML  Markdown  Search  LLM
```

If changing released software could make a statement false, that statement is
a generated fact or tested scenario. Editorial content refers to it by stable
identity and does not copy it.

## Platform epics

| ID | Epic | Responsibility |
|---|---|---|
| P1 | [Freeze the documentation surface contract](./epic_1.md) | Stable semantic joins |
| P2 | [Make the public API self-documenting](./epic_2.md) | Source-owned public documentation |
| P3 | [Export runtime and assurance facts](./epic_3.md) | Non-SDK product facts |
| P4 | [Publish the immutable docs bundle](./epic_4.md) | Installed-artifact extraction |
| P5 | [Build the static docs foundation](./epic_5.md) | MDX, design system, page compiler |
| P6 | [Build journey composition contracts](./epic_6.md) | Typed editorial composition primitives |
| P7 | [Build executable examples](./epic_7.md) | Tested cross-language scenarios |
| P8 | [Generate deep reference](./epic_8.md) | Generated fact pages |
| P9 | [Build deep-content composition contracts](./epic_9.md) | Architecture, operations, integration, and assurance components |
| P10 | [Deliver machine-readable documentation](./epic_10.md) | HTML-adjacent machine projections |
| P11 | [Enforce qualification and release](./epic_11.md) | Cross-repository CI and deployment |

## Content epics

The editorial lane is indexed in [content/README.md](./content/README.md).
Content Epic 0 must complete first.

## Combined execution order

```text
P1 -> P2/P3 -> P4 -> P5
 |                    |
 +------------------> C0
                      |
                 +----+----+
                 v         v
                P6       C1-C3
                 |         |
                 +----+----+
                      v
                  P7 + C4
                      |
                  P8 + C5
                      |
                  P9 + C6-C9
                      |
                     P10
                      |
                     P11
```

Platform primitives may be implemented using bounded fixture content before
their corresponding editorial epic is complete. Fixture prose must be visibly
synthetic and must not become an accidental public corpus.

## Completion rules

- A platform epic cannot author or approve public narrative.
- A content epic cannot define extractors, generated facts, rendering forks,
  or CI orchestration.
- Generated reference pages are never hand-edited.
- Displayed executable code comes from a qualified scenario artifact.
- Authored MDX declares stable dependencies in frontmatter.
- All outputs are projections of one `VerifiedPageGraph`.
- A cross-lane change is split into a platform commit and a content commit when
  ownership crosses repositories; their immutable artifact identities join
  them without mutable sibling dependencies.

