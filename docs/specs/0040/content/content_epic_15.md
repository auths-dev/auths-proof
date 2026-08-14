# Content Epic 15 — Complete Agents and MCP Documentation

**Depends on:** Content Epics 10–14 and agent/plan scenarios.

## Outcome

Agent builders can implement a bounded tool, approved plan, multi-agent
handoff, MCP client, or protected MCP server entirely within the Agents
journey.

## Implementation

- [ ] Replace every current Agents landing destination with a real `/agents/*`
  page.
- [ ] Build the complete Agents tree in the proposed hierarchy.
- [ ] Turn “Delegate one tool” into an executable synchronized quickstart.
- [ ] Show the exact delegated scope and one prohibited action on every agent
  workflow page.
- [ ] Separate MCP client use from protected MCP server construction.
- [ ] Add MCP tool-profile and transport-boundary pages; explicitly state that
  MCP delivery is not authority.
- [ ] Add executable approved-plan and multi-agent examples.
- [ ] Document identity composition, skills/plugins, production ownership, and
  adversarial testing without bundling them as mandatory components.
- [ ] Add failures for widening, prompt substitution, plan substitution,
  ambient credentials, transport success, replay, and provider uncertainty.

## Acceptance

- The Agents landing contains no generic `/integrations` card labelled MCP.
- Every Agents child renders Agents navigation and meaningful code where the
  reader job is implementation.
- A reader can protect an MCP server without first learning unrelated
  integration categories.

