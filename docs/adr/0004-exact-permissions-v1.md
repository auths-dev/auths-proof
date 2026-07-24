# ADR 0004: Exact Permissions in V1

**Status:** Accepted

## Decision

V1 grants exact `(capability, resource)` pairs. Attenuation is set inclusion.

## Rejected for V1

- wildcards and globs;
- regex or JSONPath;
- arbitrary claim maps;
- embedded Rego/Cedar;
- application callbacks that redefine delegation.

Profiles may map rich application policy to exact identifiers before signing.
