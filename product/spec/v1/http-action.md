# Auths HTTP Action Profile V1

**Profile:** `auths.http/1`  
**Media type:** `application/vnd.auths.http-action.v1+json`

The body is RFC 8785 canonical JSON with a closed schema containing `profile`,
`profile_version`, uppercase `method`, lowercase `scheme` and `authority`,
absolute `path`, explicit repeated query values, lowercase selected headers,
optional content type, and an optional lowercase SHA-256 body digest.

V1 accepts `DELETE`, `GET`, `HEAD`, `PATCH`, `POST`, and `PUT`; `http` and
`https`; at most 64 query names and 64 selected headers; and at most 256 KiB of
canonical action bytes. Dot path components, repeated path separators,
unknown fields, implicit default ports, and non-lowercase authorities or
header names are rejected rather than normalized.

```text
capability = http/<lowercase method>
resource   = <scheme>://<authority><path>
```

The verified decoder re-parses canonical bytes, re-derives the permission,
and produces the only command accepted by an executor. The approval display
shows method, target, body digest, and the canonical action digest.

