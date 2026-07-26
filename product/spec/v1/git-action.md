# Auths Git Action Profile V1

**Profile:** `auths.git/1`  
**Media type:** `application/vnd.auths.git-action.v1+json`

The closed RFC 8785 JSON schema binds a lowercase repository namespace, one
operation (`create-ref`, `delete-ref`, `merge`, `push`, or `tag`), an explicit
reference, and a 32-byte lowercase hexadecimal object identifier. No symbolic
resolution, ref inference, abbreviated object ID, or unknown field is allowed.

```text
capability = git/<operation>
resource   = git://<repository>/refs/<reference>
```

The object identifier remains in the exact signed body, so approval for one
commit cannot authorize a different target with the same repository and ref.
The verified decoder re-checks canonicality and permission before returning an
executor command. The approval display includes repository, operation,
reference, object ID, and canonical action digest.

