# Delegate to an agent

Delegation gives another **Identity** narrower **Authority**. Approval remains
optional and does not create permission.

```ts
await using child = await auths.delegate({
  identity: reportAgent,
  authority: mcp.allowTools(["publish_report"], { expiresIn: "10m", uses: 1 }),
});
const result = await child.execute({ action, provider });
```

```python
async with await auths.delegate(
    identity=report_agent,
    authority=mcp.allow_tools(["publish_report"], expires_in="10m", uses=1),
) as child:
    result = await child.execute(action=action, provider=provider)
```

Outcome: a child Auths instance whose authority cannot exceed its parent’s.
