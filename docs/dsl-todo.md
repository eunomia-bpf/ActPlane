# DSL TODO

Pending changes, not yet implemented.

## Decided, do next

1. **`open` is independent, not sugar for `read`+`write`**: `open` matches any file access, `read` matches read-only, `write` matches write-only. Three distinct operations.

2. **`recv` implementation**: hook `socket_recvmsg` for inbound network. DSL keyword already exists, kernel hook missing.

3. **Remove `label` keyword**: runner auto-seeds labels from `source` declarations that match the agent binary. `source AGENT = exec "claude"` is sufficient — no separate `label AGENT` needed.

4. **`reason` → `because`**: more natural English. `because "Schema changed."` reads better than `reason "Schema changed."`

## Discussed, not decided

4. `unless after exec` → `unless ran` (shorter)
5. `since write` → `after changed` (less ambiguous)
6. Remove `label` keyword entirely, unify with `source`
