# secret-agent design notes

Concise record of settled constraints and open tensions. Supersedes parts of `plan-process-io.md` (that doc describes old `process/io` polling).

## Domain model

- **Secret** — versioned plan (scripts for create/activate/…).
- **Instance** — deployed copy of a secret; many instances, **one active** per secret.
- **Operation** (`secrets.Operation`) — audit record: op number, name, status, timestamps. Not the same as HTTP attach state.
- **Per secret**, mutating work is effectively **serial** for a given principal; reads (`List`/`Get`) are unconstrained.

## Layering

| Layer | Package (target) | Role |
|-------|------------------|------|
| **Catalog** | `store` | Read-only: secrets, instances, operation history. |
| **Runner** | `store` | `Run(name, target, params, proposer, stdio)` — blocking mutation + I/O. |
| **Porcelain** | `ops` (separate) | Typed `Create`/`Activate`/… calling `Runner.Run`. CLI imports `ops`, not raw runner. |
| **HTTP** | `server` | Attach routes + JSON start; maps to runner semantics. |
| **Execute** | `executor` | Run subprocess; **`executor.OperationParameters`** is the single domain params type. |
| **Wire DTOs** | `server` | JSON request bodies only (e.g. `RunRequest`); map to `executor.OperationParameters` + peer identity. |

## HTTP attach (current direction)

- **Attach before start**: open stdio upgrades, then POST start/run.
- **Slot key**: `(secretId, principal)` — principal from transport (Unix peer creds), not request body.
- **One slot per (secret, principal)**; no reattach; **disconnect = cancel** op.
- Routes (target shape): `POST /secrets/{secretId}/attach/{stdin|stdout|stderr}` → then `POST …/instances` or `…/operations`.
- Server in-memory type: **`attachSlot`** (not `operation`) — pipes, attach claims, `startedBy`. Registry keyed by `(secretId, principal)` until op number exists.

## Store `Run` — caller feedback & cancellation

**Not two moments — an active session.** Caller receives:

| When | What |
|------|------|
| Op recorded | `Instance` (op number, `startedAt`, …) |
| During run | **stdio** streams; **`Propose`** callbacks for dependent-secret auth |
| Op finished | `OperationResult` (exit code, final status) |

**Start / Wait split** is about the first and last rows, not the whole story. **`Wait` owns the interactive phase** (stdio + proposals), not just “block until exit”.

**Two cancellation lifecycles** (tension with Start/Wait):

1. **Start (HTTP POST)** — runs under **`r.Context()`** only long enough to validate, persist op, return `Instance`. Request ends; that ctx must **not** bound subprocess or attach pumps.
2. **Run (async)** — stdio, proposals, executor run under **attach-slot / conn lifetime**, not the start request ctx.

Locally, `Run` + immediate `Wait(ctx)` can share the caller’s ctx. **HTTP is asymmetric:** start is request-scoped; the op continues on attach connections (server) or client-held conns after POST returns.

**Design rule:** server never passes `r.Context()` from POST start into `Execute` or attach copy loops. Slot cancel = attach disconnect or explicit cancel API, not “response sent”.

**Likely shape:**

```go
type Run struct {
    Instance *secrets.Instance   // valid as soon as op is persisted
    Wait(ctx) (OperationResult, error)  // stdio + Proposer fire here
}
Runner.Run(..., proposer, stdio) (*Run, error)
```

- **HTTP:** POST start → initial `Instance`; attach conns + control channel carry stdio/proposals until done.
- Drop **`/result` long-poll** and **`trackOperation`** once Wait/attach own completion.

## Parameters naming

- **`executor.OperationParameters`** — domain (reason, forced, env, startedBy, expectedOpNumber).
- **`server.RunRequest`** (rename from `OperationParameters`) — JSON subset; controller sets `StartedBy` from identity.

## Proposer

- **`Proposer`** on `Run` — hook for dependent-secret proposals from **inside** a script (future).
- **`Propose(ctx, name, params) error`** — nil = approve; error = reject. HTTP serialises over attach session later.
- No behaviour in sqlite yet.

## Catalog / Runner split — why

1. **Different contracts** — catalog calls are idempotent reads; runner holds blocking I/O, proposer, and `(secret, principal)` attach semantics.
2. **HTTP mapping** — GET handlers vs attach + POST; awkward to implement `List` on something that also needs `Run(..., stdio)`.
3. **Testing / mocks** — list/get tests without stubbing stdio or proposer.
4. **Future aggregate “web” API** — catalog can fan out across hosts; runner stays on the agent that executes the secret.
5. **Mental model** — browse secrets ≠ run an op (same as k8s list/get vs attach/exec).

If the split feels heavy, minimum viable split is still **`Runner` only for mutations**; catalog can remain nested accessors on the same concrete type.

## Exit code

- **`OperationResult.ExitCode`** from subprocess when available (`exec.ExitError`).
- If `Wait` returns an error and there is no exit code, return **zero `OperationResult`** and the error.

## Federation (later)

- Originating principal sets `startedBy`; attach auth `principal == startedBy`.
- U@C orchestrates; B attaches. Not implemented on wire yet.
- See `plan-process-io.md` for sketch; attach-token model may change with attach-before-start slots.

## Open / deferred

- Startup cleanup of DB ops stuck without `completedAt` after agent restart (attach fails; row may lie until cleaned).
- Orphan slot if attach never followed by start (timeout?).
- Control stream for `Proposer` on HTTP (4th upgrade vs mux).
