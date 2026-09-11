# secret-agent design notes

Concise record of settled constraints and open tensions. Supersedes [`plan-process-io.md`](plan-process-io.md) (deprecated; old `process/io` polling).

## Domain model

- **Secret** — versioned plan (scripts for create/activate/…).
- **Instance** — deployed copy of a secret; many instances, **one active** per secret.
- **Operation** (`secrets.Operation`) — audit record: op number, name, status, timestamps. Not the same as HTTP attach state.
- Attach discovery is serial only while assembling one unnamed pending slot per
  `(secretId, principal)`. Consuming that slot does **not** serialize operation execution.
  Reads (`List`/`Get`) are unconstrained.

## Layering

| Layer | Package (target) | Role |
|-------|------------------|------|
| **Catalog** | `backend` | Read-only: secrets, instances, operation history. |
| **Runner** | `backend` | `Run(name, target, params, proposer, stdio)` — blocking mutation + I/O. |
| **Porcelain** | `ops` (separate) | Typed `Create`/`Activate`/… calling `Runner.Run`. CLI imports `ops`, not raw runner. |
| **HTTP** | `server` | Attach routes + JSON start; maps to runner semantics. |
| **Execute** | `executor` | Run subprocess; **`executor.OperationParameters`** is the single domain params type. |
| **Wire DTOs** | `server` | JSON request bodies only (e.g. `OperationRequest`); map to `executor.OperationParameters` + peer identity. |

## HTTP attach (current direction)

- **Attach before start**: open stdio upgrades, then POST start/run.
- **Slot key**: `(secretId, principal)` — principal from transport (Unix peer creds), not request body.
- **One pending slot per (secret, principal)**; POST consumes it, allowing the next
  slot to attach while the previous operation runs. No reattach to a consumed slot.
- Routes (target shape): `POST /secrets/{secretId}/attach/{stdin|stdout|stderr}` → then `POST /instances` or `/operations`.
- Instances and operations are **root collections** (`/instances`, `/operations`) because instance ids are globally unique: a nested `secretId` would be ignored by the lookup, or worse, trusted for slot selection without being checked. Creates carry the parent id in the body (`secretId` / `instanceId`); catalog reads filter by query. `POST /operations` derives the secret from the instance. See [`http-api.md`](http-api.md).
- Server in-memory type: **`attachSlot`** (not `operation`) — pipes, attach claims, `startedBy`. Registry keyed by `(secretId, principal)` until op number exists.

## Store `Run` — caller feedback & cancellation

**Not two moments — an active session.** Caller receives:

| When | What |
|------|------|
| Op recorded | `Instance` (op number, `startedAt`, …) |
| During run | **stdio** streams; **`Propose`** callbacks for dependent-secret auth |
| Op finished | final `*Instance` (`completedAt` or `failedAt`); failure via **`error`** |

**Start / Handle split:** **`Run`** returns the accepted snapshot quickly plus a **`Handle`**; **interactive work runs in the background** as soon as accept completes. **`Handle.Wait`** joins until that work finishes. **`Handle.Cancel`** stops the in-flight op (sqlite: cancel execute ctx; HTTP: slot disconnect maps here).

**Two cancellation lifecycles** (explicit, not conflated):

1. **`wait(ctx)` ctx** — abandons **waiting only**; op keeps running.
2. **`cancel(ctx)`** — stops the **op** (subprocess / attach pumps).

**Likely shape:**

```go
type Handle interface {
    Wait(ctx context.Context) (instance *secrets.Instance, err error)
    Cancel(ctx context.Context) error
}

Runner.Run(...) (instance *secrets.Instance, handle Handle, err error)
```

**Background work starts before `Run` returns** (not on first `Wait`):

| Path | What starts in background when `Run` succeeds |
|------|-----------------------------------------------|
| **sqlite** | Goroutine: `executor.Execute` + complete op in DB |
| **HTTP client** | Goroutines: attach pumps; POST invokes the server runner |
| **HTTP server** | `Runner.Run` starts execute before returning the accepted snapshot |

**`Handle.Wait` = join:** blocks until background work completes. **`wait(ctx)`** ctx abandons **waiting only** — the op keeps running; **`Handle.Wait` may be called again** on the same handle to join later. **`Handle.Cancel`** stops the op. If `Run` returns `err != nil`, **`handle` is nil**.

**`Runner.Run(ctx, …)`:** `ctx` covers **this call only** (accept / persist). It must not outlive `Run` as the execute or attach-pump lifetime — that would be surprising, and HTTP POST’s `r.Context()` ends when the response is written. Background work is joined/stopped via **`Handle`**. Passing `r.Context()` into `Run` is correct.

**Start (HTTP POST)** uses **`r.Context()`** as that accept ctx. Request ends; subprocess and attach copies use **attach-slot / execute ctx**. Slot **`Cancel`** = stdout/stderr disconnect (or any stream drop before POST). Stdin EOF while running closes the process stdin; it does not cancel the op.

### Unified invariant (both backend implementations)

**Subprocess starts when I/O is ready at the end of accept — never when the caller first calls `wait`.**

If HTTP only started the op on `wait`, attach-before-start would be pointless (you could POST, attach, then “really start” on await). Attach-first exists precisely so **streams are connected before `Execute`**, with start triggered by the server's **`Runner.Run`** call during POST, not by the client’s join.

| | When is I/O ready? | When does `Execute` start? | What does `Handle.Wait` do? |
|--|-------------------|---------------------------|------------------------------|
| **sqlite** | `Run` has `command.Stdio` in-process | **`launch`** goroutine before `Run` returns | Join on per-Run `opHandle.done` channel |
| **HTTP** | Attach upgrades done before POST | **Server** `Runner.Run` starts execute before returning the POST snapshot | Join pump + terminal instance |

**Historical “delay until attach” (Jul 2025):** for **HTTP / federation**, not sqlite. Problems it solved:

1. **Fast-script race** — subprocess must not run until stdio streams exist (otherwise exit before attach, or block on full pipe buffers).
2. **Decoupled attacher** — ~~starter ≠ attacher (human B attaches later)~~ **replaced:** orchestrator A is always starter+attacher on B; B gates on **John’s authorisation proof**, not a second attach principal (federation; Phase 8).

That delay is **“until attach + start gate”**, not **“until `wait()`”**. Attach-before-start is the gate: attach streams → POST → then execute. Sqlite has no transport gap — stdio is wired before any goroutine starts — so no attach delay; it still matches the invariant because execute starts at end of accept with I/O already connected.

**Today’s code:** `internal/sqlite/repo.go` + `backend.go` — persist in the repository; `Run` starts execute in a background goroutine before return; `Handle.Wait` joins; `Handle.Cancel` stops the op.

Success after join: terminal instance with **`completedAt`**, `err == nil`.  
Failure: **`failedAt`** in store, `err != nil` — **`errors.As`** for typed exit error when subprocess exited non-zero.

- **HTTP:** POST start → initial `Instance`; attach conns + control channel carry stdio/proposals until done.
- Drop **`/result` long-poll** and **`trackOperation`** once `Handle`/attach own completion.

## Parameters naming

- **`executor.OperationParameters`** — domain (reason, forced, env, startedBy, expectedOpNumber).
- **`server.OperationRequest`** — JSON subset common to every operation request; controller sets `StartedBy` from identity.
- **`server.SecretOperationRequest`** / **`InstanceOperationRequest`** — `OperationRequest` plus the parent id (`secretId` / `instanceId`); the instance form also carries `name`.

## Proposer

- **`Proposer`** on **`Runner.Run(...)`** — invoked from **inside** a parent op script when a dependent op on another secret/host is needed (Phase 8).
- **`Propose(ctx, name, params) error`** — nil = approved; error = rejected. Blocks the parent script until resolved.

**Federated shape (sketch):** parent host **A** must not be able to approve on **John’s** behalf by assertion alone. One viable implementation:

1. Script on A hits `Propose` for an op on host **B**.
2. **A forwards a pipe** (e.g. SSH `-L` / socket forward) so **John talks to B directly** — prompt, challenge, or confirm UI on B’s side.
3. **John authenticates to B** (peer creds, SSH, mTLS, … — B verifies John, John verifies B).
4. **John’s OK** is recorded **by B** (signed approval, session on B, audit row) — not “A says John OK’d”.

**Threat model:** **A must not MITM John ↔ B.** A may relay bytes for stdio of the parent op and for a **forwarded authorisation channel**, but must not be able to forge John’s approval or impersonate B to John. Concretely:

| Allowed | Not allowed |
|---------|-------------|
| A forwards a channel; John establishes **E2E trust with B** | A sends `approved: true` on B’s API with no John↔B auth |
| B issues nonce/challenge; **John’s response verified by B** (key/credential B already trusts) | A replays or edits John’s response |
| Parent op on A blocks in `Propose` until B records John’s decision | Policy “trust parent op X” **without** a John↔B step when cross-host |

Same-host tests can use two Unix peers (John vs A) with the same logic: B still verifies **John**, not A’s say-so.

No behaviour in sqlite yet; HTTP control stream for `Propose` deferred (see Open).

## Catalog / Runner split — why

1. **Different contracts** — catalog calls are idempotent reads; runner holds blocking I/O, proposer, and `(secret, principal)` attach semantics.
2. **HTTP mapping** — GET handlers vs attach + POST; awkward to implement `List` on something that also needs `Run(..., stdio)`.
3. **Testing / mocks** — list/get tests without stubbing stdio or proposer.
4. **Future aggregate “web” API** — catalog can fan out across hosts; runner stays on the agent that executes the secret.
5. **Mental model** — browse secrets ≠ run an op (same as k8s list/get vs attach/exec).

If the split feels heavy, minimum viable split is still **`Runner` only for mutations**; catalog can remain nested accessors on the same concrete type.

## Exit code

- **Not stored** on `secrets.Operation` / instance status — only **`completedAt`** vs **`failedAt`** (already what sqlite `completeOperation` does).
- **Non-zero subprocess exit** → op marked **`failedAt`**, `Wait` returns **`err != nil`**. Caller uses **`errors.As(err, *command.ExitError)`** (or similar) for the numeric code when needed (CLI exit status, logging).
- **Exit code 0** → **`completedAt`**, `err == nil`.
- **Other failures** (start failed, ctx canceled, DB error) → also `err != nil`; only subprocess exits carry an exit code on the error. No parallel `ExitCode` field on backend types.
- **`command.Process`** should wrap with **`%w`** so `exec.ExitError` survives (today it does not).

## Federation (later)

Supersedes the “U@C starts, human B attaches later” sketch in `plan-process-io.md`.

**Starter is always attacher.** No decoupled second connection from a different principal to attach stdio.

Example: John runs an op on **host A**; the script triggers a dependent op on **host B**.

| Host | Who runs the op (transport) | `startedBy` on audit row | Who attaches stdio |
|------|----------------------------|--------------------------|-------------------|
| **A** | John | John | John (local CLI or John’s client session) |
| **B** | **Host A** (orchestrator) | **Host A** | **Host A** — same connection/session that started the op |

**Attach rule unchanged:** `transport principal == startedBy` on that host. On B, A is both starter and attacher.

**What B must gate on:** **John’s authorisation for this specific op on B at this time** — verified **on B**, not taken on faith from A.

**How (Phase 8 — not v1):** A is starter+attacher on B for **stdio of B’s script**. **John’s consent** is a separate leg: A’s `Proposer` may **forward a pipe** so John authenticates **directly to B** and B records OK. B then allows A’s attach/start (or unblocks a pending proposal). A must not be able to MITM that leg — see **Proposer** § threat model. Reject designs where A submits a bearer “John approved” token B cannot cryptographically or session-wise tie to John.

**Implications for attach-before-start:** unchanged for A↔B stdio — A attaches streams, then POST invokes B's `Runner.Run`. **Authorisation** may complete inside `Propose` (blocking parent on A) before A POSTs start on B, or B holds start until John’s OK is on record — exact ordering TBD in Phase 8.

**Audit:** B’s op records `startedBy = A`; John’s involvement is in the **authorisation proof** and/or parent op on A (reason chain, proposer log), not as B’s transport principal.

## Open / deferred

- Startup cleanup of DB ops stuck without `completedAt` after agent restart (attach fails; row may lie until cleaned).
- Orphan slot if attach never followed by start (timeout?).
- Control stream for `Proposer` on HTTP (4th upgrade vs mux).
- Real exit code over HTTP attach (typed error on remote client; local caller still has stderr).

---

## Decisions (Phase 0)

Written before Phase 1 implementation. Wire details: [`http-api.md`](http-api.md).

### 0.1 Store surface

| Question | Decision |
|----------|----------|
| Top-level type | **`Backend`**: `Catalog()` + `Runner(secretId string)` |
| Target | **No `Target` struct.** `Runner` is bound to `secretId`; `Run` takes **`instanceId string`** (empty = create). |
| Op name | **`secrets.OperationName`** |
| History | **`Catalog.Operations().List(...)`** only; runner does not list |
| `Run` return | **`(*Instance, Handle, error)`** — accept snapshot + **join/cancel** handle (background already running) |

**Copy-pasteable signatures:**

```go
package backend

type Backend interface {
    Catalog() Catalog
    Runner(secretId string) Runner
}

type Catalog interface {
    Secrets() Secrets
    Instances() Instances
    Operations() Operations
}

type Secrets interface {
    List(ctx context.Context) (secrets.Secrets, error)
    Get(ctx context.Context, secretId string) (*secrets.Secret, error)
}

type Instances interface {
    List(ctx context.Context, secretId *string, from, to int) (secrets.Instances, error)
    Get(ctx context.Context, instanceId string) (*secrets.Instance, error)
    GetActive(ctx context.Context, secretId string) (*secrets.Instance, error)
}

type Operations interface {
    List(ctx context.Context, secretId, instanceId *string, from, to int) ([]*secrets.Operation, error)
}

type Runner interface {
    Run(
        ctx context.Context,
        name secrets.OperationName,
        instanceId string, // empty for create
        params executor.OperationParameters,
        proposer Proposer,
        stdio command.Stdio,
    ) (instance *secrets.Instance, handle Handle, err error)
}

type Handle interface {
    Wait(ctx context.Context) (instance *secrets.Instance, err error)
    Cancel(ctx context.Context) error
}

type Proposer interface {
    Propose(ctx context.Context, name secrets.OperationName, params executor.OperationParameters) error
}
```

**Server vs `Backend`:** HTTP server holds a concrete **`backend.Backend`** (sqlite). Controller does **not** expose `Runner` to handlers directly; POST start uses the same sqlite persist path as `Run`’s first phase, then **`attachSlot`** runs `Execute` on **slot context**. Slot disconnect calls **`Handle.Cancel`**. Client and in-process CLI call `Run` + `Handle.Wait` end-to-end.

**Snapshots:** first `*Instance` from **`Run`** = op accepted (`startedAt`). **`Handle.Wait`** returns the terminal instance (`completedAt` or `failedAt`). Same type, different moment — distinguished by call, not wrapper structs.

**Why `Handle` not bare `Wait`:** join and op-cancel are distinct; **`wait(ctx)` must not be overloaded** to kill the subprocess. HTTP attach disconnect, CLI Ctrl+C, and sqlite all map to **`Cancel`**; **`Wait`** only joins.

**Why `Operations` not `OperationsHistory`:** Same accessor name as today’s catalog surface; only **`List`** remains (mutations moved to `Runner`). Distinct from `secrets.Operation` (audit row type) — package prefix disambiguates.

**Active instance:** **`Instances.GetActive(ctx, secretId)`** + **`GET /secrets/{secretId}/active`** — kept as a singular read (not a list filter); see [`http-api.md`](http-api.md).

### 0.2 `Run` / `Handle` contract

**Phases:**

| Phase | Who | What runs |
|-------|-----|-----------|
| **Accept** | `Runner.Run` (sync) | Persist op; HTTP client: attach + POST. Return accepted `*Instance` + **`Handle`**. |
| **Background** | Goroutine / slot (async) | Sqlite/server runner: `Execute` + DB complete. HTTP client: pump attach. |
| **Join** | `Handle.Wait(ctx)` | Block until background done; return terminal `(instance, err)`. Abandoning wait (`ctx` done) does **not** stop the op; call **`Wait` again** to re-join. **`Handle.Cancel`** is the only op-stop path on the handle (porcelain may call **`Cancel`** when wait ctx dies — CLI policy). |

**Do not:** maintain a global `map[opNumber]operationRuntime` (or similar) for join/cancel lookup. Each successful **`Run`** returns a **`Handle`** that closes over that op’s goroutine state (`done` channel, execute ctx, terminal snapshot). Idempotent re-**`Wait`** after completion is fine; multi-caller join before done is not a hard HTTP requirement.

**Who passes `stdio` / `proposer`?**

| Implementation | `Run(..., stdio, proposer)` | Background | `Handle` |
|----------------|----------------------------|------------|----------|
| **sqlite** | Passed into background `Execute` goroutine started before `Run` returns | **`Execute`** | `Wait` joins; `Cancel` stops execute ctx |
| **HTTP client** | Attach in `Run`; pump uses stdio in background goroutines | **Pump attach** (POST starts server runner) | `Wait` joins pump; `Cancel` tears down attach |
| **HTTP server POST** | Slot pipes bound before POST | **`Runner.Run`** starts execute before returning | Handle kept by slot; disconnect → **`Cancel`** |

**Context rule (mandatory):** `Runner.Run(ctx)` uses `ctx` only for accept. **`Execute` and attach copy loops use the handle/slot lifetime**, cancelled on slot teardown. Never retain `Run`’s ctx (including `r.Context()`) for subprocess or attach pumps.

**Exit code:** subprocess non-zero → **`failedAt`** in DB + typed error from **`Handle.Wait`**. No **`ExitCode`** field on backend results.

**HTTP client completion (replaces `/result` long-poll):**

1. **`Handle.Wait`** blocks until attach copies finish (server closed write end → EOF).
2. Reload instance; **`err == nil`** iff **`completedAt`** set.
3. If **`failedAt`** set → return instance **and** an error (`OperationFailed` or synthesized from attach session). Numeric exit code on remote attach deferred unless control channel adds it; **stderr** already streamed to caller.

**Cancel before POST start:** If attach disconnects before POST, **no op row** — slot torn down, nothing to roll back. If POST succeeds then client disconnects, **disconnect cancels** running op (slot `cancel()` → kill subprocess, mark op failed).

#### Pseudo-code — per-Run handle (sqlite + client)

**Anti-pattern (Phase 3 lesson):** global op registry + mutex-backed result cache for join/cancel by op number. **Use a closure per `Run` instead.**

```go
type opHandle struct {
    done       chan struct{}
    execCancel context.CancelFunc
    final      *secrets.Instance
    waitErr    error
}

func (h *opHandle) Wait(ctx context.Context) (*secrets.Instance, error) {
    select {
    case <-h.done:
        return h.final, h.waitErr
    case <-ctx.Done():
        return nil, ctx.Err() // abandon join only; op keeps running
    }
}

func (h *opHandle) Cancel(ctx context.Context) error {
    h.execCancel()
    select {
    case <-h.done:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    }
}

func (st *secretState) launch(inst *secrets.Instance, op secrets.Operation, params executor.OperationParameters, stdio command.Stdio) *opHandle {
    execCtx, execCancel := context.WithCancel(context.Background())
    h := &opHandle{done: make(chan struct{}), execCancel: execCancel}
    go func() {
        defer close(h.done)
        h.waitErr = completeOperation(execCtx, st.repo.db, st.secretId, inst, op, params, stdio)
        h.final, _ = st.repo.getInstance(context.Background(), inst.Id)
    }()
    return h
}

func (r *sqliteRunner) Run(ctx, name, instanceId, params, proposer, stdio) (*secrets.Instance, Handle, error) {
    inst, op, err := r.beginOp(ctx, name, instanceId, params)
    if err != nil { return nil, nil, err }
    _ = proposer // Phase 8 executor hook
    return inst, r.launch(inst, op, params, stdio), nil
}
```

#### Pseudo-code — HTTP server (POST handler)

```go
func (c *Controller) startOp(w, r, secretId, instanceId, name, params) {
    slot := c.slots.take(secretId, principal(r))
    inst, handle, err := c.agent.Runner(secretId).Run(
        r.Context(), name, instanceId, params, noopProposer{}, slot.pipes.Stdio(),
    )
    if err != nil { return err }
    slot.watch(handle)
    writeJSON(w, inst)
}
```

#### Pseudo-code — HTTP client

```go
func (r *clientRunner) Run(ctx, ...) (*secrets.Instance, Handle, error) {
    slot, err := r.openAttach(ctx, secretId)
    inst, err := r.postStart(ctx, ...)
    if err != nil { return nil, nil, err }
    // handle.Wait joins pump goroutine; handle.Cancel closes attach / slot ctx
    return inst, slot.Handle(), nil
}
```

#### Sequence — HTTP client

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant Slot as attachSlot
    participant DB as sqlite

    C->>S: POST attach/stdin,stdout,stderr (Upgrade)
    S->>Slot: create slot(principal)
    C->>S: POST …/operations (r.Context)
    S->>DB: Runner.Run (accept + start background execute)
    DB-->>S: Instance
    S-->>C: 200 Instance JSON
    Note over C,S: POST ctx ends
    Note over C: Run starts pump goroutine
    Slot->>Slot: Handle + copy loops remain active
    Slot-->>C: pipe EOF on done
    C->>C: wait(ctx) joins pump; returns instance + err
```

#### Sequence — server POST must not leak ctx

```mermaid
sequenceDiagram
    participant H as POST handler
    participant RC as r.Context
    participant R as Runner
    participant Op as background op

    H->>R: Run(RC, ..., slot stdio)
    R->>RC: persist
    R->>Op: start with independent execute ctx
    R-->>H: Instance + Handle
    H-->>H: write response
    Note over RC: cancelled when handler returns
    Note over Op: NOT using RC; stopped via Handle.Cancel
```

### 0.3 HTTP routes

See [`http-api.md`](http-api.md). Summary:

- **Remove** op-number attach paths, **`/result` long-poll**, **`DELETE …/operations/{n}`**.
- **Attach before start** on `/secrets/{secretId}/attach/{stdin|stdout|stderr}`.
- **v1 readiness:** require **stdout + stderr** attached before POST; **stdin required** if we want one simple rule — **require all three streams** for v1 (stricter, easier to reason about).
- Status codes: **404** no pending slot, **409** not ready / stream already claimed, **426** missing Upgrade, **403** wrong principal.

### 0.5 `attachSlot` state machine

Rename server `operation` → **`attachSlot`**. Registry: **`map[attachSlotKey]*attachSlot`** where `attachSlotKey = {secretId, principal}`.

```go
type attachSlotKey struct {
    secretId  string
    principal string
}

type attachSlot struct {
    key     attachSlotKey
    pipes   attachPipes
    ctx     context.Context // attach-copy lifetime
    cancel  context.CancelFunc
    claimed map[attachStream]bool
}
```

The controller map contains **pending slots only**. Attach calls **`claim(stream)`** on
the pending slot. Both claims and take run under the single controller registry lock.
POST atomically **takes and removes** a ready slot, then invokes `Runner.Run` with its
stdio. A new set of attaches may immediately create the next
pending slot for the same `(secretId, principal)` while the previous operation runs.

The consumed slot remains reachable only by its attach handlers and completion
watcher. It needs no mutex: cancellation is represented by its context, and the watcher
owns the handle. **`close()`** cancels that context and closes the pipes; if close raced
with `Runner.Run`, the watcher observes the already-cancelled context and cancels the
new handle. There is no unclaim/repair path: attach setup or `Run` failure discards
that slot.

**On stdout/stderr disconnect after take:** close slot → `Handle.Cancel` → kill
subprocess and mark op failed. Successful stdin EOF only closes process stdin.

**Orphan `ready` slot:** defer timeout (Phase 7+); Phase 0 notes only.

### 0.6 Porcelain (`internal/ops`)

- Package: **`internal/ops`** (empty package + doc comment in Phase 0; implementations Phase 2).
- Functions: **`Create`**, **`Destroy`**, … — each **`Run` + `wait(ctx)`** → **`(*secrets.Instance, error)`**.

### Phase 0 still open for Phase 1+

| Item | Note |
|------|------|
| `Begin` vs export split on sqlite runner | POST and `Run` share persist path; name in Phase 1 |
| Proposer on HTTP | Defer wire; local `Proposer` nil OK in v1 |
| Stuck DB rows after agent restart | Cleanup job deferred |
