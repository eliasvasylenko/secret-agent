# Implementation plan

Detailed plan to migrate secret-agent to the architecture in [`design.md`](design.md). Work is ordered so each phase produces a compilable, testable increment where possible.

**Current state:** branch has HTTP 101 attach (per-stream) but old store/controller/sqlite/client shapes; `store.go` is a partial sketch; tree does not compile against it.

**Out of scope for early phases:** federation wire format, `Proposer` behaviour inside scripts, aggregate web API, SSH transport.

---

## Phase 0 — Lock API shapes (discovery)

Goal: written decisions before large refactors. No requirement to implement yet.

### 0.1 Store surface

Decide and document in `design.md` (append “Decisions” section):

| Question | Options | Notes |
|----------|---------|-------|
| Top-level type | `Agent` with `.Catalog()` + `.Runner(secretId)` vs nested accessors on one struct | Runner must be per-secret; catalog is global |
| `Target` | struct `{SecretID, InstanceID}` vs encode in `Run` args | InstanceID empty for create |
| Op name type | `secrets.OperationName` vs string | Prefer typed |
| History | `Catalog.Operations().List(...)` vs `Runner` doesn’t list | List is read-only |
| `Run` return | `*Run` + `Wait(ctx)` vs callback `onStarted(*Instance)` + block | See 0.2 |

**Deliverable:** `docs/design.md` “Decisions” with chosen signatures (copy-pasteable Go).

### 0.2 `Run` / `Wait` contract

Write pseudo-code for three implementations:

1. **sqlite** — attach not on wire; stdio direct; single caller ctx OK.
2. **HTTP server** — POST start under `r.Context()`; run under slot ctx.
3. **HTTP client** — attach before POST; POST returns instance; pump on conn ctx.

Resolve:

- Does `Runner.Run` take `stdio` + `proposer`, or does HTTP server ignore those params (slot already bound)?
- Who calls `Wait` on server — nobody (slot goroutine); client/sqlite only?
- Exit code parsing: add helper in `command` or `executor`?

**Deliverable:** sequence diagram (server + client) in `design.md` or here; explicit “ctx must not cross” rule for server POST handler.

### 0.3 HTTP routes

Finalize path matrix:

| Action | Method | Path (draft) |
|--------|--------|--------------|
| Attach stdin/stdout/stderr | POST+Upgrade | `/secrets/{secretId}/attach/{stream}` |
| Create | POST | `/secrets/{secretId}/instances` |
| Instance op | POST | `/secrets/{secretId}/instances/{instanceId}/operations` body `{name, ...RunRequest}` |
| List ops | GET | `/secrets/{secretId}/instances/{instanceId}/operations` or filtered list |

Decide:

- Remove `/operations/{n}/attach/...` (attach before op number exists)?
- Remove `/operations/{n}/result` and `/operations/{n}` DELETE cancel (replace with attach disconnect)?
- Require all three streams before POST start, or start when slot “ready enough”?

**Deliverable:** route table + status codes (404 no slot, 409 slot busy, 426 upgrade required).

### 0.4 Wire DTOs

- Rename `server.OperationParameters` → `RunRequest`.
- Rename `CreateOperationParameters` → `StartOperationRequest` (or fold into one type with `name` field).
- Document JSON examples for create vs activate.

**Deliverable:** small `docs/http-api.md` or section in `design.md`.

### 0.5 `attachSlot` server struct

Rename `operation` → `attachSlot`; define:

```go
type attachSlotKey struct { secretId, principal string }
type attachSlot struct {
    pipes, startedBy, slotCtx, cancel
    attach claims; optional opNumber after start
    // subprocess / executor goroutine
}
```

Decide slot states: `waiting_attach` → `waiting_start` → `running` → `done`.

**Deliverable:** state machine bullet list + what each transition triggers.

### 0.6 Porcelain package

- Package name: `internal/ops` (confirm).
- Functions: `Create`, `Destroy`, `Activate`, `Deactivate`, `Test` taking `store.Runner` + ids + params + proposer + stdio.
- Whether porcelain wraps `Run`+immediate `Wait` for CLI convenience.

**Deliverable:** `ops` package doc comment only (empty package OK).

---

## Phase 1 — Store interfaces (`internal/store`)

Goal: stable interfaces; compile with stub mocks only.

1. Replace `Store` / `Operations` / `Start` with:
   - `Catalog` (or `Agent.Catalog()`): `Secrets`, `Instances`, `Operations.List`
   - `Runner`: `Run(name, target, params, proposer, stdio) (*Run, error)`
   - `Run.Wait(ctx) (OperationResult, error)`
2. Add `Target`, use `secrets.OperationName`, `Proposer.Propose(ctx, name, params)`.
3. Keep error types (`StaleOperationError`, `UnknownOperationError`).
4. Update `internal/mocks` to match (minimal compile stubs).
5. **Do not** update sqlite/client/server yet — expect repo broken except `store` + `mocks` package tests.

**Verification:** `go build ./internal/store/... ./internal/mocks/...`

---

## Phase 2 — Porcelain (`internal/ops`)

Goal: typed entry points for CLI/tests without touching HTTP.

1. Create `internal/ops` with wrappers calling `Runner.Run` + `Wait`.
2. Unit tests with mock `Runner` (optional, light).

**Verification:** `go test ./internal/ops/...`

---

## Phase 3 — Sqlite runner

Goal: in-process agent path works end-to-end without HTTP.

1. Refactor `SecretRespository`:
   - Implement `Catalog` accessors (`Secrets()`, `Instances()`, `Operations().List` only).
   - Implement `Runner(secretId)` (or single repo implementing `Runner` with target).
2. **No HTTP attach slot** — `Run`:
   - Persist op (existing `startOperation` tx logic).
   - Return `*Run` with initial `Instance`.
   - `Wait`: start subprocess with caller stdio (delay until Wait — per design), `completeOperation`, return `OperationResult` + exit code.
3. Remove old `Create(..., stdio)` on `InstanceRepository`, `Await`, `Cancel`, nested `Operations(instanceId)` methods.
4. `Proposer`: accept on `Run`, store on run state, no invoke until executor hook exists.
5. Rewrite `internal/sqlite/store_test.go` via `ops` or direct `Runner`.

**Discovery during implementation:**

- Orphan row if `Run` returns but `Wait` never called — accept for v1 or add slot cleanup timer?
- `GetActive` / list filters with `secretId *string` nil = all secrets.

**Verification:** `go test ./internal/sqlite/...`

---

## Phase 4 — HTTP server attach slot + routes

Goal: attach-before-start, per `(secretId, principal)`, no reattach.

1. Rename `operation` → `attachSlot`; registry `attachSlotKey`.
2. New attach routes: `/secrets/{secretId}/attach/{stream}` (drop op number from path).
3. Attach handler:
   - Create or join slot for `(secretId, principal)`.
   - Claim stream once; disconnect → cancel slot ctx, fail op if running.
4. Refactor `createInstance` / `createOperation`:
   - Under `r.Context()`: validate slot exists + attach ready, persist op, return `Instance` JSON.
   - **Do not** pass `r.Context()` to executor.
   - Start executor on slot ctx using existing pipes.
5. Remove `trackOperation` background await, `/result` poll, old attach paths keyed by opNumber (unless temporarily kept behind flag — prefer delete).
6. Rename wire DTOs (`RunRequest`, etc.); map to `executor.OperationParameters`.
7. Controller depends on `store.Catalog` for reads; start path uses catalog/runner or inlined store calls — **decide in 0.1** whether server holds `store.Agent` or talks to sqlite directly today.

**Discovery during implementation:**

- Must all three streams attach before POST? Enforce in slot state machine.
- Stdin body prefix before hijack (keep current pattern).

**Verification:** `go test ./internal/server/...`; manual curl/upgrade smoke test script (optional).

---

## Phase 5 — HTTP client runner

Goal: `client` implements `store.Runner` using attach + POST + Wait.

1. Refactor `SecretClient` → implement `Catalog`.
2. `Runner(secretId)`:
   - Open 3 upgrades to new attach paths (principal implicit).
   - POST start with `RunRequest`.
   - Return `*Run` with `Instance` from response body.
   - `Wait`: pump stdio on conn ctx; on disconnect return error; collect completion (how — see discovery).
3. **Discovery:** how client learns op finished without `/result`:
   - Option A: attach conn EOF + server closes pipes when done; client infers from copy return + GET instance.
   - Option B: small JSON “done” frame on control stream (later).
   - Option C: keep `/result` temporarily for client only (reluctant — document choice).

4. Remove old `InstanceClient.Create(..., stdio)` + `runAttach` split if fully subsumed by `Runner`.

**Verification:** `go test ./internal/client/...`; integration with server tests if present.

---

## Phase 6 — CLI + serve wiring

1. `NewStore` returns type with `Catalog()` + `Runner(secretId)`.
2. CLI read commands → `Catalog`.
3. CLI mutating commands → `ops.Create` etc. with terminal stdio + noop `Proposer`.
4. `serve` passes sqlite repo (implements catalog + runner) into server.

**Verification:** `go test ./...`; `nix/checks/stdio.nix` if applicable.

---

## Phase 7 — Cleanup and docs

1. Delete or archive obsolete code paths (`client/operations.go` dead methods, old attach URLs).
2. Mark `plan-process-io.md` deprecated; point to `design.md` + this plan.
3. Update `docs/http-api.md` with final routes.
4. Optional: agent restart marks in-flight DB ops failed (deferred in design).

---

## Phase 8 — Proposer + federation (later)

Only after local path solid.

1. **Executor hook** — script calls agent API to propose dependent op; invokes slot’s `Proposer`.
2. **HTTP control channel** — decide 4th upgrade vs mux; request/response envelope for `Propose`.
3. **Originating principal** — `RunRequest` or header; policy on secret plan.
4. Same-host Nix e2e (`plan-process-io.md` phase 2, revised).

---

## Dependency graph

```
Phase 0 (decisions)
    ↓
Phase 1 (store interfaces)
    ↓
Phase 2 (ops) ─────────────┐
    ↓                      ↓
Phase 3 (sqlite)     Phase 4 (server attach)
    ↓                      ↓
    └──────────┬───────────┘
               ↓
         Phase 5 (client)
               ↓
         Phase 6 (CLI)
               ↓
         Phase 7 (cleanup)
               ↓
         Phase 8 (federation)
```

Phases 3 and 4 can proceed in parallel after Phase 1 if two people; Phase 5 needs both.

---

## Risk register

| Risk | Mitigation |
|------|------------|
| Client can’t detect op completion without `/result` | Decide in Phase 0.2 / 5; prototype early |
| Start/Wait awkward on server | Server never exposes `Wait`; slot goroutine only |
| Large bang refactor | Phase 1 mocks; phase 3 sqlite before client |
| `Run` API still wrong after Phase 1 | Phase 0 must finish first; cheap to change only `store` |
| Tests assume old `Create(..., stdio)` | Rewrite tests per phase, not in one go |

---

## Success criteria

- Single domain params type: `executor.OperationParameters`.
- Catalog reads work without stdio; mutations go through `Runner` + `ops`.
- HTTP: attach before start; per `(secretId, principal)`; disconnect cancels.
- POST start returns initial `Instance` under request ctx; subprocess outlives request.
- No reattach; no `/result` long-poll (unless explicitly kept with documented reason).
- `go test ./...` and stdio nix check pass.
