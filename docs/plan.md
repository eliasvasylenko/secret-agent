# Implementation plan

Detailed plan to migrate secret-agent to the architecture in [`design.md`](design.md). Work is ordered so each phase produces a compilable, testable increment where possible.

**Current state:** Phases 0–4 done (server attach-before-start + `Catalog` reads). `internal/client` still uses old attach-after-POST flow; `internal/cli` still uses old store API — tree does not fully compile until Phases 5–6.

**Out of scope for early phases:** federation wire format, `Proposer` behaviour inside scripts, aggregate web API, SSH transport.

---

## Phase 0 — Lock API shapes (discovery) ✅

Goal: written decisions before large refactors. No requirement to implement yet.

**Done:** [`design.md` § Decisions](design.md#decisions-phase-0), [`http-api.md`](http-api.md), [`internal/ops/doc.go`](../internal/ops/doc.go). Review and confirm before Phase 1.

### 0.1 Store surface

Decide and document in `design.md` (append “Decisions” section):

| Question | Options | Notes |
|----------|---------|-------|
| Top-level type | `Agent` with `.Catalog()` + `.Runner(secretId)` vs nested accessors on one struct | Runner must be per-secret; catalog is global |
| `Target` | struct `{SecretID, InstanceID}` vs encode in `Run` args | InstanceID empty for create |
| Op name type | `secrets.OperationName` vs string | Prefer typed |
| History | `Catalog.Operations().List(...)` vs `Runner` doesn’t list | List is read-only |
| `Run` return | `(*Instance, Handle, error)` — see design.md §0.1 |

**Deliverable:** `docs/design.md` “Decisions” with chosen signatures (copy-pasteable Go).

### 0.2 `Run` / `Handle` contract

Write pseudo-code for three implementations:

1. **sqlite** — attach not on wire; stdio direct; single caller ctx OK.
2. **HTTP server** — POST start under `r.Context()`; run under slot ctx.
3. **HTTP client** — attach before POST; POST returns instance; pump on conn ctx.

Resolve:

- Does `Runner.Run` take `stdio` + `proposer`, or does HTTP server ignore those params (slot already bound)?
- Who calls `Handle.Wait` on server — nobody (slot goroutine); client/sqlite only?
- Exit code parsing: add helper in `command` or `executor`?

**Deliverable:** sequence diagram (server + client) in `design.md` or here; explicit “ctx must not cross” rule for server POST handler.

### 0.3 HTTP routes

Finalize path matrix:

| Action | Method | Path (draft) |
|--------|--------|--------------|
| Attach stdin/stdout/stderr | POST+Upgrade | `/secrets/{secretId}/attach/{stream}` |
| Create | POST | `/secrets/{secretId}/instances` |
| Instance op | POST | `/secrets/{secretId}/instances/{instanceId}/operations` body `{name, ...OperationRequest}` |
| List ops | GET | `/secrets/{secretId}/instances/{instanceId}/operations` or filtered list |

Decide:

- Remove `/operations/{n}/attach/...` (attach before op number exists)?
- Remove `/operations/{n}/result` and `/operations/{n}` DELETE cancel (replace with attach disconnect)?
- Require all three streams before POST start, or start when slot “ready enough”?

**Deliverable:** route table + status codes (404 no slot, 409 slot busy, 426 upgrade required).

### 0.4 Wire DTOs

- Rename `server.OperationParameters` → `OperationRequest`.
- Rename `CreateOperationParameters` → `NamedOperationRequest`.
- Document JSON examples for create vs activate.

**Deliverable:** small `docs/http-api.md` or section in `design.md`.

### 0.5 `attachSlot` server struct

Rename `operation` → `attachSlot`; define:

```go
type attachSlotKey struct { secretId, principal string }
type attachSlot struct {
    pipes, ctx, cancel
    attach claims
}
```

Controller map holds pending slots only. POST atomically takes/removes a ready slot;
claims and take share the controller registry lock. After take, the slot needs no lock:
its watcher owns the handle and reacts to the slot cancellation context.

**Deliverable:** state machine bullet list + what each transition triggers.

### 0.6 Porcelain package

- Package name: `internal/ops` (confirm).
- Functions: `Create`, `Destroy`, `Activate`, `Deactivate`, `Test` taking `backend.Runner` + ids + params + proposer + stdio.
- Whether porcelain wraps `Run`+immediate `Handle.Wait` for CLI convenience.

**Deliverable:** `ops` package doc comment only (empty package OK).

---

## Phase 1 — Backend interfaces (`internal/backend`) ✅

Goal: stable interfaces; compile with stub mocks only.

1. Replace `Store` / `Operations` / `Start` with:
   - `Backend`: `Catalog()` + `Runner(secretId)`
   - `Catalog`: `Secrets`, `Instances` (incl. `GetActive`), `Operations.List`
   - `Runner`: `Run(...) (*secrets.Instance, Handle, error)`; `Handle.Wait` joins; `Handle.Cancel` stops the op
2. Use `secrets.OperationName` on `Proposer.Propose`; keep `StaleOperationError`, `UnknownOperationError`.
3. Update `internal/mocks` to match (minimal compile stubs).
4. **Do not** update sqlite/client/server yet — expect repo broken except `store` + `mocks` package tests.

**Verification:** `go build ./internal/backend/... ./internal/mocks/...`

---

## Phase 2 — Porcelain (`internal/ops`) ✅

Goal: typed entry points for CLI/tests without touching HTTP.

1. Create `internal/ops` with wrappers: `inst, handle, err := runner.Run(...); return handle.Wait(ctx)`.
2. Unit tests with mock `Runner` (optional, light).

**Verification:** `go test ./internal/ops/...`

---

## Phase 3 — Sqlite runner ✅

Goal: in-process agent path works end-to-end without HTTP.

1. Refactor sqlite into `Repository` (persistence) + `Backend` (`backend.Backend` adapter):
   - Implement `Catalog` accessors (`Secrets()`, `Instances()`, `Operations().List` only).
   - Implement `Runner(secretId)` (or single repo implementing `Runner` with target).
2. **No HTTP attach slot** — `Run` persists then starts **`Execute` in background**; **`Handle.Wait`** joins; **`Handle.Cancel`** stops execute ctx; failure → `failedAt` + typed error.
3. Remove old `Create(..., stdio)` on `InstanceRepository`, `Await`, `Cancel`, nested `Operations(instanceId)` methods.
4. `Proposer`: accepted on `Run` but not invoked until executor hook exists (Phase 8); `_ = proposer` in sqlite today.
5. Rewrite `internal/sqlite/backend_test.go` via `ops` or direct `Runner`.
6. **`Open` / `Backend` / `Repository`** — persistence in `repo.go`, thin `backend.Backend` adapter in `backend.go` (not “store”).

**Discovery during implementation:**

- Orphan row if caller never joins — **background still completes** op; row reaches terminal state. Orphan **attach slot** before POST still possible.
- `GetActive` / list filters with `secretId *string` nil = all secrets.
- **No global op registry** — do not use `map[opNumber]…` + mutex for join/cancel; each `Run` returns an **`opHandle`** closure (channel + `execCancel`).
- **`Handle.Wait` abandon is repeatable** — `wait(ctx)` ctx expiry abandons waiting only; op keeps running; a later `Handle.Wait` can still join. **`ops`** additionally calls **`Handle.Cancel`** when wait ctx dies (CLI Ctrl+C policy).
- **`syncPlanRevisions`** — pre-existing; pins instance plan version in DB at create/update (not new Phase 3 logic).
- Secret-level op history: **`Catalog.Operations().List(ctx, &secretId, nil, from, to)`** — CLI `History` command migrates here in Phase 6 (replaces old `Backend.History`).

**Verification:** `go test ./internal/sqlite/...`

---

## Phase 4 — HTTP server attach slot + routes ✅

Goal: attach-before-start, per `(secretId, principal)`, no reattach.

1. Rename `operation` → `attachSlot`; registry `attachSlotKey`.
2. New attach routes: `/secrets/{secretId}/attach/{stream}` (drop op number from path).
3. Attach handler:
   - Create or join slot for `(secretId, principal)`.
   - Claim stream once; stdout/stderr disconnect (or any drop before POST) → **`Handle.Cancel`**. Stdin EOF while running does not cancel.
   - POST consumes/removes the pending slot, so another slot may attach while that op runs.
4. Refactor `createInstance` / `createOperation`:
   - Under `r.Context()`: validate slot exists + attach ready, persist op, return `Instance` JSON.
   - **Do not** pass `r.Context()` to executor.
   - Start executor on slot ctx using existing pipes.
5. Remove `trackOperation` background await, `/result` poll, old attach paths keyed by opNumber (unless temporarily kept behind flag — prefer delete).
6. Rename wire DTOs (`OperationRequest`, `NamedOperationRequest`); map to `executor.OperationParameters`.
7. Controller depends on `backend.Catalog` for reads; start path uses catalog/runner or inlined sqlite calls — server holds sqlite directly today, not full `Backend` on wire handlers.

**Discovery during implementation:**

- Must all three streams attach before POST? Enforce in slot state machine.
- Stdin body prefix before hijack (keep current pattern).

**Verification:** `go test ./internal/server/...`; manual curl/upgrade smoke test script (optional).

---

## Phase 5 — HTTP client runner

Goal: `client` implements `backend.Runner` using attach + POST + `Handle`.

1. Refactor `SecretClient` → implement `backend.Backend` (`Catalog` + `Runner`).
2. `Runner(secretId)`:
   - Open attach upgrades, POST start.
   - Return accepted `*Instance` + **`Handle`** (background pump already running; server executes after POST; **`Cancel`** tears down attach).
3. **Discovery:** how client learns op finished without `/result`:
   - Option A: attach conn EOF + server closes pipes when done; client infers from copy return + GET instance.
   - Option B: small JSON “done” frame on control stream (later).
   - Option C: keep `/result` temporarily for client only (reluctant — document choice).

4. Remove old `InstanceClient.Create(..., stdio)` + `runAttach` split if fully subsumed by `Runner`.

**Verification:** `go test ./internal/client/...`; integration with server tests if present.

---

## Phase 6 — CLI + serve wiring

1. `NewStore` returns `backend.Backend` (sqlite or HTTP client).
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

1. **Executor hook** — parent script on A calls `Proposer.Propose` for dependent op on B.
2. **John ↔ B authorisation** — A may forward a pipe; John authenticates to B directly; B records OK; **no A MITM** (see `design.md` § Proposer).
3. **HTTP control channel** — carry `Propose` prompts/responses (4th upgrade vs mux); distinct from stdio attach A↔B.
4. Same-host Nix e2e (revised; see `design.md` § Federation).

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
| Start/Handle awkward on server | Server never exposes `Handle` to wire; slot goroutine only |
| Global op map for join/cancel by op number | **`Handle` closure per `Run`** — no registry (Phase 3 lesson) |
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
