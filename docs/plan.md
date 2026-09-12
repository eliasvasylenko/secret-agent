# Implementation plan — local agent (Phases 0–7)

Detailed plan to migrate secret-agent to the architecture in [`design.md`](design.md).
Work is ordered so each phase produces a compilable, testable increment.

**Status: complete (Sep 2026).** Phases 0–7 shipped: sqlite + HTTP attach-before-start,
`backend.Backend` / `Handle`, flat catalog routes, CLI via `ops`, docs cleanup.

**Next work:** remote secrets and authentication — **[plan-remote.md](plan-remote.md)**.
Federation / `Proposer` is parked in [plan-federation.md](plan-federation.md).

---

## Phase 0 — Lock API shapes (discovery) ✅

Goal: written decisions before large refactors.

**Done:** [`design.md` § Decisions](design.md#decisions-phase-0), [`http-api.md`](http-api.md), [`internal/ops/doc.go`](../internal/ops/doc.go).

<details>
<summary>Phase 0 deliverables (reference)</summary>

- Store surface: `Backend` with `Catalog()` + `Runner(secretId)`; `Run` → `(*Instance, Handle, error)`
- `Handle`: `Wait` joins; `Cancel` stops op; two ctx lifecycles
- HTTP routes: attach before start; flat `/instances` and `/operations`
- Wire DTOs: `OperationRequest`, `SecretOperationRequest`, `InstanceOperationRequest`
- `attachSlot` state machine documented

</details>

---

## Phase 1 — Backend interfaces (`internal/backend`) ✅

Stable interfaces; mocks compile.

**Verification:** `go build ./internal/backend/... ./internal/mocks/...`

---

## Phase 2 — Porcelain (`internal/ops`) ✅

Typed `Create` / `Destroy` / … wrapping `Run` + `Wait`.

**Verification:** `go test ./internal/ops/...`

---

## Phase 3 — Sqlite runner ✅

In-process path: persist → background execute → `Handle`; no global op registry.

**Verification:** `go test ./internal/sqlite/...`

---

## Phase 4 — HTTP server attach slot + routes ✅

Attach-before-start per `(secretId, principal)`; POST consumes pending slot; flat routes.

**Verification:** `go test ./internal/server/...`

---

## Phase 5 — HTTP client runner ✅

Client: attach → POST → pumps → `Handle.Wait` (GET instance).

**Verification:** `go test ./internal/client/...`

---

## Phase 6 — CLI + serve wiring ✅

`NewBackend`; reads via `Catalog`; mutations via `ops`; `serve` uses `backend.Backend`.

**Verification:** `go test ./...`

---

## Phase 7 — Cleanup and docs ✅

Deprecated `plan-process-io.md`; final `http-api.md`; stale code removed.

---

## Dependency graph (completed)

```
Phase 0 → Phase 1 → Phase 2
              ↓         ↓
         Phase 3   Phase 4
              ↓         ↓
              └── Phase 5
                    ↓
                 Phase 6
                    ↓
                 Phase 7  ✓
```

---

## Success criteria (met)

- Single domain params type: `executor.OperationParameters`.
- Catalog reads without stdio; mutations through `Runner` + `ops`.
- HTTP: attach before start; per `(secretId, principal)`; disconnect cancels.
- POST returns accepted `Instance` under request ctx; subprocess outlives request.
- No `/result` long-poll; no op-number attach paths.
- `go test ./...` passes.

---

## Deferred (not blocking federation)

| Item | Notes |
|------|--------|
| Agent restart marks in-flight ops failed | design.md § Open |
| Orphan attach-slot timeout | `OutputTTL` CLI flag reserved |
| Rich exit code over HTTP | `errors.As` on local path; stderr on wire |
| Remote access / auth | **[plan-remote.md](plan-remote.md)** |
| Federation / Proposer wire | Parked — [plan-federation.md](plan-federation.md) |
