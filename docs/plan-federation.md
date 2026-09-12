# Federation and Proposer — implementation plan

> **Parked (Sep 2026).** Do **direct remote sessions** first: [plan-remote.md](plan-remote.md).
> Resume when John can reach an agent as himself (Unix, HTTPS via reverse proxy, and/or
> OpenSSH). Authn stays **outside** the agent ([plan-remote.md](plan-remote.md)).
> This plan then adds **`Proposer`**, A-as-orchestrator on B, and **both** John↔B hops:
> **introduce** (John dials B) and **pipe** (A splices; John has no view of B) on the same
> `Dialer` seam — not a new `Backend`.

Plan for **dependent-secret operations across hosts/principals**: parent script on host **A**
calls `Proposer.Propose` for work on host **B**, with **John’s authorisation verified on B**
(not asserted by A). This is new work on top of the attach-before-start architecture
completed in [plan.md](plan.md) (Phases 0–7).

**Prerequisites:** Phases 0–7 complete — `backend.Backend`, attach-before-start HTTP,
`Handle`/`Wait`, flat catalog routes, CLI via `ops`. See [design.md](design.md) § Proposer
and § Federation for constraints and threat model.

**Supersedes** federation sketches in deprecated [plan-process-io.md](plan-process-io.md)
(decoupled attach, `process/io`, op-number tokens — all replaced by current attach model).

---

## Goals

1. **In-script `Propose`** — parent op blocks until a dependent op on another secret/host is
   approved or rejected.
2. **John ↔ B authorisation** — B records John’s OK; A cannot forge approval or MITM the
   consent leg (see design.md threat model).
3. **Orchestrator on B** — host A is **starter and attacher** on B for stdio (same
   attach-before-POST flow as local CLI); John’s consent is a **separate** channel.
4. **Same-host PoC first** — two Unix principals on one machine before cross-host plumbing.
5. **John↔B path** — **introduce** and **pipe** both in scope. Inner authn on a pipe is
   still B’s reverse proxy or B’s `sshd`, not the agent.

**Out of scope for early federation phases:** production hardening beyond what
[plan-remote.md](plan-remote.md) already provides for HTTPS/SSH. Forward-auth and
OpenSSH are remote-plan work, not re-litigated here.

---

## Phase 0 — Federation decisions (discovery)

Lock before implementation. Append decisions to `design.md` when settled.

| Question | Options | Notes |
|----------|---------|-------|
| `Propose` wire | 4th HTTP upgrade vs mux on attach vs separate `/propose` route | Distinct from stdio attach A↔B |
| Ordering on B | John OK before A may POST start vs start pending until OK recorded | Affects attach slot + `Propose` blocking |
| Originating principal | JSON field vs header vs audit-only parent chain | B’s `startedBy` = A (transport); John in auth proof |
| John↔B hop | **Introduce** and **pipe** — both in scope | design.md § Proposer |
| Same-host test principals | Synthetic users in `permissions.json` | John, orchestrator, runner |
| Control message schema | JSON frames on control stream | Request/response for propose prompt + outcome |

**Deliverable:** decision table in `design.md`; sequence diagram A → B with John leg.

---

## Phase 1 — Executor `Propose` hook (local / sqlite)

Goal: scripts can invoke `Proposer` in-process; parent op blocks; no HTTP yet.

1. **Executor hook** — call `proposer.Propose(ctx, name, params)` from script runtime when
   dependent-secret builtin/API is invoked.
2. **Sqlite** — wire real `Proposer` into `Runner.Run` (remove `_ = proposer`); in-process
   implementation for tests (approve/reject callbacks).
3. **Audit** — log proposal attempts on parent op (reason chain).
4. **Tests** — parent script proposes child create; approve → continues; reject → parent fails.

**Verification:** `go test ./internal/executor/... ./internal/sqlite/...`

---

## Phase 2 — HTTP control channel

Goal: remote `Proposer` when parent runs on A and child target is B’s agent.

1. **Wire format** — control stream schema (Phase 0 decision); document in `http-api.md`.
2. **Server** — accept control upgrade (or mux); map to blocking `Propose` on server side.
3. **Client** — orchestrator’s `Proposer` implementation sends/receives on control conn
   while stdio uses existing attach routes.
4. **Lifecycle** — control conn tied to parent op on A; close on parent `Handle` cancel.

**Verification:** unit tests with mock control stream; integration with Phase 1 executor.

---

## Phase 3 — Orchestrator: parent on A, child on B (same host)

Goal: A starts and attaches on B using HTTP client as principal A; stdio path unchanged.

1. **Orchestrator helper** — given parent context, `Runner` on B via client socket as A
   (attach-before-POST + POST + pumps).
2. **Permissions** — A may start ops on B’s secrets per policy; `startedBy` on B = A.
3. **Parent script API** — trigger child op (create/activate/…) with parameters.
4. **Tests (Go)** — two mock backends or two sockets, same machine, different principals.

**Verification:** Go integration test; no John leg yet (auto-approve `Proposer` stub).

---

## Phase 4 — John ↔ B authorisation

Goal: B gates child op on John’s consent; A cannot MITM. **Both hops:**

1. **Introduce (same-host first)** — John dials B as himself (second Unix peer / later HTTPS or SSH). A only coordinates (`Propose` blocks until B has John’s OK).
2. **Pipe** — A splices one opaque conn per call toward **B’s** reverse proxy or
   **B’s `sshd`** (not onto B’s agent socket). John authenticates to B on that pipe.
   Needed when John cannot see B. If the inner hop is SSH, B’s `command=` is still
   the stdio↔unix-socket splice; A’s `command=` (if any) is the splice to B:22 / B’s
   proxy.
3. **B records OK** — from peercreds, or from the name header when that Unix peer
   matches `ForwardAuth.Peers`; never from A’s say-so.
4. **Unblock** — parent on A continues only after B records OK; reject on timeout/deny.
5. **Threat-model tests** — A cannot approve without the John leg; A as splicer cannot forge inner auth; replay/edited response fails.

**Verification:** same-host Go tests for introduce; pipe tests on the `Dialer` seam. Document principals in test permissions.

---

## Phase 5 — Same-host Nix e2e

Goal: end-to-end on NixOS with real CLI + two secrets.

1. **New check** — e.g. `nix/checks/federated-stdio.nix` (or extend stdio.nix).
2. **Secrets** — `secret-b` create triggers dependent op on `secret-a`; John authorises;
   runner attaches stdin on A; proof file written.
3. **Permissions** — test users mapped in module; document principal names.

**Verification:** `nix flake check` (federated check).

---

## Phase 6 — Cross-host (deferred)

Sketch only until Phase 5 is green. Outside authenticators are [plan-remote.md](plan-remote.md).

| Item | Notes |
|------|--------|
| Cross-host **introduce** | John → B’s reverse proxy or B’s `sshd` |
| Cross-host **pipe** | A splices to B’s proxy/`sshd`; John still authenticates to B; mix HTTPS outer × SSH inner (and the reverse) |
| Originating principal field | If needed for audit beyond transport `startedBy` |
| Operation / attach timeouts | Orphan slot TTL (`OutputTTL` CLI flag reserved) |
| Agent restart cleanup | Mark in-flight DB ops failed |

---

## Dependency graph

```
Phase 0 (decisions)
    ↓
Phase 1 (executor Propose, sqlite)
    ↓
Phase 2 (HTTP control channel)
    ↓
Phase 3 (orchestrator A→B, same host)
    ↓
Phase 4 (John ↔ B auth)
    ↓
Phase 5 (Nix e2e)
    ↓
Phase 6 (cross-host introduce + pipe) — optional
```

Phases 1–2 can overlap partially once Phase 0 locks control-stream shape.

---

## Risk register

| Risk | Mitigation |
|------|------------|
| A MITM on John↔B | John authenticates to B (introduce or inner handshake on a splice). Reject bearer tokens from A; A must not terminate the pipe. |
| `Propose` blocks parent forever | Timeout + cancel propagation parent → child |
| Control + stdio stream confusion | Separate upgrade protocol or mux with clear framing |
| Same-host tests don’t catch cross-host bugs | Phase 6 explicitly after Nix PoC |

---

## Success criteria

- Parent script on A can propose dependent op on B; blocks until resolved.
- B records John’s authorisation (introduce **or** pipe); A cannot forge it.
- A is starter+attacher on B for child stdio (attach-before-POST unchanged).
- Same-host Nix check passes.
- `go test ./...` remains green.

---

## References

- [design.md](design.md) — Proposer (introduce **and** pipe), Federation, threat model
- [plan-remote.md](plan-remote.md) — direct sessions this plan reuses as `Dialer`
- [http-api.md](http-api.md) — current attach + catalog routes (control stream TBD)
- [plan.md](plan.md) — completed local-agent migration (Phases 0–7)
- [plan-process-io.md](plan-process-io.md) — deprecated historical notes
