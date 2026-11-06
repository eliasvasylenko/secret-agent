# Federation and Proposer — implementation plan

> **Model settled (Oct 2026).** Phases 0.5–2 below are implementable now against the local
> agent; the branch `new-auth` already carries a first cut (see § Current code). Phases 4+
> need John to reach B as himself ([plan-remote.md](plan-remote.md)). The terminal /
> approval-prompt work ([plan-terminal.md](plan-terminal.md), branch `tty-terminal`) is
> parallel: it decides *how* John's CLI shows and answers a proposal; this plan decides
> *what* a proposal is.

Last updated: 25 Oct 2026.

**Problem:** a parent op on host **A** needs a dependent op on secret **X** held by host
**B**. A holds a *parent role* of X on B, which lets A **ask**; it does not let A run X.
**John**, the operator who started the parent op, holds permission on X. B must run X only
when A asked for it *and* John started it, and B must verify both itself.

---

## The model

Three parties, three trust statements:

| Party | Trusts | For |
|-------|--------|-----|
| John | B, and his own CLI | B holds X anyway; the CLI is his |
| B | its own authenticator for John; A **only to ask** | parent role = may request, nothing more |
| A | nothing | A gets the stdio of an operation John started, and that is all |

**Flow (one start, by John):**

All operations — direct and federated — use the same workflow; approval is a state of an
operation, not a separate resource:

1. **A creates a pending operation:** `POST /operations`, as A, with the start body
   (see § HTTP surface). B assigns a global operation ID and records who created it.
   Nothing has started; no started-operation record exists yet. Because A holds only a parent role, the
   operation is `awaiting-approval` and B includes a proposal token in the response.
2. **A attaches** its files to it: `POST /operations/{operationId}/attach` with a
   JSON body such as `{"fds":[0,1,2],"mode":"ctty"}`, as A. The upgrades stay open.
3. **A puts John on B.** A's `Propose` callback gives John's CLI the handle
   `{operationId, token}` and a way to reach B: John's own route (**introduce**) or a raw
   connection A splices toward B's `sshd`/proxy (**pipe**). The handle is the only thing
   John takes from A.
4. **B tells John.** John's CLI, authenticated to B as John, fetches
   `GET /operations/{operationId}` with the token. B returns its own record: secret,
   instance, operation name, parameters, requesting principal, expiry. The CLI shows
   *that*, not anything A said.
5. **John starts it:** `POST /operations/{operationId}/start` with the token, as John. B
   checks John's permission, requires the streams attached, runs it, and records
   `startedBy = John`, `createdBy = A`.
6. **A learns the result.** `Propose` returns nil once John's start was accepted. A's
   client fetches `GET /operations/{operationId}` for the instance (for a `create`, this
   is the only way A learns the instance ID) and again for the outcome once its attach
   pumps finish. Decline, expiry, cancel, or any A attach stream dropping deletes the
   pending operation.

A direct operation is the same three steps with one principal throughout: the creator
attaches and starts their own operation. The client's `Runner.Run` performs all three.

**Why this shape** (decisions from the Oct 2026 discussion):

| Question | Decision | Why |
|----------|----------|-----|
| Who starts? | **John**, by reference to `R` | The person authorised to run X is the one whose call runs it. No op row is created by someone without permission. |
| Who describes the op to John? | **B**, from its record of A's request | A is the party that must not be trusted to describe. John's CLI renders B's record; A can lie only about things B does not hold, and B holds the whole request. |
| Start-by-reference vs re-spelling the start | **By reference** | Field-by-field equality of a reconstructed request (env, defaults, reason text) is brittle and false mismatches look like attacks. The reference *is* a start call: B still checks John's permission and records John as starter. |
| Does John confirm A's identity? | **No** | The parent role on B already says who may ask about X. John cannot evaluate a principal name. B shows it for the record. |
| Binding John's start to A's request | **Token** issued by B to A, carried to John | Without it a compromised A could point John at another parent's pending request on X. When the pipe lands on an agent-created per-request endpoint the tunnel itself is the binding; the token still applies for introduce. |
| A tells B *and* John? | A tells only B. John gets the description from B | See "who describes". A's `Propose` carries the handle, not the content. |
| Where does a pending op live? | **On the operation itself** (`/operations/{operationId}`), in a pre-start state | A proposal and an attach slot would be two pre-start containers needing a binding step. One container: the operation is created pending, hangs its streams, then starts. Direct and federated ops share the workflow; approval is a state, not a resource. |
| Resource name | **Operation**; "proposal" is the `awaiting-approval` state | "Proposal" is already load-bearing (`Proposer`, the threat model's approval vs authorisation). Spending it on every direct start — including cron — would blur exactly that distinction. |
| Attach target | The operation ID, replacing `(secret, principal)` slots | Removes the one-pending-slot-per-principal limit (parallel dependent ops on one secret), makes orphans addressable (GET/DELETE, expiry), and revives the legacy attach-by-op route shape — now sound, because the ID exists before the op number does. |
| Who may attach? | Only the operation's creator | The proposal token grants inspection and start, never attach — stdio belongs to the orchestrator, not the approver. |
| A creates but turns out to be permitted | The operation is simply self-startable; A starts it (step 3 of `Run`) | No auto-start side effect: creation never runs anything, for anyone. Whoever starts is who B checks and records. |
| Starter is always attacher? | **Replaced:** starter is John, attacher is A; the started operation record carries both | This is the asymmetry the old rule tried to avoid, resolved the other way: the start is by the authorised person, the stdio by the orchestrator John chose. |
| Is an operation a permanent record? | **No.** `/operations/{operationId}` is an ephemeral workflow resource, not an archive | It exists so the operation can be attached, inspected, started, cancelled, and its outcome collected. The instance's status snapshot is the durable consequence; a browsable full operation history is not a product feature, and the `operation` table goes (see § Operation and status model). |
| Direct start on a secret with parents by a permitted non-parent | **Refused** | A secret that names parents is only ever run through a parent. John runs X only as the starter of an awaiting-approval operation. |
| Run while waiting for John? | **No.** Nothing executes until John's start | Once the script runs, a parent-role caller has executed code on B. |
| Expiry | Pending operations expire (default 10 min, `--proposal-ttl`) | A caller who never brings John must not pin attaches forever. |

**What a compromised A can do:** request operations it holds a parent role for; lie to
John about which (caught: John sees B's record); drop the pipe (denial). It cannot make B
run anything John did not start, cannot run as John, and gets only the stdio of what John
started. **A compromised third parent C** has no path to John and, without A's token,
cannot have its request started by John's call.

---

## HTTP surface (B)

One workflow for every operation. The create body is the flattened start body:
`{secretId, instanceId, name, env, forced, reason}` — `create` requires `secretId` and
forbids `instanceId`; other names require `instanceId`, derive the secret from it, and a
`secretId` sent anyway must match.

| Route | As | Does |
|-------|----|------|
| `POST /operations` | creator | Creates a **pending** operation, `201 {operationId, state, token?, expiresAt}`. Never runs anything. `state: awaiting-approval` (+ token) when the creator holds a parent role without permission; otherwise `state: pending`. No started-operation record yet. |
| `POST /operations/{operationId}/attach` (JSON body) | creator only | One upgrade per distinct open file, held open. Replaces `/secrets/{secretId}/attach/...`. |
| `GET /operations/{operationId}` | creator | The operation record (§ model); once started, also the resulting instance. `?untilDone=30s` holds until it is `completed` or `failed`, or for that long. `expiresAt` is reset when it finishes so the creator can collect the outcome; after that, `404`. |
| `GET /operations/{operationId}` + token | John | B's full record of what A proposed: secret, instance, name, params, `createdBy`, `createdAt`, `expiresAt`. (Per-instance numbers can't identify a pending op — hence the global ID.) |
| `POST /operations/{operationId}/start` | creator, or John + token | Permission check for the *starter* on the described op; `Runner.Run` with the attached files; `startedBy = starter` (`createdBy` already recorded); returns the instance. Second start → `409`. |
| `DELETE /operations/{operationId}` | creator, or John + token | Decline / cancel: drops attaches; a started run is cancelled and the outcome stays readable. |

Token: 32 random bytes, base64url; header `X-Proposal-Token`. Issued only for
`awaiting-approval` operations; single use for `start`. Document in
[http-api.md](http-api.md) when Phase 0–1 land.

---

## Operation and status model (minimal, secret-specific)

Settled in the Oct 2026 status discussion. This is deliberately **not** the
generalised user-definable state machine explored in [plan-generic.md](plan-generic.md);
it is the smallest coherent model for the fixed secret lifecycle
(`create`/`destroy`/`activate`/`deactivate`/`test`) that the federation work needs.

The lifecycle is a state machine in which **operation names do double duty**:
imperative when requested (the edge), past-participle when they name the state a
success establishes (the node: `activate` ⇒ activated). Several edges can arrive at the
same node (`test` from `create` or from `test`). The model separates the two.

**Node — `State`.** The instance's established state: the name of the last operation
that *completed*, and when. Zero value = nothing established yet (only `create` may be
in flight). The secret's active instance is **not** an instance state; it stays the
secret-level pointer `activeInstanceId`, acquired by a completed `activate` and
released by a completed `deactivate`.

**Edge — `Operation`.** One operation, from `POST /operations` to its outcome:

```go
type Operation struct {
    Id         string        // workflow identity; assigned at POST /operations
    SecretId   string
    InstanceId string        // empty for create until start assigns the instance
    Name       OperationName
    Forced     bool
    Reason     string

    CreatedBy string         // who asked (A in the federated flow)
    CreatedAt time.Time

    StartedBy   string       // who ran it (John); == CreatedBy for a direct start
    StartedAt   *time.Time
    CompletedAt *time.Time
    FailedAt    *time.Time
}
```

Workflow state is derived, not stored: no `StartedAt` ⇒ pending (`awaiting-approval`
when the registry holds a token for it); started with neither outcome ⇒ running; then
completed or failed. Decline, expiry, and cancel-before-start need no timestamps — the
registry drops the record and `GET` 404s. `CreatedBy` **replaces** the earlier
`requestedBy` idea: the requester is the creator, and for a direct start creator and
starter coincide, so no "empty for direct starts" case exists.

**Snapshot — `Instance`.** Current status is a snapshot, not a derivation over history:

```go
type Instance struct {
    Id       string
    Secret   Secret
    Revision int        // optimistic concurrency; bumps on every status write

    State     State     // node
    Operation Operation // edge: the last operation that *started* on this instance
}
type State struct {
    Name OperationName
    At   time.Time
}
```

Invariants (the state machine written as data):

- `Operation.CompletedAt != nil` ⇒ `State.Name == Operation.Name` and
  `State.At == *CompletedAt`. A successful edge *is* the arrival at the node.
- `Operation.FailedAt != nil` ⇒ `State` is unchanged from before the attempt. A failed
  operation establishes nothing, but still constrains what may follow: retry the same
  operation, or `force` another.
- Both nil ⇒ the edge is in progress; `State` is still the departure node.
- `State` zero ⇒ nonexistent; `Operation.Name == create`.
- An unstarted operation never appears on an instance; it establishes nothing and
  constrains nothing beyond its own conduct. The instance only ever embeds a started
  operation, so `Instance.Operation.StartedAt` is always set.
- `Instance.Operation.Id` is **empty**: the operation ID is workflow identity and dies
  with the workflow. The durable store does not reference an ephemeral thing.

**Identifiers and ordering:**

- `operationId` identifies the operation *workflow* — create, attach, inspect, start,
  cancel, collect the outcome — and lives only in the server's registry.
- `Revision` replaces `operationNumber`. It is a per-instance counter of status
  writes (start, completion, failure each bump it), not a count of operations.
  `ExpectedRevision` replaces `ExpectedOperationNumber` as the "start only if the
  instance is still as I inspected it" guard. Nothing is ordered by `startedAt`, so no
  clock-monotonicity invariant is needed.

**Where outcomes are read from.** A client learns an operation's outcome from
`GET /operations/{operationId}`, which stays readable until `expiresAt` (reset when
the operation finishes) and returns the outcome and the resulting instance — not by reading
the instance's current status and assuming the latest operation is its own. In the
federated `create` case this route is needed post-start anyway: John's start response
goes to John, and A learns the instance ID only from the operation.

**History and audit — explicitly not product features of this model:**

- There is **no full operation history** in the product. The `operation` table and
  `GET /operations?secretId=&instanceId=&from=&to=` exist only because status used
  to be derived from history; both go. `/operations` survives as the workflow resource
  above, not as an archive. The `history` CLI command goes with it.
- Current status is **not an audit log**, and should not be described as one. After a
  failed attempt it no longer records who performed the last *successful* transition
  (only when, via `State.At`); approval events that never start (proposal
  created/declined/expired, denied starts) leave no durable trace. Both are accepted
  for now. A real audit trail — append-only events under their own retention and
  access policy, carrying the operation ID — is a separate future feature, to be
  designed as audit rather than inherited from a status table.

**Go surface:**

```go
// backend
type Proposal struct {
    ID, Token string
    Dial      func(ctx context.Context) (net.Conn, error) // reach B as John; nil = dial B's address directly
}
type Proposer interface {
    // Propose puts the operator on B for one pending proposal. Nil = John's start was
    // accepted by B. Error = declined, expired, or could not reach B.
    Propose(ctx context.Context, p Proposal) error
}
```

`Runner.Run` keeps its signature; the HTTP runner implements it as
create → attach → (maybe `Propose`) → start → `GET /operations/{operationId}`. The
sqlite runner keeps the `Proposer` for Phase 3.

---

## Current code (branch `new-auth`, uncommitted)

A first cut that predates the decisions above. Keep / change:

| Have | Do |
|------|----|
| `admit()` in `server/controller.go`: parent without permission → `200 {"wireApproval":{"secretId"}}` before `takeSlot` | **Delete.** `wireApproval` goes; creation records creator/roles, and the gate moves to `start`, where the starter is checked. |
| `requirePermission` / `HasRole` / parent-role refusal for permitted non-parents | Keep; applied at `start`, not create. |
| `Proposer.Propose(ctx, secretID, name, params, pipe io.ReadWriteCloser)` | Change to `Propose(ctx, Proposal)`. The content fields go away (John gets them from B). |
| `attachSlot` + `/secrets/{secretId}/attach/{stream}` | Promote to the pending-operation registry (Phase 0): slot fields (pipes, claimed, watch) move onto the operation record; attach routes key by operation ID. |
| `client/runner.go`: one `postStart`, on wire approval dial pipe → `Propose` → error "did not start" | Rebuild on the unified workflow (Phase 2): create → attach → `Propose` if awaiting → start → pumps/join. |
| `client/dial.go` `dialPipe`: raw TCP to B's host; unix refused | This is **introduce** from John's CLI, not A's splice. Move behind `Proposal.Dial` default. Unix refusal stays (peercreds would be the CLI's own process — correct for same-host John, wrong for A). |
| `sqlite` keeps the proposer on `opHandle` | Keep; used in Phase 3. |
| Two start endpoints (`POST /instances`, `POST /operations`), two body DTOs | Flatten into `POST /operations` (Phase 0). |
| Tests: `TestRunner_wireApprovalOpensPipe`, controller parent/permission subtests | Rewrite against the workflow above in Phase 0–2. |

---

## Phase 0 — Unified operation workflow (preliminary) — **done Oct 2026**

Goal: flatten the start endpoints and hang attach off the operation, replacing slots.
Breaking change inside this repo only; cheaper now than after federation entrenches the
slot binding.

1. `POST /operations` takes `{secretId, instanceId, name, env, forced, reason}` and
   creates a **pending** operation with a global ID (`201`). `create`: `secretId`
   required, `instanceId` forbidden. Other names: `instanceId` required, secret derived
   from the instance; a `secretId` sent anyway must match (keeps the slot-selection
   guard). `POST /instances` and the `SecretOperationRequest`/`InstanceOperationRequest`
   pair go away.
2. Pending-operation registry on `Controller` succeeds `slots`: creator, target, params,
   token (when awaiting approval), attach pipes/claims (today's `attachSlot` fields),
   expiry, state. Attach routes move to `POST /operations/{operationId}/attach/{stream}`,
   creator only.
3. `POST /operations/{operationId}/start`: creator starts their own (permission checked
   here); requires all streams attached; `Runner.Run`; returns the instance.
   `GET /operations/{operationId}`: state, then the started operation/instance.
   `DELETE` before start drops the pending op.
4. HTTP runner implements `Run` as create → attach → start → pumps/join. Expiry and
   attach-drop delete the pending op (today's orphan-slot behaviour, now addressable).
5. Update [http-api.md](http-api.md) and the route/shape notes in [design.md](design.md).
6. Tests: tests posting `POST /instances` move to the workflow; create-with-instanceId →
   400; mismatched secretId → 4xx; start before attach → 409; two pending ops for one
   `(secret, principal)` coexist; non-creator attach → 403; expiry deletes.

**Verification:** `go test ./...`

## Phase 0.5 — Status snapshot model (prerequisite for Phase 1) — **done Oct 2026**

Goal: land the § Operation and status model before federation adds a second principal
to the record. Breaking change inside this repo only (zero users; no migration path
for existing databases — a fresh schema).

1. `secrets`: `Operation` per § model (`Id`, `CreatedBy`/`CreatedAt`,
   `StartedBy`/`StartedAt *`, outcomes); `State{Name, At}`; `Instance{Revision, State,
   Operation}`. `Status` is deleted. `Instances` JSON ordering by `Revision` is
   meaningless across instances — order by `State.At`/`Operation.StartedAt` or by ID.
2. `executor.OperationParameters.ExpectedRevision` replaces `ExpectedOperationNumber`;
   `StartedBy` stays as the start-time principal, `CreatedBy` is threaded alongside.
3. sqlite: drop the `operation` table. Status columns live on `instance`: `revision`,
   `state`, `stateEnteredAt`, and the `op*` group (`opName`, `opForced`, `opReason`,
   `opCreatedBy`, `opCreatedAt`, `opStartedBy`, `opStartedAt`, `opCompletedAt`,
   `opFailedAt`). `beginCreate`/`beginUpdate` write the edge and bump `revision` in the
   same transaction as the transition guards; completion copies the edge into
   `state`/`stateEnteredAt`, updates `activeInstanceId` for `activate`/`deactivate`, bumps
   `revision`; failure sets `opFailedAt`, bumps `revision`, leaves `state` alone.
   Guards read `state`, the `op*` outcome, and `activeInstanceId` instead of
   `MAX(id)` joins. `getInstance`/list queries lose their joins.
4. Transition guards, restated against the snapshot (behaviour-preserving):
   `ExpectedRevision` mismatch → refuse; edge running or failed with a different name →
   refuse; `activate` while `activeInstanceId` set → refuse; `test`/`deactivate` while
   not the active instance → refuse. `forced` logs and proceeds, as today.
5. Remove `Catalog.Operations()`, `GET /operations?…&from=&to=`, the `history` CLI
   command, and their client methods and tests.
6. Server registry: `operationEntry` wraps a `secrets.Operation` (the domain record)
   plus pipes/claims/token/expiry, and owns its own lock and transitions
   (`claimAttach`, `start`, `finish`, `cancel`, `expire`). `operationRegistry`
   owns membership only; removal is two-phase (close the entry, then
   compare-and-remove), so no two locks are ever held together. Expiry is a
   timer per deadline, not a check on lookup. `GET /operations/{operationId}`
   returns the record and, once started, the instance. `expiresAt` starts at
   `pendingTTL` (default 10 min, `--pending-operation-ttl`) and resets to
   `finishedTTL` (default 2 min, `--finished-operation-ttl`) when the
   operation finishes, including when the backend rejects it at start.
7. HTTP runner: the join reads the outcome from `GET /operations/{operationId}`, not
   `GET /instances/{id}`.
8. Docs: [http-api.md](http-api.md) (remove the list route; document the record and
   `expiresAt`), [design.md](design.md) glossary (“Operation — audit record” →
   edge/node wording; Catalog loses history), README (“full history” claim goes).
9. Tests: invariants above (completed ⇒ state advanced; failed ⇒ state unchanged and
   only same-name retry allowed unforced; `Revision` bumps per write;
   `ExpectedRevision` guard); finished-operation expiry; runner join via the operation.

**Verification:** `go test ./...`

## Phase 1 — Approval gate at start (server)

Goal: an `awaiting-approval` operation can be inspected and started by a permitted
principal who is not its creator; B records both principals.

1. At create: creator with a parent role but no permission → `state: awaiting-approval`,
   token issued. Creator with permission → `pending` (self-startable). Secret with
   parents + non-parent creator → `403` at create.
2. `GET` with the token returns B's full record. `start` with the token: validate token,
   `permitted(starter, X)`, `Runner.Run` with the attached stdio, `startedBy = starter`
   (`createdBy` already on the record), token consumed.
3. Tests: parent-without-permission creates → awaiting, instance untouched; John `GET`
   without token → 404; John `start` with token → op runs with A's stdio, instance
   snapshot has both principals; token from op 1 cannot start op 2; starter without
   permission → 403; direct self-start on a parents-secret by a permitted non-parent →
   403.

**Verification:** `go test ./internal/server/...`

## Phase 2 — Client and CLI proposer (introduce, same host)

Goal: A's HTTP runner and John's CLI complete the loop against one agent.

1. `backend.Proposal`, `Proposer` signature change; all `noopProposer`s.
2. HTTP runner: create → attach → if `awaiting-approval`, `Propose` → `GET
   /operations/{operationId}` → pumps/join as today. Decline → close attaches, return the
   error.
3. CLI proposer: `Propose` dials B (`Proposal.Dial`, default = the CLI's configured
   address for that host), `GET /operations/{operationId}`, renders B's record through
   the console prompt (plan-terminal), on `yes` → `POST /operations/{operationId}/start`,
   else `DELETE`.
4. Tests: runner against a fake server (proposal → Propose → instance); CLI proposer
   against `httptest` (shows B's record, not the caller's; `yes` starts; anything else
   deletes).

**Verification:** `go test ./internal/client/... ./internal/cli/...`

## Phase 3 — Executor `Propose` hook (parent script → John)

Goal: a parent script running on A can trigger a dependent op and block on it.

1. Executor hook: a builtin/API the script calls with `(host, secret, op, params)`.
2. sqlite runner: route the hook to the stored `Proposer` (via the orchestrator of Phase 4
   for the A→B hop; in-process stub for tests).
3. Control channel John's CLI ↔ A's agent so `Propose` can reach John's CLI when the
   parent op itself runs over HTTP (4th upgrade on the parent op's attach, JSON frames:
   `proposal{operationId, token, host}` → `result{ok|error}`). Lifecycle tied to the
   parent operation.
4. Tests: parent script proposes; approve → continues; decline → parent fails; parent
   cancel → pending operation deleted on B.

## Phase 4 — Orchestrator: A → B, same host

Goal: A's agent is the HTTP client on B for the child's stdio, as principal A.

1. Orchestrator in A's agent: `client.New(B)` as A, `Runner(X).Run(...)` with the parent
   op's `Proposer` and the child's stdio (from the parent script's request).
2. Permissions: A's parent role on X in B's policy; synthetic principals in test
   `permissions.json` (John, A, runner).
3. Tests: two agents (two sockets) on one host, or one agent with two Unix peers.

## Phase 5 — Pipe (A splices John to B)

Goal: John cannot see B; A relays bytes, terminates nothing.

1. Per-operation tunnel endpoint on B: `POST /operations/{operationId}/tunnel` (as A) upgrades to a
   raw stream that B's agent hands to its *outside* authenticator path (B's `sshd` or
   proxy) for the inner hop — never onto the peercred Unix socket. Arrival on this tunnel
   is bound to `R`; the token is still required.
2. A: `Proposal.Dial` returns A's splice (through the Phase 3 control channel when John's
   CLI is remote from A).
3. Threat tests: A as splicer cannot read or alter the inner handshake (TLS/SSH); A cannot
   start `R`; replayed/edited `start` fails.

## Phase 6 — Same-host Nix e2e

`nix/checks/federated-stdio.nix`: `secret-b` create (parent) triggers `secret-a` on the
same agent; John approves at the console; proof file written; the instance snapshot
shows `startedBy = John`, `createdBy = A`.

## Phase 7 — Cross-host (deferred)

Introduce and pipe over real HTTPS/SSH per [plan-remote.md](plan-remote.md); orphan
timeouts; restart cleanup.

---

## Dependency graph

```
Phase 0 (flatten + pending operations, attach by operation ID)
    ↓
Phase 0.5 (status snapshot: node/edge, Revision, operation table goes)
    ↓
Phase 1 (approval gate at start)
    ↓
Phase 2 (client + CLI proposer, introduce)        ← needs plan-terminal console for the prompt
    ↓
Phase 3 (executor hook, control channel)
    ↓
Phase 4 (orchestrator A→B)
    ↓
Phase 5 (pipe) ──→ Phase 6 (Nix) ──→ Phase 7 (cross-host)
```

Phases 0.5–2 are implementable now on the local agent. Phase 2's prompt can land with a
plain line prompt and move onto the plan-terminal console when `tty-terminal` merges.

---

## Risk register

| Risk | Mitigation |
|------|------------|
| A lies to John about the op | John sees B's record only. A's `Propose` carries a handle, not content. |
| A points John at another parent's request | Token issued to A per request; per-request tunnel in the pipe model. |
| John starts something A did not ask for | Impossible: John starts `R`, and `R` is A's request verbatim. |
| Pending operation pins attaches forever | Expiry; A stream drop deletes it; `DELETE`. |
| Token leaks via A's logs | Single use; expires with `R`; John's start still needs John's permission. |
| A MITM on John↔B | John authenticates to B (TLS/SSH) on introduce or on A's splice; A never terminates it. |
| Same-host tests miss cross-host bugs | Phase 7 after Phase 6. |

---

## Success criteria

- A parent without permission gets an `awaiting-approval` operation, never a
  started-operation record; creating an operation never runs anything, for anyone.
- John sees B's description and starts by reference; B records `startedBy = John`,
  `createdBy = A`.
- A's stdio attaches are opened once and carry the op John started.
- A cannot start, describe, or redirect an awaiting-approval operation.
- Same-host Nix check passes; `go test ./...` green.

---

## References

- [design.md](design.md) — § Proposer, § Federation (rule replaced here), threat model
- [plan-terminal.md](plan-terminal.md) — the console John answers on (`tty-terminal`)
- [plan-remote.md](plan-remote.md) — how John reaches B as himself
- [http-api.md](http-api.md) — routes; operation workflow in Phase 0–1
- [plan.md](plan.md) — completed local-agent migration
