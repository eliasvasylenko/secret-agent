# HTTP API

Wire format for the operation model. Domain logic uses `executor.OperationParameters`; JSON uses **`OperationRequest`** embedded in **`StartOperationRequest`**.

Principal is always from transport, never from the request body. The agent does not
authenticate. Local Unix: peer credentials. Name header **`X-Secret-Agent-User`** is
used only when `SO_PEERCRED` matches `ForwardAuth.Peers` (Caddy, or a shared-account
SSH helper that injects the header). If that name is a local user, principal is
`linux:{user}/{uid}`; otherwise `http:{name}` (not a local account — not “HTTPS vs
SSH”). SSH as a real unix user: `dial-stdio` helper, identity from peercreds, no header.
See [plan-remote.md](plan-remote.md).

Attach uses HTTP `101` + `Upgrade: secret-agent-process/1` — the same Upgrade
mechanism as WebSockets. Caddy `reverse_proxy` forwards it; e2e should confirm the
custom protocol name is not filtered.

Every operation is created **pending** under its own global operation ID, hangs its
attach streams, and starts as a separate call. Execute begins only at the start call,
with the streams already connected. Only the operation's creator may attach to it.
A file drop **before start** deletes the pending operation; **a process-writable
file disconnecting while running** cancels it. **Input EOF while running** closes
process input only. An attach is one open file: its JSON body's `fds` lists
every process descriptor that refers to it, the way a local `dup` does, and
`mode` is what the process does with it: today `r`, `w`, `tty`, or `ctty`.
`{"fds":[1,2],"mode":"w"}` is `2>&1`. `{"fds":[0,1,2],"mode":"ctty"}` is a
shared controlling terminal. The client chooses the mode from the file it is
forwarding. Separate files are separate attaches. Bytes after the `101` are
that mode's stream; a later mode may speak a file protocol on the same
upgrade instead of raw copies.

`expiresAt` is how long the operation stays readable: 10 minutes
(`--pending-operation-ttl`) from creation while it is pending, reset to 2 minutes
(`--finished-operation-ttl`) when it completes or fails. A running operation is
kept until it finishes. After `expiresAt`, `GET` returns 404.

---

## Routes

Instances and operations are **root collections**: ids are globally unique, so nesting
them under a secret would put an identifier in the path that the lookup ignores.
Filtering by secret is a query parameter; the owning secret of a *new* operation
travels in the body.

### Catalog

| Method | Path | Response |
|--------|------|----------|
| GET | `/secrets` | `{ "items": { ... } }` |
| GET | `/secrets/{secretId}` | secret plan |
| GET | `/secrets/{secretId}/active` | instance or null |
| GET | `/instances?secretId=&from=&to=` | `{ "items": { ... } }` — `secretId` optional |
| GET | `/instances/{instanceId}` | instance (current status snapshot) |

### Operation workflow

| Method | Path | Notes |
|--------|------|-------|
| POST | `/operations` | Create a **pending** operation. `201 {operationId, state, expiresAt}`. Never runs anything. |
| POST + Upgrade | `/operations/{operationId}/attach` | Protocol `secret-agent-process/1`. JSON body `{"fds":[0,1,2],"mode":"ctty"}` claims one file. `mode` is required (`r`/`w`/`tty`/`ctty`). `Content-Type` must be `application/json`. The body is read before the upgrade; bytes after the `101` are the file's stream. Creator only. |
| GET | `/operations/{operationId}` | `{operation, state, expiresAt, instance?}`. `?untilDone=30s` holds until the operation is `completed` or `failed`, or for that long, then returns the snapshot. Omitting it returns the snapshot immediately. Creator only. |
| POST | `/operations/{operationId}/start` | Starts; the starter must hold permission. Returns the `Instance`. Second start is `409`. |
| DELETE | `/operations/{operationId}` | Cancels a pending or started operation. A finished one is `409`. |

For non-create operations the secret is derived from the instance, so a request
cannot attach one secret's streams while operating on another secret's instance; a
`secretId` sent anyway must match the derived secret.

### Removed (legacy)

| Removed | Replacement |
|---------|-------------|
| `POST /instances` (create + start) | `POST /operations` with `name: "create"`, attach, then `.../start` |
| `POST /secrets/{secretId}/attach/{stream}` (slot-keyed attach) | `/operations/{operationId}/attach` with a JSON body |
| `POST …/operations/{opNumber}/result` (long-poll) | Attach stream EOF + `GET /operations/{operationId}` |
| `GET /operations?…&from=&to=` (history listing) | No replacement. Current status is on the instance. |
| `GET/POST /secrets/{secretId}/instances…` | Root `/instances`, `/operations` collections |
| `POST …/process/io` | Attach upgrade streams |

---

## Start readiness

Start does not require any attaches. A descriptor that was not attached is
simply not supplied: fds 0, 1 and 2 fall back to the null device when the
process starts, and higher descriptors stay closed.

When start succeeds, the response returns the initial **`Instance`** JSON (op
accepted, `startedAt` set). `Runner.Run` starts the subprocess before returning that
snapshot, using an execute context independent of the request context.

---

## Status codes

| Code | When |
|------|------|
| 101 | Attach upgrade OK |
| 201 | Pending operation created |
| 204 | Pending operation deleted |
| 426 | Attach without Upgrade header |
| 404 | Unknown operation, secret or instance |
| 400 | Missing `secretId` on create, `instanceId` on a create, missing `instanceId` on other operations, mismatched `secretId` |
| 409 | Stream already claimed; operation already started or already finished |
| 415 | Attach or create without `Content-Type: application/json` |
| 403 | Attach/start/GET principal ≠ operation creator; starter lacks permission |

---

## JSON types (wire)

### `OperationRequest`

Shared payload for any operation:

```json
{
  "env": { "KEY": "value" },
  "forced": false,
  "reason": "audit reason"
}
```

`startedBy` is **not** in the body; server sets it from peer identity.

### Create operation — `POST /operations`

Body: **`StartOperationRequest`** — the target plus `OperationRequest`.

```json
{
  "secretId": "my-secret",
  "name": "create",
  "env": null,
  "forced": false,
  "reason": "initial rollout"
}
```

Missing `secretId` is **400**; an `instanceId` on a create is **400**.

### Instance operation — `POST /operations`

```json
{
  "instanceId": "0f4d…",
  "name": "activate",
  "env": null,
  "forced": false,
  "reason": "rolling out"
}
```

`name`: one of `create`, `destroy`, `activate`, `deactivate`, `test` (`create`
carries `secretId` instead of `instanceId`). Missing `instanceId` is **400**;
unknown `instanceId` is **404**.

---

## Client flow (summary)

```
1. POST /operations                             (pending operation, get operationId)
2. POST upgrade attach for each distinct open file
   (body `{"fds":[0,1,2],"mode":"ctty"}` when stdio is one controlling terminal)
3. POST /operations/{operationId}/start         (short request ctx)
4. Read Instance from response body             (op accepted)
5. GET /operations/{operationId}?untilDone=30s (outcome; poll again while it is still running)
6. Server closes the attaches when the process exits; drain output before Wait returns
```

Completion: server closes pipe ends when subprocess exits → the client's output copies read EOF. Client **`Wait`** maps to steps 5–6. Input is copied in the background for as long as the local file stays open. Exit code: see design.md (coarse from the operation's `completedAt`/`failedAt` until control channel exists). The instance's `state` is the last completed operation; `operation` is the last one that started. `revision` bumps on each of those writes.

---

## Proposals (future)

Dependent-secret authorization during run: an operation created by a principal who
may ask but not run is `awaiting-approval` until a permitted principal starts it.
Parked with federation — [plan-federation.md](plan-federation.md) (Phase 1+). John↔B
is either **introduce** (John dials B) or **pipe** (opaque splice through A; John still
authenticates to B’s proxy or `sshd`). Remote access (John talking to one agent) is
[plan-remote.md](plan-remote.md).
