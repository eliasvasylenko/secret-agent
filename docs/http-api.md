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
A stream drop **before start** deletes the pending operation; **stdout/stderr
disconnect while running** cancels it. **Stdin EOF while running** closes process
stdin only. Pending operations expire after 10 minutes.

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
| GET | `/instances/{instanceId}` | instance |
| GET | `/operations?secretId=&instanceId=&from=&to=` | operations; both filters optional |

### Operation workflow

| Method | Path | Notes |
|--------|------|-------|
| POST | `/operations` | Create a **pending** operation. `201 {operationId, state, expiresAt}`. Never runs anything. |
| POST + Upgrade | `/operations/{operationId}/attach/stdin` | Protocol `secret-agent-process/1`. Optional body bytes before hijack (buffered stdin). Creator only. |
| POST + Upgrade | `/operations/{operationId}/attach/stdout` | Server → client copy |
| POST + Upgrade | `/operations/{operationId}/attach/stderr` | Server → client copy |
| GET | `/operations/{operationId}` | `{operationId, state, secretId, instanceId, name, instance?}`. Creator only. |
| POST | `/operations/{operationId}/start` | Starts; the starter must hold permission. Returns the `Instance`. Second start is `409`. |
| DELETE | `/operations/{operationId}` | Cancels a pending operation. After start, `409`. |

For non-create operations the secret is derived from the instance, so a request
cannot attach one secret's streams while operating on another secret's instance; a
`secretId` sent anyway must match the derived secret.

### Removed (legacy)

| Removed | Replacement |
|---------|-------------|
| `POST /instances` (create + start) | `POST /operations` with `name: "create"`, attach, then `.../start` |
| `POST /secrets/{secretId}/attach/{stream}` (slot-keyed attach) | `/operations/{operationId}/attach/{stream}` |
| `POST …/operations/{opNumber}/result` (long-poll) | Attach stream EOF + GET instance |
| `GET/POST /secrets/{secretId}/instances…` | Root `/instances`, `/operations` collections |
| `POST …/process/io` | Attach upgrade streams |

---

## Start readiness

Start is rejected (**409**) until stdin, stdout and stderr are all attached.

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
| 409 | Start before all streams attached; stream already claimed; operation already started |
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
2. POST upgrade attach/stdin, stdout, stderr    (against operationId, same principal)
3. POST /operations/{operationId}/start         (short request ctx)
4. Read Instance from response body             (op accepted)
5. Pump attach conns until server closes them   (op ctx / conn lifetime)
6. GET /instances/{id}                          (final status, reported by Handle.Wait)
```

Completion: server closes pipe ends when subprocess exits → attach reads/writes hit EOF. Client **`Wait`** maps to steps 5–6. Exit code: see design.md (coarse from `completedAt`/`failedAt` until control channel exists).

---

## Proposals (future)

Dependent-secret authorization during run: an operation created by a principal who
may ask but not run is `awaiting-approval` until a permitted principal starts it.
Parked with federation — [plan-federation.md](plan-federation.md) (Phase 1+). John↔B
is either **introduce** (John dials B) or **pipe** (opaque splice through A; John still
authenticates to B’s proxy or `sshd`). Remote access (John talking to one agent) is
[plan-remote.md](plan-remote.md).
