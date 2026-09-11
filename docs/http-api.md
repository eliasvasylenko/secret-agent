# HTTP API (target)

Wire format for the attach-before-start model. Domain logic uses `executor.OperationParameters`; JSON uses **`OperationRequest`** / **`NamedOperationRequest`**.

Principal is always from transport (Unix peer credentials), never from the request body.

Pending attach slot key: **`(secretId, principal)`**. POST atomically consumes that
slot; subsequent attaches may prepare another operation while the consumed one runs.
**Stdout/stderr disconnect** (or any stream drop **before POST**) cancels the associated
op. **Stdin EOF while running** closes process stdin only.

---

## Routes

Instances and operations are **root collections**: instance ids are globally unique, so
nesting them under a secret would put an identifier in the path that the lookup ignores.
Filtering by secret is a query parameter; the owning secret of a *new* instance or
operation travels in the body. What genuinely belongs to a secret — its plan, its active
instance, its attach slot — stays nested.

### Catalog

| Method | Path | Response |
|--------|------|----------|
| GET | `/secrets` | `{ "items": { ... } }` |
| GET | `/secrets/{secretId}` | secret plan |
| GET | `/secrets/{secretId}/active` | instance or null |
| GET | `/instances?secretId=&from=&to=` | `{ "items": { ... } }` — `secretId` optional |
| GET | `/instances/{instanceId}` | instance |
| GET | `/operations?secretId=&instanceId=&from=&to=` | operations; both filters optional |

### Attach + run

| Method | Path | Notes |
|--------|------|-------|
| POST + Upgrade | `/secrets/{secretId}/attach/stdin` | Protocol `secret-agent-process/1`. Optional body bytes before hijack (buffered stdin). |
| POST + Upgrade | `/secrets/{secretId}/attach/stdout` | Server → client copy |
| POST + Upgrade | `/secrets/{secretId}/attach/stderr` | Server → client copy |
| POST | `/instances` | Create instance + start op; `secretId` in body. **Requires attach slot ready.** |
| POST | `/operations` | Start named op; `instanceId` in body, secret derived from it. **Requires attach slot ready.** |

`POST /operations` derives the secret from the instance, so a request cannot name one
secret's attach slot while operating on another secret's instance. There is no
`GET /operations/{n}`: `operationNumber` is reported per instance, so it is not used as a
URL identifier.

### Removed (vs current branch)

| Removed | Replacement |
|---------|-------------|
| `POST …/operations/{opNumber}/attach/{stream}` | Attach before op number exists |
| `GET …/operations/{opNumber}/result` (long-poll) | Attach stream EOF + GET instance |
| `DELETE …/operations/{opNumber}` | Stdout/stderr disconnect cancels op |
| `GET/POST /secrets/{secretId}/instances…` | Root `/instances`, `/operations` collections |

---

## Attach slot readiness

**v1 rule:** POST start is rejected (**409**) until **stdout and stderr** are attached. **Stdin** attach required only when the operation’s script may read stdin (server may always require all three for simplicity in v1 — see design decisions).

When POST succeeds, response returns initial **`Instance`** JSON (op accepted, `startedAt` set). `Runner.Run` starts the subprocess before returning that snapshot, using an execute context independent of the POST request context.

---

## Status codes

| Code | When |
|------|------|
| 101 | Attach upgrade OK |
| 426 | Attach without Upgrade header |
| 404 | No attach slot / unknown secret or instance |
| 400 | Missing `secretId` on create, missing `instanceId` on operation, `create` posted to `/operations` |
| 409 | Pending slot not ready; stream already claimed |
| 403 | Attach/start principal ≠ slot `startedBy` |

---

## JSON types (wire)

### `OperationRequest`

Shared payload for starting any operation:

```json
{
  "env": { "KEY": "value" },
  "forced": false,
  "reason": "audit reason"
}
```

`startedBy` is **not** in the body; server sets it from peer identity.

### Create — `POST /instances`

Body: **`InstanceRequest`** — `OperationRequest` plus the owning secret.

```json
{
  "secretId": "my-secret",
  "env": null,
  "forced": false,
  "reason": "initial rollout"
}
```

Missing `secretId` is **400**. Response **200**: `secrets.Instance` with new `id`, `status.operationNumber`, `status.startedAt`, etc.

### Instance operation — `POST /operations`

Body: **`NamedOperationRequest`**

```json
{
  "instanceId": "0f4d…",
  "name": "activate",
  "env": null,
  "forced": false,
  "reason": "rolling out"
}
```

`name`: one of `destroy`, `activate`, `deactivate`, `test` (`create` is rejected here — use `POST /instances`). Missing `instanceId` is **400**; unknown `instanceId` is **404**.

Response **200**: updated `Instance` snapshot (same shape as today).

---

## Client flow (summary)

```
1. POST upgrade attach/stdin, stdout, stderr   (same principal on all connections)
2. POST /instances or /operations              (short request ctx)
3. Read Instance from response body             (op accepted)
4. Pump attach conns until server closes them  (slot ctx / conn lifetime)
5. GET /instances/{id}                          (final status, reported by Handle.Wait)
```

Completion: server closes pipe ends when subprocess exits → attach reads/writes hit EOF. Client **`Wait`** maps to steps 4–5. Exit code: see design.md (coarse from `completedAt`/`failedAt` until control channel exists).

---

## Proposals (future)

Dependent-secret authorization during run: **control messages** on a separate upgraded stream or mux (`/attach/control`). Not in v1 wire format.
