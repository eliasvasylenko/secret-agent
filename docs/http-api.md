# HTTP API (target)

Wire format for the attach-before-start model. Domain logic uses `executor.OperationParameters`; JSON uses **`OperationRequest`** / **`NamedOperationRequest`**.

Principal is always from transport (Unix peer credentials), never from the request body.

Pending attach slot key: **`(secretId, principal)`**. POST atomically consumes that
slot; subsequent attaches may prepare another operation while the consumed one runs.
**Stdout/stderr disconnect** (or any stream drop **before POST**) cancels the associated
op. **Stdin EOF while running** closes process stdin only.

---

## Routes

### Catalog (unchanged shape)

| Method | Path | Response |
|--------|------|----------|
| GET | `/secrets` | `{ "items": { ... } }` |
| GET | `/secrets/{secretId}` | secret plan |
| GET | `/secrets/{secretId}/instances` | `{ "items": { ... } }` |
| GET | `/secrets/{secretId}/instances/{instanceId}` | instance |
| GET | `/secrets/{secretId}/active` | instance or null |
| GET | `/secrets/{secretId}/operations?from=&to=&instanceId=` | optional: all ops for secret |

### Attach + run (new)

| Method | Path | Notes |
|--------|------|-------|
| POST + Upgrade | `/secrets/{secretId}/attach/stdin` | Protocol `secret-agent-process/1`. Optional body bytes before hijack (buffered stdin). |
| POST + Upgrade | `/secrets/{secretId}/attach/stdout` | Server → client copy |
| POST + Upgrade | `/secrets/{secretId}/attach/stderr` | Server → client copy |
| POST | `/secrets/{secretId}/instances` | Create instance + start op. **Requires attach slot ready.** |
| POST | `/secrets/{secretId}/instances/{instanceId}/operations` | Start named op. **Requires attach slot ready.** |

### Removed (vs current branch)

| Removed | Replacement |
|---------|-------------|
| `POST …/operations/{opNumber}/attach/{stream}` | Attach before op number exists |
| `GET …/operations/{opNumber}/result` (long-poll) | Attach stream EOF + GET instance |
| `DELETE …/operations/{opNumber}` | Stdout/stderr disconnect cancels op |

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
| 409 | Pending slot not ready; stream already claimed |
| 403 | Attach/start principal ≠ slot `startedBy` |

---

## JSON types (wire)

### `OperationRequest`

```json
{
  "env": { "KEY": "value" },
  "forced": false,
  "reason": "audit reason"
}
```

`startedBy` is **not** in the body; server sets it from peer identity.

### Create — `POST /secrets/{secretId}/instances`

Body: `OperationRequest` only.

Response **200**: `secrets.Instance` with new `id`, `status.operationNumber`, `status.startedAt`, etc.

### Instance operation — `POST …/instances/{instanceId}/operations`

Body: **`NamedOperationRequest`**

```json
{
  "name": "activate",
  "env": null,
  "forced": false,
  "reason": "rolling out"
}
```

`name`: one of `create`, `destroy`, `activate`, `deactivate`, `test` (same as `secrets.OperationName`; `create` not used on this route).

Response **200**: updated `Instance` snapshot (same shape as today).

---

## Client flow (summary)

```
1. POST upgrade attach/stdin, stdout, stderr   (same principal on all connections)
2. POST …/instances or …/operations            (short request ctx)
3. Read Instance from response body             (op accepted)
4. Pump attach conns until server closes them  (slot ctx / conn lifetime)
5. GET …/instances/{id}                         (final status, optional if Instance in Wait)
```

Completion: server closes pipe ends when subprocess exits → attach reads/writes hit EOF. Client **`Wait`** maps to steps 4–5. Exit code: see design.md (coarse from `completedAt`/`failedAt` until control channel exists).

---

## Proposals (future)

Dependent-secret authorization during run: **control messages** on a separate upgraded stream or mux (`/attach/control`). Not in v1 wire format.
