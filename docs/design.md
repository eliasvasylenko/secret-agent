# secret-agent design

Current contracts and security invariants. HTTP routes and JSON live in
[http-api.md](http-api.md); unfinished federation work lives in
[plan-federation.md](plan-federation.md).

## Domain and layers

- **Secret** — a versioned plan containing create/destroy/activate/deactivate/test scripts.
- **Instance** — a deployed copy of a secret; at most one is active per secret.
- **Operation** — an audit row for one attempted mutation.
- **Catalog** — read-only secret, instance, and operation history.
- **Runner** — accepts and runs mutations with stdio and session callbacks.
- **Executor** — starts the configured subprocess.

`executor.OperationParameters` contains caller-supplied operation data: environment,
reason, forced flag, starter identity, and expected operation number. It never contains
an instruction to bypass or require approval.

## Run, attach, and cancellation

`Runner.Run` returns an accepted `Instance` snapshot and a per-run `Handle`.
Background work starts before `Run` returns; `Handle.Wait` only joins it.
Cancelling a wait does not cancel the operation. `Handle.Cancel` does.

The `Run` context covers acceptance and persistence only. Execution has an independent
lifetime because an HTTP POST context ends when its response is written.

HTTP attaches stdin/stdout/stderr before POST. A pending attach slot is keyed by
`(secretId, principal)` and consumed atomically by POST. The starter is always the
attacher. After consumption, another slot for the same key may be assembled while the
operation runs. Stdin EOF closes subprocess stdin; stdout/stderr disconnect cancels the
operation.

Instances and operations are root HTTP collections because instance ids are globally
unique. `POST /operations` derives the secret from the instance rather than trusting a
second secret id.

## Authentication and remote transport

Authentication remains outside the agent:

- local Unix socket: kernel `SO_PEERCRED`;
- HTTPS: a trusted reverse proxy authenticates and supplies
  `X-Secret-Agent-User`;
- SSH: host OpenSSH runs `secret-agent dial-stdio`, either as the real Unix user or
  through a shared account whose forced command supplies the authenticated name.

The agent accepts a forwarded name only when the Unix peer is in
`ForwardAuth.Peers`. Peer credentials are local kernel metadata and never travel over
TCP, TLS, SSH, or a federation pipe.

The application protocol is always HTTP, including over SSH stdio. There is no embedded
SSH server, TLS terminator, OIDC implementation, or HTTP multiplexer in the agent.

The NixOS SSH integration uses the host's `services.openssh` with a `Match User
secret-agent` block. `services.secret-agent.ssh.enable` is its only feature switch.
Shared-account keys may be Nix-pinned or stored as agent-managed fragments under
`/var/lib/secret-agent/ssh/authorized_keys.d`; no separate sshd or CA is required.

## Delegating parents and approval

An originating principal is whoever global auth already admits. That is the same on
every secret, whether the call is direct or delegated. A direct start by that
principal runs after acceptance.

The secret-specific list is the delegating parents allowed to call it. Today that
list is the parent principal:

```nix
services.secret-agent.secrets.child = {
  parents = [ "linux:agent-a/200" ];
};
```

The pinned federation rule also names which secret on A may call. That shape and the
check around it are in [Proposals and federation](#proposals-and-federation). They
are not enforced yet.

A start by a listed parent is accepted and held until an originating principal
approves. The parent cannot approve its own start. Any other authenticated principal
can. The start request cannot name an originator or waive the hold.

At acceptance B records that this start requires approval. Later edits to `parents`
do not release an in-flight hold. The durable fields are:

- `approvalRequired` — frozen at accept;
- `awaitingApproval` — exposed status while execution is held;
- `approvedBy` — originating principal that released the hold, retained after finish.

Global roles still control coarse HTTP access. Secret-specific permissions, beyond
which parents may call, are deferred.

`POST /instances/{id}/approve` carries no identity in its body. It resumes the
`Propose` call the executing server passed into `Run`. That call returns nil only
after the originating principal has been recorded, and then execution continues.
The delegating parent that started the operation is rejected and the call stays parked.
The handler does not call a catalog mutation. A missing `Propose`, or a nil return
that did not record an eligible principal, fails the operation.

Approval state is attached to the accepted operation, not issued as a pre-POST token.
Cancel, deny, or timeout marks the operation failed without starting a subprocess.
One-of-N approval is the first model; quorum policies are deferred.

## Proposals and federation

A parent script's `Propose` starts a child and returns when that child is terminal.
The `Propose` the executing server passes into `Run` is the approval of the operation
it accepted:

1. John starts and attaches to a parent operation on A.
2. The parent script calls `Propose` for a child operation on B.
3. A authenticates to B, attaches stdio, and starts the child.
4. A reports the calling secret. B accepts the child when that principal and secret
   are a listed parent, and holds execute.
5. While the parent is blocked, its instance has `status.proposal`. John observes it
   through the same `GET /instances/{id}` used to observe completion. The proposal
   carries the child instance id.
6. John authenticates directly to B and approves that child, naming the secret he
   started on A. He already knows that secret; B is not the source of it.
7. B records `approvedBy` only when the secret John names, the secret A reported for
   that child, and the secret B allows for A's principal are the same. Otherwise B
   rejects and the hold stays. On a match, B runs the child and returns its terminal
   result to A.
8. The parent `Propose` returns only when the child is terminal (or denied), then the
   parent proposal is cleared.

`Handle.Wait` remains finish-only. A running parent may have no proposal, so finish and
proposal are not a sum type and there is no second poll endpoint.

John can reach B by:

- **introduce** — John dials B directly; or
- **pipe** — A splices opaque bytes while John authenticates to B's proxy or `sshd`.

A must never terminate or forge John's authentication. A pipe must not land directly on
B's peercred Unix socket because B would observe A as the peer.

A sibling secret that can speak as A's principal can claim an allowed secret id and
park a different child. John does not approve that child: it is not the proposal on
the instance he started, and his approval names the secret he started. B still trusts
A to attach a proposal only to the operation that called. A compromised agent can
point that instance at a sibling's child, and the three values then match.

`Propose` returning nil is the approval. The executing server supplies that callback
on `Run`. The parent script's `Propose` is a later call that starts a child and
returns when the child is terminal. Both use the same return: nil continues, an
error rejects. On a parent start the store calls the server's `Propose` and runs
the script only after that nil return has recorded an originating principal.

## Operation outcome

Success is `completedAt` plus a nil wait error. Failure is `failedAt` plus a non-nil
error. A subprocess exit code belongs on the typed error when available; it is not a
second persisted outcome field.

## Deferred

- cleanup of operations left non-terminal after agent restart;
- timeout for attach slots never followed by POST;
- numeric remote exit status beyond streamed stderr;
- approval denial and timeout policy;
- N-of-M approval.
