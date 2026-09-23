# Federation — remaining work

The settled model is in [design.md](design.md) § Delegating parents and approval and
§ Proposals and federation. Wire details are in [http-api.md](http-api.md).
This file contains only implementation work that remains.

## Phase 1 — Script proposal

1. Invoke `Proposer.Propose` from the parent script runtime when it requests a dependent
   operation.
2. Publish `status.proposal` on the parent before blocking and clear it after return.
3. Keep the parent blocked until the child is terminal or denied, not merely until its
   approval hold clears.

Test that one `GET /instances/{parent}` distinguishes running with no proposal,
running with a proposal, and terminal.

## Phase 2 — Parent drives child

Parent entries become a principal plus the calling secret. A reports that secret when
it starts the child. John's approve names the secret he started. B rejects unless
that name, A's report, and B's allowlist entry match. See design.md § Proposals and
federation.

Implement A's proposer:

1. open B's attach streams and POST the child as A, reporting A's calling secret;
2. publish the accepted child id and address on the parent proposal;
3. observe B's `awaitingApproval`/failure state;
4. wait for the child to become terminal;
5. return that outcome to the parent script.

Test with two agents on one host. B's row must show `startedBy = A`; John's identity
appears only as `approvedBy`. A second secret on A that uses A's principal and claims
the allowed secret id must not be approved by John watching the secret he started.

## Phase 3 — John reaches B

Implement and test both transports:

- **introduce:** John opens a normal authenticated session to B;
- **pipe:** A splices bytes to B's proxy or `sshd`, where John authenticates to B.

Never splice onto B's peercred Unix socket. Test that A cannot forge John or approve
using its own identity.

## Phase 4 — End-to-end and failure cleanup

Add `nix/checks/federated-stdio.nix`: John starts a parent on A, A starts a held child
on B, John approves on B, and both operations finish.

Then add timeout/denial behavior and startup cleanup for accepted operations whose
parked `Propose` was lost.
