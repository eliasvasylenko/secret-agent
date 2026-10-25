# Generic script / operation / resource manager — exploration

> **Parked (Oct 2026) — a pin, not a plan of record.** Noticed while designing the
> federation operation workflow ([plan-federation.md](plan-federation.md)): the core
> machinery is barely about secrets. Written down so the thought survives; **nothing here
> is to be implemented** until a second real "kind" (below) shows up and demands it.

Last updated: 25 Oct 2026.

---

## The observation

Strip the word "secret" off the current design and what remains is a small lifecycle
engine:

| Today (secret-flavoured) | Generic reading |
|---|---|
| Secret definition in config | A **kind**: a named definition with lifecycle operations backed by scripts |
| `create` / `destroy` / `activate` / `deactivate` / `test` | Conventional operation names a kind may adopt |
| Instance | A stateful **resource instance** of a kind |
| Instance status | The outcome of the last operation run against it |
| Operation | An audited, stdio-attached, approval-gated script execution |
| Pending operation, attach-by-ID, proposals | Execution workflow entirely indifferent to what the script manages |

The genuinely secret-specific parts are thin: the config schema, and the fact that
outputs/state are sensitive. The engine does not care whether a script provisions a TLS
certificate, a VM, a database, or a backup policy — each is "define a kind, create
instances, run named operations on them, gate dangerous ones on a human."

## Terraform / Kubernetes comparison (brief; fuller exploration owed)

The shape rhymes with both: Terraform resources and Kubernetes operators are also
"definition → instances → lifecycle actions → recorded state." We arrive at it from the
script side (arbitrary lifecycle hooks, human approval as a first-class gate) rather
than the declarative-API side (desired state, reconciliation loop) — that difference is
the interesting part and is **not yet explored**.

**TODO when resumed:** a deliberate comparison — declarative vs scripted lifecycle,
reconciliation vs explicit operations, where approval/federation fits in each —
before borrowing any vocabulary from either.

## State-machine precedents and concepts (Oct 2026)

A later discussion asked what a user-definable resource *state machine* would even
look like, rather than today's fixed secret lifecycle. No single open-source system
appears to do the whole thing; the useful precedent is an intersection:

- **TOSCA** (xOpera, Cloudify, formerly Apache ARIA) is the closest direct precedent:
  user-defined node types with scripted lifecycle operations, and a normative state
  machine whose states are derived from operation outcomes (`initial → creating →
  created → configuring → configured → starting → started → … → deleted`, plus
  `error`). It validates our historical reading in which an operation name doubles
  as the state it establishes when read as a past participle, though TOSCA also
  makes transient and error conditions resource states where we keep them on the
  operation record.
- **Kubernetes / Crossplane** are the precedent for *decomposing* status: custom
  resource types, a summary phase at most, and orthogonal `status.conditions`
  (`Ready`, `Synced`, `Progressing`, …), each with its own reason, transition time,
  and `observedGeneration`. A claim such as "tested" is stamped with the revision it
  was observed at, so a later change makes it stale without an explicit reset
  transition.
- **Statecharts** (SCXML, XState) supply the formalism for sub-state machines:
  hierarchy plus *parallel regions* — orthogonal sub-machines that evolve
  independently inside a containing state. "Tested/untested" is a parallel region
  inside "instance exists", not another node competing with created/activated.
- **Puppet custom types** make the same point from configuration management:
  independent *properties*, each synchronised separately, rather than one monolithic
  status string.
- **Terraform/OpenTofu providers and Kubernetes operators** show the code-first end
  of the spectrum: arbitrary resource types whose lifecycle behaviour lives in
  provider/controller code rather than in a declarative machine definition.

Two concepts from that discussion look load-bearing for any generalisation:

1. **Singleton states are not per-instance states.** "Active" is already stored as a
   pointer on the secret (`activeInstanceId`), not a flag on the instance — and the
   precedents agree: Kubernetes uses `Lease` objects and endpoint pointers, Argo
   Rollouts keeps `stableRS` on the rollout. The formal analogue is a Petri-net place
   with capacity one: `activate` acquires the parent's token, `deactivate`/`destroy`
   release it. So a generalised model needs *scope-level occupancy constraints on
   transitions* (acquired atomically when the transition completes), not states that
   merely happen to be unique. A failed activation must not silently take the token.
2. **Failure and non-start are transparent to the established state.** In our model
   the instance state is the last *completed* operation; a failed operation
   establishes nothing (but leaves the state honestly "unknown since" a possibly
   partial script ran, which is why only retrying the same operation is allowed
   unforced), and an unstarted operation establishes nothing at all. Any generalised
   model has to keep the operation record (attempt, outcome, identity) distinct from
   the resource state it may or may not have advanced.

A generalised kind definition would therefore plausibly combine: a primary lifecycle
region with scripted transitions (the TOSCA part), parallel condition regions stamped
with the operation/revision they describe (the statechart/Kubernetes part), and
scope-level occupancy constraints attached to target states (the Petri-net part).
That is a sketch for the resume discussion, not a design to build now.

## What would generalise / what must not

**Generalises cleanly:** kind definitions with scripted operations; instance store
(kind-scoped instead of secret-scoped); operation execution, attach, audit
(`startedBy`/`requestedBy`), approval gating; the HTTP workflow wholesale.

**Must be allowed to leak per kind:** sensitivity of outputs and state, who may read
state, audit retention. A framework that makes those someone else's problem would be
worse at the original job (secrets) — these belong in the kind definition, not in
plumbing every kind re-implements.

## Sketch of a path (only if triggered)

1. Prove it with a second kind end-to-end (certificates are the obvious candidate)
   *before* abstracting; the abstraction extracted from one example is always wrong in
   the details.
2. Generalise the store: instances and operations scoped by kind; secret becomes the
   first kind, not the schema.
3. Operation names become conventions a kind declares, not a hardcoded enum.
4. Only then consider surfacing "kinds" in config/API as a user-facing concept.

## When to resume (triggers)

- A concrete second kind we actually want to manage with this agent, or
- A third party asking to define their own lifecycle workflows on it.

Absent one of those: stay a secret manager with a clean core. The recent operation
work already keeps the concepts kind-agnostic *in shape*; don't pay for the
generalisation itself speculatively.

## Risks

- **Premature framework:** generalising on one example ossifies the wrong seams.
- **Scope explosion:** desired-state/reconciliation expectations arrive with the
  Terraform/Kubernetes comparison whether invited or not.
- **Diluting the security model:** sensitivity and approval semantics are the product;
  a generic frame must not sand them down to defaults.
