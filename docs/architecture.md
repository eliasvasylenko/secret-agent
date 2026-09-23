# Architecture notes (scratch)

> Informal notes only. For the maintained architecture, see [design.md](design.md),
> [plan.md](plan.md), [plan-remote.md](plan-remote.md), [plan-federation.md](plan-federation.md),
> and [http-api.md](http-api.md).

## Future directions (unscoped)

**Client**

- Remote HTTPS / OpenSSH: [plan-remote.md](plan-remote.md) (authn outside the agent)
- Federation introduce vs pipe: [plan-federation.md](plan-federation.md) / [design.md](design.md) § Proposer
- OAuth?

**Service**

- Local secrets
- List of hosts

**Canonical server (aggregate)**

- List of hosts
- Aggregates secret list from across all hosts
