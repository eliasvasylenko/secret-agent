# Remote secrets and authentication — implementation plan

Plan for **plain remote access**: John on machine X operates secrets on **one** agent (host B).
John is **starter and attacher**. No dependent ops, no `Proposer`, no orchestrator principal.

**Status: Phase 0 locked (Sep 2026).** Federation remains **parked** — [plan-federation.md](plan-federation.md).
This plan ships **direct** John→agent access only. Federation later uses the same
outside authenticators for **introduce** and **pipe**.

**Prerequisites:** local Unix-socket agent complete ([plan.md](plan.md) Phases 0–7).

---

## Why this before federation

Federation assumes John can already authenticate **to B as John**. Today that is only
Unix peer credentials. Both later hops reuse these outside authenticators:

- **Introduce** — John reaches B’s reverse proxy (HTTPS) or B’s `sshd` (SSH); A only coordinates.
- **Pipe** — John cannot see B; A splices a conn; John still authenticates to **B’s** proxy or `sshd` on that pipe.

---

## Goals

1. **Same product loop remotely** — catalog, attach, POST start, `Handle.Wait` / cancel.
2. **Application protocol is always HTTP** — existing client/server. Not `Backend`.
3. **Authentication stays outside the agent** — kernel, reverse proxy, or OpenSSH.
   The agent only **authorises** (`Identify` + roles). Same split as Git + `sshd`.
4. **No embedded SSH or in-app OIDC/JWT/mTLS.**
5. **Leave space for federation** — per-call `Dial` to unix / HTTPS / SSH-stdio.
   Pipe is later (`OpenPipe`). Neither changes `Backend`.

---

## Phase 0 — Decisions (locked)

| Question | Decision |
|----------|----------|
| Remote story | CLI on X talks to B (not only “ssh then local CLI”) |
| Application | **Always HTTP** (including over SSH stdio) |
| Authn | **Always outside** the agent |
| Local | Unix socket + `SO_PEERCRED` |
| HTTPS | Reverse proxy (Caddy or anything) terminates TLS + forward-auth; agent on Unix; name header **`X-Secret-Agent-User`** |
| Hop trust | **Peercreds.** `ForwardAuth` honours the name header only when `SO_PEERCRED` matches `ForwardAuth.Peers`. Not “whoever can dial the socket.” |
| `ForwardAuth.Peers` | Allowlist of **last hops** (OR), not a chain. Typically one process (Caddy). A second entry only if another local process independently dials the same socket and asserts the header. |
| Header | One name for the agent (`X-Secret-Agent-User`, overridable). Hops are configured to set that; the agent is not a per-peer header polyglot. |
| SSH | **OpenSSH**. **No** `x/crypto/ssh` in secret-agent. Prefer `Match User` on the host `sshd`; optional dedicated `sshd` if port 22 stays closed. |
| SSH `command=` | Forces a **stdio↔unix-socket splice** (`socat` or a tiny helper). Not the CLI, not `serve` (already listening). HTTP (including attach `101`) lives **on** that stdio. One `ssh` per REST call and per attach stream. This is Git’s session-stdio shape, not `-L` / streamlocal forwarding (`restrict` disables forwarding). |
| SSH identity | **Real unix user** (`ssh eli@host`) → helper runs as Eli → peercreds, no header. **Shared account** (`ssh secret-agent@host`, key maps to a person via `command=` argv, like Gitolite) → peercreds is the shared user; helper injects the same name header (trusted hop, same seam as Caddy). Git itself does not use a header; we translate `command=` into one because the agent speaks HTTP. |
| Pipe / mix-and-match | **Reserved** — [plan-federation.md](plan-federation.md). A splices to B’s `sshd` or proxy (e.g. `command="nc B 22"` / `ProxyJump`). B’s `command=` is still the agent splice. A must not terminate HTTP. |
| HTTP attach | `101` Upgrade through the reverse proxy (WebSocket-style), or through the SSH splice as raw stdio after `101` |
| TLS in the agent | No |
| Client | Each REST call and each attach **dials once** (unix, HTTPS, or `ssh` stdio) |

Written into [design.md](design.md) § Remote transports.

**Still TBD in implementation:** exact Nix `Match User` vs second `sshd`; helper binary vs `socat`; whether the shared-account helper is HTTP-aware (header inject) or `setuid` then splice. Mux / keep-alive is an optional optimisation, not a primitive.

---

## Primitives (not `Backend`)

```
internal/client  (HTTP API)
        ↓ Dial() → one net.Conn per call / attach
   unix | HTTPS (to proxy) | ssh stdio (to sshd)
        ↓
internal/server  (HTTP API; identity from peercreds or forward-auth header)
```

| Primitive | This plan | Federation later |
|-----------|-----------|------------------|
| **HTTP API** | Existing client/server | Unchanged |
| **Dial** | unix, HTTPS, SSH stdio | Same for introduce; inner authn still `sshd` or B’s proxy on a pipe |
| **Pipe** | Not built | Optional: A splices; John authenticates to B outside the agent |

**No mux.** One dial per REST call and per attach stream.

---

## What already works (local)

| Piece | Today |
|-------|--------|
| Listen | Unix socket only (`server` rejects non-`UnixConn` for identity) |
| Authenticate | `SO_PEERCRED` → uid/username/groups |
| Principal | `linux:{username}/{uid}` |
| Client | `internal/client` dials **unix** for REST and attach upgrades |
| CLI | `CLIENT_SOCKET` / `-c`; empty socket → in-process sqlite |

---

## Implementation phases

### Phase 1 — Identity seam (HTTP) ✅

`Bindings.Identify` authenticates the Unix peer (`SO_PEERCRED`), then authorises.
`ForwardAuth` honours the name header only when that peer matches `Peers`.
`SO_PEERCRED` is never taken from a non-Unix conn, the body, or a tunnel.
If the header name is a local user, principal is `linux:{user}/{uid}`; otherwise
`http:{name}` (header identity, not “this arrived over HTTPS”).

**Verification:** `go test ./internal/auth/... ./internal/server/...`

### Phase 2 — HTTP client over TCP/HTTPS

`internal/client` dials `http://` / `https://` as well as unix. Attach Upgrade on the
same host. CLI flag/env for URL.

**Verification:** `go test ./internal/client/...` with httptest TLS or loopback.

### Phase 3 — Nix reverse-proxy e2e

Module/docs: reverse proxy in front of the agent socket (Caddy as the example). Check:
CLI on “X” creates/activates a secret on “B” over HTTPS, including attach streams.

**Verification:** `nix flake check` (new remote-http check).

### Phase 4 — SSH via OpenSSH

`authorized_keys` along the lines of:

```
restrict,command="socat STDIO UNIX-CONNECT:/run/secret-agent/agent.sock" ssh-ed25519 …
```

(or a helper that copies stdio the same way, and for a shared account injects
`X-Secret-Agent-User` from the forced `command=` identity). The CLI `Dialer` is
`ssh` / `ProxyCommand`; each dial’s stdio is one HTTP `net.Conn`. No SSH server in Go.

**Verification:** helper unit tests; optional Go test that speaks HTTP over a pipe.

### Phase 5 — Nix SSH e2e

CLI on X uses `ssh` to B; attach/stdio works; helper has no shell/PTY/forwarding.

**Verification:** `nix flake check` (remote-ssh check).

---

## Success criteria

- John on another machine can run the CLI against B over **HTTPS** and over **SSH**.
- `startedBy` is John’s identity as authorised by the agent, not a body field.
- The agent binary does not authenticate (no embedded SSH, no OIDC).
- Local Unix path unchanged.
- Attach `101` works through a reverse proxy.
- `go test ./...` green.

---

## References

- [design.md](design.md) — § Remote transports
- [http-api.md](http-api.md) — routes; Upgrade protocol
- [plan.md](plan.md) — completed local agent
- [plan-federation.md](plan-federation.md) — parked
- [plan-process-io.md](plan-process-io.md) — historical Caddy / embedded-SSH sketches
