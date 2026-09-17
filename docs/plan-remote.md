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
| SSH `command=` | Forces **`secret-agent dial-stdio`** (Docker-style stdio↔unix-socket bridge). Not catalog commands, not `serve` (already listening). HTTP (including attach `101`) lives **on** that stdio. One `ssh` per REST call and per attach stream. Client runs `ssh host secret-agent dial-stdio` (or `dial-stdio -s /path` when the socket is not default). `ssh://` `/socket` is that `-s` only if sshd runs the requested command; with `restrict,command=`, `-s`/`-u`/`-H` are in the forced command. Not `-L` / streamlocal forwarding (`restrict` disables forwarding). |
| SSH identity | **Real unix user** (`ssh eli@host`) → helper runs as Eli → peercreds, no header. **Shared account** (`ssh secret-agent@host`, key maps to a person via `command=` argv, like Gitolite) → peercreds is the shared user; helper injects the same name header (trusted hop, same seam as Caddy). Git itself does not use a header; we translate `command=` into one because the agent speaks HTTP. |
| Pipe / mix-and-match | **Reserved** — [plan-federation.md](plan-federation.md). A splices to B’s `sshd` or proxy (e.g. `command="nc B 22"` / `ProxyJump`). B’s `command=` is still the agent splice. A must not terminate HTTP. |
| HTTP attach | `101` Upgrade through the reverse proxy (WebSocket-style), or through the SSH splice as raw stdio after `101` |
| TLS in the agent | No |
| Client | Each REST call and each attach **dials once** (unix, HTTPS, or `ssh` stdio) |

Written into [design.md](design.md) § Remote transports.

**Still TBD in implementation:** exact Nix `Match User` vs second `sshd` (Phase 5). Mux / keep-alive is an optional optimisation, not a primitive.

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

## What already works (local + HTTPS + SSH)

| Piece | Today |
|-------|--------|
| Listen | Unix socket only (`server` rejects non-`UnixConn` for identity) |
| Authenticate | `SO_PEERCRED` → uid/username/groups |
| Principal | `linux:{username}/{uid}`, or `http:{name}` via `ForwardAuth` |
| Client | `internal/client` dials **unix**, **http**, **https**, or **ssh://** for REST and attach upgrades |
| CLI | `CLIENT_ADDRESS` / `-a`: unix path, `http(s)://`, or `ssh://[user@]host[:port][/socket]`; empty → in-process sqlite; `dial-stdio` for `sshd` `command=` (URL `/socket` is `-s` only without a forced command) |
| Reverse proxy | NixOS `bindings.forwardAuth`; Caddy e2e in `nix/checks/remote-http.nix` |

---

## Implementation phases

### Phase 1 — Identity seam (HTTP) ✅

`Bindings.Identify` authenticates the Unix peer (`SO_PEERCRED`), then authorises.
`ForwardAuth` honours the name header only when that peer matches `Peers`.
`SO_PEERCRED` is never taken from a non-Unix conn, the body, or a tunnel.
If the header name is a local user, principal is `linux:{user}/{uid}`; otherwise
`http:{name}` (header identity, not “this arrived over HTTPS”).

**Verification:** `go test ./internal/auth/... ./internal/server/...`

### Phase 2 — HTTP client over TCP/HTTPS ✅

`internal/client` dials `http://` / `https://` as well as unix. Attach Upgrade on the
same host. `-a` / `CLIENT_ADDRESS` accepts a unix path or an `http(s)://` URL.

**Verification:** `go test ./internal/client/...` with httptest TLS or loopback.

### Phase 3 — Nix reverse-proxy e2e ✅

Module/docs: reverse proxy in front of the agent socket (Caddy as the example). Check:
CLI on “X” creates/activates a secret on “B” over HTTPS, including attach streams.

**Verification:** `nix flake check` (`checks.*.remote-http`).

### Phase 4 — SSH via OpenSSH ✅

`secret-agent dial-stdio` proxies stdio to the agent Unix socket (`internal/dialstdio`;
shared-account header inject in `cli` via `auth`),
like Docker’s `docker system dial-stdio`. Socket path is `-s` on that subcommand only
(default `/tmp/secret-agent.socket`); `-a` remains the normal client dial target.
Shared-account `-u` rewrites the first HTTP request to set `X-Secret-Agent-User`
(or `-H` if `ForwardAuth.Header` is overridden), then
raw-copies the rest (including attach after `101`). Real unix user: omit `-u`, identity
from peercreds. Client `ssh://[user@]host[:port][/socket]` runs
`ssh … secret-agent dial-stdio [-s /path]` (`-T`, `BatchMode`, `ClearAllForwardings`);
that `-s` is ignored when `authorized_keys` forces `command=`. Each dial’s stdio is one
HTTP `net.Conn`. `DisableKeepAlives`. No SSH server in Go.

```
restrict,command="secret-agent dial-stdio" ssh-ed25519 …
restrict,command="secret-agent dial-stdio -s /tmp/secret-agent.socket -u john" ssh-ed25519 …
restrict,command="secret-agent dial-stdio -u john -H X-Remote-User" ssh-ed25519 …
```

**Verification:** `go test ./internal/dialstdio/ ./internal/auth/ ./internal/cli/ ./internal/client/` (HTTP + attach over stdio).

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
