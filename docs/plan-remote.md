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
| Application | **Always HTTP** |
| Authn | **Always outside** the agent |
| Local | Unix socket + `SO_PEERCRED` |
| HTTPS | Reverse proxy (Caddy or anything) terminates TLS + forward-auth; agent on Unix; name header **`X-Secret-Agent-User`** |
| SSH | **OpenSSH**, Git-style: `restrict,command=` stdio helper onto the Unix socket. Prefer `Match User` on the host `sshd` already running; optional dedicated `sshd` if port 22 stays closed. **No** `x/crypto/ssh` server in secret-agent |
| SSH identity | SSH user is a real unix user → peercreds; or one `git`-style user and the helper asserts the name header (trusted hop, same as the reverse proxy) |
| Pipe / mix-and-match | **Reserved** — [plan-federation.md](plan-federation.md) |
| HTTP attach | `101` Upgrade through the reverse proxy (WebSocket-style) |
| TLS in the agent | No |
| Client | Each REST call and each attach **dials once** (unix, HTTPS, or `ssh` stdio) |

Written into [design.md](design.md) § Remote transports.

**Still TBD in implementation:** exact Nix `Match User` vs second `sshd`; helper binary vs `socat`; header name override (`forwardAuth.header`). Mux / keep-alive is an optional optimisation, not a primitive.

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

`Bindings.Identify` authenticates the Unix peer, then authorises. A forward-auth
name header is used only when `ForwardAuth` trusts that peer. `SO_PEERCRED` is
never taken from a non-Unix conn, the body, or a tunnel.

**Verification:** `go test ./internal/auth/... ./internal/server/...`

### Phase 2 — HTTP client over TCP/HTTPS

`internal/client` dials `http://` / `https://` as well as unix. Attach Upgrade on the
same host. CLI flag/env for URL.

**Verification:** `go test ./internal/client/...` with httptest TLS or loopback.

### Phase 3 — Nix reverse-proxy e2e

Module/docs: reverse proxy in front of the agent socket (Caddy as the example). Check:
CLI on “X” creates/activates a secret on “B” over HTTPS, including attach streams.

**Verification:** `nix flake check` (new remote-http check).

### Phase 4 — SSH via OpenSSH (Git-style)

Stdio helper: copy SSH session stdio to the Unix socket. Nix: system user, `authorized_keys`
`restrict,command=…` (and/or `Match User`). CLI: `ssh` / `ProxyCommand` as the `Dialer`.
No SSH server in Go.

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
