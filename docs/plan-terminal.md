# Terminals, PTYs, and the approval prompt

> Branch `tty-terminal` carries steps 1–3. Last updated: 24 Nov 2026.
>
> How a secret script gets a terminal, how the operator's own terminal is kept
> away from the script and from servers, and where an approval prompt fits.
> *What* a proposal is, and when one is needed, is
> [plan-federation.md](plan-federation.md).

---

## The problem in one paragraph

Today the local CLI gives the script the operator's own terminal: the same
device as its stdin/stdout/stderr, and it asks for that device to become the
script's controlling terminal too. That is unsafe, because the script can
reconfigure the operator's terminal, read keys meant for someone else, and
(as root) inject keystrokes. It is also broken for an unprivileged CLI: the
kernel refuses to hand a terminal owned by one session to another, so the
request fails with `EPERM`. A root CLI would instead *steal* the terminal
from the operator's shell (Go's `Setctty` passes the kernel's steal flag).
And Ctrl-C reaches the script directly while cancelling does not kill its
children. The fix: put the script on its **own** pseudo terminal (PTY), keep
the operator's terminal with the CLI, and copy bytes between the two. `ssh`,
`sudo` (`use_pty`), `script(1)`, and `systemd-run --pty` all do this.

---

## Terms

These get confused, and the design depends on keeping them apart.

| Term | Meaning |
|------|---------|
| Terminal fd | Any descriptor on a terminal device. `test -t 0` asks only this. Holding one lets you read, write, and change its settings (`stty`). |
| Controlling terminal (ctty) | The one terminal a session owns. `/dev/tty` opens it. Ctrl-C/Ctrl-Z on it signal that session's foreground group. A terminal belongs to at most one session. |
| PTY | A pair: the *slave* behaves like a terminal for the script; the *master* is held by whoever forwards it. Closing the master hangs up everything still holding the slave. |
| Device access vs byte stream | Holding the operator's terminal fd gives *device* access (settings, flushes, maybe injection). Copying bytes to and from it only lets the other side send and receive *text*, but text includes escape sequences. Both matter; they are defended differently. |

---

## What we checked (Linux, this repo's tests and probes)

| Fact | Consequence |
|------|-------------|
| `Setctty` on a terminal another session owns fails with `EPERM` unless the caller is root. Go passes the steal flag (`TIOCSCTTY` arg 1). | An unprivileged local run that marks the operator's terminal as ctty cannot work once the script has its own session. A root CLI would take the terminal away from the operator's shell. |
| A script in its own session that holds the operator's terminal as fd 0 cannot open `/dev/tty`. | `Setsid` alone hides `/dev/tty`. |
| That script **can** run `stty -echo` on fd 0, and it changes the operator's terminal. | `Setsid` does not protect the operator's terminal settings. Flushing input and reading the operator's keys work the same way. |
| Keystroke injection (`TIOCSTI`) needs the terminal to be the caller's ctty, or `CAP_SYS_ADMIN`. Linux 6.2+ can disable it except for `CAP_SYS_ADMIN` (`dev.tty.legacy_tiocsti=0`, set on this host). | `Setsid` blocks injection for unprivileged scripts. **Root scripts can still inject into any terminal fd they hold**, and secret scripts often run as root. (Kernel rule; the injection probe itself did not report, so this is not demonstrated here.) |
| A background process the script leaves behind keeps any fd it inherited, forever. | With the operator's terminal passed directly, a leftover can write to it, or change it, after the operation ends. With a PTY, closing the master revokes it. |
| `bash` started as a session leader with an **unowned** terminal on stdin makes it its ctty at startup (`cat` does not). | Attach `mode: tty` without `ctty` is not enforced for bash scripts. Open decision: accept and document, or keep the old contract (see § Open questions). The operator's terminal is owned, so this cannot happen to it, and the CLI no longer sends `tty` attaches. |
| HTTP attach sends bytes, never descriptors. For `mode: tty`/`ctty` the server opens its own PTY. | Over HTTP neither the server nor the script ever holds the operator's terminal device. Only the byte stream crosses. |
| The HTTP client copies a local terminal to the attach as-is (cooked, echoing). Since step 3 that local terminal is the CLI's PTY slave, which starts cooked. | A remote script on the server's PTY gets double echo and line-buffered input. Needs raw mode on the client side (step 4). |
| The server PTY is opened with no window size (0×0). | Full-screen tools misbehave remotely until a size is sent. |

---

## On main

Shipped; do not redo:

- Operation-first attach: create → attach → start. One attach per open file,
  `{"fds":[…],"mode":"r"|"w"|"tty"|"ctty"}`.
- Server opens a PTY for `tty`/`ctty` and installs `ctty` as the script's
  controlling terminal (`internal/server/attach.go`, `operation_entry.go`).
- `command.Files` with `Tty` (descriptor to install as ctty, or `NoTty`).
  `Process` does `Setsid` + `Setctty` only when `Tty` is set.
- HTTP client groups local files into attaches and marks the `Files.Tty` group
  `ctty` (`internal/client/attach.go`).
- `Proposer` exists as a callback on `Runner.Run`. Nothing calls it; CLI and
  server pass `noopProposer`.

Wrong on main:

- Linux `Apply` does not start a new session, and cancel kills only the shell,
  so `bash -c`'s children survive.
- The CLI has no signal handling; SIGINT kills it, and nothing cancels.
- Local `files()` sets `Files.Tty` to the operator's terminal (the `EPERM` and
  trust problems above).

---

## This branch: steps 1–3

**Step 1 — script out of the operator's session.**

| Change | Effect |
|--------|--------|
| `Setsid` always (`command.go` `Process`) | Script has its own session and process group; terminal Ctrl-C no longer reaches it. |
| Cancel kills the process group (`kill(-pid, SIGKILL)`, `ESRCH` → done) | Children die with the script. No `WaitDelay`: its timer also fires after a successful exit. |
| `interruptContext` on CLI `Run` (SIGINT, SIGTERM, SIGHUP, SIGQUIT) | First signal cancels the operation. A second restores the terminal, then uses the default action, so a stuck cancel cannot trap the operator. `serve` restores default handling first, or `systemctl stop` would hang. |
| `Run` returns its error; `main` exits | Deferred restores run. Kong's `FatalIfErrorf` calls `os.Exit` and would leave the terminal raw. |

The platform hook `CommandOptions.Apply` is gone: `Setsid`, the group kill,
and `Credential` are set directly in `Process`. Only Linux is supported, and
other platforms fail to build.

**Step 2 — shared helpers.** `creack/pty` and `x/term` are added. `OpenPty`
wraps `pty.Open` and sets close-on-exec on both ends. It replaces the server's
opener and the test helpers. Grouping by open file (`groupByOpenFile`, using
kcmp) and `FileGroups` live in `command`, shared by the broker, the HTTP
client, and the server. `setRaw` is `term.MakeRaw` with `ISIG` turned back
on. At exec, `ownTerminals` chowns each terminal the script receives to
`Credential`'s uid.

**Step 3 — CLI broker, forwarding only.** `command.OpenBroker` takes the CLI's
descriptors (index = descriptor number) and returns the `FileGroups` every
backend receives (see § Target design). `operate` in `cli.go` opens it for each
operation. `Run` closes it before writing the JSON result, so the terminal is
restored first, and again in a defer and on the second signal.

Tests: new session; group kill on cancel; Ctrl-C on a PTY cancels and reaps
children; the script gets a ctty locally and over HTTP; `read` under
`stty -echo` on `/dev/tty` hides input and still receives it; an
`ssh-keygen`-style prompt on `/dev/tty` works with stdout redirected; a
leftover background writer is hung up at exit; another terminal on stdout
becomes a pipe and its settings are unchanged after `stty -echo` in the
script; a read-write file such as `/dev/null` passes through unchanged;
`setRaw` keeps `ISIG`; `serve` dies on SIGTERM; a second signal kills a stuck
CLI.

Still open after step 3:

- Over HTTP, double echo and line-buffered input remain, and the server PTY
  is 0×0 (step 4).
- Nothing calls `Propose`, so there is no gate hold or prompt yet (step 5).
- The server still accepts `tty` attaches from other clients (§ Open
  questions 1).

---

## Implementation choice

Use [`github.com/creack/pty`](https://github.com/creack/pty) for PTY
allocation and window-size operations. Use `pty.Open`, not `pty.Start`: the
operation executor starts the process later and needs the slave in
`command.Files`. Replace the three hand-written PTY openers (server and tests)
with one wrapper around it.

Use `golang.org/x/term` where its API matches (terminal checks, size, saved
state / restore). `term.MakeRaw` disables `ISIG`, but Ctrl-C must continue to
signal and cancel the CLI, so `setRaw` turns `ISIG` back on with a small
`x/sys/unix` termios call. The controlling terminal is the only terminal the
CLI ever puts in raw mode.

`creack/pty` deliberately does not provide the higher-level broker. We still
own fd grouping, copy lifetime, prompt gating, signal policy, restore on exit,
and HTTP attach integration. It does remove `/dev/ptmx`, unlock, slave-name,
and window-size ioctl code from this repository.

No library replaces the copy loop. Go's `SetReadDeadline` does not work on a
PTY master (a probe hung), so each copy polls its source with a 100 ms
timeout and checks a stop channel. `containerd/console` and `moby/term` add
nothing over `creack/pty` plus `x/term`.

SSH was considered as a subprotocol for each `tty`/`ctty` attach while
retaining ordinary `r`/`w` attaches. It would provide terminal-mode and resize
messages, but still needs an operation-specific SSH server which allocates a
PTY and hands its slave to a process started later; outer-auth-to-SSH binding
and host-key setup; and the same CLI broker for the trusted prompt. Standard
SSH session semantics launch and own the command rather than supplying one
file group to our operation. Do not add SSH here. Keep its raw/restore,
resize, suspend/resume, and unfiltered-output behaviour as precedent.

---

## Target design: one broker in the CLI

One rule: **a backend never receives a terminal device the CLI did not
create.** Before calling any backend, the CLI groups its descriptors by open
file (a `dup` is one group, as attach already does). The controlling terminal
gets the one PTY, like `ssh -t`. Every other terminal becomes a pipe:

```
operator's ctty ──(gate, prompt, Ctrl-C = cancel)── master │ slave ── Files (Tty, ctty)
other terminal  ──(copy)──────────────────────────── pipe end │ pipe end ── Files (r or w)
pipe / file     ─────────────────────────────────────────────────────────── Files
```

- A redirected stream is not a terminal and stays what it is
  (`create foo > out.json` is still clean JSON). Its mode is `r` or `w` from
  the open file's access mode. Every fd in a group shares one open file, so
  they share one access mode.
- A read-write non-terminal (`/dev/null` opened `O_RDWR`) has no attach mode.
  `LocalMode` refuses it (`errReadWriteFile`). The broker passes it through
  unchanged with an empty mode, and the HTTP client skips it.
- **The ctty group** (the operator's controlling terminal, if it is among
  the CLI's descriptors) is the **operator PTY**. Its slave is `Files.Tty`,
  attach mode `ctty`. The CLI puts the operator's terminal in raw mode with
  `ISIG` kept, copies both ways, and gets the gate below: Ctrl-C cancels,
  prompts appear here. `SIGWINCH` copies the size to the master; `SIGTSTP`
  restores the terminal, stops the CLI, and re-enters raw mode on resume.
- **Any other terminal group** (`> /dev/pts/5`, another pane) becomes a pipe
  the CLI copies. Stdin gets the read end; every other descriptor gets the
  write end. A group holding both stdin and output fds is split into two
  streams. The CLI never changes that terminal's settings, and the script
  sees a pipe (`test -t` false, no colour by default, no `stty`).
- No controlling terminal among stdio (cron, CI, `systemd-run`, or all three
  redirected): no operator PTY, so no `Files.Tty`. Prompts auto-decline (see
  below). Other terminals still become pipes.
- **Pinned:** the CLI today only passes fds 0, 1 and 2. A ctty that is not
  on those (stdio redirected, operator still at a keyboard) is the same
  problem as passing any extra fd. Do not inherit every open fd: that would
  leak the agent's sockets, database, lock files. Explicit extra fds later;
  `OpenBroker` already takes a descriptor-indexed list.

Why the other terminals are not passed through: what a script can do through
a terminal fd (change settings, flush or read input, inject as root, write
after the operation ends) does not depend on it being a ctty. A pipe removes
all of it. Closing the CLI's end at exit gives a leftover writer `EPIPE`.
Why a pipe and not a PTY of its own: only the controlling terminal needs to
look like a terminal to the script (`/dev/tty`, passphrases, `stty -echo`).
A second PTY would bring its own raw mode, `ISIG` choice, echo, and resize
for a case nobody has asked for. A script that needs a terminal uses
`/dev/tty`.

The backend then receives the same `Files` whichever it is:

**Sqlite (in-process).** The operator PTY's slave is the script's ctty. That
fixes reuse (the slave has no owner, so `Setctty` works), device trust (the
script never holds a terminal someone is using), and leftovers (closing the
master hangs them up). This is what `sudo` does with `use_pty`, the default
since sudo 1.9.14, for the same injection reason.

**HTTP.** The HTTP client forwards the slave as the `ctty` attach and the
pipes as `r`/`w` attaches. The CLI never produces a `tty` attach. The server
opens its own PTY for the `ctty` attach, as it does today. That is two PTYs
in a row, the same as running `ssh` inside `tmux`. It works because of one
rule in the HTTP client:

> A terminal the HTTP client forwards over an attach is put in raw mode for
> the duration, and restored afterwards. The far end's PTY does echo, line
> editing, output processing, and `stty -echo`.

That rule is what `ssh` does to its local terminal. It belongs in the HTTP
client, not the CLI, because it composes: a server whose backend is itself an
HTTP client forwards its own attach PTY by the same rule, hop after hop.

It is only safe **after the CLI broker exists**. Before, the HTTP client saw
the operator's real terminal: raw mode would make Ctrl-C a byte (cancel stops
working) and a crash would leave the operator's terminal raw. That is why the
broker (step 3) shipped before this rule (step 4). Now the only terminal the
HTTP client receives from the CLI is the operator PTY's slave, so step 4 sets
raw mode and size on one terminal.

Why the broker sits in the CLI for both backends, rather than only in sqlite:

- Over HTTP the device boundary already exists (bytes only). The broker adds
  one place that controls **when** the operator's keys are forwarded and
  **when** output is shown. The prompt needs exactly that, and it should not
  depend on which backend runs the script.
- The HTTP client stays free of prompt logic; it just forwards a terminal.
- The server is trusted with what the script is given (keys typed for the
  script, output from it), never with the operator's device or the operator's
  approval answer.

### The gate (broker behaviour)

Between the operator's ctty and the operator PTY's master. Piped terminals
are only copied. Step 3 implements forwarding and exit; hold and pause come
with the prompt (step 5).

- **Forwarding** (normal): operator terminal in raw mode except `ISIG`, so
  Ctrl-C still signals the CLI and cancels the operation. Keys → master;
  master → screen. The script's PTY does its own echo.
- **Hold** while a prompt is showing: stop reading the master. The kernel
  buffer fills and the script blocks on write. No unbounded buffering in the
  CLI, and over HTTP the backpressure reaches the server.
- **Pause input** while a prompt is showing: stop writing keys to the master.
  Keys already forwarded stay in the script's line buffer, so a half-typed
  line resumes after the prompt.
- **Exit**: after the operation, stop the copies and restore the operator's
  terminal. Close the CLI's slave, read the master until `EIO` (all slaves
  closed) or 250 ms (a leftover still holds it), then close the master. Close
  both ends of each pipe.

This is simpler than the console on the old branch: no `io.Pipe` routing of
stdin and no in-memory output buffer. One goroutine still owns all reads of
the operator's terminal so that flushes and reads are ordered.

### The prompt (once something calls `Propose`)

The byte stream from the script is hostile: escape sequences can move the
cursor, erase lines, change modes, write the clipboard (OSC 52), or provoke
replies that arrive as "typed" input (`\x1b[6n`). We do not parse or filter
it; a terminal emulator in the agent would lose. Instead the prompt is safe
because the script is not connected while it is up:

1. Hold output and pause input (the gate).
2. Restore the operator's normal terminal mode for the prompt.
3. Write a reset first (`\x1b[!p\x1b(B\x0f\x1b[0m\r\n`: soft reset, ASCII
   charset, plain text) so earlier output cannot hide the prompt.
4. Discard input for 150 ms after the prompt, then flush the input queue
   (`TCIFLUSH`). Catches reflex typing and query replies.
5. Read one line from the operator's **controlling** terminal only
   (`/dev/tty` in the CLI), never stdin, never some other tty fd. Accept
   only `yes`.
6. Back to forwarding; release the hold.

If the CLI has no controlling terminal, `Propose` returns declined
(auto-no). Do not hang, do not read stdin, do not prompt on a non-ctty
tty (that may be another pane). A distinct "could not ask" error can wait
until remembered approvals exist.

Accepted leftovers: the script can print convincing text *above* the prompt
(the operator must read the `Proposal:` line); between prompts the screen can
be trashed exactly as `ssh host cmd` can trash it.

Federation's start-by-reference *could* approve from another terminal (the
wire is a token plus `POST /start`). Today the token only reaches John's CLI
through `Propose`, and no command exists to approve from elsewhere. Until
that exists, the in-band prompt is the only operator path.

---

## Remaining steps

Each is its own change, in this order. Steps 1–3 are above.

**4. HTTP client raw rule.** Step 3 made the `ctty` attach's local file the
operator PTY's slave, not the operator's device. Put it in raw mode for the
attach and restore after. Send its initial window size with the attach; the
server sets it on its PTY. Live resize reaches the local master through the
broker's `SIGWINCH` handler, but the HTTP client cannot learn of it from
`Files`. That stays pinned (§ Open questions 3). Tests: no double echo
through a real server PTY; `stty -echo` on the far side hides typed input;
size arrives. Until this ships, remote scripts still see double echo.

**5. Prompt.** Replace `noopProposer` with the gate + prompt above once
federation has a caller. Tests inject the terminal opener so they never block
on a developer's real terminal.

**6. Nix check.** Real VT or `script -qc` in a VM: hidden passphrase, clean
redirected stdout, no `/dev/tty` under `systemd-run`.

---

## Consequences to design for

- **Ctrl-C means cancel**, not "SIGINT to the script" as under `ssh`. An
  interactive tool inside a script cannot be interrupted on its own. Deliberate:
  the operator must always be able to stop the operation.
- **Restore the terminal on every exit.** Done in step 3: the broker is
  closed before the result is written, in a defer, and by the second signal
  (SIGINT, SIGTERM, SIGHUP, SIGQUIT) before the default action. Errors return
  from `Run` instead of `os.Exit`, so the defers run.
- **Ctrl-Z.** Forwarded as a byte, the script's PTY would stop the script
  and nothing would resume it. So `ISIG` stays on and Ctrl-Z stops the CLI:
  the broker restores the terminal, stops itself, and re-enters raw mode on
  resume (what `vim` and `less` do). The script keeps running and blocks when
  its output buffer fills.
- **Eager key forwarding.** Keys typed while the script is not reading sit in
  its PTY and are dropped at exit, as with `ssh`. Accept.
- **Another terminal given as stdin** (`< /dev/pts/5`) is read by the CLI as
  it is: cooked, echoing, line at a time, settings untouched. The CLI competes
  with whatever else reads that pane. Lines it reads go to the script's stdin
  pipe. Ctrl-C there signals that pane's own foreground job; it neither
  cancels the operation nor reaches the script. The operator chose to give
  that terminal.
- **Another terminal given as output** (`> /dev/pts/5`) receives the script's
  bytes unchanged, but the script sees a pipe: `test -t 1` is false, so tools
  may drop colour or progress bars there.
- **A CLI killed with SIGKILL** leaves the operator's terminal raw (`reset`
  fixes it), as with `ssh`. No other terminal is ever changed, so no other
  terminal is left broken.
- **An existing `gpg-agent`** shows pinentry on whatever terminal it was
  started with, not the script's PTY. Out of scope.
- **Defence in depth on NixOS:** `dev.tty.legacy_tiocsti = 0` blocks
  injection by unprivileged processes even on their own terminal.

---

## Decisions

| Question | Decision |
|----------|----------|
| PTY implementation | `github.com/creack/pty` (`pty.Open` plus size helpers); one repository wrapper. |
| Terminal state | `golang.org/x/term` for save/restore; `setRaw` is `MakeRaw` then `ISIG` back on via `x/sys/unix`. |
| SSH per terminal attach | No. It does not remove the broker and needs custom operation-bound SSH server semantics, auth/host-key setup, and process handoff. |
| Give the script the operator's terminal as ctty | Never. |
| Give a backend any terminal device the CLI did not create | Never, ctty or not. |
| Where PTYs are opened | In the CLI, before any backend, for the controlling terminal only. The server keeps opening its own PTY for HTTP `ctty`/`tty` attaches. |
| Other terminals on stdio | A pipe the CLI copies: stdin reads, other fds write, a group with both is split. Never passed to the script. |
| Which source terminals the CLI reconfigures | Only the ctty (raw with `ISIG`). Other terminals are read or written as they are. |
| Ctrl-C | On the operator ctty: cancels the operation (`ISIG` on). On another terminal: that terminal's own business; neither cancel nor the script. |
| Read-write non-terminal (`/dev/null`) | Passed through unchanged with no attach mode; the HTTP client skips it. |
| Who sets a forwarded terminal raw | Whoever forwards it over attach (the HTTP client, step 4). Since step 3 that terminal is the operator PTY's slave. |
| Filter or prefix script output | No. Hold during prompts; otherwise unfiltered, like `ssh`. |
| Alternate screen for the prompt | No. One alternate buffer; a script already on it is wrecked. |
| How many PTYs | At most one per hop, for the ctty. Descriptors on the same open file share it (stdin, stdout and stderr on the operator's terminal are one PTY). |
| Answer token | `yes` (trimmed, case-insensitive). |
| Answers from stdin | Never. `yes \| secret-agent create` cannot approve. |
| When to prompt | Only if the CLI has a **controlling** terminal (`/dev/tty` opens). Any other tty fd is not enough. Otherwise auto-no (decline), do not hang. |
| Extra fds (ctty not on 0/1/2, or other fds) | Pinned. See § Open questions. Do not inherit all fds. |
| Window size | Locally: initial size with the PTY, `SIGWINCH` resizes it. Over HTTP: initial size with the attach (step 4); live resize is not in-band bytes, pinned. |

---

## Precedents

- `sudo` with `use_pty`: runs the command on a new PTY specifically so it
  cannot inject into the user's terminal. Closest match to local mode.
- `ssh`: new PTY on the far side, local terminal raw, output unfiltered,
  resize as a control message, restore before suspend and on exit. Behaviour
  to copy, not a transport dependency.
- `tmux` + `ssh`: two PTYs in a row, the inner one raw. Our HTTP chain.
- `script(1)`, `systemd-run --pty`: a PTY forwarder in front of a child.

---

## Open questions

**1. When we say "this is a terminal but not the controlling one", do we
still promise `/dev/tty` is closed?**

Attach has two terminal modes. `ctty` means "this is `/dev/tty`". `tty`
means "this is a terminal, but not `/dev/tty`" — so `test -t 0` is true
and opening `/dev/tty` fails. A test on main encoded that.

Step 1 always starts the script in its own session. If bash gets a
*brand new* terminal on stdin, it quietly makes that terminal `/dev/tty`
anyway, even when we asked for `tty` not `ctty`. (`cat` does not.) This
cannot happen to the operator's own terminal (someone already owns it).
It can happen to a PTY we created for the script.

Since step 3 the CLI never asks for `tty`: its only terminal is `ctty`, and
other terminals arrive as pipes. The question remains for the server's
`tty` attach, which other HTTP clients can still request.

Choices:

- **Live with it**, and say so in [http-api.md](http-api.md): `tty` vs
  `ctty` is what we *ask* for; bash may still take stdin as `/dev/tty`.
- **Keep the old promise:** never put a terminal on stdin unless it is
  `ctty`. A "terminal but not controlling" stdin would have to be a
  different descriptor (fd 3), which scripts would not treat as stdin.
- **Drop `tty`** from the attach API, now that the CLI does not use it.

**2. Extra fds — pinned.**

The CLI currently passes only 0, 1 and 2. A controlling terminal that is
not on those (`<in >out 2>err` from a real keyboard) is one case of a
broader need: pass extra descriptors into the script.

Do **not** inherit every fd the CLI has open. Children would see the
agent's database, Unix sockets, lock files, and whatever else. Go already
does not inherit extra fds (`O_CLOEXEC`). Extra fds, when we add them,
should be an explicit list. Until then, redirected stdio means the script
has no `/dev/tty` even if the operator has a keyboard.

**3. Window resize over HTTP — pinned, not in-band bytes.**

Resizing the glass does **not** put bytes on the PTY. The kernel sends
`SIGWINCH` to the process group of that terminal. Locally the broker
copies the new size to the PTY master it holds (`pty.InheritSize`), and the
kernel then signals the script. Remotely the PTY is on the server; the attach is a raw byte
copy, so there is no resize packet to forward. SSH does the same with a
separate channel message, not with PTY data. How we carry that over HTTP
(a framed message on the attach would mean we no longer have a raw file
stream; or a separate request) is undecided. Initial size at attach time
is enough until something needs live resize.

**4. When to prompt — decided.**

Prompt only if the CLI has a **controlling** terminal (`/dev/tty` opens).
A tty on some other fd is not "the operator is at this keyboard"; it may
be another pane. No ctty → `Propose` returns declined (auto-no): do not
hang, do not read stdin. `--no-prompt` for an unattended run that *has* a
ctty, and a distinct "could not ask" error for remembered approvals, are
later.

**5. Approve from another window.** Not now.

**6. Debug logs during a prompt.** Later.

Out of scope: Darwin. Delivering the approval across hosts:
[plan-federation.md](plan-federation.md).

---

## References

- `internal/command/command.go`: `Process` (`Setsid`, group kill, `Setctty`,
  `Credential`), `ownTerminals`
- `internal/command/broker_linux.go`: `OpenBroker`, PTY and pipe copies,
  signals, exit drain
- `internal/command/files.go`, `group.go`: `FileMode`, `LocalMode`,
  `FileGroups`, grouping by open file
- `internal/command/pty.go`, `termios_linux.go`: `OpenPty`, `setRaw`
- `internal/cli/cli.go`: `interruptContext`, `operate`, broker lifetime
- `internal/cli/e2e_linux_test.go`, `interrupt_test.go`,
  `internal/command/broker_linux_test.go`: tests for steps 1–3
- `internal/server/attach.go`: server PTY for `tty`/`ctty`
- `internal/client/attach.go`, `runner.go`: copying attaches
- [http-api.md](http-api.md): attach modes
