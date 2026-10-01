# AGENTS.md

This file provides guidance to AI code agents when working with code in this repository.

auditview is a single-user, localhost-only web UI over the Linux audit log (`/var/log/audit/audit.log`). It shows who ran which commands, from which login session and source IP. See README.md for flags, pages and the user-facing security model.

## Commands

```sh
make build                     # CGO_ENABLED=0 static binary ./auditview (Go 1.26, required by modernc.org/sqlite)
make test                      # go vet + go test
go test -run TestIngestFixture ./...   # single test
sudo ./auditview               # real use: prints http://127.0.0.1:8765/?token=...
```

To run without root against the fixture, replace the `<GS>` placeholder with the 0x1d byte:

```sh
mkdir -p /tmp/av/log && sed 's/<GS>/\x1d/g' testdata/audit.log.in > /tmp/av/log/audit.log
./auditview -addr 127.0.0.1:18765 -log-dir /tmp/av/log -db /tmp/av/audit.db
```

When it isn't root, the program skips the privilege drop and reads `-log-dir` with the current user's permissions.

Two gotchas:
- **Stopping it:** use `kill -INT $(pgrep -xo auditview)`. `pkill -f auditview...` also matches the invoking shell and kills it.
- **The root path is untested here:** the privilege drop and reading the real `/var/log/audit` can't be exercised without sudo.

## Architecture

### Privilege split (main.go, reader.go)
Started via sudo, the binary re-executes itself as `auditview __reader -log-dir DIR` and keeps that child as root. Then `dropPrivileges` permanently switches the main process to `SUDO_UID`: setgroups/setgid/setuid, verifies root can't be regained, and sets `PR_SET_NO_NEW_PRIVS`. This happens **before** the database or the HTTP server is opened.

Invariants to keep:
- **The reader stays minimal.** It only lists, reads and follows log files: rotated `audit.log.N` oldest first, open file descriptors kept across rotation, partial lines buffered. It writes raw lines to stdout. It must never parse log content (which contains user-controlled argv), open the network, or touch the DB.
- **Pipe protocol:** the parent sends one line `start <unix-secs>`, and the reader skips rotated files older than that. Lines starting with `#` are control lines (`#caughtup`, `#error ...`). The reader exits on stdin EOF, on a change of its parent PID, or via Pdeathsig. It ignores SIGINT; shutdown means the parent closes its stdin.

### Ingest pipeline (ingest.go, parse.go, store.go)
1. **Skip:** `ingest()` reads the reader's lines. `parseHeader` cheaply skips anything older than `checkpoint − 60s`.
2. **Parse:** `parseRecord` turns a line into a `Record`:
   - `Fields` keeps raw values **with quotes**: quoted means literal, unquoted means hex for exe/comm/cwd/name/argv/cmd/acct/proctitle.
   - Accessors: `Str` (unquote), `Text` (hex-aware decode), `Name` (prefers the ENRICHED uppercase fields auditd appends after 0x1d).
   - Nested `msg='...'` payloads from user-space records are flattened into `Fields`.
3. **Assemble:** the `assembler` groups records by `(ts, serial)` and **emits strictly in arrival order**, because session logic depends on it. An event is complete on EOE, at once for standalone user-space types (`USER_*`, `CRED_*`, …), when a record 2s newer arrives, or when the input goes idle.
4. **Store:** `store.ingest` applies a batch in one transaction. `apply` classifies each event into the tables `sessions`, `execs`, `auth` and `changes`.

### Sessions (the "who / from which IP" link)
- A kernel `LOGIN` record creates a session row.
- `USER_START`/`USER_LOGIN` with the same `ses` fill in addr, hostname, terminal and exe, but only fields that are still empty. Records from `privTools` (sudo, su, pkexec, …) are ignored, because they reuse the login's `ses`.
- `USER_END` ends a session only if its exe matches the login program.
- Kernel `ses` IDs restart at every boot. `noteBoot` detects a reboot from `SYSTEM_BOOT` or from the event serial dropping sharply. Session lookups (`sessionFor`) only match sessions started after `bootTS`. If no match exists, a `partial=1` session is created.
- `sesCache` maps `ses` to `sessions.id`. It is cleared on reboot, on prune, and when a batch fails.

### Database rules
- **Single writer:** `rw` has `MaxOpenConns(1)`. Never query `s.rw` while a transaction is open, or it deadlocks. That's why the checkpoint lives in memory (`ckptTS`). The UI reads through the separate `ro` pool (`query_only`).
- **Re-imports must be idempotent:** after a restart the last 60s are replayed, so every table has `UNIQUE(ts, serial)` (sessions: `start_ts, start_serial`) and inserts use `INSERT OR IGNORE`. Updates must stay idempotent too. New tables need the same scheme.
- **Clearing keeps the checkpoint:** `clearAll` deletes the data but keeps `checkpoint_ts`, so logs that were already imported aren't imported again.

### Coupling to the audit rules
The categories come from the audit keys in `/etc/audit/rules.d/50-exec-audit.rules`. `queries.go` hardcodes them in `criticalKeys`, `highKeys`, `privExecKeys` and `netExecKeys`. `sessionCols` also inlines the privileged key list in SQL. Keep all of these in sync when rules change.

### Web (web.go, templates/, static/)
- **Templates:** `layout.html` is cloned for each page, and each page template defines `content` and receives its data in `.Data`. The shared partials `execTable` and `changeTable` live in `layout.html`.
- **No JavaScript:** the CSP (`default-src 'none'; style-src 'self'`) also blocks inline `style=` attributes and scripts. Use CSS classes, and server-side SVG for charts (`buildChart`).
- **The `guard` middleware** enforces:
  - a Host header allowlist (blocks DNS rebinding);
  - token exchange to an `HttpOnly`, `SameSite=Strict` cookie, then a redirect that strips the token;
  - the security headers.

  The only POST (`/data/clear`) also requires the `csrf` form field.
- **The time range** comes from the `range` query parameter (`server.since`) and is carried along in every link.
- **Outgoing targets** come from `targets()`, a best-effort per-tool parse of the stored `argv` JSON (each argument is clipped to 64 entries × 512 bytes).

## Tests
`testdata/audit.log.in` is a hand-written ENRICHED-format log that uses a literal `<GS>` in place of 0x1d. It covers a console login, an SSH login, sudo inside the SSH session, hex and chunked argv, a failed exec, a watched file, kmod, CONFIG_CHANGE, failed remote auth, and a reboot that reuses `ses=7`. `TestIngestFixture` asserts exact counts (11 commands, 10 in the SSH session, and so on), so update those assertions when you add fixture lines.
