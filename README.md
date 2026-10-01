# auditview

A local, single-user web UI for the Linux audit log: **who ran which commands,
from which login session and source IP**, plus logins, failed authentications,
outgoing connections made by network tools, and changes to watched files.

It reads what `auditd` already writes to `/var/log/audit/audit.log`
(rules in `/etc/audit/rules.d/50-exec-audit.rules`), stores it in SQLite, and
serves pages on `127.0.0.1` only.

> **Heads up:** this is a personal side project, mostly "vibe coded" with an AI
> assistant rather than written and reviewed line by line. It works well enough
> for keeping an eye on my own machine, but it hasn't been audited or tested
> much beyond that. Feel free to try it or borrow ideas from it, but please
> don't rely on it in production or anywhere security really matters. It runs
> with `sudo`, after all.

## Build and run

```sh
make build          # static binary ./auditview (Go 1.26+)
sudo ./auditview    # prints a URL with a one-time token; open it in your browser
```

Stop with `Ctrl+C`. Starting it again resumes from where it stopped; anything
written to the audit log in the meantime is imported, as long as auditd has not
rotated it away (currently 10 × 100 MB).

| Flag | Default | |
|---|---|---|
| `-addr` | `127.0.0.1:8765` | Listen address; only loopback is accepted |
| `-db` | `~/.local/share/auditview/audit.db` | Database file (mode 0600) |
| `-retention-days` | `365` | Older data is deleted automatically; `0` keeps everything |
| `-log-dir` | `/var/log/audit` | Where `audit.log` and its rotations live |
| `-user` | the user who ran `sudo` | Account the main process switches to |

## Pages

- **Overview**: totals, activity chart, top users and programs, latest privileged commands, remote logins and watched changes.
- **Commands**: every recorded command with user, effective user, category (audit key), and the session/IP it came from. Filters: user, key, text, ran as root, failed.
- **Sessions**: each login (SSH, console, desktop, cron, …) with source address, duration and the full ordered list of what it ran.
- **Users**: per login user: commands, privileged commands, failures, logins and source addresses.
- **Connections**: incoming logins and failed attempts per source IP; outgoing targets parsed from `ssh`/`scp`/`curl`/… command lines; authentication events.
- **Changes**: watched file writes, sudo's own command records (including denied ones), kernel module and audit-config changes.
- **Data**: database size and counts; delete data older than N days, or everything.

## Security model

`sudo ./auditview` starts as root, but root is used for one thing only:

1. The binary re-executes itself as a **reader** process that keeps root. It
   only lists and reads the audit log files and copies raw lines to a pipe.
   It does not parse anything, and has no network or database access
   (`reader.go`, ~200 lines).
2. The **main** process then permanently switches to your user (`setgroups`,
   `setgid`, `setuid`, verified, plus `PR_SET_NO_NEW_PRIVS`) *before* it opens
   the database or the web server. All parsing of log content — which includes
   user-controlled command lines — happens here, unprivileged.

The web UI:

- listens on loopback only and rejects requests whose `Host` header is not
  `127.0.0.1`/`localhost` (DNS-rebinding protection);
- requires the random token printed at startup, then uses an `HttpOnly`,
  `SameSite=Strict` cookie; the token is new on every start;
- sends a strict Content-Security-Policy and uses no JavaScript at all;
- escapes all log content through `html/template`;
- protects the only state-changing action (deleting data) with a CSRF token,
  and "delete all" requires typing `DELETE`.

The database contains full command lines, which can include secrets passed as
arguments. It is created with mode 0600 in your home directory.

## Limitations

- Only programs that are executed are recorded; shell built-ins (`cd`, `echo`,
  `export`, …) are not.
- Commands inside Docker containers are not attributed to your login.
- Outgoing connections are only seen through the network tools' command lines,
  not every socket a program opens.
- Failed SSH public-key attempts never reach PAM, so they are not in the audit log.
- Sessions that started before the oldest imported log line are shown as
  "earlier", with no source address.
