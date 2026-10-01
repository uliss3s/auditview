package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"os/user"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Commands longer than this are truncated in the database (compiler and
// linker invocations can carry hundreds of KB of arguments).
const maxCmdline = 8192

// Tools whose PAM session records belong to an existing login session; they
// must not be mistaken for the login itself.
var privTools = map[string]bool{
	"sudo": true, "su": true, "pkexec": true, "ksu": true, "runuser": true,
	"doas": true, "run0": true, "systemd-run": true, "sudo-rs": true,
}

var syscallNames = map[string]string{
	"59": "execve", "322": "execveat", "2": "open", "257": "openat", "437": "openat2",
	"82": "rename", "264": "renameat", "316": "renameat2", "87": "unlink", "263": "unlinkat",
	"90": "chmod", "268": "fchmodat", "92": "chown", "260": "fchownat", "76": "truncate",
	"175": "init_module", "313": "finit_module", "176": "delete_module",
}

func syscallName(r *Record) string {
	if v, ok := r.Enriched["SYSCALL"]; ok {
		return unquote(v)
	}
	n := r.Str("syscall")
	if name, ok := syscallNames[n]; ok && r.Str("arch") == "c000003e" {
		return name
	}
	switch r.Str("arch") + "/" + n {
	case "40000003/11":
		return "execve"
	case "40000003/358":
		return "execveat"
	}
	return "syscall " + n
}

func recordKey(r *Record) string {
	k := r.Fields["key"]
	if k == "(null)" || k == "" {
		return ""
	}
	// Multiple keys are hex-encoded and separated by 0x01.
	return strings.ReplaceAll(decodeValue(k), "\x01", ",")
}

func sesOf(r *Record) (int64, bool) {
	v := r.Str("ses")
	if v == "" || v == unsetID || v == "-1" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil
}

func succeeded(r *Record) bool {
	switch r.Str("res") {
	case "success", "yes", "1":
		return true
	}
	return r.Str("success") == "yes"
}

func clean(v string) string {
	if v == "?" || v == "(none)" {
		return ""
	}
	return cleanText(v)
}

func nullable(ok bool, v int64) any {
	if !ok {
		return nil
	}
	return v
}

var userNames sync.Map

func lookupUserName(uid string) string {
	if v, ok := userNames.Load(uid); ok {
		return v.(string)
	}
	name := uid
	if u, err := user.LookupId(uid); err == nil {
		name = u.Username
	}
	userNames.Store(uid, name)
	return name
}

// apply turns one assembled event into rows.
func (s *store) apply(tx *sql.Tx, ev *Event) error {
	s.noteBoot(ev)

	if login := ev.First("LOGIN"); login != nil {
		if ses, ok := sesOf(login); ok && login.Str("res") == "1" {
			if err := s.newSession(tx, ev, ses, login.Name("auid")); err != nil {
				return err
			}
		}
	}

	for _, r := range ev.Records {
		switch r.Type {
		case "USER_START", "USER_LOGIN":
			if err := s.describeSession(tx, ev, r); err != nil {
				return err
			}
		case "USER_END":
			if err := s.endSession(tx, ev, r); err != nil {
				return err
			}
		case "USER_CMD":
			if err := s.addSudo(tx, ev, r); err != nil {
				return err
			}
		}
		switch r.Type {
		case "USER_AUTH", "USER_ACCT", "USER_LOGIN", "USER_ERR", "ANOM_LOGIN_FAILURES", "ANOM_LOGIN_LOCATION", "ANOM_LOGIN_TIME", "ANOM_LOGIN_SESSIONS":
			if err := s.addAuth(tx, ev, r); err != nil {
				return err
			}
		}
	}

	sc := ev.First("SYSCALL")
	switch {
	case sc != nil && (ev.First("EXECVE") != nil || strings.HasPrefix(syscallName(sc), "execve")):
		return s.addExec(tx, ev, sc)
	case ev.First("CONFIG_CHANGE") != nil:
		return s.addConfigChange(tx, ev, sc)
	case sc != nil && recordKey(sc) != "":
		return s.addChange(tx, ev, sc)
	}
	return nil
}

func (s *store) describeSession(tx *sql.Tx, ev *Event, r *Record) error {
	ses, ok := sesOf(r)
	if !ok || !succeeded(r) || privTools[path.Base(r.Text("exe"))] {
		return nil
	}
	id, err := s.sessionFor(tx, ses, ev.TS, ev.Serial, r.Name("auid"))
	if err != nil {
		return err
	}
	addr, host := clean(r.Str("addr")), clean(r.Str("hostname"))
	if addr == host {
		host = ""
	}
	_, err = tx.Exec(`UPDATE sessions SET
		addr     = CASE WHEN addr = '' THEN ? ELSE addr END,
		hostname = CASE WHEN hostname = '' THEN ? ELSE hostname END,
		terminal = CASE WHEN terminal = '' THEN ? ELSE terminal END,
		exe      = CASE WHEN exe = '' THEN ? ELSE exe END
		WHERE id = ?`, addr, host, clean(r.Str("terminal")), clean(r.Text("exe")), id)
	return err
}

func (s *store) endSession(tx *sql.Tx, ev *Event, r *Record) error {
	ses, ok := sesOf(r)
	exe := r.Text("exe")
	if !ok || privTools[path.Base(exe)] {
		return nil
	}
	id, err := s.sessionFor(tx, ses, ev.TS, ev.Serial, r.Name("auid"))
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE sessions SET end_ts = ? WHERE id = ? AND end_ts IS NULL AND (exe = '' OR exe = ?)`, ev.TS, id, exe)
	return err
}

func (s *store) addAuth(tx *sql.Tx, ev *Event, r *Record) error {
	ses, hasSes := sesOf(r)
	acct := r.Text("acct")
	if acct == "" {
		if id := r.Str("id"); id != "" && id != unsetID {
			acct = r.Name("id")
		}
	}
	_, err := tx.Exec(`INSERT OR IGNORE INTO auth (ts, serial, type, op, acct, auid, ses, addr, hostname, terminal, exe, success)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TS, ev.Serial, r.Type, clean(r.Str("op")), clean(acct), r.Name("auid"), nullable(hasSes, ses),
		clean(r.Str("addr")), clean(r.Str("hostname")), clean(r.Str("terminal")), clean(r.Text("exe")), succeeded(r))
	return err
}

func (s *store) addExec(tx *sql.Tx, ev *Event, sc *Record) error {
	// argv may be split across several EXECVE records.
	fields := map[string]string{}
	for _, r := range ev.All("EXECVE") {
		for k, v := range r.Fields {
			fields[k] = v
		}
	}
	var argv []string
	argc, _ := strconv.Atoi(unquote(fields["argc"]))
	for i := 0; i < argc; i++ {
		k := "a" + strconv.Itoa(i)
		if v, ok := fields[k]; ok {
			argv = append(argv, decodeValue(v))
			continue
		}
		if _, ok := fields[k+"_len"]; ok { // long argument split in chunks
			var b strings.Builder
			for j := 0; ; j++ {
				chunk, ok := fields[k+"["+strconv.Itoa(j)+"]"]
				if !ok {
					break
				}
				b.WriteString(chunk)
			}
			v, _ := decodeHex(b.String())
			argv = append(argv, v)
		}
	}
	exe := sc.Text("exe")
	if len(argv) == 0 { // failed exec: no EXECVE record, use the attempted path
		if p := ev.First("PATH"); p != nil {
			argv = []string{p.Text("name")}
		} else {
			argv = []string{exe}
		}
		if p := ev.First("PATH"); p != nil && sc.Str("success") == "no" {
			exe = p.Text("name")
		}
	}
	cmdline := shellJoin(argv)
	if len(cmdline) > maxCmdline {
		cmdline = strings.ToValidUTF8(cmdline[:maxCmdline], "") + " …[truncated]"
	}
	clipped := argv
	if len(clipped) > 64 {
		clipped = clipped[:64]
	}
	for i, a := range clipped {
		if len(a) > 512 {
			clipped[i] = strings.ToValidUTF8(a[:512], "")
		}
	}
	argvJSON, _ := json.Marshal(clipped)

	cwd := ""
	if c := ev.First("CWD"); c != nil {
		cwd = c.Text("cwd")
	}
	ses, hasSes := sesOf(sc)
	var sessionID any
	if hasSes {
		id, err := s.sessionFor(tx, ses, ev.TS, ev.Serial, sc.Name("auid"))
		if err != nil {
			return err
		}
		sessionID = id
	}
	pid, _ := strconv.ParseInt(sc.Str("pid"), 10, 64)
	ppid, _ := strconv.ParseInt(sc.Str("ppid"), 10, 64)
	_, err := tx.Exec(`INSERT OR IGNORE INTO execs (ts, serial, key, auid, uid, euid, ses, session_id, tty, pid, ppid, exe, cwd, cmdline, argv, success)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TS, ev.Serial, recordKey(sc), sc.Name("auid"), sc.Name("uid"), sc.Name("euid"), nullable(hasSes, ses), sessionID,
		clean(sc.Str("tty")), pid, ppid, cleanText(exe), cleanText(cwd), cmdline, string(argvJSON), sc.Str("success") == "yes")
	return err
}

func (s *store) insertChange(tx *sql.Tx, ev *Event, kind, key string, r *Record, summary string, ok bool) error {
	ses, hasSes := sesOf(r)
	var sessionID any
	if hasSes {
		id, err := s.sessionFor(tx, ses, ev.TS, ev.Serial, r.Name("auid"))
		if err != nil {
			return err
		}
		sessionID = id
	}
	uid := ""
	if r.Str("uid") != "" {
		uid = r.Name("uid")
	}
	_, err := tx.Exec(`INSERT OR IGNORE INTO changes (ts, serial, kind, key, auid, uid, ses, session_id, exe, summary, success)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TS, ev.Serial, kind, key, r.Name("auid"), uid, nullable(hasSes, ses), sessionID,
		clean(r.Text("exe")), cleanText(summary), ok)
	return err
}

func (s *store) addSudo(tx *sql.Tx, ev *Event, r *Record) error {
	summary := r.Text("cmd")
	if t := clean(r.Str("terminal")); t != "" {
		summary += "   [" + t + "]"
	}
	if cwd := r.Text("cwd"); cwd != "" {
		summary += "   cwd=" + cwd
	}
	return s.insertChange(tx, ev, "sudo", "", r, summary, succeeded(r))
}

func (s *store) addConfigChange(tx *sql.Tx, ev *Event, sc *Record) error {
	cc := ev.First("CONFIG_CHANGE")
	parts := []string{}
	for _, k := range []string{"op", "key", "list", "audit_enabled", "audit_backlog_limit", "audit_failure", "res"} {
		if v := cc.Str(k); v != "" {
			if k == "key" {
				v = recordKey(cc)
			}
			parts = append(parts, k+"="+v)
		}
	}
	r := cc
	if sc != nil {
		r = sc // has exe/uid/ses of the process that changed the config
	}
	return s.insertChange(tx, ev, "audit_config", "audit_cfg", r, strings.Join(parts, " "), cc.Str("res") != "0")
}

func (s *store) addChange(tx *sql.Tx, ev *Event, sc *Record) error {
	name := syscallName(sc)
	kind := "file"
	if strings.HasSuffix(name, "_module") {
		kind = "kmod"
	}
	cwd := ""
	if c := ev.First("CWD"); c != nil {
		cwd = c.Text("cwd")
	}
	var paths []string
	for _, p := range ev.All("PATH") {
		n := p.Text("name")
		if n == "" || p.Str("nametype") == "PARENT" {
			continue
		}
		if !strings.HasPrefix(n, "/") && cwd != "" {
			n = path.Join(cwd, n)
		}
		if nt := p.Str("nametype"); nt == "CREATE" || nt == "DELETE" {
			n += " (" + strings.ToLower(nt) + ")"
		}
		paths = append(paths, n)
	}
	summary := name + " " + strings.Join(paths, ", ")
	if kind == "kmod" {
		if pt := ev.First("PROCTITLE"); pt != nil {
			summary = name + ": " + strings.ReplaceAll(pt.Text("proctitle"), "\x00", " ")
		}
	}
	return s.insertChange(tx, ev, kind, recordKey(sc), sc, strings.TrimSpace(summary), sc.Str("success") == "yes")
}

// ---------------------------------------------------------------------------

// Status is shared between the ingester and the web UI.
type Status struct {
	mu        sync.Mutex
	state     string // "starting", "catching up", "live", "stopped"
	err       string
	lastEvent int64
	ingested  int64
}

func (st *Status) set(f func(st *Status)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	f(st)
}

type StatusView struct {
	State, Err string
	LastEvent  int64
	Ingested   int64
}

func (st *Status) view() StatusView {
	st.mu.Lock()
	defer st.mu.Unlock()
	return StatusView{st.state, st.err, st.lastEvent, st.ingested}
}

// ingest reads the reader's output until it ends, storing events in batches.
// Events older than minTS were stored in a previous run and are skipped
// cheaply; the replay window just before it is deduplicated by the database.
func ingest(r io.Reader, st *store, status *Status, minTS int64) {
	lines := make(chan []byte, 4096)
	go func() {
		br := bufio.NewReaderSize(r, 1<<20)
		for {
			line, err := br.ReadBytes('\n')
			if len(line) > 0 {
				lines <- line
			}
			if err != nil {
				close(lines)
				return
			}
		}
	}()

	var batch []*Event
	asm := newAssembler(func(ev *Event) { batch = append(batch, ev) })
	commit := func() {
		if len(batch) == 0 {
			return
		}
		err := st.ingest(batch)
		n, last := int64(len(batch)), batch[len(batch)-1].TS
		batch = batch[:0]
		status.set(func(s *Status) {
			if err != nil {
				s.err = "storing events: " + err.Error()
				return
			}
			s.ingested += n
			s.lastEvent = max(s.lastEvent, last)
		})
	}
	status.set(func(s *Status) { s.state = "catching up" })

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	lastLine := time.Now()
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				asm.flushAll()
				commit()
				status.set(func(s *Status) { s.state = "stopped" })
				return
			}
			lastLine = time.Now()
			if line[0] == '#' {
				msg := string(bytes.TrimSpace(line))
				switch {
				case msg == "#caughtup":
					asm.flushAll()
					commit()
					status.set(func(s *Status) { s.state = "live" })
				case strings.HasPrefix(msg, "#error "):
					status.set(func(s *Status) { s.err = "log reader: " + strings.TrimPrefix(msg, "#error ") })
				}
				continue
			}
			if _, ts, _, _, ok := parseHeader(line); !ok || ts < minTS {
				continue
			}
			if rec, ok := parseRecord(line); ok {
				asm.add(rec)
			}
			if len(batch) >= 2000 {
				commit()
			}
		case <-ticker.C:
			if time.Since(lastLine) > time.Second {
				asm.flushAll()
			}
			commit()
		}
	}
}
