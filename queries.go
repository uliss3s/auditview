package main

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// Key categories, matching /etc/audit/rules.d/50-exec-audit.rules.
var (
	criticalKeys = []string{"priv_esc", "root_exec", "account_mgmt", "kmod", "identity", "sudoers", "pam", "sshd_cfg", "ssh_keys", "audit_cfg", "audit_tools"}
	highKeys     = []string{"net_remote", "net_transfer", "net_tools", "docker", "persistence", "packages", "firewall"}
	privExecKeys = []string{"priv_esc", "root_exec", "account_mgmt", "kmod"}
	netExecKeys  = []string{"net_remote", "net_transfer", "net_tools"}
)

func keyLevel(k string) string {
	for _, c := range criticalKeys {
		if k == c {
			return "critical"
		}
	}
	for _, h := range highKeys {
		if k == h {
			return "high"
		}
	}
	return "normal"
}

func inList(col string, vals []string, args *[]any) string {
	ph := make([]string, len(vals))
	for i, v := range vals {
		ph[i] = "?"
		*args = append(*args, v)
	}
	return col + " IN (" + strings.Join(ph, ",") + ")"
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(s) + "%"
}

// ---------------------------------------------------------------------------

type ExecRow struct {
	ID, TS, PID        int64
	Key, Auid, UID     string
	EUID, TTY, Exe     string
	Cwd, Cmdline, Addr string
	Success            bool
	SessionID          sql.NullInt64
	Argv               []string
}

const execCols = `e.id, e.ts, COALESCE(e.pid, 0), e.key, e.auid, e.uid, e.euid, e.tty, e.exe, e.cwd, e.cmdline, COALESCE(s.addr, ''), e.success, e.session_id, e.argv`

func scanExecs(rows *sql.Rows, err error) ([]ExecRow, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExecRow
	for rows.Next() {
		var r ExecRow
		var argv string
		if err := rows.Scan(&r.ID, &r.TS, &r.PID, &r.Key, &r.Auid, &r.UID, &r.EUID, &r.TTY, &r.Exe, &r.Cwd, &r.Cmdline, &r.Addr, &r.Success, &r.SessionID, &argv); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(argv), &r.Argv)
		out = append(out, r)
	}
	return out, rows.Err()
}

type ExecFilter struct {
	Since, Session int64
	User, Key, Q   string
	Failed, AsRoot bool
	Offset, Limit  int
}

func (s *store) execs(f ExecFilter) ([]ExecRow, error) {
	where := []string{"e.ts >= ?"}
	args := []any{f.Since}
	if f.User != "" {
		where = append(where, "e.auid = ?")
		args = append(args, f.User)
	}
	switch f.Key {
	case "":
	case "@privileged":
		where = append(where, inList("e.key", privExecKeys, &args))
	case "@network":
		where = append(where, inList("e.key", netExecKeys, &args))
	default:
		where = append(where, "e.key = ?")
		args = append(args, f.Key)
	}
	if f.Q != "" {
		where = append(where, `e.cmdline LIKE ? ESCAPE '\'`)
		args = append(args, likeEscape(f.Q))
	}
	if f.Session > 0 {
		where = append(where, "e.session_id = ?")
		args = append(args, f.Session)
	}
	if f.Failed {
		where = append(where, "e.success = 0")
	}
	if f.AsRoot {
		where = append(where, "e.euid = 'root'")
	}
	order := "e.ts DESC, e.id DESC"
	if f.Session > 0 {
		order = "e.ts ASC, e.id ASC"
	}
	args = append(args, f.Limit, f.Offset)
	return scanExecs(s.ro.Query(`SELECT `+execCols+` FROM execs e LEFT JOIN sessions s ON s.id = e.session_id
		WHERE `+strings.Join(where, " AND ")+` ORDER BY `+order+` LIMIT ? OFFSET ?`, args...))
}

func (s *store) distinct(q string, args ...any) []string {
	rows, err := s.ro.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil && v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *store) knownUsers() []string {
	return s.distinct(`SELECT DISTINCT auid FROM execs WHERE auid != 'unset' UNION SELECT DISTINCT auid FROM sessions WHERE auid != '' AND auid != 'unset' ORDER BY 1`)
}

func (s *store) knownKeys() []string {
	return s.distinct(`SELECT DISTINCT key FROM execs ORDER BY 1`)
}

// ---------------------------------------------------------------------------

type SessionRow struct {
	ID, Ses, StartTS                 int64
	EndTS                            sql.NullInt64
	Auid, Addr, Hostname, Terminal   string
	Exe                              string
	Partial                          bool
	Commands, Privileged, LastActive int64
}

func (r SessionRow) Kind() string {
	b := path.Base(r.Exe)
	switch {
	case strings.Contains(b, "sshd"):
		return "ssh"
	case b == "login" || strings.HasPrefix(r.Terminal, "/dev/tty") || strings.HasPrefix(r.Terminal, "tty"):
		return "console"
	case strings.Contains(b, "sddm") || strings.Contains(b, "gdm") || strings.Contains(b, "lightdm") || strings.HasPrefix(r.Terminal, ":"):
		return "desktop"
	case strings.Contains(b, "cron"):
		return "cron"
	case strings.HasPrefix(b, "systemd"):
		return "systemd"
	case r.Addr != "":
		return "remote"
	case r.Exe == "":
		return "unknown"
	}
	return b
}

const sessionCols = `s.id, s.ses, s.start_ts, s.end_ts, s.auid, s.addr, s.hostname, s.terminal, s.exe, s.partial,
	(SELECT COUNT(*) FROM execs e WHERE e.session_id = s.id),
	(SELECT COUNT(*) FROM execs e WHERE e.session_id = s.id AND e.key IN ('priv_esc','root_exec','account_mgmt','kmod')),
	COALESCE((SELECT MAX(ts) FROM execs e WHERE e.session_id = s.id), s.start_ts)`

func scanSessions(rows *sql.Rows, err error) ([]SessionRow, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		if err := rows.Scan(&r.ID, &r.Ses, &r.StartTS, &r.EndTS, &r.Auid, &r.Addr, &r.Hostname, &r.Terminal, &r.Exe, &r.Partial,
			&r.Commands, &r.Privileged, &r.LastActive); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type SessionFilter struct {
	Since                int64
	User, Addr           string
	RemoteOnly, WithCmds bool
}

func (s *store) sessions(f SessionFilter, limit int) ([]SessionRow, error) {
	where := []string{"(s.start_ts >= ? OR s.id IN (SELECT DISTINCT session_id FROM execs WHERE ts >= ? AND session_id IS NOT NULL))"}
	args := []any{f.Since, f.Since}
	if f.User != "" {
		where = append(where, "s.auid = ?")
		args = append(args, f.User)
	}
	if f.Addr != "" {
		where = append(where, "s.addr = ?")
		args = append(args, f.Addr)
	}
	if f.RemoteOnly {
		where = append(where, "s.addr != ''")
	}
	if f.WithCmds {
		where = append(where, "EXISTS (SELECT 1 FROM execs e WHERE e.session_id = s.id)")
	}
	args = append(args, limit)
	return scanSessions(s.ro.Query(`SELECT `+sessionCols+` FROM sessions s WHERE `+strings.Join(where, " AND ")+
		` ORDER BY s.start_ts DESC LIMIT ?`, args...))
}

func (s *store) session(id int64) (*SessionRow, error) {
	rows, err := scanSessions(s.ro.Query(`SELECT `+sessionCols+` FROM sessions s WHERE s.id = ?`, id))
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// ---------------------------------------------------------------------------

type ChangeRow struct {
	ID, TS               int64
	Kind, Key, Auid, UID string
	Exe, Summary, Addr   string
	Success              bool
	SessionID            sql.NullInt64
}

func (s *store) changes(since int64, kind string, session int64, limit int) ([]ChangeRow, error) {
	where := []string{"c.ts >= ?"}
	args := []any{since}
	if kind != "" {
		where = append(where, "c.kind = ?")
		args = append(args, kind)
	}
	if session > 0 {
		where = append(where, "c.session_id = ?")
		args = append(args, session)
	}
	args = append(args, limit)
	rows, err := s.ro.Query(`SELECT c.id, c.ts, c.kind, c.key, c.auid, c.uid, c.exe, c.summary, COALESCE(s.addr, ''), c.success, c.session_id
		FROM changes c LEFT JOIN sessions s ON s.id = c.session_id
		WHERE `+strings.Join(where, " AND ")+` ORDER BY c.ts DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChangeRow
	for rows.Next() {
		var r ChangeRow
		if err := rows.Scan(&r.ID, &r.TS, &r.Kind, &r.Key, &r.Auid, &r.UID, &r.Exe, &r.Summary, &r.Addr, &r.Success, &r.SessionID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------

type Bucket struct {
	TS, Total, Priv int64
}

type Count struct {
	Name        string
	Count, Priv int64
}

type Overview struct {
	Commands, Privileged, Failed int64
	Sessions, RemoteSessions     int64
	FailedAuth, Changes          int64
	Buckets                      []Bucket
	BucketMs                     int64
	ByKey, TopUsers, TopPrograms []Count
	RecentPriv                   []ExecRow
	RecentRemote                 []SessionRow
	RecentChanges                []ChangeRow
}

func (s *store) count(q string, args ...any) int64 {
	var n int64
	s.ro.QueryRow(q, args...).Scan(&n)
	return n
}

func (s *store) counts(q string, args ...any) []Count {
	rows, err := s.ro.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		if rows.Scan(&c.Name, &c.Count, &c.Priv) == nil {
			out = append(out, c)
		}
	}
	return out
}

func (s *store) overview(since int64) (*Overview, error) {
	o := &Overview{}
	var a []any
	priv := inList("key", privExecKeys, &a)
	o.Commands = s.count(`SELECT COUNT(*) FROM execs WHERE ts >= ?`, since)
	o.Privileged = s.count(`SELECT COUNT(*) FROM execs WHERE ts >= ? AND `+priv, append([]any{since}, a...)...)
	o.Failed = s.count(`SELECT COUNT(*) FROM execs WHERE ts >= ? AND success = 0`, since)
	o.Sessions = s.count(`SELECT COUNT(*) FROM sessions WHERE start_ts >= ? AND partial = 0`, since)
	o.RemoteSessions = s.count(`SELECT COUNT(*) FROM sessions WHERE start_ts >= ? AND addr != ''`, since)
	o.FailedAuth = s.count(`SELECT COUNT(*) FROM auth WHERE ts >= ? AND success = 0`, since)
	o.Changes = s.count(`SELECT COUNT(*) FROM changes WHERE ts >= ? AND kind != 'sudo'`, since)

	// Activity chart, bucketed in local time.
	now := time.Now().UnixMilli()
	start := since
	if start == 0 {
		start = s.count(`SELECT COALESCE(MIN(ts), 0) FROM execs`)
		if start == 0 {
			start = now - 24*3600_000
		}
	}
	span := now - start
	bucket := int64(3600_000)
	switch {
	case span > 90*24*3600_000:
		bucket = 7 * 24 * 3600_000
	case span > 2*24*3600_000:
		bucket = 24 * 3600_000
	}
	o.BucketMs = bucket
	_, off := time.Now().Zone()
	offMs := int64(off) * 1000
	rows, err := s.ro.Query(`SELECT (ts + ?) / ? AS b, COUNT(*), SUM(`+priv+`) FROM execs WHERE ts >= ? GROUP BY b`,
		append(append([]any{offMs, bucket}, a...), start)...)
	if err != nil {
		return nil, err
	}
	got := map[int64]Bucket{}
	for rows.Next() {
		var b Bucket
		var idx int64
		if rows.Scan(&idx, &b.Total, &b.Priv) == nil {
			got[idx] = b
		}
	}
	rows.Close()
	for idx := (start + offMs) / bucket; idx <= (now+offMs)/bucket; idx++ {
		b := got[idx]
		b.TS = idx*bucket - offMs
		o.Buckets = append(o.Buckets, b)
	}

	o.ByKey = s.counts(`SELECT name, SUM(n), 0 FROM (
			SELECT key AS name, COUNT(*) AS n FROM execs WHERE ts >= ? GROUP BY key
			UNION ALL SELECT COALESCE(NULLIF(key, ''), kind), COUNT(*) FROM changes WHERE ts >= ? GROUP BY 1
		) GROUP BY name ORDER BY 2 DESC`, since, since)
	o.TopUsers = s.counts(`SELECT auid, COUNT(*), SUM(`+priv+`) FROM execs WHERE ts >= ? GROUP BY auid ORDER BY 2 DESC LIMIT 10`,
		append(a, since)...)
	o.TopPrograms = s.counts(`SELECT exe, COUNT(*), SUM(`+priv+`) FROM execs WHERE ts >= ? GROUP BY exe ORDER BY 2 DESC LIMIT 12`,
		append(a, since)...)
	if o.RecentPriv, err = s.execs(ExecFilter{Since: since, Key: "@privileged", Limit: 10}); err != nil {
		return nil, err
	}
	if o.RecentRemote, err = s.sessions(SessionFilter{Since: since, RemoteOnly: true}, 10); err != nil {
		return nil, err
	}
	if o.RecentChanges, err = s.changes(since, "", 0, 10); err != nil {
		return nil, err
	}
	return o, nil
}

// ---------------------------------------------------------------------------

type UserRow struct {
	Name                             string
	Commands, Privileged, Failed     int64
	Sessions, RemoteSessions, LastTS int64
	Addrs                            []string
}

func (s *store) users(since int64) ([]UserRow, error) {
	var a []any
	priv := inList("key", privExecKeys, &a)
	byName := map[string]*UserRow{}
	get := func(n string) *UserRow {
		if byName[n] == nil {
			byName[n] = &UserRow{Name: n}
		}
		return byName[n]
	}
	rows, err := s.ro.Query(`SELECT auid, COUNT(*), SUM(`+priv+`), SUM(success = 0), MAX(ts) FROM execs WHERE ts >= ? GROUP BY auid`, append(a, since)...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n string
		var c, p, f, last int64
		if rows.Scan(&n, &c, &p, &f, &last) == nil {
			u := get(n)
			u.Commands, u.Privileged, u.Failed, u.LastTS = c, p, f, last
		}
	}
	rows.Close()
	rows, err = s.ro.Query(`SELECT auid, COUNT(*), SUM(addr != ''), COALESCE(GROUP_CONCAT(DISTINCT NULLIF(addr, '')), ''), MAX(start_ts)
		FROM sessions WHERE start_ts >= ? AND partial = 0 AND auid != '' GROUP BY auid`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n, addrs string
		var c, r, last int64
		if rows.Scan(&n, &c, &r, &addrs, &last) == nil {
			u := get(n)
			u.Sessions, u.RemoteSessions = c, r
			u.LastTS = max(u.LastTS, last)
			if addrs != "" {
				u.Addrs = strings.Split(addrs, ",")
			}
		}
	}
	rows.Close()
	out := make([]UserRow, 0, len(byName))
	for _, u := range byName {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastTS > out[j].LastTS })
	return out, nil
}

// ---------------------------------------------------------------------------

type AuthRow struct {
	ID, TS                               int64
	Type, Op, Acct, Auid, Addr, Hostname string
	Terminal, Exe                        string
	Success                              bool
}

type SourceRow struct {
	Addr, Hostname     string
	Users, FailedAccts []string
	Sessions, Failures int64
	FirstTS, LastTS    int64
}

type OutboundRow struct {
	Target        string
	Tools, Users  []string
	Count, LastTS int64
}

type Connections struct {
	Sources  []SourceRow
	Auth     []AuthRow
	Outbound []OutboundRow
	Recent   []ExecRow
}

func (s *store) connections(since int64, failedOnly, remoteOnly bool) (*Connections, error) {
	c := &Connections{}
	bySrc := map[string]*SourceRow{}
	src := func(addr string) *SourceRow {
		if bySrc[addr] == nil {
			bySrc[addr] = &SourceRow{Addr: addr}
		}
		return bySrc[addr]
	}
	rows, err := s.ro.Query(`SELECT addr, MAX(hostname), GROUP_CONCAT(DISTINCT auid), COUNT(*), MIN(start_ts), MAX(start_ts)
		FROM sessions WHERE addr != '' AND start_ts >= ? GROUP BY addr`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var addr, host, users string
		var n, first, last int64
		if rows.Scan(&addr, &host, &users, &n, &first, &last) == nil {
			r := src(addr)
			r.Hostname, r.Sessions, r.FirstTS, r.LastTS = host, n, first, last
			r.Users = strings.Split(users, ",")
		}
	}
	rows.Close()
	rows, err = s.ro.Query(`SELECT addr, COUNT(*), GROUP_CONCAT(DISTINCT acct), MIN(ts), MAX(ts)
		FROM auth WHERE addr != '' AND success = 0 AND ts >= ? GROUP BY addr`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var addr, accts string
		var n, first, last int64
		if rows.Scan(&addr, &n, &accts, &first, &last) == nil {
			r := src(addr)
			r.Failures, r.FailedAccts = n, strings.Split(accts, ",")
			if r.FirstTS == 0 || first < r.FirstTS {
				r.FirstTS = first
			}
			r.LastTS = max(r.LastTS, last)
		}
	}
	rows.Close()
	for _, r := range bySrc {
		c.Sources = append(c.Sources, *r)
	}
	sort.Slice(c.Sources, func(i, j int) bool { return c.Sources[i].LastTS > c.Sources[j].LastTS })

	where := []string{"ts >= ?"}
	args := []any{since}
	if failedOnly {
		where = append(where, "success = 0")
	}
	if remoteOnly {
		where = append(where, "addr != ''")
	}
	rows, err = s.ro.Query(`SELECT id, ts, type, op, acct, auid, addr, hostname, terminal, exe, success FROM auth
		WHERE `+strings.Join(where, " AND ")+` ORDER BY ts DESC LIMIT 300`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r AuthRow
		if rows.Scan(&r.ID, &r.TS, &r.Type, &r.Op, &r.Acct, &r.Auid, &r.Addr, &r.Hostname, &r.Terminal, &r.Exe, &r.Success) == nil {
			c.Auth = append(c.Auth, r)
		}
	}
	rows.Close()

	if c.Recent, err = s.execs(ExecFilter{Since: since, Key: "@network", Limit: 2000}); err != nil {
		return nil, err
	}
	byTarget := map[string]*OutboundRow{}
	for _, e := range c.Recent {
		for _, t := range targets(e.Argv) {
			o := byTarget[t]
			if o == nil {
				o = &OutboundRow{Target: t}
				byTarget[t] = o
			}
			o.Count++
			o.LastTS = max(o.LastTS, e.TS)
			o.Tools = addUnique(o.Tools, path.Base(e.Exe))
			o.Users = addUnique(o.Users, e.Auid)
		}
	}
	for _, o := range byTarget {
		c.Outbound = append(c.Outbound, *o)
	}
	sort.Slice(c.Outbound, func(i, j int) bool { return c.Outbound[i].LastTS > c.Outbound[j].LastTS })
	if len(c.Recent) > 200 {
		c.Recent = c.Recent[:200]
	}
	return c, nil
}

func addUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// sshArgOpts are ssh/scp/sftp options that take a value.
const sshArgOpts = "BbcDEeFIiJLlmOoPpQRSWw"

// targets extracts remote hosts from a network command line (best effort).
func targets(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	tool := path.Base(argv[0])
	var out []string
	add := func(h string) {
		h = strings.Trim(h, "[]")
		if h != "" {
			out = addUnique(out, h)
		}
	}
	skipNext := false
	for _, a := range argv[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			if (tool == "ssh" || tool == "scp" || tool == "sftp") && len(a) == 2 && strings.ContainsRune(sshArgOpts, rune(a[1])) {
				skipNext = true
			}
			continue
		}
		if u, err := url.Parse(a); err == nil && u.Scheme != "" && u.Host != "" {
			add(u.Hostname())
			continue
		}
		switch tool {
		case "curl", "wget":
			continue // only URLs are reliable targets
		case "socat", "socat1":
			// e.g. TCP:host:port, TCP4-LISTEN:port, OPENSSL:host:port
			parts := strings.Split(a, ":")
			if len(parts) >= 3 && !strings.Contains(strings.ToUpper(parts[0]), "LISTEN") {
				add(parts[1])
			}
			continue
		}
		if at := strings.LastIndex(a, "@"); at > 0 && !strings.Contains(a[:at], "/") {
			add(hostPart(a[at+1:]))
		} else if i := strings.Index(a, ":"); i > 0 && (tool == "scp" || tool == "rsync") && !strings.Contains(a[:i], "/") {
			add(hostPart(a))
		} else if tool == "ssh" || tool == "sftp" || (!fileArgsTool[tool] && looksLikeHost(a)) {
			add(a)
		}
		if tool == "ssh" {
			break // the rest is the remote command
		}
	}
	return out
}

// For these tools a bare argument is a local file, never a host.
var fileArgsTool = map[string]bool{"scp": true, "rsync": true, "curl": true, "wget": true}

// hostPart strips a ":path" or ":port" suffix, handling [ipv6] literals.
func hostPart(s string) string {
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			return s[1:i]
		}
	}
	if i := strings.Index(s, ":"); i >= 0 {
		return s[:i]
	}
	return s
}

func looksLikeHost(a string) bool {
	if net.ParseIP(strings.Trim(a, "[]")) != nil {
		return true
	}
	if strings.ContainsAny(a, "/ =") || !strings.Contains(a, ".") {
		return false
	}
	for _, r := range a {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------

type DataInfo struct {
	Path                             string
	Size                             int64
	Execs, Sessions, Auth, Changes   int64
	OldestTS, NewestTS, CheckpointTS int64
}

func (s *store) dataInfo() DataInfo {
	return DataInfo{
		Path:         s.path,
		Size:         s.size(),
		Execs:        s.count(`SELECT COUNT(*) FROM execs`),
		Sessions:     s.count(`SELECT COUNT(*) FROM sessions`),
		Auth:         s.count(`SELECT COUNT(*) FROM auth`),
		Changes:      s.count(`SELECT COUNT(*) FROM changes`),
		OldestTS:     s.count(`SELECT COALESCE(MIN(m), 0) FROM (SELECT MIN(ts) AS m FROM execs UNION ALL SELECT MIN(ts) FROM auth UNION ALL SELECT MIN(ts) FROM changes)`),
		NewestTS:     s.count(`SELECT COALESCE(MAX(m), 0) FROM (SELECT MAX(ts) AS m FROM execs UNION ALL SELECT MAX(ts) FROM auth UNION ALL SELECT MAX(ts) FROM changes)`),
		CheckpointTS: s.checkpoint(),
	}
}
