package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);

-- One row per login session (kernel LOGIN record), enriched with where it came
-- from by the PAM USER_START/USER_LOGIN records of the same session id.
CREATE TABLE IF NOT EXISTS sessions (
	id           INTEGER PRIMARY KEY,
	ses          INTEGER NOT NULL,
	auid         TEXT NOT NULL DEFAULT '',
	start_ts     INTEGER NOT NULL,
	start_serial INTEGER NOT NULL,
	end_ts       INTEGER,
	addr         TEXT NOT NULL DEFAULT '',
	hostname     TEXT NOT NULL DEFAULT '',
	terminal     TEXT NOT NULL DEFAULT '',
	exe          TEXT NOT NULL DEFAULT '',
	-- 1 when the login happened before the data we have; origin unknown.
	partial      INTEGER NOT NULL DEFAULT 0,
	UNIQUE (start_ts, start_serial)
);
CREATE INDEX IF NOT EXISTS sessions_ses ON sessions (ses, start_ts);
CREATE INDEX IF NOT EXISTS sessions_start ON sessions (start_ts);
CREATE INDEX IF NOT EXISTS sessions_addr ON sessions (addr, start_ts);

CREATE TABLE IF NOT EXISTS execs (
	id         INTEGER PRIMARY KEY,
	ts         INTEGER NOT NULL,
	serial     INTEGER NOT NULL,
	key        TEXT NOT NULL DEFAULT '',
	auid       TEXT NOT NULL DEFAULT '',
	uid        TEXT NOT NULL DEFAULT '',
	euid       TEXT NOT NULL DEFAULT '',
	ses        INTEGER,
	session_id INTEGER,
	tty        TEXT NOT NULL DEFAULT '',
	pid        INTEGER,
	ppid       INTEGER,
	exe        TEXT NOT NULL DEFAULT '',
	cwd        TEXT NOT NULL DEFAULT '',
	cmdline    TEXT NOT NULL DEFAULT '',
	argv       TEXT NOT NULL DEFAULT '[]',
	success    INTEGER NOT NULL,
	UNIQUE (ts, serial)
);
CREATE INDEX IF NOT EXISTS execs_ts ON execs (ts);
CREATE INDEX IF NOT EXISTS execs_auid ON execs (auid, ts);
CREATE INDEX IF NOT EXISTS execs_key ON execs (key, ts);
CREATE INDEX IF NOT EXISTS execs_session ON execs (session_id);

-- Authentication / account events (PAM), local and remote.
CREATE TABLE IF NOT EXISTS auth (
	id       INTEGER PRIMARY KEY,
	ts       INTEGER NOT NULL,
	serial   INTEGER NOT NULL,
	type     TEXT NOT NULL,
	op       TEXT NOT NULL DEFAULT '',
	acct     TEXT NOT NULL DEFAULT '',
	auid     TEXT NOT NULL DEFAULT '',
	ses      INTEGER,
	addr     TEXT NOT NULL DEFAULT '',
	hostname TEXT NOT NULL DEFAULT '',
	terminal TEXT NOT NULL DEFAULT '',
	exe      TEXT NOT NULL DEFAULT '',
	success  INTEGER NOT NULL,
	UNIQUE (ts, serial)
);
CREATE INDEX IF NOT EXISTS auth_ts ON auth (ts);
CREATE INDEX IF NOT EXISTS auth_addr ON auth (addr, ts);

-- Watched file changes, kernel module operations, audit config changes and
-- sudo command records.
CREATE TABLE IF NOT EXISTS changes (
	id         INTEGER PRIMARY KEY,
	ts         INTEGER NOT NULL,
	serial     INTEGER NOT NULL,
	kind       TEXT NOT NULL,
	key        TEXT NOT NULL DEFAULT '',
	auid       TEXT NOT NULL DEFAULT '',
	uid        TEXT NOT NULL DEFAULT '',
	ses        INTEGER,
	session_id INTEGER,
	exe        TEXT NOT NULL DEFAULT '',
	summary    TEXT NOT NULL DEFAULT '',
	success    INTEGER NOT NULL,
	UNIQUE (ts, serial)
);
CREATE INDEX IF NOT EXISTS changes_ts ON changes (ts);
CREATE INDEX IF NOT EXISTS changes_kind ON changes (kind, ts);
`

type store struct {
	path string
	rw   *sql.DB // single writer connection
	ro   *sql.DB // read-only pool for the web UI

	// mu serialises writers (ingest, retention, clear) and guards the
	// session cache below.
	mu         sync.Mutex
	sesCache   map[int64]int64 // kernel session id -> sessions.id, current boot
	bootTS     int64           // start of the current boot, as seen in the log
	ckptTS     int64           // newest event stored (ms)
	lastSerial uint64
	lastTS     int64
}

func openStore(path string) (*store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(OFF)"
	rw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	rw.SetMaxOpenConns(1)
	if _, err := rw.Exec(schema); err != nil {
		rw.Close()
		return nil, fmt.Errorf("init database: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		rw.Close()
		return nil, err
	}
	ro, err := sql.Open("sqlite", dsn+"&_pragma=query_only(1)")
	if err != nil {
		rw.Close()
		return nil, err
	}
	ro.SetMaxOpenConns(4)
	s := &store{path: path, rw: rw, ro: ro, sesCache: map[int64]int64{}}
	s.bootTS, _ = strconv.ParseInt(s.meta("boot_ts"), 10, 64)
	s.ckptTS, _ = strconv.ParseInt(s.meta("checkpoint_ts"), 10, 64)
	return s, nil
}

func (s *store) close() {
	s.ro.Close()
	s.rw.Close()
}

func (s *store) meta(k string) string {
	var v string
	s.rw.QueryRow(`SELECT v FROM meta WHERE k = ?`, k).Scan(&v)
	return v
}

func setMeta(tx *sql.Tx, k, v string) error {
	_, err := tx.Exec(`INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

// checkpoint is the timestamp (ms) of the newest event stored.
func (s *store) checkpoint() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ckptTS
}

// ingest stores a batch of events in one transaction.
func (s *store) ingest(events []*Event) error {
	if len(events) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.rw.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	bootBefore := s.bootTS
	committed := false
	defer func() {
		if !committed { // the cache may point at rolled-back rows
			clear(s.sesCache)
			s.bootTS = bootBefore
		}
	}()
	var newest int64
	for _, ev := range events {
		if err := s.apply(tx, ev); err != nil {
			return fmt.Errorf("event %d:%d: %w", ev.TS, ev.Serial, err)
		}
		newest = max(newest, ev.TS)
	}
	ckpt := max(s.ckptTS, newest)
	if ckpt != s.ckptTS {
		if err := setMeta(tx, "checkpoint_ts", strconv.FormatInt(ckpt, 10)); err != nil {
			return err
		}
	}
	if s.bootTS != bootBefore {
		if err := setMeta(tx, "boot_ts", strconv.FormatInt(s.bootTS, 10)); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	s.ckptTS = ckpt
	return nil
}

// noteBoot tracks reboots so that kernel session ids, which restart from 1
// after every boot, are never matched against a previous boot's sessions.
func (s *store) noteBoot(ev *Event) {
	reboot := ev.First("SYSTEM_BOOT") != nil
	// The kernel's event serial also restarts at boot.
	if s.lastSerial > 1000 && ev.Serial < s.lastSerial/2 && ev.TS >= s.lastTS {
		reboot = true
	}
	if reboot && ev.TS > s.bootTS {
		s.bootTS = ev.TS
		clear(s.sesCache)
	}
	if ev.TS >= s.lastTS {
		s.lastTS, s.lastSerial = ev.TS, ev.Serial
	}
}

// sessionFor returns the sessions.id for a kernel session id at time ts. If
// the session's login is not in our data, a partial session is created so
// commands still group together.
func (s *store) sessionFor(tx *sql.Tx, ses int64, ts int64, serial uint64, auid string) (int64, error) {
	if id, ok := s.sesCache[ses]; ok {
		return id, nil
	}
	var id int64
	err := tx.QueryRow(`SELECT id FROM sessions WHERE ses = ? AND start_ts >= ? AND start_ts <= ? ORDER BY start_ts DESC LIMIT 1`,
		ses, s.bootTS, ts).Scan(&id)
	if err == sql.ErrNoRows {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO sessions (ses, auid, start_ts, start_serial, partial) VALUES (?, ?, ?, ?, 1)`,
			ses, auid, ts, serial); err != nil {
			return 0, err
		}
		err = tx.QueryRow(`SELECT id FROM sessions WHERE start_ts = ? AND start_serial = ?`, ts, serial).Scan(&id)
	}
	if err != nil {
		return 0, err
	}
	s.sesCache[ses] = id
	return id, nil
}

func (s *store) newSession(tx *sql.Tx, ev *Event, ses int64, auid string) error {
	if _, err := tx.Exec(`INSERT OR IGNORE INTO sessions (ses, auid, start_ts, start_serial) VALUES (?, ?, ?, ?)`,
		ses, auid, ev.TS, ev.Serial); err != nil {
		return err
	}
	var id int64
	if err := tx.QueryRow(`SELECT id FROM sessions WHERE start_ts = ? AND start_serial = ?`, ev.TS, ev.Serial).Scan(&id); err != nil {
		return err
	}
	s.sesCache[ses] = id
	return nil
}

// prune deletes data older than cutoff (ms). Session rows go once nothing in
// the retained data refers to them.
func (s *store) prune(cutoff int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.rw.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var total int64
	for _, q := range []string{
		`DELETE FROM execs WHERE ts < ?`,
		`DELETE FROM auth WHERE ts < ?`,
		`DELETE FROM changes WHERE ts < ?`,
		`DELETE FROM sessions WHERE COALESCE(end_ts, start_ts) < ?
			AND id NOT IN (SELECT session_id FROM execs WHERE session_id IS NOT NULL)
			AND id NOT IN (SELECT session_id FROM changes WHERE session_id IS NOT NULL)`,
	} {
		res, err := tx.Exec(q, cutoff)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	clear(s.sesCache)
	return total, nil
}

// clearAll deletes all collected data but keeps the checkpoint, so the logs
// are not imported again.
func (s *store) clearAll() error {
	_, err := s.prune(time.Now().Add(24 * time.Hour).UnixMilli())
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.rw.Exec(`DELETE FROM sessions`)
	return err
}

func (s *store) vacuum() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.rw.Exec(`VACUUM`)
	return err
}

func (s *store) size() int64 {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if st, err := os.Stat(s.path + suffix); err == nil {
			total += st.Size()
		}
	}
	return total
}
