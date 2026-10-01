package main

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

// unsetID is the value the kernel uses for "no login uid / no session".
const unsetID = "4294967295"

// Record is one line of audit.log.
type Record struct {
	Type   string
	TS     int64 // milliseconds since epoch
	Serial uint64
	// Fields holds raw values as written by the kernel/auditd, quotes included,
	// so callers can tell literal ("...") values from hex-encoded ones.
	Fields map[string]string
	// Enriched holds the uppercase fields auditd appends after 0x1d when
	// log_format=ENRICHED (resolved user names, syscall names, ...).
	Enriched map[string]string
}

// parseHeader extracts type, timestamp and serial without parsing the body,
// so lines that are going to be skipped stay cheap.
func parseHeader(line []byte) (typ string, ts int64, serial uint64, body []byte, ok bool) {
	// Optional "node=<name> " prefix when auditd name_format is set.
	if bytes.HasPrefix(line, []byte("node=")) {
		i := bytes.IndexByte(line, ' ')
		if i < 0 {
			return
		}
		line = line[i+1:]
	}
	if !bytes.HasPrefix(line, []byte("type=")) {
		return
	}
	line = line[len("type="):]
	sp := bytes.IndexByte(line, ' ')
	if sp < 0 {
		return
	}
	typ = string(line[:sp])
	line = line[sp+1:]
	if !bytes.HasPrefix(line, []byte("msg=audit(")) {
		return
	}
	line = line[len("msg=audit("):]
	end := bytes.IndexByte(line, ')')
	if end < 0 {
		return
	}
	stamp := line[:end]
	colon := bytes.IndexByte(stamp, ':')
	if colon < 0 {
		return
	}
	sec, msec, found := bytes.Cut(stamp[:colon], []byte("."))
	s, err := strconv.ParseInt(string(sec), 10, 64)
	if err != nil {
		return
	}
	var ms int64
	if found {
		if ms, err = strconv.ParseInt(string(msec), 10, 64); err != nil {
			return
		}
	}
	serial, err = strconv.ParseUint(string(stamp[colon+1:]), 10, 64)
	if err != nil {
		return
	}
	body = bytes.TrimLeft(bytes.TrimPrefix(line[end+1:], []byte(":")), " ")
	body = bytes.TrimRight(body, "\r\n")
	return typ, s*1000 + ms, serial, body, true
}

// parseRecord parses a full audit.log line.
func parseRecord(line []byte) (*Record, bool) {
	typ, ts, serial, body, ok := parseHeader(line)
	if !ok {
		return nil, false
	}
	r := &Record{Type: typ, TS: ts, Serial: serial, Fields: map[string]string{}}
	raw, enriched, hasEnriched := bytes.Cut(body, []byte{0x1d})
	parseFields(string(raw), r.Fields)
	// User-space messages carry their payload in msg='...'; flatten it.
	if m, ok := r.Fields["msg"]; ok && len(m) >= 2 && m[0] == '\'' {
		inner := map[string]string{}
		parseFields(strings.Trim(m, "'"), inner)
		for k, v := range inner {
			if _, exists := r.Fields[k]; !exists {
				r.Fields[k] = v
			}
		}
	}
	if hasEnriched {
		r.Enriched = map[string]string{}
		parseFields(string(enriched), r.Enriched)
	}
	return r, true
}

// parseFields splits `k=v k="v w" k='v w'` into the map, keeping quotes.
func parseFields(s string, into map[string]string) {
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] == ' ' {
			continue // token without '=', ignore
		}
		key := s[start:i]
		i++ // '='
		vstart := i
		if i < len(s) && (s[i] == '"' || s[i] == '\'') {
			q := s[i]
			j := strings.IndexByte(s[i+1:], q)
			if j < 0 {
				i = len(s)
			} else {
				i += j + 2
			}
		} else {
			for i < len(s) && s[i] != ' ' {
				i++
			}
		}
		if key != "" {
			into[key] = s[vstart:i]
		}
	}
}

// Str returns a field with surrounding quotes removed.
func (r *Record) Str(k string) string {
	return unquote(r.Fields[k])
}

// Text returns a field that the kernel may hex-encode (exe, comm, cwd, name, ...).
func (r *Record) Text(k string) string {
	return decodeValue(r.Fields[k])
}

// Name returns the resolved user name for an id field (auid, uid, euid, acct id),
// preferring the ENRICHED value written by auditd.
func (r *Record) Name(k string) string {
	if v, ok := r.Enriched[strings.ToUpper(k)]; ok {
		return unquote(v)
	}
	v := r.Str(k)
	if v == unsetID || v == "-1" {
		return "unset"
	}
	return lookupUserName(v)
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// decodeValue handles the kernel's encoding of untrusted strings: quoted means
// literal, unquoted means hex (used when the value has spaces, quotes or
// control characters).
func decodeValue(v string) string {
	if v == "" || v == "(null)" || v == "?" {
		return ""
	}
	if v[0] == '"' || v[0] == '\'' {
		return unquote(v)
	}
	if b, ok := decodeHex(v); ok {
		return b
	}
	return v
}

func decodeHex(v string) (string, bool) {
	if len(v)%2 != 0 {
		return "", false
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// cleanText makes a decoded value safe to display on one line: invalid UTF-8
// and control characters are replaced by visible escapes.
func cleanText(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == utf8.RuneError }) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			b.WriteString(`\x` + strconv.FormatUint(uint64(s[i]), 16))
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\x` + strconv.FormatUint(uint64(r), 16))
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// shellJoin renders argv the way it would be typed in a shell.
func shellJoin(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = shellQuote(cleanText(a))
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_@%+=:,./-~^", r) || r > 0x7f) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Event is the set of records sharing one msg=audit(ts:serial) id.
type Event struct {
	TS      int64
	Serial  uint64
	Records []*Record
}

func (e *Event) First(typ string) *Record {
	for _, r := range e.Records {
		if r.Type == typ {
			return r
		}
	}
	return nil
}

func (e *Event) All(typ string) []*Record {
	var out []*Record
	for _, r := range e.Records {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

type eventID struct {
	ts     int64
	serial uint64
}

// assembler groups records into events and emits them in arrival order.
// Kernel syscall events end with an EOE record; user-space messages (USER_*,
// CRED_*, ...) are always single records. Anything else is considered complete
// once records 2s newer show up or the input goes idle. Order matters: a
// session's LOGIN must be processed before the USER_START that describes it.
type assembler struct {
	queue []*pendingEvent
	index map[eventID]*pendingEvent
	emit  func(*Event)
}

type pendingEvent struct {
	ev   *Event
	done bool
}

const maxPending = 10000

func newAssembler(emit func(*Event)) *assembler {
	return &assembler{index: map[eventID]*pendingEvent{}, emit: emit}
}

func standaloneType(t string) bool {
	for _, p := range []string{"USER_", "CRED_", "SERVICE_", "DAEMON_", "SYSTEM_", "ANOM_LOGIN", "GRP_", "ADD_", "DEL_", "ROLE_"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func (a *assembler) add(r *Record) {
	id := eventID{r.TS, r.Serial}
	p := a.index[id]
	if r.Type == "EOE" {
		if p != nil {
			p.done = true
		}
		a.drain()
		return
	}
	if p == nil {
		p = &pendingEvent{ev: &Event{TS: r.TS, Serial: r.Serial}, done: standaloneType(r.Type)}
		a.queue = append(a.queue, p)
		a.index[id] = p
	}
	p.ev.Records = append(p.ev.Records, r)
	for _, q := range a.queue {
		if !q.done && q.ev.TS < r.TS-2000 {
			q.done = true
		}
	}
	if len(a.queue) > maxPending {
		a.queue[0].done = true
	}
	a.drain()
}

func (a *assembler) drain() {
	n := 0
	for n < len(a.queue) && a.queue[n].done {
		ev := a.queue[n].ev
		delete(a.index, eventID{ev.TS, ev.Serial})
		a.emit(ev)
		n++
	}
	if n > 0 {
		a.queue = append(a.queue[:0], a.queue[n:]...)
	}
}

func (a *assembler) flushAll() {
	for _, q := range a.queue {
		q.done = true
	}
	a.drain()
}
