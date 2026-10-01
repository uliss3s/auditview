package main

import (
	"crypto/subtle"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/*.html static/*
var assets embed.FS

const cookieName = "auditview"

type server struct {
	st        *store
	status    *Status
	token     string
	csrf      string
	hosts     map[string]bool // accepted Host headers
	retention int
	pages     map[string]*template.Template
}

var ranges = []struct {
	Key   string
	Label string
	Dur   time.Duration
}{
	{"1h", "1 hour", time.Hour},
	{"24h", "24 hours", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour},
	{"365d", "1 year", 365 * 24 * time.Hour},
	{"all", "All", 0},
}

func newServer(st *store, status *Status, token, csrf string, port string, retention int) (*server, error) {
	s := &server{
		st: st, status: status, token: token, csrf: csrf, retention: retention,
		hosts: map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true, "[::1]:" + port: true},
		pages: map[string]*template.Template{},
	}
	funcs := template.FuncMap{
		"ts":      fmtTS,
		"ago":     ago,
		"dur":     dur,
		"base":    path.Base,
		"level":   keyLevel,
		"num":     fmtNum,
		"bytes":   fmtBytes,
		"join":    strings.Join,
		"qs":      url.QueryEscape,
		"default": func(d, v string) string { return map[bool]string{true: d, false: v}[v == ""] },
	}
	layout := template.Must(template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html"))
	names, _ := fs.Glob(assets, "templates/*.html")
	for _, n := range names {
		name := path.Base(n)
		if name == "layout.html" {
			continue
		}
		t, err := template.Must(layout.Clone()).ParseFS(assets, n)
		if err != nil {
			return nil, err
		}
		s.pages[strings.TrimSuffix(name, ".html")] = t
	}
	return s, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /{$}", s.overview)
	mux.HandleFunc("GET /commands", s.commands)
	mux.HandleFunc("GET /sessions", s.sessions)
	mux.HandleFunc("GET /sessions/{id}", s.sessionDetail)
	mux.HandleFunc("GET /users", s.users)
	mux.HandleFunc("GET /connections", s.connections)
	mux.HandleFunc("GET /changes", s.changes)
	mux.HandleFunc("GET /data", s.data)
	mux.HandleFunc("POST /data/clear", s.clear)
	return s.guard(mux)
}

// guard enforces: loopback Host header (blocks DNS rebinding), token login,
// and strict security headers. The UI uses no JavaScript at all.
func (s *server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hosts[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")

		if t := r.URL.Query().Get("token"); t != "" {
			if !equal(t, s.token) {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			q := r.URL.Query()
			q.Del("token")
			u := *r.URL
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.RequestURI(), http.StatusSeeOther)
			return
		}
		if c, err := r.Cookie(cookieName); err != nil || !equal(c.Value, s.token) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<!doctype html><title>auditview</title><p>Not signed in. Open the URL printed in the terminal where auditview is running.</p>")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------

type rangeLink struct {
	Key, Label, URL string
	Active          bool
}

type page struct {
	Title, Active string
	Status        StatusView
	Range         string
	RangeLabel    string
	Ranges        []rangeLink
	CSRF          string
	Refresh       bool
	Data          any
}

// since returns the start of the selected time range (ms; 0 = all).
func (s *server) since(r *http.Request) (string, int64) {
	key := r.URL.Query().Get("range")
	for _, rg := range ranges {
		if rg.Key == key {
			if rg.Dur == 0 {
				return key, 0
			}
			return key, time.Now().Add(-rg.Dur).UnixMilli()
		}
	}
	return "24h", time.Now().Add(-24 * time.Hour).UnixMilli()
}

func (s *server) render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	rk, _ := s.since(r)
	p := page{Title: title, Active: name, Status: s.status.view(), Range: rk, CSRF: s.csrf, Data: data}
	for _, rg := range ranges {
		q := r.URL.Query()
		q.Set("range", rg.Key)
		q.Del("page")
		p.Ranges = append(p.Ranges, rangeLink{rg.Key, rg.Label, r.URL.Path + "?" + q.Encode(), rg.Key == rk})
		if rg.Key == rk {
			p.RangeLabel = rg.Label
		}
	}
	p.Refresh = p.Status.State == "catching up"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages[name].ExecuteTemplate(w, "layout.html", p); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

func (s *server) fail(w http.ResponseWriter, err error) {
	log.Printf("query: %v", err)
	http.Error(w, "query failed: "+err.Error(), http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------

type chartBar struct {
	X, W, Y, H, PY, PH float64
	Title              string
}

type chartTick struct {
	X     float64
	Label string
}

type chart struct {
	Bars  []chartBar
	Ticks []chartTick
	Max   int64
}

const chartW, chartH = 1000.0, 180.0

func buildChart(buckets []Bucket, bucketMs int64) chart {
	c := chart{}
	if len(buckets) == 0 {
		return c
	}
	for _, b := range buckets {
		c.Max = max(c.Max, b.Total)
	}
	scale := 1.0
	if c.Max > 0 {
		scale = (chartH - 4) / float64(c.Max)
	}
	slot := chartW / float64(len(buckets))
	gap := math.Min(2, slot*0.2)
	format := "15:04"
	if bucketMs >= 24*3600_000 {
		format = "Jan 2"
	}
	every := max(1, len(buckets)/6)
	for i, b := range buckets {
		x := float64(i) * slot
		h := float64(b.Total) * scale
		ph := float64(b.Priv) * scale
		label := time.UnixMilli(b.TS).Format("2006-01-02 15:04")
		c.Bars = append(c.Bars, chartBar{
			X: x + gap/2, W: math.Max(slot-gap, 0.5), Y: chartH - h, H: h, PY: chartH - ph, PH: ph,
			Title: fmt.Sprintf("%s — %s commands, %s privileged", label, fmtNum(b.Total), fmtNum(b.Priv)),
		})
		if i%every == 0 {
			c.Ticks = append(c.Ticks, chartTick{x + slot/2, time.UnixMilli(b.TS).Format(format)})
		}
	}
	return c
}

func (s *server) overview(w http.ResponseWriter, r *http.Request) {
	_, since := s.since(r)
	o, err := s.st.overview(since)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "overview", "Overview", struct {
		*Overview
		Chart chart
	}{o, buildChart(o.Buckets, o.BucketMs)})
}

const pageSize = 200

func (s *server) commands(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	_, since := s.since(r)
	pg, _ := strconv.Atoi(q.Get("page"))
	pg = max(pg, 0)
	f := ExecFilter{
		Since: since, User: q.Get("user"), Key: q.Get("key"), Q: strings.TrimSpace(q.Get("q")),
		Failed: q.Get("failed") == "1", AsRoot: q.Get("root") == "1",
		Offset: pg * pageSize, Limit: pageSize + 1,
	}
	rows, err := s.st.execs(f)
	if err != nil {
		s.fail(w, err)
		return
	}
	more := len(rows) > pageSize
	if more {
		rows = rows[:pageSize]
	}
	link := func(p int) string {
		q2 := r.URL.Query()
		q2.Set("page", strconv.Itoa(p))
		return "/commands?" + q2.Encode()
	}
	data := struct {
		Rows        []ExecRow
		F           ExecFilter
		Users, Keys []string
		Prev, Next  string
		Page        int
		Range       string
	}{Rows: rows, F: f, Users: s.st.knownUsers(), Keys: s.st.knownKeys(), Page: pg + 1, Range: q.Get("range")}
	if pg > 0 {
		data.Prev = link(pg - 1)
	}
	if more {
		data.Next = link(pg + 1)
	}
	s.render(w, r, "commands", "Commands", data)
}

func (s *server) sessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	_, since := s.since(r)
	f := SessionFilter{Since: since, User: q.Get("user"), Addr: q.Get("addr"), RemoteOnly: q.Get("remote") == "1", WithCmds: q.Get("cmds") == "1"}
	rows, err := s.st.sessions(f, 300)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "sessions", "Sessions", struct {
		Rows  []SessionRow
		F     SessionFilter
		Users []string
		Range string
	}{rows, f, s.st.knownUsers(), q.Get("range")})
}

func (s *server) sessionDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sess, err := s.st.session(id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if sess == nil {
		http.NotFound(w, r)
		return
	}
	execs, err := s.st.execs(ExecFilter{Session: id, Limit: 5000})
	if err != nil {
		s.fail(w, err)
		return
	}
	changes, err := s.st.changes(0, "", id, 1000)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "session", fmt.Sprintf("Session %d", sess.Ses), struct {
		S       *SessionRow
		Execs   []ExecRow
		Changes []ChangeRow
	}{sess, execs, changes})
}

func (s *server) users(w http.ResponseWriter, r *http.Request) {
	_, since := s.since(r)
	rows, err := s.st.users(since)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "users", "Users", struct {
		Rows  []UserRow
		Range string
	}{rows, r.URL.Query().Get("range")})
}

func (s *server) connections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	_, since := s.since(r)
	failed, remote := q.Get("failed") == "1", q.Get("remote") == "1"
	c, err := s.st.connections(since, failed, remote)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "connections", "Connections", struct {
		*Connections
		Failed, Remote bool
		Range          string
	}{c, failed, remote, q.Get("range")})
}

func (s *server) changes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	_, since := s.since(r)
	kind := q.Get("kind")
	rows, err := s.st.changes(since, kind, 0, 500)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "changes", "Changes", struct {
		Rows  []ChangeRow
		Kind  string
		Kinds []string
		Range string
	}{rows, kind, []string{"file", "sudo", "kmod", "audit_config"}, q.Get("range")})
}

func (s *server) data(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "data", "Data", struct {
		Info      DataInfo
		Retention int
		Msg       string
	}{s.st.dataInfo(), s.retention, r.URL.Query().Get("msg")})
}

func (s *server) clear(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !equal(r.PostForm.Get("csrf"), s.csrf) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	var msg string
	switch r.PostForm.Get("mode") {
	case "older":
		days, err := strconv.Atoi(r.PostForm.Get("days"))
		if err != nil || days < 1 {
			http.Error(w, "days must be a positive number", http.StatusBadRequest)
			return
		}
		n, err := s.st.prune(time.Now().AddDate(0, 0, -days).UnixMilli())
		if err != nil {
			s.fail(w, err)
			return
		}
		msg = fmt.Sprintf("Deleted %s rows older than %d days.", fmtNum(n), days)
	case "all":
		if r.PostForm.Get("confirm") != "DELETE" {
			http.Error(w, `type DELETE to confirm`, http.StatusBadRequest)
			return
		}
		if err := s.st.clearAll(); err != nil {
			s.fail(w, err)
			return
		}
		msg = "All collected data was deleted. Audit logs in /var/log/audit were not touched."
	default:
		http.Error(w, "unknown mode", http.StatusBadRequest)
		return
	}
	if err := s.st.vacuum(); err != nil {
		log.Printf("vacuum: %v", err)
	}
	http.Redirect(w, r, "/data?msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

// ---------------------------------------------------------------------------

func fmtTS(ms int64) string {
	if ms == 0 {
		return "—"
	}
	return time.UnixMilli(ms).Format("2006-01-02 15:04:05")
}

func ago(ms int64) string {
	if ms == 0 {
		return "never"
	}
	d := time.Since(time.UnixMilli(ms))
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func dur(start, end int64) string {
	e := end
	if e == 0 {
		return "open"
	}
	d := time.Duration(e-start) * time.Millisecond
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func fmtNum(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func fmtBytes(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if f < 1024 || u == "GB" {
			if u == "B" {
				return fmt.Sprintf("%d B", n)
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return ""
}
