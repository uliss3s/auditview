package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const fixtureBase = int64(1790860000) * 1000

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/audit.log.in")
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(b, []byte("<GS>"), []byte{0x1d})
}

func TestParseRecord(t *testing.T) {
	line := []byte(`type=USER_START msg=audit(1790860005.050:5013): pid=40000 uid=0 auid=1000 ses=7 subj=? msg='op=PAM:session_open acct="alice" exe="/usr/lib/ssh/sshd-session" hostname=198.51.100.7 addr=198.51.100.7 terminal=ssh res=success'` + "\x1d" + `UID="root" AUID="alice"`)
	r, ok := parseRecord(line)
	if !ok {
		t.Fatal("not parsed")
	}
	if r.Type != "USER_START" || r.TS != 1790860005050 || r.Serial != 5013 {
		t.Fatalf("header: %+v", r)
	}
	checks := [][2]string{
		{r.Str("addr"), "198.51.100.7"},
		{r.Str("op"), "PAM:session_open"},
		{r.Text("exe"), "/usr/lib/ssh/sshd-session"},
		{r.Name("auid"), "alice"},
		{r.Name("uid"), "root"},
		{r.Str("ses"), "7"},
		{r.Str("res"), "success"},
		{r.Text("acct"), "alice"},
		{r.Str("terminal"), "ssh"},
	}
	for i, c := range checks {
		if c[0] != c[1] {
			t.Errorf("check %d: got %q, want %q", i, c[0], c[1])
		}
	}
}

func TestDecodeAndQuote(t *testing.T) {
	if got := decodeValue("6563686F206869"); got != "echo hi" {
		t.Errorf("hex: %q", got)
	}
	if got := decodeValue(`"plain"`); got != "plain" {
		t.Errorf("quoted: %q", got)
	}
	if got := shellJoin([]string{"bash", "-c", `echo "hi"; id`, "it's"}); got != `bash -c 'echo "hi"; id' 'it'\''s'` {
		t.Errorf("shellJoin: %s", got)
	}
	if got := cleanText("a\x1b[31mb\nc\xff"); got != `a\x1b[31mb\nc\xff` {
		t.Errorf("cleanText: %q", got)
	}
}

func TestTargets(t *testing.T) {
	cases := []struct {
		argv []string
		want []string
	}{
		{[]string{"curl", "-o", "out.json", "https://example.com/api?x=1"}, []string{"example.com"}},
		{[]string{"ssh", "-p", "2222", "admin@192.168.1.50", "uptime", "other.host"}, []string{"192.168.1.50"}},
		{[]string{"ssh", "-i", "key.pem", "server.lan"}, []string{"server.lan"}},
		{[]string{"scp", "notes.txt", "backup.lan:/srv/"}, []string{"backup.lan"}},
		{[]string{"rsync", "-a", "./dir/", "user@[fe80::1]:/x"}, []string{"fe80::1"}},
		{[]string{"socat1", "-", "TCP:10.0.0.5:443"}, []string{"10.0.0.5"}},
		{[]string{"nmap", "-sV", "10.0.0.0/24", "scanme.nmap.org"}, []string{"scanme.nmap.org"}},
		{[]string{"wget", "-O", "file.tar.gz", "http://mirror.local/f.tgz"}, []string{"mirror.local"}},
	}
	for _, c := range cases {
		if got := targets(c.argv); !reflect.DeepEqual(got, c.want) {
			t.Errorf("targets(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

func TestAssemblerOrder(t *testing.T) {
	var got []uint64
	a := newAssembler(func(ev *Event) { got = append(got, ev.Serial) })
	rec := func(typ string, ts int64, serial uint64) *Record {
		return &Record{Type: typ, TS: ts, Serial: serial, Fields: map[string]string{}}
	}
	a.add(rec("LOGIN", 1000, 1))      // kernel record without EOE
	a.add(rec("USER_START", 1010, 2)) // standalone, must wait for LOGIN
	a.add(rec("SYSCALL", 1020, 3))
	a.add(rec("EXECVE", 1020, 3))
	if len(got) != 0 {
		t.Fatalf("emitted too early: %v", got)
	}
	a.add(rec("EOE", 1020, 3))
	a.add(rec("USER_END", 5000, 4)) // 2s later: LOGIN is complete
	if want := []uint64{1, 2, 3, 4}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func openTestStore(t *testing.T) *store {
	t.Helper()
	st, err := openStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.close)
	return st
}

func TestIngestFixture(t *testing.T) {
	st := openTestStore(t)
	data := fixture(t)
	status := &Status{}
	ingest(bytes.NewReader(data), st, status, 0)
	if v := status.view(); v.Err != "" {
		t.Fatalf("ingest error: %s", v.Err)
	}

	// --- sessions
	ss, err := st.sessions(SessionFilter{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	bySes := map[int64][]SessionRow{}
	for _, s := range ss {
		bySes[s.Ses] = append(bySes[s.Ses], s)
	}
	if len(bySes[2]) != 1 || bySes[2][0].Kind() != "console" || bySes[2][0].Terminal != "/dev/tty1" {
		t.Errorf("console session: %+v", bySes[2])
	}
	if len(bySes[7]) != 2 {
		t.Fatalf("want 2 sessions with kernel id 7 (before and after reboot), got %+v", bySes[7])
	}
	after, ssh := bySes[7][0], bySes[7][1] // newest first
	if ssh.Addr != "198.51.100.7" || ssh.Kind() != "ssh" || ssh.Exe != "/usr/lib/ssh/sshd-session" || ssh.Partial {
		t.Errorf("ssh session: %+v", ssh)
	}
	if !ssh.EndTS.Valid || ssh.EndTS.Int64 != fixtureBase+120_000 {
		t.Errorf("ssh session must end at sshd's USER_END, not sudo's: %+v", ssh.EndTS)
	}
	if ssh.Commands != 10 || ssh.Privileged != 2 {
		t.Errorf("ssh session commands=%d privileged=%d", ssh.Commands, ssh.Privileged)
	}
	if !after.Partial || after.Addr != "" || after.Commands != 1 {
		t.Errorf("post-reboot session must be a separate partial session: %+v", after)
	}

	// --- commands
	ex, err := st.execs(ExecFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	cmd := map[string]ExecRow{}
	for _, e := range ex {
		cmd[e.Cmdline] = e
	}
	for _, want := range []string{
		"ls -la /tmp",
		`bash -c 'echo "hi there"; id'`,
		"printf helloworld",
		"sudo systemctl restart sshd",
		"curl -o out.json 'https://example.com/api?x=1'",
		"./does-not-exist",
		"cat /etc/hostname",
	} {
		if _, ok := cmd[want]; !ok {
			t.Errorf("missing command %q; have %v", want, keys(cmd))
		}
	}
	if e := cmd["./does-not-exist"]; e.Success {
		t.Error("failed exec recorded as success")
	}
	if e := cmd["id"]; e.Key != "root_exec" || e.EUID != "root" || e.Auid != "alice" || e.Addr != "198.51.100.7" {
		t.Errorf("root exec: %+v", e)
	}
	if len(ex) != 11 {
		t.Errorf("want 11 commands, got %d", len(ex))
	}

	// --- changes
	ch, err := st.changes(0, "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	summaries := map[string]string{}
	for _, c := range ch {
		summaries[c.Kind] = c.Summary
	}
	wantCh := map[string]string{
		"file":         "openat /etc/ssh/sshd_config.d/10-custom.conf",
		"kmod":         "finit_module: modprobe dummy",
		"audit_config": "op=add_rule key=exec list=4 res=1",
		"sudo":         "systemctl restart sshd   [pts/1]   cwd=/home/alice",
	}
	if !reflect.DeepEqual(summaries, wantCh) {
		t.Errorf("changes:\n got %v\nwant %v", summaries, wantCh)
	}

	// --- connections
	c, err := st.connections(0, false, false)
	if err != nil {
		t.Fatal(err)
	}
	src := map[string]SourceRow{}
	for _, s := range c.Sources {
		src[s.Addr] = s
	}
	if s := src["198.51.100.7"]; s.Sessions != 1 || s.Failures != 0 {
		t.Errorf("198.51.100.7: %+v", s)
	}
	if s := src["203.0.113.9"]; s.Sessions != 0 || s.Failures != 3 || len(s.FailedAccts) != 3 {
		t.Errorf("203.0.113.9: %+v", s)
	}
	var tg []string
	for _, o := range c.Outbound {
		tg = append(tg, o.Target)
	}
	if strings.Join(tg, ",") != "backup.lan,192.168.1.50,example.com" {
		t.Errorf("outbound targets: %v", tg)
	}

	// --- overview / users render without error
	if _, err := st.overview(0); err != nil {
		t.Fatal(err)
	}
	us, err := st.users(0)
	if err != nil || len(us) != 1 || us[0].Name != "alice" || us[0].RemoteSessions != 1 {
		t.Fatalf("users: %+v %v", us, err)
	}

	// --- re-importing the same data must not duplicate anything
	before := st.dataInfo()
	ingest(bytes.NewReader(data), st, &Status{}, 0)
	if after := st.dataInfo(); after.Execs != before.Execs || after.Sessions != before.Sessions || after.Auth != before.Auth || after.Changes != before.Changes {
		t.Errorf("re-import duplicated rows: before %+v after %+v", before, after)
	}

	// --- clearing keeps the checkpoint
	if err := st.clearAll(); err != nil {
		t.Fatal(err)
	}
	if info := st.dataInfo(); info.Execs+info.Sessions+info.Auth+info.Changes != 0 || info.CheckpointTS == 0 {
		t.Errorf("after clear: %+v", info)
	}
}

func keys(m map[string]ExecRow) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
