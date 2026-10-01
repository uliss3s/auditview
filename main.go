// auditview is a local, single-user web UI for Linux audit logs: who ran which
// commands, from which session and remote address.
//
// Run it with sudo. The process immediately splits in two:
//   - a reader child that keeps root only to read /var/log/audit (see reader.go)
//   - the main process, which drops to the invoking user before it opens the
//     database or the web server.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == readerCmd {
		os.Exit(runReader(os.Args[2:]))
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "auditview:", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:8765", "listen address; must be a loopback address")
	logDir := flag.String("log-dir", "/var/log/audit", "directory with audit.log and its rotations")
	dbPath := flag.String("db", "", "database file (default: ~/.local/share/auditview/audit.db of the target user)")
	userName := flag.String("user", "", "user to run as after startup (default: the user who ran sudo)")
	retention := flag.Int("retention-days", 365, "delete data older than this many days; 0 keeps everything")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sudo %s [flags]\n\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	host, port, err := net.SplitHostPort(*addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("refusing to listen on %s: only loopback addresses are allowed", *addr)
	}

	var target *user.User
	if os.Geteuid() == 0 {
		if target, err = targetUser(*userName); err != nil {
			return err
		}
	} else {
		log.Printf("not running as root: reading %s with the current user's permissions", *logDir)
	}

	// Start the reader while we still have root, then give root up for good.
	reader, err := startReader(*logDir)
	if err != nil {
		return err
	}
	if target != nil {
		if err := dropPrivileges(target); err != nil {
			reader.Process.Kill()
			return fmt.Errorf("dropping privileges: %w", err)
		}
	}

	if *dbPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		*dbPath = filepath.Join(home, ".local", "share", "auditview", "audit.db")
	}
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o700); err != nil {
		return err
	}
	st, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.close()

	if *retention > 0 {
		pruneOld(st, *retention)
	}

	// Resume from the checkpoint; re-read a minute before it to pick up events
	// that were still being assembled when we last stopped (duplicates are
	// ignored by the database).
	ckpt := st.checkpoint()
	minTS := int64(0)
	since := int64(0)
	if ckpt > 0 {
		minTS = ckpt - 60_000
		since = minTS/1000 - 60
	}
	if _, err := fmt.Fprintf(reader.stdin, "start %d\n", since); err != nil {
		return fmt.Errorf("log reader did not start: %w", err)
	}
	status := &Status{state: "starting"}
	ingestDone := make(chan struct{})
	go func() {
		ingest(reader.stdout, st, status, minTS)
		close(ingestDone)
	}()

	token, csrf := randomHex(24), randomHex(24)
	srv, err := newServer(st, status, token, csrf, port, *retention)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: srv.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http: %v", err)
		}
	}()

	who, _ := user.Current()
	if target != nil {
		fmt.Printf("auditview running as %s (only the log reader keeps root)\n", who.Username)
	} else {
		fmt.Printf("auditview running as %s\n", who.Username)
	}
	fmt.Printf("database: %s\n", *dbPath)
	fmt.Printf("\n  Open: http://%s/?token=%s\n\n", net.JoinHostPort(host, port), token)
	fmt.Println("Press Ctrl+C to stop.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-ticker.C:
			if *retention > 0 {
				pruneOld(st, *retention)
			}
		}
	}

	fmt.Println("\nstopping…")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
	reader.stdin.Close() // tells the reader to exit
	select {
	case <-ingestDone:
	case <-time.After(10 * time.Second):
		log.Print("timed out waiting for the log reader")
	}
	reader.Wait()
	return nil
}

func pruneOld(st *store, days int) {
	n, err := st.prune(time.Now().AddDate(0, 0, -days).UnixMilli())
	if err != nil {
		log.Printf("retention: %v", err)
	} else if n > 0 {
		log.Printf("retention: deleted %d rows older than %d days", n, days)
	}
}

// targetUser picks the unprivileged account to switch to.
func targetUser(name string) (*user.User, error) {
	var u *user.User
	var err error
	switch {
	case name != "":
		u, err = user.Lookup(name)
	case os.Getenv("SUDO_UID") != "":
		u, err = user.LookupId(os.Getenv("SUDO_UID"))
	default:
		return nil, errors.New("run auditview with sudo from your normal account, or pass -user NAME")
	}
	if err != nil {
		return nil, err
	}
	if u.Uid == "0" {
		return nil, errors.New("refusing to keep running as root; pass -user NAME")
	}
	return u, nil
}

type readerProc struct {
	*exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func startReader(logDir string) (*readerProc, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, readerCmd, "-log-dir", logDir)
	cmd.Stderr = os.Stderr
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	// If we die without closing its stdin, the kernel stops the reader too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting log reader: %w", err)
	}
	return &readerProc{cmd, stdin, stdout}, nil
}

// dropPrivileges switches the whole process (all threads) to u, irreversibly.
func dropPrivileges(u *user.User) error {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	groupIDs, err := u.GroupIds()
	if err != nil {
		return err
	}
	groups := make([]int, 0, len(groupIDs))
	for _, g := range groupIDs {
		if n, err := strconv.Atoi(g); err == nil {
			groups = append(groups, n)
		}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	if syscall.Setuid(0) == nil || os.Geteuid() == 0 {
		return errors.New("root privileges could still be regained")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	os.Setenv("HOME", u.HomeDir)
	os.Setenv("USER", u.Username)
	os.Setenv("LOGNAME", u.Username)
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
