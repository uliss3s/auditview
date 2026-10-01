package main

// The reader is the only part of auditview that keeps root privileges. It is
// the same binary re-executed with readerCmd before the main process drops to
// the invoking user. It deliberately does nothing but find the audit log files
// and copy their lines to stdout: no parsing (log content includes
// user-controlled command lines), no network, no database.
//
// Protocol: the parent writes one line "start <unix-seconds>" to stdin; rotated
// files last modified before that time are skipped. The reader then streams
// raw audit lines, followed by control lines starting with '#':
//
//	#caughtup        all existing data has been sent; now following new lines
//	#error <text>    fatal error, the reader exits
//
// The reader exits when its stdin is closed or its parent goes away.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const readerCmd = "__reader"

var rotatedName = regexp.MustCompile(`^audit\.log\.(\d+)$`)

func runReader(args []string) int {
	logDir := "/var/log/audit"
	if len(args) == 2 && args[0] == "-log-dir" {
		logDir = args[1]
	}
	// Ctrl+C reaches the whole process group; let the parent decide when to
	// stop us (by closing stdin) so no line is cut in half.
	signal.Ignore(syscall.SIGINT)

	in := bufio.NewReader(os.Stdin)
	first, err := in.ReadString('\n')
	if err != nil {
		return 1
	}
	var since int64
	if _, err := fmt.Sscanf(first, "start %d", &since); err != nil {
		return 1
	}
	go func() {
		io.Copy(io.Discard, in)
		os.Exit(0)
	}()

	out := bufio.NewWriterSize(os.Stdout, 1<<16)
	if err := follow(logDir, since, out); err != nil {
		fmt.Fprintf(out, "#error %s\n", strings.ReplaceAll(err.Error(), "\n", " "))
		out.Flush()
		return 1
	}
	return 0
}

// rotatedLogs returns audit.log.N files, oldest (highest N) first.
func rotatedLogs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type numbered struct {
		n    int
		path string
	}
	var files []numbered
	for _, e := range entries {
		if m := rotatedName.FindStringSubmatch(e.Name()); m != nil && e.Type().IsRegular() {
			n, _ := strconv.Atoi(m[1])
			files = append(files, numbered{n, filepath.Join(dir, e.Name())})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].n > files[j].n })
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.path
	}
	return paths, nil
}

func follow(dir string, since int64, out *bufio.Writer) error {
	active := filepath.Join(dir, "audit.log")
	rotated, err := rotatedLogs(dir)
	if err != nil {
		return err
	}
	// Open everything up front: if auditd rotates while we catch up, the open
	// descriptors still point at the right data.
	var old []*os.File
	for _, p := range rotated {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		if st, err := f.Stat(); err == nil && since > 0 && st.ModTime().Unix() < since {
			f.Close()
			continue
		}
		old = append(old, f)
	}
	cur, err := os.Open(active)
	if err != nil {
		return err
	}
	for _, f := range old {
		err := drainFile(f, out)
		f.Close()
		if err != nil {
			return err
		}
	}

	ppid := os.Getppid()
	r := bufio.NewReaderSize(cur, 1<<16)
	var partial []byte
	caughtUp := false
	for {
		if cur != nil {
			if partial, err = pump(r, out, partial); err != nil {
				return err
			}
		}
		if err := out.Flush(); err != nil {
			return nil // parent closed the pipe
		}
		if !caughtUp {
			out.WriteString("#caughtup\n")
			if err := out.Flush(); err != nil {
				return nil
			}
			caughtUp = true
		}
		time.Sleep(500 * time.Millisecond)
		if os.Getppid() != ppid {
			return nil
		}

		st, statErr := os.Stat(active)
		if cur == nil {
			if statErr == nil {
				if cur, err = os.Open(active); err == nil {
					r.Reset(cur)
				} else {
					cur = nil
				}
			}
			continue
		}
		cst, err := cur.Stat()
		if err != nil {
			return err
		}
		if statErr != nil || !os.SameFile(st, cst) {
			// Rotated: finish the old file, then switch to the new one.
			if partial, err = pump(r, out, partial); err != nil {
				return err
			}
			if len(partial) > 0 {
				out.Write(partial)
				out.WriteByte('\n')
				partial = partial[:0]
			}
			cur.Close()
			cur = nil
			if statErr == nil {
				if cur, err = os.Open(active); err == nil {
					r.Reset(cur)
				} else {
					cur = nil
				}
			}
		}
	}
}

func drainFile(f *os.File, out *bufio.Writer) error {
	partial, err := pump(bufio.NewReaderSize(f, 1<<16), out, nil)
	if err != nil {
		return err
	}
	if len(partial) > 0 {
		out.Write(partial)
		return out.WriteByte('\n')
	}
	return nil
}

// pump copies complete lines to out until EOF and returns any trailing
// partial line (auditd may be in the middle of writing it).
func pump(r *bufio.Reader, out *bufio.Writer, partial []byte) ([]byte, error) {
	for {
		chunk, err := r.ReadSlice('\n')
		switch err {
		case nil:
			if len(partial) > 0 {
				out.Write(partial)
				partial = partial[:0]
			}
			if _, err := out.Write(chunk); err != nil {
				return nil, err
			}
		case bufio.ErrBufferFull:
			partial = append(partial, chunk...)
		case io.EOF:
			return append(partial, chunk...), nil
		default:
			return partial, err
		}
	}
}
