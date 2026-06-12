package sulla

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// logf writes a formatted message to stderr, optionally prefixed with a timestamp
// at the start of each new line.
func logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logMu.Lock()
	defer logMu.Unlock()
	// Clear ticker line if one is showing
	if tickerLine != "" {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", len(tickerLine)))
		tickerLine = ""
	}
	for len(msg) > 0 {
		if logAtLineStart && timestampMode {
			fmt.Fprintf(os.Stderr, "[%s] ", time.Now().Format("2006-01-02 15:04:05"))
		}
		idx := strings.IndexByte(msg, '\n')
		if idx == -1 {
			fmt.Fprint(os.Stderr, msg)
			logAtLineStart = false
			break
		}
		fmt.Fprint(os.Stderr, msg[:idx+1])
		logAtLineStart = true
		msg = msg[idx+1:]
	}
}

// logln writes a line to stderr, optionally prefixed with a timestamp.
func logln(msg string) {
	logf("%s\n", msg)
}

// shareStatus tracks live scan metrics for a single share.
type shareStatus struct {
	tag       string
	state     string // "connecting" or "scanning"
	fileCount *int64
	dirCount  *int64
	startTime time.Time
}

// shareTracker maintains the set of currently-scanning shares and prints
// their status when requested (Enter keypress) or via a periodic ticker.
type shareTracker struct {
	mu        sync.Mutex
	shares    map[string]*shareStatus // keyed by tag
	order     []string                // insertion order for stable output
	stopCh    chan struct{}
	total     int64 // total number of targets (set once at start)
	completed int64 // atomically incremented as shares finish
	findings  int64 // atomically incremented as findings are discovered
	startTime time.Time
	tickerOn  bool // whether the periodic ticker is active
}

// tickerLine holds the last ticker string written to stderr so logf can clear it.
var tickerLine string

// isTerminal reports whether f is a terminal (character device).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func newShareTracker(total int) *shareTracker {
	return &shareTracker{
		shares:    make(map[string]*shareStatus),
		stopCh:    make(chan struct{}),
		total:     int64(total),
		startTime: time.Now(),
	}
}

func (st *shareTracker) registerConnecting(tag string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.shares[tag] = &shareStatus{
		tag:       tag,
		state:     "connecting",
		startTime: time.Now(),
	}
	st.order = append(st.order, tag)
}

func (st *shareTracker) register(tag string, fileCount, dirCount *int64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.shares[tag]; ok {
		// Transition from connecting to scanning
		s.state = "scanning"
		s.fileCount = fileCount
		s.dirCount = dirCount
	} else {
		st.shares[tag] = &shareStatus{
			tag:       tag,
			state:     "scanning",
			fileCount: fileCount,
			dirCount:  dirCount,
			startTime: time.Now(),
		}
		st.order = append(st.order, tag)
	}
}

func (st *shareTracker) deregister(tag string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.shares, tag)
	for i, t := range st.order {
		if t == tag {
			st.order = append(st.order[:i], st.order[i+1:]...)
			break
		}
	}
	atomic.AddInt64(&st.completed, 1)
}

func (st *shareTracker) printStatus() {
	st.mu.Lock()
	defer st.mu.Unlock()
	total := atomic.LoadInt64(&st.total)
	done := atomic.LoadInt64(&st.completed)
	active := int64(len(st.shares))
	queued := total - done - active
	if queued < 0 {
		queued = 0
	}
	if len(st.shares) == 0 {
		if queued > 0 {
			logf("[status] %d/%d complete, %d queued (waiting for worker slot)\n", done, total, queued)
		} else {
			logf("[status] %d/%d complete\n", done, total)
		}
		return
	}
	logf("[status] %d/%d complete, %d active, %d queued:\n", done, total, active, queued)
	for _, tag := range st.order {
		s, ok := st.shares[tag]
		if !ok {
			continue
		}
		elapsed := time.Since(s.startTime).Round(time.Second)
		if s.state == "connecting" {
			fmt.Fprintf(os.Stderr, "  %s  connecting (%s elapsed)\n", s.tag, elapsed)
		} else {
			fc := atomic.LoadInt64(s.fileCount)
			dc := atomic.LoadInt64(s.dirCount)
			fmt.Fprintf(os.Stderr, "  %s  %d files, %d dirs, %s elapsed\n", s.tag, fc, dc, elapsed)
		}
	}
}

// startStdinListener reads lines from stdin in a goroutine and calls
// printStatus on each Enter keypress. Returns a stop function.
func (st *shareTracker) startStdinListener() {
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			// scanner.Scan blocks until a line is available or EOF
			if !scanner.Scan() {
				return
			}
			select {
			case <-st.stopCh:
				return
			default:
				st.printStatus()
			}
		}
	}()
}

func (st *shareTracker) stop() {
	close(st.stopCh)
	// Clear any remaining ticker line
	logMu.Lock()
	if tickerLine != "" {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", len(tickerLine)))
		tickerLine = ""
	}
	logMu.Unlock()
}

// writeTicker prints a single-line progress update using \r overwrite.
func (st *shareTracker) writeTicker() {
	total := atomic.LoadInt64(&st.total)
	done := atomic.LoadInt64(&st.completed)
	active := int64(len(st.shares))
	finds := atomic.LoadInt64(&st.findings)
	elapsed := time.Since(st.startTime).Round(time.Second)

	line := fmt.Sprintf("[*] %d/%d complete, %d scanning, %d findings (%s) — hit Enter for full status",
		done, total, active, finds, elapsed)

	logMu.Lock()
	// Clear previous ticker if longer
	if len(tickerLine) > len(line) {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", len(tickerLine)))
	}
	fmt.Fprintf(os.Stderr, "\r%s", line)
	tickerLine = line
	logMu.Unlock()
}

// startTicker runs a periodic status ticker (every 5s) when in default mode.
func (st *shareTracker) startTicker() {
	st.tickerOn = true
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				st.writeTicker()
			case <-st.stopCh:
				return
			}
		}
	}()
}

// outputFileTracker collects paths of files created by sulla for zip packaging.
type outputFileTracker struct {
	mu    sync.Mutex
	paths []string
}

func (t *outputFileTracker) add(path string) {
	t.mu.Lock()
	t.paths = append(t.paths, path)
	t.mu.Unlock()
}

func (t *outputFileTracker) list() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, len(t.paths))
	copy(out, t.paths)
	return out
}

// createdFiles tracks all output files sulla writes, for --zip packaging.
var createdFiles = &outputFileTracker{}
