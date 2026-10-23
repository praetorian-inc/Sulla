package sulla

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/praetorian-inc/titus/pkg/enum"
)

// ExtractedBlob is one extracted text blob, gob-serializable across the worker process boundary.
type ExtractedBlob struct {
	Name    string
	Content []byte
}

const (
	extractWorkerFlag = "--__extract_worker"
	extractMemLimitMB = 1536 // per-extraction heap bound (1.5 GB)
)

// extractSem caps concurrent extraction child processes so we don't fork-bomb the host.
var extractSem = make(chan struct{}, 4)

// MaybeRunExtractWorker must be the first statement of main() in every binary linking this package.
// If this process was re-exec'd as an extraction worker it runs one bounded extraction and exits;
// otherwise it returns immediately. Args: [1]=flag [2]=tmpContentFile [3]=memLimitMB [4]=origPath.
//
// Extraction (notably the ledongthuc/pdf path used by titus) can allocate without bound on a
// malformed file — a 2 MB PDF has been observed allocating >13 GB. There is no in-process way to
// bound or interrupt that, so each extraction runs here in a short-lived child process guarded by a
// heap watchdog; if the child balloons it is killed (os.Exit) and the parent treats the file as skipped.
func MaybeRunExtractWorker() {
	if len(os.Args) < 5 || os.Args[1] != extractWorkerFlag {
		return
	}
	memLimitMB, err := strconv.Atoi(os.Args[3])
	if err != nil || memLimitMB <= 0 {
		memLimitMB = extractMemLimitMB
	}
	limit := uint64(memLimitMB) * 1024 * 1024
	debug.SetMemoryLimit(int64(limit))

	go func() {
		var ms runtime.MemStats
		for {
			time.Sleep(25 * time.Millisecond)
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > limit {
				os.Exit(137)
			}
		}
	}()

	content, err := os.ReadFile(os.Args[2])
	if err != nil {
		os.Exit(2)
	}
	extracted, err := enum.ExtractText(os.Args[4], content, enum.DefaultExtractionLimits())
	if err != nil {
		os.Exit(3)
	}
	blobs := make([]ExtractedBlob, len(extracted))
	for i, ec := range extracted {
		blobs[i] = ExtractedBlob{Name: ec.Name, Content: ec.Content}
	}
	if err := gob.NewEncoder(os.Stdout).Encode(blobs); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

// BoundedExtractText runs titus text extraction in a short-lived child process (a re-exec of this
// binary) bounded by a heap watchdog. It is a drop-in replacement for enum.ExtractText at the call
// site. A child OOM/abort is returned as an error (so the caller skips the file) and never affects
// this process's memory.
func BoundedExtractText(origPath string, content []byte) ([]ExtractedBlob, error) {
	extractSem <- struct{}{}
	defer func() { <-extractSem }()

	tmp, err := os.CreateTemp("", "sulla-extract-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file for extraction of %s: %w", origPath, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write temp file for extraction of %s: %w", origPath, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close temp file for extraction of %s: %w", origPath, err)
	}

	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, extractWorkerFlag, tmp.Name(), strconv.Itoa(extractMemLimitMB), origPath)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("bounded extraction aborted (likely exceeded %d MB) for %s: %w", extractMemLimitMB, origPath, err)
	}

	var blobs []ExtractedBlob
	if err := gob.NewDecoder(&buf).Decode(&blobs); err != nil {
		return nil, fmt.Errorf("decode extraction result for %s: %w", origPath, err)
	}
	return blobs, nil
}
