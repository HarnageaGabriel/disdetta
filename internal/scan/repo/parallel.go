package repo

import (
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// WorkersEnv is the environment variable that sets the number of workers used
// to read and parse files. A positive value sets the worker count exactly; any
// other value leaves the default in place. A value of 1 makes the scan fully
// sequential.
const WorkersEnv = "DISDETTA_WORKERS"

// MaxWorkers is the highest number of workers the file pool uses, so a scan
// never takes more than eight cores.
const MaxWorkers = 8

// fileJob is one file the scan reads and parses.
type fileJob struct {
	path    string
	display string
	info    fs.FileInfo
}

// workerCount returns the number of workers used to read and parse files: the
// value of DISDETTA_WORKERS when it holds a positive number, otherwise the
// number of CPUs, capped at MaxWorkers.
func workerCount() int {
	if raw, ok := os.LookupEnv(WorkersEnv); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
			return n
		}
	}
	n := runtime.NumCPU()
	if n > MaxWorkers {
		n = MaxWorkers
	}
	if n < 1 {
		return 1
	}
	return n
}

// runPool reads and parses every job with at most workers goroutines and
// returns one report per job, in job order.
//
// The walk decides which files are scanned and in which order, so the result
// of a job never depends on the order in which the jobs finish: every job is
// handled by exactly one goroutine and writes to its own slot of the result
// slice. The merged report is therefore the same for every worker count.
//
// The pool does not observe the context. The walk is the phase that observes
// it, and it fails the scan before any file is handed to a worker, so a
// cancelled scan fails the same way for every worker count and the report of
// a scan never depends on the number of workers.
func runPool[J any](workers int, jobs []J, fn func(J) diag.Report) []diag.Report {
	reports := make([]diag.Report, len(jobs))
	if len(jobs) == 0 {
		return reports
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers <= 1 {
		for i := range jobs {
			reports[i] = fn(jobs[i])
		}
		return reports
	}
	queue := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range queue {
				reports[i] = fn(jobs[i])
			}
		}()
	}
	for i := range jobs {
		queue <- i
	}
	close(queue)
	wg.Wait()
	return reports
}
