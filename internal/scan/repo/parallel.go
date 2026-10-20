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

// MaxWorkers is the default cap of the file pool: without an override the
// scan uses at most eight workers, so it never takes more than eight cores.
// DISDETTA_WORKERS sets the worker count exactly and can raise it above this
// cap.
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

// jobPanic is the panic a job raised, if it raised one.
type jobPanic struct {
	raised bool
	value  any
}

// jobPanics collects the panics raised by the jobs of a pool.
type jobPanics struct {
	mu     sync.Mutex
	values []jobPanic
}

// record stores the value a job panicked with.
func (p *jobPanics) record(index int, value any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.values[index] = jobPanic{raised: true, value: value}
}

// first returns the value of the panic of the lowest job index, so the pool
// always raises the same panic, whatever the order in which the jobs finished.
func (p *jobPanics) first() (any, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range p.values {
		if entry.raised {
			return entry.value, true
		}
	}
	return nil, false
}

// raise raises the panic of the lowest job index again, on the goroutine of
// the caller.
func (p *jobPanics) raise() {
	if value, ok := p.first(); ok {
		panic(value)
	}
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
//
// A panic in a job does not take the process down: the worker recovers it,
// the pool drains the queue and waits for the other workers, and the panic is
// raised again on the goroutine of the caller with the value of the panic. A
// failed scan therefore never returns a partial report.
func runPool[J any](workers int, jobs []J, fn func(int, J) diag.Report) []diag.Report {
	reports := make([]diag.Report, len(jobs))
	if len(jobs) == 0 {
		return reports
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	panics := &jobPanics{values: make([]jobPanic, len(jobs))}
	call := func(i int) {
		raised := true
		defer func() {
			if raised {
				panics.record(i, recover())
			}
		}()
		reports[i] = fn(i, jobs[i])
		raised = false
	}
	if workers <= 1 {
		for i := range jobs {
			call(i)
		}
		panics.raise()
		return reports
	}
	queue := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range queue {
				call(i)
			}
		}()
	}
	for i := range jobs {
		queue <- i
	}
	close(queue)
	wg.Wait()
	panics.raise()
	return reports
}
