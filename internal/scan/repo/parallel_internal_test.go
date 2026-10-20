package repo

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// TestWorkerCount covers the worker count of the file pool: the environment
// variable sets it exactly, and every other value leaves the default in
// place.
func TestWorkerCount(t *testing.T) {
	t.Setenv(WorkersEnv, "1")
	if got := workerCount(); got != 1 {
		t.Fatalf("worker count %d, want 1", got)
	}
	t.Setenv(WorkersEnv, "3")
	if got := workerCount(); got != 3 {
		t.Fatalf("worker count %d, want 3", got)
	}
	t.Setenv(WorkersEnv, " 5 ")
	if got := workerCount(); got != 5 {
		t.Fatalf("worker count %d, want 5", got)
	}
	for _, raw := range []string{"", "0", "-2", "many"} {
		t.Setenv(WorkersEnv, raw)
		got := workerCount()
		if got < 1 || got > MaxWorkers {
			t.Fatalf("worker count %d for %q, want between 1 and %d", got, raw, MaxWorkers)
		}
	}
	if err := os.Unsetenv(WorkersEnv); err != nil {
		t.Fatal(err)
	}
	got := workerCount()
	if got < 1 || got > MaxWorkers {
		t.Fatalf("worker count %d, want between 1 and %d", got, MaxWorkers)
	}
}

// TestRunPoolKeepsJobOrder checks that the pool returns the reports in job
// order, whatever order the jobs finish in.
func TestRunPoolKeepsJobOrder(t *testing.T) {
	jobs := []int{0, 1, 2, 3, 4, 5, 6, 7}
	reports := runPool(4, jobs, func(_ int, job int) diag.Report {
		return diag.Report{Findings: []diag.Finding{{Location: diag.Location{Path: fmt.Sprint(job)}}}}
	})
	if len(reports) != len(jobs) {
		t.Fatalf("got %d reports, want %d", len(reports), len(jobs))
	}
	for i, r := range reports {
		if len(r.Findings) != 1 || r.Findings[0].Location.Path != fmt.Sprint(i) {
			t.Fatalf("report %d is %v, want the report of job %d", i, r.Findings, i)
		}
	}
}

// TestRunPoolWithOneWorker checks that one worker gives the same result as
// many workers.
func TestRunPoolWithOneWorker(t *testing.T) {
	jobs := []int{0, 1, 2}
	reports := runPool(1, jobs, func(_ int, job int) diag.Report {
		return diag.Report{Summary: diag.Summary{FilesScanned: job}}
	})
	for i, r := range reports {
		if r.Summary.FilesScanned != i {
			t.Fatalf("report %d scanned %d files, want %d", i, r.Summary.FilesScanned, i)
		}
	}
}

// TestRunPoolRaisesThePanicOfAJob checks that a panic in a job does not take
// the process down: the worker recovers it, the pool drains the queue and
// waits for the other jobs, and the panic is raised again on the goroutine of
// the caller with the value of the panic. The pool never returns a partial
// report when a job panics.
func TestRunPoolRaisesThePanicOfAJob(t *testing.T) {
	sentinel := errors.New("the job failed")
	jobs := []int{0, 1, 2, 3}
	var finished atomic.Int64
	raised := make(chan any, 1)
	before := runtime.NumGoroutine()
	go func() {
		defer func() { raised <- recover() }()
		runPool(len(jobs), jobs, func(_ int, job int) diag.Report {
			if job == 1 {
				panic(sentinel)
			}
			finished.Add(1)
			return diag.Report{}
		})
	}()
	select {
	case value := <-raised:
		err, ok := value.(error)
		if !ok || !errors.Is(err, sentinel) {
			t.Fatalf("the pool raised %v, want %v", value, sentinel)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the pool did not finish after a panic in a job")
	}
	if got := finished.Load(); got != int64(len(jobs)-1) {
		t.Fatalf("%d jobs finished, want %d: the pool must drain the queue", got, len(jobs)-1)
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before {
		t.Fatalf("%d goroutines are still running, want at most %d: the pool must not leak a worker", got, before)
	}
}
