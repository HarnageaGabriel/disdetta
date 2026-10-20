package repo_test

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/report"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
)

const benchmarkTreeSeed int64 = 0x5eed_b00c_17

// The tiers hold the same kind of file and differ only in file count, so
// comparing them measures the cost of walking more files and not the cost of
// reading bigger files. The big file stress case is a separate benchmark
// (BenchmarkScanRepoBigFiles) and the size limit case another one
// (BenchmarkScanRepoOversizedFile).
const (
	benchmarkSmallFiles  = 20
	benchmarkMediumFiles = 200
	benchmarkLargeFiles  = 2000
	benchmarkWideFiles   = 100000
	benchmarkWideDirs    = 100
)

// benchmarkBigFileMiB are the sizes of the big file stress fixtures. Every
// one of them is below the 16 MiB per file limit, so the scanner reads them
// all.
var benchmarkBigFileMiB = []int{5, 7, 9}

func BenchmarkScanRepoSmall(b *testing.B) {
	benchmarkScanRepo(b, benchmarkSmallFiles)
}

func BenchmarkScanRepoMedium(b *testing.B) {
	benchmarkScanRepo(b, benchmarkMediumFiles)
}

func BenchmarkScanRepoLarge(b *testing.B) {
	benchmarkScanRepo(b, benchmarkLargeFiles)
}

// BenchmarkScanRepoWide measures repository-walk overhead. Almost every file
// has an extension the scanner ignores; a small deterministic subset is YAML.
// The fixture holds 100000 files, so building it takes about a minute.
func BenchmarkScanRepoWide(b *testing.B) {
	root := wideBenchTree(b)
	b.ReportAllocs()
	peak := peakHeap(func() {
		for b.Loop() {
			got, err := repo.Scan(context.Background(), root)
			if err != nil {
				b.Fatal(err)
			}
			if got.Summary.FilesScanned != benchmarkWideDirs {
				b.Fatalf("scanned %d files, want %d", got.Summary.FilesScanned, benchmarkWideDirs)
			}
		}
	})
	b.ReportMetric(float64(peak)/(1<<20), "peak-heap-MB")
	b.ReportMetric(filesPerSecond(benchmarkWideFiles, b.N, b.Elapsed()), "files/s")
}

// peakHeap runs fn and returns the peak live heap of the process, in bytes.
// The heap is sampled with runtime/metrics, which does not stop the world, so
// the measurement does not change what is measured.
func peakHeap(fn func()) uint64 {
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	stop := make(chan struct{})
	done := make(chan uint64, 1)
	go func() {
		var peak uint64
		for {
			metrics.Read(sample)
			if value := sample[0].Value.Uint64(); value > peak {
				peak = value
			}
			select {
			case <-stop:
				done <- peak
				return
			default:
			}
			time.Sleep(500 * time.Microsecond)
		}
	}()
	fn()
	close(stop)
	return <-done
}

func benchmarkScanRepo(b *testing.B, fileCount int) {
	root, treeBytes := generateBenchTree(b, fileCount, benchmarkTreeSeed)
	b.ReportAllocs()
	b.SetBytes(treeBytes)
	for b.Loop() {
		got, err := repo.Scan(context.Background(), root)
		if err != nil {
			b.Fatal(err)
		}
		if got.Summary.FilesScanned != fileCount {
			b.Fatalf("scanned %d files, want %d", got.Summary.FilesScanned, fileCount)
		}
	}
	b.ReportMetric(filesPerSecond(fileCount, b.N, b.Elapsed()), "files/s")
}

// BenchmarkScanRepoBigFiles is the big file stress case: three large YAML
// manifests of 5, 7 and 9 MiB, 21 MiB in total, in a tree with few files. It
// is kept out of the file count tiers so that those stay comparable.
func BenchmarkScanRepoBigFiles(b *testing.B) {
	root, treeBytes := generateBigFileTree(b)
	fileCount := len(benchmarkBigFileMiB)
	b.ReportAllocs()
	b.SetBytes(treeBytes)
	for b.Loop() {
		got, err := repo.Scan(context.Background(), root)
		if err != nil {
			b.Fatal(err)
		}
		if got.Summary.FilesScanned != fileCount {
			b.Fatalf("scanned %d files, want %d", got.Summary.FilesScanned, fileCount)
		}
	}
	b.ReportMetric(filesPerSecond(fileCount, b.N, b.Elapsed()), "files/s")
}

// BenchmarkScanRepoOversizedFile measures the 16 MiB per file limit: the file
// is rejected on its metadata, so the scanner never reads it.
func BenchmarkScanRepoOversizedFile(b *testing.B) {
	root := generateOversizedFileTree(b)
	b.ReportAllocs()
	for b.Loop() {
		got, err := repo.Scan(context.Background(), root)
		if err != nil {
			b.Fatal(err)
		}
		if got.Summary.FilesScanned != 0 || got.Summary.FilesSkipped != 1 {
			b.Fatalf("scanned %d files and skipped %d, want 0 scanned and 1 skipped", got.Summary.FilesScanned, got.Summary.FilesSkipped)
		}
	}
}

// filesPerSecond converts the measured scan time into a file rate. The
// benchmark loop runs the scan b.N times over the same tree, so the number of
// scanned files is fileCount*b.N, not fileCount.
func filesPerSecond(fileCount, iterations int, elapsed time.Duration) float64 {
	if iterations <= 0 || elapsed <= 0 {
		return 0
	}
	return float64(fileCount) * float64(iterations) / elapsed.Seconds()
}

func TestFilesPerSecondMatchesNsPerOp(t *testing.T) {
	const fileCount = 200
	const iterations = 7
	elapsed := 350 * time.Millisecond
	got := filesPerSecond(fileCount, iterations, elapsed)
	nsPerOp := float64(elapsed.Nanoseconds()) / float64(iterations)
	want := float64(fileCount) * 1e9 / nsPerOp
	if math.Abs(got-want) > want*1e-9 {
		t.Fatalf("files/s %v, want %v (fileCount*1e9/ns-per-op)", got, want)
	}
}

func TestScanRepoMediumDeterministicJSON(t *testing.T) {
	root, _ := generateBenchTree(t, benchmarkMediumFiles, benchmarkTreeSeed)
	render := func() []byte {
		got, err := repo.Scan(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := report.JSON(&out, got); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	first := render()
	second := render()
	if !bytes.Equal(first, second) {
		t.Fatalf("medium tree JSON differs between scans:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

// TestScanWideTreeResourceBounds is the regression test of the walk on a
// large tree: the scan of a tree of many files the scanner does not read must
// stay inside its time and memory budget.
func TestScanWideTreeResourceBounds(t *testing.T) {
	const fileCount = 5000
	root := generateWideBenchTree(t, fileCount, 50)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if raceBuild() {
		if _, err := repo.Scan(ctx, root); err != nil {
			t.Fatal(err)
		}
		return
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var got diag.Report
	peak := peakHeap(func() {
		var err error
		got, err = repo.Scan(ctx, root)
		if err != nil {
			t.Fatal(err)
		}
	})
	runtime.ReadMemStats(&after)
	if got.Summary.FilesScanned != 50 {
		t.Fatalf("scanned %d files, want 50", got.Summary.FilesScanned)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	const maxAllocated = 6 * 1024 * 1024
	if allocated > maxAllocated {
		t.Fatalf("scan allocated %d bytes, want at most %d", allocated, maxAllocated)
	}
	const maxPeak = 8 * 1024 * 1024
	if peak > maxPeak {
		t.Fatalf("the scan peaked at %d bytes of live heap, want at most %d", peak, maxPeak)
	}
}

func raceBuild() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" && setting.Value == "true" {
			return true
		}
	}
	return false
}

// generateBenchTree writes a tree of fileCount small files with the same
// shape as a GitOps repository, and returns its root and its size in bytes.
func generateBenchTree(tb testing.TB, fileCount int, seed int64) (string, int64) {
	if fileCount < 4 {
		tb.Fatalf("benchmark tree needs at least 4 files, got %d", fileCount)
	}
	root := tb.TempDir()
	rng := rand.New(rand.NewSource(seed))
	var total int64

	write := func(rel, contents string) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			tb.Fatal(err)
		}
		total += int64(len(contents))
	}

	write("charts/bench/Chart.yaml", "apiVersion: v2\nname: bench\nversion: 1.0.0\n")
	for i := 0; i < fileCount-1; i++ {
		switch i % 8 {
		case 0, 1, 2:
			write(fmt.Sprintf("values/values-%04d.yaml", i), makeNestedValues(rng, false))
		case 3:
			write(fmt.Sprintf("values/values-%04d.yaml", i), makeNestedValues(rng, true))
		case 4:
			write(fmt.Sprintf("charts/bench/templates/deployment-%04d.yaml", i), makeHelmTemplate(i))
		case 5:
			write(fmt.Sprintf("docker/Dockerfile.%04d", i), makeDockerfile(i))
		case 6:
			write(fmt.Sprintf("kustomize/kustomization-%04d.yaml", i), makeKustomize(i))
		default:
			write(fmt.Sprintf("compose/compose-%04d.yaml", i), makeCompose(i))
		}
	}
	return root, total
}

// wideTreeEnv names the directory of the wide benchmark tree. When it is set
// and holds the tree already, the benchmark uses it as it is and the profile
// of a measurement holds the scan only, not the building of the tree.
const wideTreeEnv = "DISDETTA_WIDE_TREE"

// TestBuildWideTree builds the wide benchmark tree under the directory the
// environment variable names, so a measurement can be repeated without
// building 100000 files again.
func TestBuildWideTree(t *testing.T) {
	root := os.Getenv(wideTreeEnv)
	if root == "" {
		t.Skip("DISDETTA_WIDE_TREE is not set")
	}
	writeWideTree(t, root, benchmarkWideFiles, benchmarkWideDirs)
}

// generateWideBenchTree writes a tree of fileCount files in dirCount
// directories and returns its root. Almost every file has an extension the
// scanner ignores; a small deterministic subset is YAML.
func generateWideBenchTree(tb testing.TB, fileCount, dirCount int) string {
	root := tb.TempDir()
	writeWideTree(tb, root, fileCount, dirCount)
	return root
}

// wideBenchTree returns the root of the tree of BenchmarkScanRepoWide. It
// reuses the tree the environment variable names when it holds it already,
// so a measurement can be repeated without building 100000 files again.
func wideBenchTree(tb testing.TB) string {
	if root := os.Getenv(wideTreeEnv); root != "" {
		if _, err := os.Stat(filepath.Join(root, fmt.Sprintf("dir-%03d", benchmarkWideDirs-1))); err == nil {
			return root
		}
	}
	return generateWideBenchTree(tb, benchmarkWideFiles, benchmarkWideDirs)
}

func writeWideTree(tb testing.TB, root string, fileCount, dirCount int) {
	for dir := 0; dir < dirCount; dir++ {
		dirPath := filepath.Join(root, fmt.Sprintf("dir-%03d", dir))
		if err := os.MkdirAll(dirPath, 0o755); err != nil {
			tb.Fatal(err)
		}
		for file := dir; file < fileCount; file += dirCount {
			ext := ".txt"
			contents := ""
			if file < dirCount {
				ext = ".yaml"
				contents = "apiVersion: v1\nkind: ConfigMap\n"
			}
			name := fmt.Sprintf("file-%06d%s", file, ext)
			if err := os.WriteFile(filepath.Join(dirPath, name), []byte(contents), 0o600); err != nil {
				tb.Fatal(err)
			}
		}
	}
}

// generateBigFileTree writes the big file stress fixture: one YAML manifest
// per size in benchmarkBigFileMiB.
func generateBigFileTree(tb testing.TB) (string, int64) {
	root := tb.TempDir()
	var total int64
	for i, mib := range benchmarkBigFileMiB {
		path := filepath.Join(root, "manifests", fmt.Sprintf("large-%04d.yaml", i))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			tb.Fatal(err)
		}
		contents := makeLargeManifest(i, mib*1024*1024)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			tb.Fatal(err)
		}
		total += int64(len(contents))
	}
	return root, total
}

// generateOversizedFileTree writes a single file above the 16 MiB limit.
func generateOversizedFileTree(tb testing.TB) string {
	root := tb.TempDir()
	path := filepath.Join(root, "manifests", "oversized.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		tb.Fatal(err)
	}
	target := repo.MaxFileSize + 1024*1024
	contents := makeLargeManifest(0, target)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		tb.Fatal(err)
	}
	if int64(len(contents)) <= repo.MaxFileSize {
		tb.Fatalf("oversized fixture is %d bytes, want more than %d", len(contents), repo.MaxFileSize)
	}
	return root
}

func makeNestedValues(rng *rand.Rand, findings bool) string {
	var out strings.Builder
	out.WriteString("global:\n  imageRegistry: registry.example\nconfig:\n")
	for i := 0; i < 96; i++ {
		fmt.Fprintf(&out, "  group%03d:\n", i)
		for j := 0; j < 4; j++ {
			fmt.Fprintf(&out, "    key%02d: value-%03d-%03d\n", j, i, j)
		}
	}
	if findings {
		imageCount := 1 + rng.Intn(3)
		out.WriteString("  images:\n")
		for i := 0; i < imageCount; i++ {
			fmt.Fprintf(&out, "    - name: app-%d\n      image: bitnami/redis:%d\n", i, 7+i)
		}
	} else {
		out.WriteString("  image: registry.example/acme/app:1.2.3\n")
	}
	return out.String()
}

func makeHelmTemplate(index int) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: bench-%04d
spec:
  template:
    spec:
      containers:
        - name: app
          image: "bitnami/redis:{{ .Values.imageTag }}"
`, index)
}

func makeDockerfile(index int) string {
	return fmt.Sprintf(`FROM bitnami/minideb:latest
ENV BENCH_INDEX=%d
RUN echo "bench-%d" > /bench.txt
`, index, index)
}

func makeKustomize(index int) string {
	return fmt.Sprintf(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment-%04d.yaml
images:
  - name: bitnami/redis
    newName: bitnami/redis
    newTag: "7"
`, index)
}

func makeCompose(index int) string {
	return fmt.Sprintf(`services:
  app:
    image: bitnami/redis:7
    container_name: bench-%04d
`, index)
}

func makeLargeManifest(index, target int) string {
	header := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: large-%04d
  namespace: bench
data:
  payload: |
`, index)
	line := fmt.Sprintf("      bench payload line %04d: deterministic corpus content\n", index)
	var out strings.Builder
	out.Grow(target)
	out.WriteString(header)
	for out.Len()+len(line) < target {
		out.WriteString(line)
	}
	out.WriteString("...\n")
	return out.String()
}
