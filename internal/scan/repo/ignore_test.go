package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIgnoreFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "values.yaml"), []byte("image: bitnami/redis:7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := ScanWithOptions(context.Background(), root, Options{Clock: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	cfg := "ignores:\n- fingerprint: " + first.Findings[0].Fingerprint + "\n  reason: accepted temporarily\n  expires: 2026-12-31\n"
	if err := os.WriteFile(filepath.Join(root, ".disdetta.yaml"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ScanWithOptions(context.Background(), root, Options{Clock: func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }})
	if err != nil || len(got.Findings) != 0 || got.Summary.Ignored != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9: report=%#v err=%v", got, err)
	}
	expired, err := ScanWithOptions(context.Background(), root, Options{Clock: func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }})
	if err != nil || len(expired.Findings) != 1 || len(expired.Diagnostics) != 1 || expired.Diagnostics[0].Code != "DSD-SCN-006" {
		t.Fatalf("source docs/spec/v0.1.md section 9: %#v err=%v", expired, err)
	}
}

func TestInvalidIgnoreFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "bad.yaml")
	if err := os.WriteFile(p, []byte("ignores: [{reason: nope}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanWithOptions(context.Background(), root, Options{ConfigPath: p, Clock: time.Now}); err == nil {
		t.Fatal("source docs/spec/v0.1.md section 9: wanted usage error")
	}
}
