package diag

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryHasDocumentation(t *testing.T) {
	t.Parallel()
	for _, entry := range List() {
		entry := entry
		t.Run(entry.Code, func(t *testing.T) {
			t.Parallel()
			docName := filepath.Base(entry.DocURL())
			if docName != entry.Code+".md" {
				t.Errorf("DocURL=%q want %q", entry.DocURL(), entry.Code+".md")
			}
			path := filepath.Join("..", "..", "docs", "diagnostics", docName)
			if _, err := os.Stat(path); err != nil {
				t.Errorf("documentation for %s: %v", entry.Code, err)
			}
		})
	}
}
