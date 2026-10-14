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
			path := filepath.Join("..", "..", "docs", "diagnostics", entry.Code+".md")
			if _, err := os.Stat(path); err != nil {
				t.Errorf("documentation for %s: %v", entry.Code, err)
			}
		})
	}
}
