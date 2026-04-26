package targets_test

import (
	"os"
	"path/filepath"
	"testing"

	"iscan/internal/targets"
)

func TestBuiltinSourceLoadsWithoutError(t *testing.T) {
	source := targets.BuiltinSource{}
	result, err := source.Load()
	if err != nil {
		t.Fatalf("BuiltinSource.Load() returned error: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("BuiltinSource.Load() returned empty target list")
	}
}

func TestFileSourceLoadsValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.json")
	content := `[
		{"name":"custom1","domain":"example.org","scheme":"https","ports":[443]},
		{"name":"custom2","domain":"example.net","scheme":"http","ports":[80]}
	]`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	source := targets.FileSource{Path: path}
	result, err := source.Load()
	if err != nil {
		t.Fatalf("FileSource.Load() returned error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(result))
	}
	if result[0].Name != "custom1" || result[1].Name != "custom2" {
		t.Fatalf("unexpected target names: got %q and %q", result[0].Name, result[1].Name)
	}
}

func TestFileSourceRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	content := `{"not":"an array"}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	source := targets.FileSource{Path: path}
	_, err := source.Load()
	if err == nil {
		t.Fatal("expected error for non-array JSON, got nil")
	}
}

func TestFileSourceValidatesEachTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.json")
	content := `[{"domain":"x.com","scheme":"https","ports":[443]}]`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	source := targets.FileSource{Path: path}
	_, err := source.Load()
	if err == nil {
		t.Fatal("expected validation error for missing name, got nil")
	}
}

func TestFileSourceFileNotFound(t *testing.T) {
	source := targets.FileSource{Path: "/nonexistent/path.json"}
	_, err := source.Load()
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestSelectSourceReturnsBuiltinForEmptyString(t *testing.T) {
	s := targets.SelectSource("")
	if _, ok := s.(targets.BuiltinSource); !ok {
		t.Fatalf("expected BuiltinSource for empty string, got %T", s)
	}
}

func TestSelectSourceReturnsBuiltinForBuiltinString(t *testing.T) {
	s := targets.SelectSource("builtin")
	if _, ok := s.(targets.BuiltinSource); !ok {
		t.Fatalf("expected BuiltinSource for 'builtin', got %T", s)
	}
}

func TestSelectSourceReturnsFileSourceForPath(t *testing.T) {
	s := targets.SelectSource("/some/path.json")
	if _, ok := s.(targets.FileSource); !ok {
		t.Fatalf("expected FileSource for path, got %T", s)
	}
}
