package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMigrationsRejectsSequenceGap(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "001_first.sql"), []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "003_third.sql"), []byte("SELECT 3;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMigrations(directory); err == nil {
		t.Fatal("expected a migration sequence error")
	}
}

func TestLoadMigrationsUsesContentChecksum(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "001_first.sql")
	if err := os.WriteFile(path, []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := loadMigrations(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("SELECT 2;"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := loadMigrations(directory)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].checksum == second[0].checksum {
		t.Fatal("different migration contents must produce a different checksum")
	}
}
