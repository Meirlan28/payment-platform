package main

import (
	"crypto/sha256"
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

func TestSplitMigrationStatementsHonorsSQLLexicalConstructs(t *testing.T) {
	source := []byte(`
-- a semicolon in a comment is not a boundary ;
CREATE TABLE "quoted;name" (value STRING DEFAULT 'one;two');
CREATE FUNCTION f() RETURNS TRIGGER AS $body$
BEGIN
  /* nested ; /* block ; */ comment */
  NEW.value := 'it''s;safe';
  RETURN NEW;
END;
$body$ LANGUAGE PLpgSQL;
INSERT INTO "quoted;name" VALUES (E'backslash\\\';still-string');
`)
	statements, err := splitMigrationStatements(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 3 {
		t.Fatalf("got %d statements, want 3", len(statements))
	}
	for index, statement := range statements {
		if statement.ordinal != int64(index+1) {
			t.Fatalf("statement %d has ordinal %d", index, statement.ordinal)
		}
		if statement.checksum != sha256.Sum256([]byte(statement.contents)) {
			t.Fatalf("statement %d checksum is not over exact executable text", index)
		}
	}
}

func TestSplitMigrationStatementsRejectsUnterminatedConstructs(t *testing.T) {
	cases := [][]byte{
		[]byte("SELECT 'unterminated"),
		[]byte(`SELECT "unterminated`),
		[]byte("SELECT $body$unterminated"),
		[]byte("SELECT 1 /* unterminated"),
	}
	for _, source := range cases {
		if _, err := splitMigrationStatements(source); err == nil {
			t.Fatalf("expected unterminated input %q to fail", source)
		}
	}
}

func TestSplitMigrationStatementsUsesStandardConformingStrings(t *testing.T) {
	statements, err := splitMigrationStatements([]byte(`SELECT '\'; SELECT 2;`))
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 2 {
		t.Fatalf("standard string backslash must not escape quote: got %d statements", len(statements))
	}
}

func TestSplitEveryRepositoryMigration(t *testing.T) {
	migrations, err := loadMigrations("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		statements, err := splitMigrationStatements(migration.contents)
		if err != nil {
			t.Fatalf("%s: %v", migration.version, err)
		}
		if len(statements) == 0 {
			t.Fatalf("%s: no statements", migration.version)
		}
	}
}

func TestMigrationsThroughRequiresExactExistingTarget(t *testing.T) {
	migrations := []migration{{version: "001_first.sql"}, {version: "002_second.sql"}}
	selected, err := migrationsThrough(migrations, "001_first.sql", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].version != "001_first.sql" {
		t.Fatalf("unexpected selected migrations: %#v", selected)
	}
	if _, err := migrationsThrough(migrations, "001_first", ""); err == nil {
		t.Fatal("expected malformed target to fail closed")
	}
	if _, err := migrationsThrough(migrations, "003_missing.sql", ""); err == nil {
		t.Fatal("expected unknown target to fail closed")
	}
	if _, err := migrationsThrough(migrations, "", ""); err == nil {
		t.Fatal("empty target without an explicit integration acknowledgement must fail closed")
	}
	all, err := migrationsThrough(migrations, "", integrationApplyAllAck)
	if err != nil || len(all) != len(migrations) {
		t.Fatalf("empty target should select all: len=%d err=%v", len(all), err)
	}
}
