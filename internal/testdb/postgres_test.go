package testdb

import (
	"database/sql"
	"testing"
)

func TestURLProvidesIsolatedSchema(t *testing.T) {
	connectionURL := URL(t)
	db, err := sql.Open("pgx", connectionURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE isolation_check (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := db.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if schema == "" || schema == "public" {
		t.Fatalf("unexpected test schema %q", schema)
	}
}
