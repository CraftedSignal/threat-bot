package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/publisher"
)

func TestCommittedExampleMatchesValidatedExporter(t *testing.T) {
	data, err := os.ReadFile("../stix-bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.ValidateSTIX(data, 1); err != nil {
		t.Fatalf("committed example violates feed contract: %v", err)
	}
	want, err := exampleBundle()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatal("STIX example is stale: review exporter changes and run go run ./examples/stix > examples/stix-bundle.json from the repository root")
	}
}
