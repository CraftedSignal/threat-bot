package eval

import (
	"path/filepath"
	"testing"
)

func TestGroupByDoc(t *testing.T) {
	records := []Record{
		{Text: "sentence A", Label: "T1003.001", DocTitle: "Doc One"},
		{Text: "sentence B", Label: "T1059", DocTitle: "Doc One"},
		{Text: "sentence C", Label: "T1003.001", DocTitle: "Doc One"}, // dup label
		{Text: "sentence D", Label: "T1566", DocTitle: "Doc Two"},
	}
	docs := GroupByDoc(records)
	if len(docs) != 2 {
		t.Fatalf("want 2 docs, got %d", len(docs))
	}
	var one EvalDoc
	for _, d := range docs {
		if d.Title == "Doc One" {
			one = d
		}
	}
	if len(one.GoldTechniques) != 2 { // T1003.001 + T1059, deduped
		t.Errorf("Doc One gold = %v, want 2 unique", one.GoldTechniques)
	}
	if len(one.GoldPairs) != 3 {
		t.Errorf("Doc One pairs = %d, want 3", len(one.GoldPairs))
	}
	if one.Text == "" {
		t.Error("Doc One text should be the joined sentences")
	}
}

func TestLoadDataset(t *testing.T) {
	recs, err := LoadDataset(filepath.Join("testdata", "single_label.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(recs) != 12 {
		t.Errorf("expected 12 synthetic records, got %d", len(recs))
	}
	if recs[0].Label == "" || recs[0].Text == "" {
		t.Errorf("first record looks empty: %+v", recs[0])
	}
	if docs := GroupByDoc(recs); len(docs) != 4 {
		t.Errorf("expected 4 synthetic documents, got %d", len(docs))
	}
}
