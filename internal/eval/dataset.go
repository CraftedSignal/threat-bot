// Package eval scores threat-bot's ATT&CK technique extraction against datasets
// in the TRAM sentence-label format. The in-tree corpus is synthetic; external
// research datasets can be supplied explicitly. Labels are sentence-level
// (one technique per sentence); threat-bot extracts a technique set per document.
// GroupByDoc bridges the two by joining a document's sentences and unioning
// their labels into a gold set.
package eval

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// Record is one labelled sentence from the TRAM dataset.
type Record struct {
	Text     string `json:"text"`
	Label    string `json:"label"`
	DocTitle string `json:"doc_title"`
}

// GoldPair links a source sentence to its gold technique label.
type GoldPair struct {
	Sentence  string
	Technique string
}

// EvalDoc is a reconstructed document: joined sentences plus the unioned
// gold technique set and the per-sentence pairs.
type EvalDoc struct {
	Title          string
	Text           string
	GoldTechniques []string
	GoldPairs      []GoldPair
}

// LoadDataset reads a TRAM single_label.json file.
func LoadDataset(path string) ([]Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var recs []Record
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

// GroupByDoc groups sentence records by doc_title into EvalDocs. Doc order is
// stable (sorted by title) so reports are deterministic.
func GroupByDoc(records []Record) []EvalDoc {
	type acc struct {
		sentences []string
		pairs     []GoldPair
		techSet   map[string]bool
	}
	byTitle := map[string]*acc{}
	var order []string
	for _, r := range records {
		a := byTitle[r.DocTitle]
		if a == nil {
			a = &acc{techSet: map[string]bool{}}
			byTitle[r.DocTitle] = a
			order = append(order, r.DocTitle)
		}
		a.sentences = append(a.sentences, r.Text)
		a.pairs = append(a.pairs, GoldPair{Sentence: r.Text, Technique: r.Label})
		a.techSet[r.Label] = true
	}
	sort.Strings(order)
	docs := make([]EvalDoc, 0, len(order))
	for _, title := range order {
		a := byTitle[title]
		gold := make([]string, 0, len(a.techSet))
		for tech := range a.techSet {
			gold = append(gold, tech)
		}
		sort.Strings(gold)
		docs = append(docs, EvalDoc{
			Title:          title,
			Text:           strings.Join(a.sentences, "\n"),
			GoldTechniques: gold,
			GoldPairs:      a.pairs,
		})
	}
	return docs
}
