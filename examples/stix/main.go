// Command stix prints a deterministic synthetic example using the real exporter.
// Run from the repository root: go run ./examples/stix > examples/stix-bundle.json
package main

import (
	"fmt"
	"os"

	"github.com/craftedsignal/threat-bot/internal/publisher"
)

func exampleBundle() ([]byte, error) {
	brief := publisher.BundleBrief{
		ID:          "synthetic-training-attachment",
		Slug:        "synthetic-training-attachment",
		Title:       "Synthetic exercise: suspicious PowerShell after an attachment",
		Summary:     "Fictional training content. A simulated attachment launched PowerShell; this is not a real incident.",
		Content:     "Review the exercise ground truth and correlate mail delivery with endpoint process ancestry.",
		Severity:    "low",
		PublishedAt: "2026-01-01T12:00:00Z",
		Source:      "synthetic-example",
		Tags:        []string{"synthetic", "training"},
		References:  []string{"https://example.org/training/report"},
		TTPs: []publisher.BundleTTP{
			{TacticID: "TA0001", TacticName: "Initial Access", TechniqueID: "T1566.001", TechniqueName: "Spearphishing Attachment"},
			{TacticID: "TA0002", TacticName: "Execution", TechniqueID: "T1059.001", TechniqueName: "PowerShell"},
		},
	}
	data, err := publisher.ExportSTIX([]publisher.BundleBrief{brief}, "https://example.org")
	if err != nil {
		return nil, err
	}
	if err := publisher.ValidateSTIX(data, 1); err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func main() {
	data, err := exampleBundle()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
