package pipeline

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

type rejectingPublicationValidator struct{ shutdownTestPublisher }

func (*rejectingPublicationValidator) ValidatePublication(string) error {
	return errors.New("public feed contract brief.revision: missing revision history")
}

func TestRejectedDraftCannotBeMergedBackIntoPublication(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	original := "id: retired-brief\ntitle: Retired brief\n"
	if err := db.CreateDraft(&storage.Draft{ID: "retired", Status: storage.StatusRejected, Source: "oss-security", BriefYAML: original, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	item := scraper.RawItem{SourceID: "new-report", Source: "mozilla", Title: "Follow-up", URL: "https://example.com/report"}
	if err := p.mergeIntoDraft(context.Background(), "retired", &ExtractionResult{AffectedVendors: []string{"eMudhra"}}, item); err == nil {
		t.Fatal("structured merge accepted a rejected draft")
	}
	if err := p.mergeAssembledBriefIntoDraft("retired", "id: new-brief\ntitle: Update\n", item); err == nil {
		t.Fatal("assembled merge accepted a rejected draft")
	}
	draft, err := db.GetDraft("retired")
	if err != nil || draft == nil || draft.BriefYAML != original || draft.Status != storage.StatusRejected {
		t.Fatalf("rejected draft changed: draft=%v err=%v", draft, err)
	}
}

func TestMergeHoldsInconsistentApprovedBriefWithoutChangingDraft(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.llmClient = nil
	p.autoPublish = true
	p.publisher = &shutdownTestPublisher{}
	var logs bytes.Buffer
	p.logger = slog.New(slog.NewTextHandler(&logs, nil))
	base := `id: brief-widget
slug: 2026-10-widget
title: "Widget: Remote code execution (CVE-2026-10001)"
summary: Widget vulnerability
severity: high
published_at: "2026-10-20T00:00:00Z"
content: Widget vulnerability.
cves: [CVE-2026-10001, CVE-2026-10002, CVE-2026-10003, CVE-2026-10004]
affected_vendors: [Acme]
affected_products: [Widget]
references: [https://vendor.example/advisory]
`
	if err := db.CreateDraft(&storage.Draft{ID: "draft-widget", Status: storage.StatusApproved, Source: "nvd", BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	item := scraper.RawItem{SourceID: "advisory:widget", Source: "advisory", Title: "Widget update", URL: "https://vendor.example/update", Content: "Widget update applies to Windows."}
	if err := p.mergeIntoDraft(context.Background(), "draft-widget", &ExtractionResult{AffectedOS: []string{"Windows"}}, item); err != nil {
		t.Fatal(err)
	}
	draft, err := db.GetDraft("draft-widget")
	if err != nil {
		t.Fatal(err)
	}
	if draft.BriefYAML != base || draft.UpdateCount != 0 {
		t.Fatalf("inconsistent update mutated approved draft: count=%d yaml=%s", draft.UpdateCount, draft.BriefYAML)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !seen || !strings.Contains(logs.String(), "held for editorial review") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("merge review state: seen=%v logs=%s", seen, logs.String())
	}
}

func TestMergePreflightsPublisherContractBeforeChangingDraft(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.llmClient = nil
	p.autoPublish = true
	p.publisher = &rejectingPublicationValidator{}
	var logs bytes.Buffer
	p.logger = slog.New(slog.NewTextHandler(&logs, nil))
	base := `id: brief-widget
slug: 2026-10-widget
title: Widget advisory
summary: Widget update
severity: high
published_at: "2026-10-20T00:00:00Z"
content: Widget update.
affected_vendors: [Acme]
affected_products: [Widget]
references: [https://vendor.example/advisory]
`
	if err := db.CreateDraft(&storage.Draft{ID: "draft-widget", Status: storage.StatusApproved, Source: "nvd", BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	item := scraper.RawItem{SourceID: "advisory:widget-2", Source: "advisory", Title: "Widget update", URL: "https://vendor.example/update", Content: "Widget update applies to Windows."}
	if err := p.mergeIntoDraft(context.Background(), "draft-widget", &ExtractionResult{AffectedOS: []string{"Windows"}}, item); err != nil {
		t.Fatal(err)
	}
	draft, err := db.GetDraft("draft-widget")
	if err != nil {
		t.Fatal(err)
	}
	if draft.BriefYAML != base || draft.UpdateCount != 0 || !strings.Contains(logs.String(), "held for editorial review") {
		t.Fatalf("publisher contract failure changed approved draft: count=%d logs=%s", draft.UpdateCount, logs.String())
	}
}
