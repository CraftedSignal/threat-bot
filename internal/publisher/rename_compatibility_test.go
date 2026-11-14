package publisher

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyDraftReceiptRestoresWithoutRepublishing(t *testing.T) {
	// A pre-rename completion-only row must remain a receipt, never a new brief.
	raw := "# ti-bot-draft-publication-v1 " + base64.StdEncoding.EncodeToString([]byte(`{"drafts":[{"draft_id":"draft-before-rename"}],"committed":true}`)) + "\n"
	payload, err := decodeDraftOutboxPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !payload.Committed || payload.BriefYAML != "" || len(payload.Drafts) != 1 || payload.Drafts[0].DraftID != "draft-before-rename" {
		t.Fatalf("lost legacy completion metadata: %+v", payload)
	}
}

func TestNewDraftReceiptPreservesRollbackWireFormat(t *testing.T) {
	raw, err := encodeDraftOutboxPayload(draftOutboxPayload{Drafts: []DraftPublication{{DraftID: "draft-after-rename"}}, Committed: true})
	if err != nil {
		t.Fatal(err)
	}
	// The pre-rename decoder recognizes this exact persisted prefix.
	prefix := "# ti-bot-draft-publication-v1 "
	if !strings.HasPrefix(raw, prefix) {
		t.Fatal("receipt cannot be recovered by the previous deployed version")
	}
	metadata, _, ok := strings.Cut(strings.TrimPrefix(raw, prefix), "\n")
	if !ok {
		t.Fatal("missing metadata terminator")
	}
	decoded, err := base64.StdEncoding.DecodeString(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var payload draftOutboxPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Committed || len(payload.Drafts) != 1 || payload.Drafts[0].DraftID != "draft-after-rename" {
		t.Fatal("rollback lost completion receipt")
	}
}
