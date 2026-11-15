package llm_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
)

type groundingVertexTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (r groundingVertexTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme, clone.URL.Host = r.target.Scheme, r.target.Host
	return r.base.RoundTrip(clone)
}

// The production incident was an HTTP 400 before inference: generic fake LLM
// clients never serialized the dynamic grounding schema. This test runs the
// actual Vertex adapter and rejects every empty enum value at its HTTP boundary.
func TestGroundingSchemasThroughVertexRequestBoundary(t *testing.T) {
	const source = "Example Harbor is fixed in 2.4.\nOtherPlugin is fixed in 2.0."
	const brief = "title: Example Harbor security notice\naffected_products: [Example Harbor, OtherPlugin]\ncontent: Example Harbor needs an update.\n"
	for _, tc := range []struct {
		name, source, brief, answer string
		wantGrounded, wantError     bool
		wantCalls                   int
	}{
		{name: "no targets", source: "A vendor notice.", brief: "title: Vendor notice\ncontent: A vendor notice.\n", answer: `{"issues":[]}`, wantGrounded: true, wantCalls: 1},
		{name: "targets without eligible source evidence", source: "A vendor notice.", brief: brief, answer: `{"issues":[]}`, wantGrounded: true, wantCalls: 1},
		{name: "multiple targets with source evidence", source: source, brief: brief, answer: `{"issues":[]}`, wantGrounded: true, wantCalls: 1},
		{name: "unsupported claim empty metadata", source: source, brief: brief, answer: `{"issues":[{"kind":"unsupported_claim","field":"content","brief_quote":"Example Harbor needs an update.","reason":"Source does not support this claim.","subject":"","source_evidence_id":"","source_quote":""}]}`, wantCalls: 1},
		{name: "minor omission empty metadata", source: source, brief: brief, answer: `{"issues":[{"kind":"omission","field":"content","brief_quote":"","reason":"Incidental background omitted.","subject":"","source_evidence_id":"","source_quote":""}]}`, wantGrounded: true, wantCalls: 1},
		{name: "material omission empty quote fallback", source: source, brief: brief, answer: `{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_evidence_id":"","source_quote":"Example Harbor is fixed in 2.4.","reason":"Missing fixed release."}]}`, wantCalls: 1},
		{name: "material omission empty reference without quote fails closed", source: source, brief: brief, answer: `{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_evidence_id":"","source_quote":"","reason":"Missing fixed release."}]}`, wantError: true, wantCalls: 2},
		{name: "material omission empty target fails closed", source: source, brief: brief, answer: `{"issues":[{"kind":"material_omission","field":"content","subject":"","source_evidence_id":"","source_quote":"Example Harbor is fixed in 2.4.","reason":"Missing fixed release."}]}`, wantError: true, wantCalls: 2},
		{name: "material omission missing metadata fails closed", source: source, brief: brief, answer: `{"issues":[{"kind":"material_omission","field":"content","reason":"Missing fixed release."}]}`, wantError: true, wantCalls: 2},
		{name: "unknown source ID fails closed", source: source, brief: brief, answer: `{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_evidence_id":"unknown","source_quote":"Example Harbor is fixed in 2.4.","reason":"Missing fixed release."}]}`, wantError: true, wantCalls: 2},
		{name: "wrong target fails closed", source: source, brief: brief, answer: `{"issues":[{"kind":"material_omission","field":"content","subject":"UnrelatedPlugin","source_evidence_id":"","source_quote":"Example Harbor is fixed in 2.4.","reason":"Missing fixed release."}]}`, wantError: true, wantCalls: 2},
		{name: "finding-only correction quote fallback", source: source, brief: brief, answer: `{"issues":[{"kind":"material_omission","field":"content","subject":"UnrelatedPlugin","source_evidence_id":"","source_quote":"","reason":"Missing fixed release."}]}`, wantCalls: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var request map[string]any
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					http.Error(w, "decode failed", 400)
					return
				}
				config, _ := request["generationConfig"].(map[string]any)
				schema, _ := config["responseSchema"].(map[string]any)
				if schema == nil {
					t.Error("actual Vertex request lost responseSchema")
					http.Error(w, "missing schema", 400)
					return
				}
				var walk func(any, string) error
				walk = func(node any, path string) error {
					switch v := node.(type) {
					case map[string]any:
						if values, ok := v["enum"].([]any); ok {
							for i, value := range values {
								if value == "" {
									return fmt.Errorf("%s.enum[%d] is empty", path, i)
								}
							}
						}
						for key, child := range v {
							if err := walk(child, path+"."+key); err != nil {
								return err
							}
						}
					case []any:
						for i, child := range v {
							if err := walk(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
								return err
							}
						}
					}
					return nil
				}
				if err := walk(schema, "responseSchema"); err != nil {
					t.Error(err)
					http.Error(w, "INVALID_ARGUMENT: empty enum value", 400)
					return
				}
				// Mixed-kind checker findings and optional reference IDs permit empty
				// metadata as strings; corrections constrain only eligible subjects.
				properties := schema["properties"].(map[string]any)
				arrayName := "issues"
				if calls > 1 {
					arrayName = "evidence"
				}
				metadata := properties[arrayName].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
				for _, field := range []string{"subject", "source_evidence_id"} {
					values, _ := metadata[field].(map[string]any)["enum"].([]any)
					if calls == 1 || field == "source_evidence_id" {
						if len(values) != 0 {
							t.Errorf("%s must allow empty metadata without enum values", field)
						}
					} else if len(values) != 2 {
						t.Errorf("correction subjects must contain only the two eligible products: %v", values)
					}
				}
				answer := tc.answer
				if calls > 1 {
					if tc.name == "finding-only correction quote fallback" {
						answer = `{"evidence":[{"subject":"Example Harbor","source_evidence_id":"","source_quote":"Example Harbor is fixed in 2.4."}]}`
					} else {
						// Preserve the invalid finding in the correction; never let missing or
						// invalid metadata become an empty issues array or remove its blocker.
						var initial struct {
							Issues []map[string]any `json:"issues"`
						}
						_ = json.Unmarshal([]byte(tc.answer), &initial)
						raw, _ := json.Marshal(map[string]any{"evidence": initial.Issues})
						answer = string(raw)
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"candidates": []any{map[string]any{"finishReason": "STOP", "content": map[string]any{"parts": []any{map[string]any{"text": answer}}}}}})
			}))
			defer srv.Close()
			target, _ := url.Parse(srv.URL)
			client := llm.NewVertexAIClientForTest(&http.Client{Transport: groundingVertexTransport{target: target, base: srv.Client().Transport}})
			result, err := pipeline.NewGroundingChecker(client).Check(context.Background(), "Vendor security notice", tc.source, tc.brief)
			if tc.wantError {
				var contract interface{ FailureKind() string }
				if err == nil || result != nil || !errors.As(err, &contract) || contract.FailureKind() != "omission_evidence_contract" {
					t.Fatalf("invalid finding must remain held, result=%+v error=%v", result, err)
				}
			} else if err != nil || result == nil || result.Grounded != tc.wantGrounded {
				t.Fatalf("result=%+v error=%v grounded want=%v", result, err, tc.wantGrounded)
			}
			if calls != tc.wantCalls {
				t.Fatalf("HTTP calls=%d want=%d", calls, tc.wantCalls)
			}
		})
	}
}
