package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type schemaInner struct {
	Name  string   `json:"name"`
	Where []string `json:"where,omitempty"`
}

type schemaSample struct {
	ID       string        `json:"id" desc:"the id"`
	Severity string        `json:"severity" enum:"low,high"`
	When     string        `json:"when,omitempty" format:"date-time"`
	Score    float64       `json:"score,omitempty"`
	Count    int           `json:"count,omitempty"`
	Flag     bool          `json:"flag,omitempty"`
	Kinds    []string      `json:"kinds,omitempty" enum:"a,b"`
	Inner    schemaInner   `json:"inner"`
	Maybe    *schemaInner  `json:"maybe,omitempty"`
	List     []schemaInner `json:"list,omitempty"`
	Skipped  string        `json:"-"`
	private  string        //nolint:unused // Reflection fixture verifies unexported fields are omitted.
}

func TestSchemaOfDerivesTypesRequiredEnumsAndFormats(t *testing.T) {
	s, err := SchemaOf[schemaSample]()
	if err != nil {
		t.Fatal(err)
	}
	if s.Type != TypeObject {
		t.Fatalf("root type = %s", s.Type)
	}
	if want := []string{"id", "severity", "inner"}; !reflect.DeepEqual(s.Required, want) {
		t.Errorf("required = %v, want %v (omitempty fields are optional)", s.Required, want)
	}
	if want := []string{"id", "severity", "when", "score", "count", "flag", "kinds", "inner", "maybe", "list"}; !reflect.DeepEqual(s.PropertyOrdering, want) {
		t.Errorf("propertyOrdering = %v, want %v", s.PropertyOrdering, want)
	}
	if _, ok := s.Properties["Skipped"]; ok || s.Properties["private"] != nil {
		t.Error("json:\"-\" and unexported fields must not appear")
	}
	if got := s.Properties["severity"]; got.Type != TypeString || !reflect.DeepEqual(got.Enum, []string{"low", "high"}) {
		t.Errorf("severity = %+v, want a closed string enum", got)
	}
	if got := s.Properties["when"]; got.Type != TypeString || got.Format != "date-time" {
		t.Errorf("when = %+v, want a date-time string", got)
	}
	if got := s.Properties["id"].Description; got != "the id" {
		t.Errorf("description = %q", got)
	}
	for name, want := range map[string]string{"score": TypeNumber, "count": TypeInteger, "flag": TypeBoolean} {
		if got := s.Properties[name].Type; got != want {
			t.Errorf("%s type = %s, want %s", name, got, want)
		}
	}
	kinds := s.Properties["kinds"]
	if kinds.Type != TypeArray || kinds.Items.Type != TypeString || !reflect.DeepEqual(kinds.Items.Enum, []string{"a", "b"}) {
		t.Errorf("kinds = %+v, want an array whose items carry the enum", kinds)
	}
	if got := s.Properties["maybe"]; got.Type != TypeObject || len(got.Required) != 1 {
		t.Errorf("pointer to struct = %+v, want an object", got)
	}
	if got := s.Properties["list"]; got.Type != TypeArray || got.Items.Type != TypeObject {
		t.Errorf("list = %+v, want an array of objects", got)
	}
}

func TestSchemaOfRejectsShapesVertexCannotExpress(t *testing.T) {
	type withMap struct {
		M map[string]string `json:"m"`
	}
	if _, err := SchemaOf[withMap](); err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Errorf("map field: err = %v, want unsupported type (a Vertex object has fixed keys)", err)
	}
	type badEnum struct {
		N int `json:"n" enum:"1,2"`
	}
	if _, err := SchemaOf[badEnum](); err == nil {
		t.Error("enum on a non-string must be rejected")
	}
	type empty struct{}
	if _, err := SchemaOf[empty](); err == nil {
		t.Error("an object without properties must be rejected; Vertex 400s on it")
	}
}

// The schema is sent as JSON; only keywords Vertex accepts may appear in it.
func TestSchemaJSONUsesOnlyVertexKeywords(t *testing.T) {
	s := MustSchemaOf[schemaSample]()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"type": true, "description": true, "format": true, "enum": true, "items": true,
		"properties": true, "required": true, "propertyOrdering": true}
	var walk func(node map[string]any)
	walk = func(node map[string]any) {
		for k, v := range node {
			if !allowed[k] {
				t.Errorf("keyword %q is not supported by Vertex responseSchema", k)
			}
			switch x := v.(type) {
			case map[string]any:
				if k == "properties" {
					for _, p := range x {
						walk(p.(map[string]any))
					}
				} else {
					walk(x)
				}
			}
		}
	}
	walk(tree)
	if tree["type"] != "OBJECT" {
		t.Errorf("type = %v, want upper-case OBJECT", tree["type"])
	}
}

func TestStructuredRequestCarriesSchemaAndNeedsJSONMIME(t *testing.T) {
	schema := MustSchemaOf[schemaSample]()
	req := newStructuredVertexRequest("p", "s", schema)
	if req.GenerationConfig == nil || req.GenerationConfig.ResponseMIMEType != jsonMIMEType || req.GenerationConfig.ResponseSchema != schema {
		t.Fatalf("generation config = %+v", req.GenerationConfig)
	}
	raw, _ := json.Marshal(req)
	if !strings.Contains(string(raw), `"responseSchema":{"type":"OBJECT"`) {
		t.Errorf("request body lacks responseSchema: %s", raw)
	}
	// The plain JSON request must stay schema-free.
	plain, _ := json.Marshal(newVertexRequest("p", "s", jsonMIMEType))
	if strings.Contains(string(plain), "responseSchema") {
		t.Errorf("GenerateJSON request gained a schema: %s", plain)
	}
}

func TestRequestKeyDistinguishesSchemasButKeepsExistingKeys(t *testing.T) {
	plain := newVertexRequest("p", "s", jsonMIMEType)
	withSchema := newStructuredVertexRequest("p", "s", MustSchemaOf[schemaInner]())
	other := newStructuredVertexRequest("p", "s", MustSchemaOf[schemaSample]())
	if requestKey(plain) == requestKey(withSchema) || requestKey(withSchema) == requestKey(other) {
		t.Error("requests that differ in schema must not share a prefetch key")
	}
	// A request without a schema must keep the key it had before schemas
	// existed, so batch answers prefetched by an older process still match.
	if got := requestKey(plain); got != legacyRequestKey(plain) {
		t.Errorf("schema-free key changed: %s", got)
	}
}

func legacyRequestKey(req vertexRequest) string {
	h := sha256.New()
	field := func(s string) { fmt.Fprintf(h, "%d:%s", len(s), s) }
	field(req.GenerationConfig.ResponseMIMEType)
	field(joinText(req.SystemInstruction))
	for _, c := range req.Contents {
		field(joinText(&c))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func vertexServer(t *testing.T, candidate string) *VertexAIClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req vertexRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.GenerationConfig == nil || req.GenerationConfig.ResponseSchema == nil || req.GenerationConfig.ResponseMIMEType != jsonMIMEType {
			t.Errorf("structured request without schema: %+v", req.GenerationConfig)
		}
		w.Write([]byte(candidate))
	}))
	t.Cleanup(srv.Close)
	c := newVertexAIClientWithHTTP("p", "us-central1", "m", srv.Client())
	c.httpClient = &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}}
	return c
}

func TestGenerateStructuredDecodesConstrainedAnswer(t *testing.T) {
	c := vertexServer(t, `{"candidates":[{"content":{"parts":[{"text":"{\"id\":\"x\",\"severity\":\"high\",\"inner\":{\"name\":\"n\"}}"}]},"finishReason":"STOP"}]}`)
	var out schemaSample
	if err := c.GenerateStructured(context.Background(), "p", "s", MustSchemaOf[schemaSample](), &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != "x" || out.Severity != "high" || out.Inner.Name != "n" {
		t.Fatalf("decoded %+v", out)
	}
}

func TestGenerateStructuredClassifiesFinishReason(t *testing.T) {
	for _, tc := range []struct {
		reason    string
		truncated bool
	}{
		{"MAX_TOKENS", true},
		{"SAFETY", false},
		{"PROHIBITED_CONTENT", false},
		{"RECITATION", false},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			// The text is cut mid-document: before finishReason was read this
			// failed as a JSON syntax error indistinguishable from a bad model answer.
			c := vertexServer(t, `{"candidates":[{"content":{"parts":[{"text":"{\"id\":\"x\",\"seve"}]},"finishReason":"`+tc.reason+`"}]}`)
			var out schemaSample
			err := c.GenerateStructured(context.Background(), "p", "s", MustSchemaOf[schemaSample](), &out)
			var finish *FinishReasonError
			if !errors.As(err, &finish) {
				t.Fatalf("err = %v (%T), want *FinishReasonError", err, err)
			}
			if finish.Reason != tc.reason || finish.Truncated() != tc.truncated || finish.Text != `{"id":"x","seve` {
				t.Errorf("finish error = %+v", finish)
			}
			var output *OutputError
			if errors.As(err, &output) {
				t.Error("a cut-off answer must not be reported as a decode failure")
			}
		})
	}
}

func TestGenerateStructuredClassifiesUndecodableAnswer(t *testing.T) {
	c := vertexServer(t, `{"candidates":[{"content":{"parts":[{"text":"{\"id\":{\"nested\":1}}"}]},"finishReason":"STOP"}]}`)
	var out schemaSample
	err := c.GenerateStructured(context.Background(), "p", "s", MustSchemaOf[schemaSample](), &out)
	var output *OutputError
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &output) || !errors.As(err, &typeErr) {
		t.Fatalf("err = %v, want *OutputError wrapping *json.UnmarshalTypeError", err)
	}
	if !strings.Contains(output.Text, "nested") {
		t.Errorf("offending text not kept: %q", output.Text)
	}
}

func TestGenerateStructuredEmptyAnswerIsOutputError(t *testing.T) {
	c := vertexServer(t, `{"candidates":[{"content":{"parts":[{"text":"  "}]},"finishReason":"STOP"}]}`)
	var out schemaSample
	var output *OutputError
	if err := c.GenerateStructured(context.Background(), "p", "s", MustSchemaOf[schemaSample](), &out); !errors.As(err, &output) {
		t.Fatalf("err = %v, want *OutputError", err)
	}
}

func TestGenerateStructuredKeepsHTTPErrorsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"schema nesting depth exceeded"}}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	c := newVertexAIClientWithHTTP("p", "us-central1", "m", srv.Client())
	c.httpClient = &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}}
	var out schemaSample
	err := c.GenerateStructured(context.Background(), "p", "s", MustSchemaOf[schemaSample](), &out)
	if status, ok := HTTPStatus(err); !ok || status != http.StatusBadRequest {
		t.Fatalf("err = %v, want an *HTTPError with status 400", err)
	}
}

func TestAbsentFinishReasonCountsAsFinished(t *testing.T) {
	c := vertexServer(t, `{"candidates":[{"content":{"parts":[{"text":"{\"id\":\"x\",\"severity\":\"low\",\"inner\":{\"name\":\"n\"}}"}]}}]}`)
	var out schemaSample
	if err := c.GenerateStructured(context.Background(), "p", "s", MustSchemaOf[schemaSample](), &out); err != nil {
		t.Fatal(err)
	}
}

func TestOllamaStructuredSendsJSONSchemaAndReportsTruncation(t *testing.T) {
	var format map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Format map[string]any `json:"format"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		format = req.Format
		if strings.Contains(r.Header.Get("X-Case"), "cut") {
			w.Write([]byte(`{"response":"{\"id\":","done_reason":"length"}`))
			return
		}
		w.Write([]byte(`{"response":"{\"id\":\"x\",\"severity\":\"low\",\"inner\":{\"name\":\"n\"}}"}`))
	}))
	defer srv.Close()
	c := NewOllamaClient(srv.URL, "m")
	var out schemaSample
	if err := c.GenerateStructured(context.Background(), "p", "s", MustSchemaOf[schemaSample](), &out); err != nil {
		t.Fatal(err)
	}
	if format["type"] != "object" {
		t.Errorf("format = %v, want a lower-case JSON schema", format)
	}
	if enum := format["properties"].(map[string]any)["severity"].(map[string]any)["enum"]; enum == nil {
		t.Error("enum missing from the JSON schema sent to Ollama")
	}

	c.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("X-Case", "cut")
		return http.DefaultTransport.RoundTrip(r)
	})}
	var finish *FinishReasonError
	if err := c.GenerateStructured(context.Background(), "p", "s", MustSchemaOf[schemaSample](), &out); !errors.As(err, &finish) || !finish.Truncated() {
		t.Fatalf("err = %v, want a truncation FinishReasonError", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
