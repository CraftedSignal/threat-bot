package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ollamaRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Model != "test-model" {
			t.Errorf("unexpected model: %s", req.Model)
		}
		if req.Stream {
			t.Error("expected stream=false")
		}

		json.NewEncoder(w).Encode(ollamaResponse{
			Response: "This is the LLM response",
		})
	}))
	defer srv.Close()

	c := NewOllamaClient(srv.URL, "test-model")
	resp, err := c.Generate(context.Background(), "test prompt", "test system prompt")
	if err != nil {
		t.Fatal(err)
	}
	if resp != "This is the LLM response" {
		t.Errorf("unexpected response: %s", resp)
	}
}

func TestGenerateJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ollamaRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Format != "json" {
			t.Error("expected format=json")
		}

		json.NewEncoder(w).Encode(ollamaResponse{
			Response: `{"score": 4.5, "reason": "high quality"}`,
		})
	}))
	defer srv.Close()

	c := NewOllamaClient(srv.URL, "test-model")

	type result struct {
		Score  float64 `json:"score"`
		Reason string  `json:"reason"`
	}

	var out result
	err := c.GenerateJSON(context.Background(), "test prompt", "system", &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.Score != 4.5 {
		t.Errorf("unexpected score: %f", out.Score)
	}
	if out.Reason != "high quality" {
		t.Errorf("unexpected reason: %s", out.Reason)
	}
}
