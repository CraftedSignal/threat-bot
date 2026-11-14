package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVertexAIGenerate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req vertexRequest
		json.NewDecoder(r.Body).Decode(&req)

		if len(req.Contents) != 1 || req.Contents[0].Parts[0].Text != "test prompt" {
			t.Errorf("unexpected prompt: %+v", req.Contents)
		}
		if req.SystemInstruction == nil || req.SystemInstruction.Parts[0].Text != "test system" {
			t.Errorf("unexpected system instruction: %+v", req.SystemInstruction)
		}
		if req.GenerationConfig != nil {
			t.Error("expected no generation config for plain generate")
		}

		json.NewEncoder(w).Encode(vertexResponse{
			Candidates: []vertexCandidate{
				{Content: vertexContent{Parts: []vertexPart{{Text: "vertex response"}}}},
			},
		})
	}))
	defer srv.Close()

	c := newVertexAIClientWithHTTP("test-project", "us-central1", "gemini-pro", srv.Client())
	c.httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL},
	}

	resp, err := c.Generate(context.Background(), "test prompt", "test system")
	if err != nil {
		t.Fatal(err)
	}
	if resp != "vertex response" {
		t.Errorf("unexpected response: %s", resp)
	}
}

func TestVertexAIGenerateRejectsNonStopFinishReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(vertexResponse{Candidates: []vertexCandidate{{
			Content: vertexContent{Parts: []vertexPart{{Text: "partial answer"}}}, FinishReason: "SAFETY",
		}}})
	}))
	defer srv.Close()
	c := newVertexAIClientWithHTTP("p", "us-central1", "gemini", &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}})
	_, err := c.Generate(context.Background(), "prompt", "")
	var finish *FinishReasonError
	if !errors.As(err, &finish) || finish.Reason != "SAFETY" {
		t.Fatalf("Generate error = %v, want FinishReasonError(SAFETY)", err)
	}
}

func TestVertexAIGenerateJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req vertexRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.GenerationConfig == nil || req.GenerationConfig.ResponseMIMEType != "application/json" {
			t.Errorf("expected JSON MIME type, got: %+v", req.GenerationConfig)
		}

		json.NewEncoder(w).Encode(vertexResponse{
			Candidates: []vertexCandidate{
				{Content: vertexContent{Parts: []vertexPart{{Text: `{"score": 4.5, "reason": "high quality"}`}}}},
			},
		})
	}))
	defer srv.Close()

	c := newVertexAIClientWithHTTP("test-project", "us-central1", "gemini-pro", srv.Client())
	c.httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL},
	}

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

func TestVertexAIEmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(vertexResponse{Candidates: nil})
	}))
	defer srv.Close()

	c := newVertexAIClientWithHTTP("test-project", "us-central1", "gemini-pro", srv.Client())
	c.httpClient = &http.Client{
		Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL},
	}

	_, err := c.Generate(context.Background(), "test prompt", "system")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestVertexAIGenerateURL(t *testing.T) {
	tests := []struct {
		name     string
		location string
		host     string
	}{
		{
			name:     "regional endpoint",
			location: "us-central1",
			host:     "https://us-central1-aiplatform.googleapis.com/",
		},
		{
			name:     "global endpoint",
			location: "global",
			host:     "https://aiplatform.googleapis.com/",
		},
		{
			name:     "eu multi-region endpoint",
			location: "eu",
			host:     "https://aiplatform.eu.rep.googleapis.com/",
		},
		{
			name:     "us multi-region endpoint",
			location: "us",
			host:     "https://aiplatform.us.rep.googleapis.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newVertexAIClientWithHTTP("test-project", tt.location, "gemini-3.1-flash-lite", nil)
			if url := c.generateURL(); !strings.HasPrefix(url, tt.host) {
				t.Fatalf("generateURL() = %q, want host prefix %q", url, tt.host)
			}
			if !strings.Contains(c.generateURL(), "/locations/"+tt.location+"/") {
				t.Fatalf("generateURL() = %q, want location %q in path", c.generateURL(), tt.location)
			}
		})
	}
}

// rewriteTransport rewrites request URLs to the test server.
type rewriteTransport struct {
	base   http.RoundTripper
	target string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.target[len("http://"):]
	if t.base != nil {
		return t.base.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}
