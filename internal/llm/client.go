package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the interface for LLM providers.
type Client interface {
	Generate(ctx context.Context, prompt, system string) (string, error)
	GenerateJSON(ctx context.Context, prompt, system string, out any) error
	// GenerateStructured asks for a JSON document of the given shape and
	// decodes it into out. Providers constrain generation to schema, so the
	// answer cannot be malformed or use values outside its enums. A cut-off
	// answer is a *FinishReasonError and an undecodable one an *OutputError.
	GenerateStructured(ctx context.Context, prompt, system string, schema *Schema, out any) error
}

var _ Client = (*OllamaClient)(nil)

// OllamaClient talks to a local Ollama instance.
type OllamaClient struct {
	endpoint string
	model    string
	client   *http.Client
}

func NewOllamaClient(endpoint, model string) *OllamaClient {
	return &OllamaClient{
		endpoint: endpoint,
		model:    model,
		client:   &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *OllamaClient) Generate(ctx context.Context, prompt, system string) (string, error) {
	req := ollamaRequest{
		Model:  c.model,
		Prompt: prompt,
		System: system,
		Stream: false,
	}
	resp, err := c.doRequest(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, nil
}

func (c *OllamaClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	req := ollamaRequest{
		Model:  c.model,
		Prompt: prompt,
		System: system,
		Stream: false,
		Format: "json",
	}
	resp, err := c.doRequest(ctx, req)
	if err != nil {
		return err
	}
	return unmarshalJSON(resp.Response, out)
}

// GenerateStructured passes schema to Ollama as a JSON Schema `format`, which
// constrains generation the same way Vertex's responseSchema does.
func (c *OllamaClient) GenerateStructured(ctx context.Context, prompt, system string, schema *Schema, out any) error {
	req := ollamaRequest{
		Model:  c.model,
		Prompt: prompt,
		System: system,
		Stream: false,
		Format: schema.jsonSchema(),
	}
	resp, err := c.doRequest(ctx, req)
	if err != nil {
		return err
	}
	if resp.DoneReason == "length" {
		return &FinishReasonError{Reason: finishMaxTokens, Text: resp.Response}
	}
	return DecodeStructured(resp.Response, out)
}

func (c *OllamaClient) doRequest(ctx context.Context, req ollamaRequest) (*ollamaResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := retryDo(c.client, httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return nil, &HTTPError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding LLM response: %w", &RequestError{Err: err})
	}
	return &result, nil
}

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	System string `json:"system,omitempty"`
	Stream bool   `json:"stream"`
	Format any    `json:"format,omitempty"`
}

type ollamaResponse struct {
	Response   string `json:"response"`
	DoneReason string `json:"done_reason,omitempty"`
}
