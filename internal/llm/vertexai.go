package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var _ Client = (*VertexAIClient)(nil)

// VertexAIClient talks to Google Vertex AI (Gemini) via REST.
type VertexAIClient struct {
	project    string
	location   string
	model      string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewVertexAIClient creates a Vertex AI client using Application Default Credentials.
func NewVertexAIClient(project, location, model string) (*VertexAIClient, error) {
	hc, err := googleHTTPClient(5 * time.Minute)
	if err != nil {
		return nil, err
	}
	return &VertexAIClient{
		project:    project,
		location:   location,
		model:      model,
		httpClient: hc,
	}, nil
}

// googleHTTPClient returns an HTTP client that signs requests with Application
// Default Credentials, valid for Vertex AI and Cloud Storage alike.
func googleHTTPClient(timeout time.Duration) (*http.Client, error) {
	creds, err := google.FindDefaultCredentials(context.Background(), "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("finding GCP credentials: %w", &RequestError{Err: err})
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &oauth2.Transport{Source: creds.TokenSource},
	}, nil
}

// newVertexAIClientWithHTTP is for testing — injects an arbitrary *http.Client.
func newVertexAIClientWithHTTP(project, location, model string, hc *http.Client) *VertexAIClient {
	return &VertexAIClient{
		project:    project,
		location:   location,
		model:      model,
		httpClient: hc,
	}
}

func (c *VertexAIClient) WithLogger(logger *slog.Logger) *VertexAIClient {
	c.logger = loggerOrDefault(logger)
	return c
}

func (c *VertexAIClient) generateURL() string {
	return fmt.Sprintf("%s/v1/projects/%s/locations/%s/publishers/google/models/%s:generateContent",
		vertexAIEndpoint(c.location), c.project, c.location, c.model)
}

func vertexAIEndpoint(location string) string {
	switch location {
	case "global":
		return "https://aiplatform.googleapis.com"
	case "us", "eu":
		return fmt.Sprintf("https://aiplatform.%s.rep.googleapis.com", location)
	default:
		return fmt.Sprintf("https://%s-aiplatform.googleapis.com", location)
	}
}

func (c *VertexAIClient) Generate(ctx context.Context, prompt, system string) (string, error) {
	req := newVertexRequest(prompt, system, "")
	return c.doGenerate(ctx, req)
}

func (c *VertexAIClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	req := newVertexRequest(prompt, system, jsonMIMEType)
	text, err := c.doGenerate(ctx, req)
	if err != nil {
		return err
	}
	return unmarshalJSON(text, out)
}

// jsonMIMEType is the response type GenerateJSON asks for.
const jsonMIMEType = "application/json"

// newVertexRequest builds the generateContent body for one call. The batch path
// builds its input lines and cache keys with it too, so a prefetched request
// can only differ from the live one if this function does.
func newVertexRequest(prompt, system, responseMIME string) vertexRequest {
	req := vertexRequest{
		Contents: []vertexContent{
			{Role: "user", Parts: []vertexPart{{Text: prompt}}},
		},
	}
	if system != "" {
		req.SystemInstruction = &vertexContent{
			Parts: []vertexPart{{Text: system}},
		}
	}
	if responseMIME != "" {
		req.GenerationConfig = &vertexGenerationConfig{
			ResponseMIMEType: responseMIME,
		}
	}
	return req
}

// GenerateStructured asks for a document of the given shape: Vertex constrains
// decoding to the schema, so the answer is JSON that decodes into out. An
// answer cut short by the token limit or a safety filter is a
// *FinishReasonError and one that does not decode an *OutputError; neither is
// worth retrying unchanged.
func (c *VertexAIClient) GenerateStructured(ctx context.Context, prompt, system string, schema *Schema, out any) error {
	resp, err := c.doRequest(ctx, newStructuredVertexRequest(prompt, system, schema))
	if err != nil {
		return err
	}
	text, err := structuredText(resp)
	if err != nil {
		return err
	}
	return DecodeStructured(text, out)
}

// structuredMaxOutputTokens is the answer cap for schema-constrained calls. A
// full brief with rules and hunt leads is long, and the model default is far
// below what the Gemini Flash / Flash-Lite family documents as its maximum
// (65,536 output tokens), so ask for that maximum rather than truncating.
const structuredMaxOutputTokens = 65536

// newStructuredVertexRequest is newVertexRequest for a schema-constrained answer.
func newStructuredVertexRequest(prompt, system string, schema *Schema) vertexRequest {
	req := newVertexRequest(prompt, system, jsonMIMEType)
	req.GenerationConfig.ResponseSchema = schema
	req.GenerationConfig.MaxOutputTokens = structuredMaxOutputTokens
	return req
}

// Finish reasons Vertex reports. An absent reason and STOP both mean the model
// finished its answer.
const (
	finishStop      = "STOP"
	finishMaxTokens = "MAX_TOKENS"
)

// structuredText returns the answer text of resp, or a *FinishReasonError when
// the model did not finish it. The text is checked before decoding so that a
// truncated document is classified instead of failing as a syntax error.
func structuredText(resp vertexResponse) (string, error) {
	text, err := candidateText(resp)
	if len(resp.Candidates) > 0 {
		if reason := resp.Candidates[0].FinishReason; reason != "" && reason != finishStop {
			return "", &FinishReasonError{Reason: reason, Text: text}
		}
	}
	return text, err
}

func (c *VertexAIClient) doGenerate(ctx context.Context, req vertexRequest) (string, error) {
	resp, err := c.doRequest(ctx, req)
	if err != nil {
		return "", err
	}
	return structuredText(resp)
}

func (c *VertexAIClient) doRequest(ctx context.Context, req vertexRequest) (result vertexResponse, requestErr error) {
	start := time.Now()
	defer func() {
		err := requestErr
		if err == nil {
			_, err = structuredText(result)
		}
		logUsage(ctx, c.logger, c.model, "online", requestKey(req), result, time.Since(start), err)
	}()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return vertexResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.generateURL(), bytes.NewReader(body))
	if err != nil {
		return vertexResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), retryTelemetryKey{}, retryTelemetry{Logger: c.logger, Model: c.model, RequestKey: requestKey(req)}))

	resp, err := retryDo(c.httpClient, httpReq)
	if err != nil {
		return vertexResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return vertexResponse{}, &HTTPError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return vertexResponse{}, fmt.Errorf("decoding LLM response: %w", &RequestError{Err: err})
	}
	return result, nil
}

// candidateText returns the answer in a response: the text parts of its first
// candidate, joined in order. Live responses and batch output lines both read
// their answer here.
func candidateText(resp vertexResponse) (string, error) {
	if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty response from Vertex AI")
	}
	var text strings.Builder
	for _, part := range resp.Candidates[0].Content.Parts {
		text.WriteString(part.Text)
	}
	return text.String(), nil
}

// Vertex AI request/response types.

type vertexRequest struct {
	Contents          []vertexContent         `json:"contents"`
	SystemInstruction *vertexContent          `json:"systemInstruction,omitempty"`
	GenerationConfig  *vertexGenerationConfig `json:"generationConfig,omitempty"`
}

type vertexContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []vertexPart `json:"parts"`
}

type vertexPart struct {
	Text string `json:"text"`
}

type vertexGenerationConfig struct {
	ResponseMIMEType string `json:"responseMimeType,omitempty"`
	// ResponseSchema constrains decoding to documents of this shape; it needs
	// ResponseMIMEType application/json.
	ResponseSchema *Schema `json:"responseSchema,omitempty"`
	// MaxOutputTokens caps the answer length; zero leaves the model default.
	MaxOutputTokens int `json:"maxOutputTokens,omitempty"`
}

func (r *vertexResponse) UnmarshalJSON(data []byte) error {
	type plain vertexResponse
	var value plain
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*r = vertexResponse(value)
	raw, ok := fields["usageMetadata"]
	r.UsagePresent = ok && string(raw) != "null"
	return nil
}

type vertexResponse struct {
	Candidates   []vertexCandidate `json:"candidates"`
	ResponseID   string            `json:"responseId,omitempty"`
	ModelVersion string            `json:"modelVersion,omitempty"`
	UsagePresent bool              `json:"-"`
	Usage        tokenUsage        `json:"usageMetadata"`
}

type vertexCandidate struct {
	Content      vertexContent `json:"content"`
	FinishReason string        `json:"finishReason,omitempty"`
}
