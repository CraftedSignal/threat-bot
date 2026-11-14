package eval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/craftedsignal/threat-bot/internal/llm"
)

// FixtureKey is the stable key for a recorded LLM call.
func FixtureKey(prompt, system string) string {
	h := sha256.Sum256([]byte(system + "\x00" + prompt))
	return hex.EncodeToString(h[:])
}

// ReplayClient implements llm.Client by returning recorded responses. Used by
// the CI gate so the eval runs deterministically with no live model.
type ReplayClient struct {
	responses map[string]string
}

var _ llm.Client = (*ReplayClient)(nil)

func NewReplayClient(responses map[string]string) *ReplayClient {
	return &ReplayClient{responses: responses}
}

func (c *ReplayClient) Generate(ctx context.Context, prompt, system string) (string, error) {
	v, ok := c.responses[FixtureKey(prompt, system)]
	if !ok {
		return "", fmt.Errorf("no fixture for prompt (len=%d); re-record with `make eval-record`", len(prompt))
	}
	return v, nil
}

func (c *ReplayClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	v, err := c.Generate(ctx, prompt, system)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(v), out)
}

// GenerateStructured replays the recorded JSON answer into out.
func (c *ReplayClient) GenerateStructured(ctx context.Context, prompt, system string, _ *llm.Schema, out any) error {
	v, err := c.Generate(ctx, prompt, system)
	if err != nil {
		return err
	}
	return llm.DecodeStructured(v, out)
}

// RecordingClient wraps a real llm.Client, capturing the post-parse JSON of
// each call so a deterministic fixture set can be written for the CI gate.
type RecordingClient struct {
	inner    llm.Client
	mu       sync.Mutex
	recorded map[string]string
}

var _ llm.Client = (*RecordingClient)(nil)

func NewRecordingClient(inner llm.Client) *RecordingClient {
	return &RecordingClient{inner: inner, recorded: map[string]string{}}
}

func (c *RecordingClient) Generate(ctx context.Context, prompt, system string) (string, error) {
	v, err := c.inner.Generate(ctx, prompt, system)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.recorded[FixtureKey(prompt, system)] = v
	c.mu.Unlock()
	return v, nil
}

func (c *RecordingClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	if err := c.inner.GenerateJSON(ctx, prompt, system, out); err != nil {
		return err
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.recorded[FixtureKey(prompt, system)] = string(b)
	c.mu.Unlock()
	return nil
}

// GenerateStructured records the post-decode JSON of the call.
func (c *RecordingClient) GenerateStructured(ctx context.Context, prompt, system string, schema *llm.Schema, out any) error {
	if err := c.inner.GenerateStructured(ctx, prompt, system, schema, out); err != nil {
		return err
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.recorded[FixtureKey(prompt, system)] = string(b)
	c.mu.Unlock()
	return nil
}

// Fixtures returns a copy of the recorded responses.
func (c *RecordingClient) Fixtures() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]string, len(c.recorded))
	for k, v := range c.recorded {
		out[k] = v
	}
	return out
}
