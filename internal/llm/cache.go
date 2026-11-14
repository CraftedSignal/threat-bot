package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// CacheStore persists fully decoded structured LLM responses.
type CacheStore interface {
	GetLLMCache(key string) (response string, ok bool, err error)
	PutLLMCache(key, response string) error
}

type cachedClient struct {
	inner Client
	model string
	store CacheStore
}

// NewCachedClient wraps structured generation with a deterministic,
// model-specific cache. Plain-text generation is intentionally never cached.
func NewCachedClient(inner Client, model string, store CacheStore) Client {
	return &cachedClient{inner: inner, model: model, store: store}
}

func (c *cachedClient) Generate(ctx context.Context, prompt, system string) (string, error) {
	return c.inner.Generate(ctx, prompt, system)
}

// GenerateStructured is never cached, like plain-text generation: the briefs
// it produces are written once per item and a stale one would outlive a fix
// to the prompt or schema.
func (c *cachedClient) GenerateStructured(ctx context.Context, prompt, system string, schema *Schema, out any) error {
	return c.inner.GenerateStructured(ctx, prompt, system, schema, out)
}

func (c *cachedClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	key := structuredCacheKey(c.model, prompt, system)
	if c.store != nil {
		if response, ok, err := c.store.GetLLMCache(key); err == nil && ok {
			if err := json.Unmarshal([]byte(response), out); err == nil {
				return nil
			}
		}
	}

	if err := c.inner.GenerateJSON(ctx, prompt, system, out); err != nil {
		return err
	}
	response, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	if c.store != nil {
		_ = c.store.PutLLMCache(key, string(response))
	}
	return nil
}

func structuredCacheKey(model, prompt, system string) string {
	digest := sha256.Sum256([]byte("threat-bot-structured-v1\x00" + model + "\x00" + system + "\x00" + prompt))
	return hex.EncodeToString(digest[:])
}
