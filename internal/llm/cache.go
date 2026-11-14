package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"reflect"
)

// CachePolicyVersion invalidates JSON artifacts when decoding/validation policy changes.
// Model, full prompts and expected schema are independently included in every key.
// The legacy prefix is a durable protocol: changing it would lose paid-job recovery.
const CachePolicyVersion = "ti-bot-json-v2"

type CacheStore interface {
	GetLLMCache(key string) (response string, ok bool, err error)
	PutLLMCache(key, response string) error
}

// ValidatedResponse can reject syntactically valid but unusable model JSON.
// Validation runs on fresh decoded data before it reaches callers or durable cache.
type ValidatedResponse interface{ ValidateLLMResponse() error }

type cachedClient struct {
	inner  Client
	model  string
	store  CacheStore
	logger *slog.Logger
}

func NewCachedClient(inner Client, model string, store CacheStore, loggers ...*slog.Logger) Client {
	logger := slog.Default()
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	}
	return &cachedClient{inner: inner, model: model, store: store, logger: logger}
}
func (c *cachedClient) Generate(ctx context.Context, prompt, system string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return c.inner.Generate(ctx, prompt, system)
}

// Grounding verdicts and generation failures are deliberately not memoized.
// Durable pipeline stages decide whether a validated candidate can be resumed.
func (c *cachedClient) GenerateStructured(ctx context.Context, prompt, system string, schema *Schema, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.inner.GenerateStructured(ctx, prompt, system, schema, out)
}
func (c *cachedClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	req := Request{Prompt: prompt, System: system, JSON: true, Schema: jsonResponseSchema(out)}
	key := persistentRequestKey(c.model, req)
	if text, ok := readPersistent(ctx, c.store, c.logger, c.model, key); ok {
		if err := decodeInto(text, out); err == nil {
			return nil
		}
		cacheLog(ctx, c.logger, c.model, key, "invalid")
	}
	if err := fillFresh(out, func(fresh any) error { return c.inner.GenerateJSON(ctx, prompt, system, fresh) }); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if encoded, err := json.Marshal(out); err == nil {
		writePersistent(ctx, c.store, c.logger, c.model, key, string(encoded))
	}
	return nil
}
func jsonResponseSchema(out any) *Schema {
	if out == nil {
		return nil
	}
	s, _ := schemaOfType(reflect.TypeOf(out))
	return s
}
func persistentRequestKey(model string, req Request) string {
	digest := sha256.Sum256([]byte(CachePolicyVersion + "\x00" + model + "\x00" + schemaKey(req.Schema) + "\x00" + req.System + "\x00" + req.Prompt))
	return hex.EncodeToString(digest[:])
}
func cacheLog(ctx context.Context, logger *slog.Logger, model, key, result string) {
	loggerOrDefault(logger).InfoContext(ctx, "llm cache", append(logAttrs(ctx), "model", model, "cache_key", key, "tier", "persistent", "result", result)...)
}
func readPersistent(ctx context.Context, store CacheStore, logger *slog.Logger, model, key string) (string, bool) {
	if store == nil || ctx.Err() != nil {
		return "", false
	}
	text, ok, err := store.GetLLMCache(key)
	if err != nil {
		cacheLog(ctx, logger, model, key, "read_error")
		return "", false
	}
	if !ok {
		cacheLog(ctx, logger, model, key, "miss")
		return "", false
	}
	var decoded any
	if err := unmarshalJSON(text, &decoded); err != nil || decoded == nil {
		cacheLog(ctx, logger, model, key, "invalid")
		return "", false
	}
	cacheLog(ctx, logger, model, key, "hit")
	return text, true
}
func writePersistent(ctx context.Context, store CacheStore, logger *slog.Logger, model, key, text string) bool {
	if store == nil || ctx.Err() != nil {
		return false
	}
	if err := store.PutLLMCache(key, text); err != nil {
		cacheLog(ctx, logger, model, key, "write_error")
		return false
	}
	cacheLog(ctx, logger, model, key, "stored")
	return true
}
