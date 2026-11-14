package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"
)

// Request is one model call as a caller makes it: what Generate is given, or
// what GenerateJSON is given when JSON is set.
type Request struct {
	Prompt string
	System string
	JSON   bool
}

func (r Request) vertexRequest() vertexRequest {
	mime := ""
	if r.JSON {
		mime = jsonMIMEType
	}
	return newVertexRequest(r.Prompt, r.System, mime)
}

// requestKey identifies a request by what the model is asked: the response
// type, the system instruction and the prompt text. It is computed from the
// request struct rather than from encoded bytes, so a request echoed back in
// batch output (which does not keep our key order) gets the key it was sent
// under.
func requestKey(req vertexRequest) string {
	h := sha256.New()
	// hash.Hash.Write never fails.
	field := func(s string) { _, _ = fmt.Fprintf(h, "%d:%s", len(s), s) }

	mime := ""
	if req.GenerationConfig != nil {
		mime = req.GenerationConfig.ResponseMIMEType
	}
	field(mime)
	// Only schema-constrained requests carry the field, so the keys of plain
	// and JSON requests are what they have always been.
	if req.GenerationConfig != nil && req.GenerationConfig.ResponseSchema != nil {
		field(schemaKey(req.GenerationConfig.ResponseSchema))
	}
	field(joinText(req.SystemInstruction))
	for _, c := range req.Contents {
		field(joinText(&c))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func joinText(c *vertexContent) string {
	if c == nil {
		return ""
	}
	text := ""
	for _, p := range c.Parts {
		text += p.Text
	}
	return text
}

// Prefetcher is a Client that can answer requests ahead of time. Calls made
// after Prefetch are served from memory when their request matches one that
// was prefetched, and go to the live model otherwise.
type Prefetcher interface {
	Client
	// Prefetch answers reqs in one go and returns when they are answered or
	// the attempt has been given up. It never fails: whatever is left
	// unanswered runs live.
	Prefetch(ctx context.Context, reqs []Request)
	// Cached decodes the prefetched answer to a JSON request into out. It
	// reports false, leaving out untouched, when there is none. It never
	// calls the live model.
	Cached(req Request, out any) bool
	// Release drops everything prefetched.
	Release()
}

// batchRunner answers requests offline and returns the answer text by request key.
type batchRunner interface {
	run(ctx context.Context, reqs []Request) (map[string]string, error)
}

// PrefetchClient wraps a live Client with an in-memory cache of answers
// fetched through a batch job. It sits outside any health tracking wrapper, so
// cache hits are not counted as live calls.
type PrefetchClient struct {
	live       Client
	runner     batchRunner
	maxPrompts int
	minPrompts int
	logger     *slog.Logger

	mu        sync.Mutex
	answers   map[string]string
	served    map[string]struct{}
	requested int
}

var _ Prefetcher = (*PrefetchClient)(nil)

// NewPrefetchClient wraps live. At most maxPrompts requests go into one batch;
// the rest run live.
func NewPrefetchClient(live Client, batch *VertexBatch, maxPrompts int, logger *slog.Logger) *PrefetchClient {
	return newPrefetchClient(live, batch, maxPrompts, logger)
}

// WithMinPrompts makes Prefetch skip the batch job, leaving the prompts to run
// live, when fewer than n are given. A small set queues for as long as a big
// one and can outlive max_wait, while live calls answer at once.
func (c *PrefetchClient) WithMinPrompts(n int) *PrefetchClient {
	c.minPrompts = n
	return c
}

func newPrefetchClient(live Client, runner batchRunner, maxPrompts int, logger *slog.Logger) *PrefetchClient {
	return &PrefetchClient{
		live:       live,
		runner:     runner,
		maxPrompts: maxPrompts,
		logger:     logger,
		answers:    make(map[string]string),
		served:     make(map[string]struct{}),
	}
}

func (c *PrefetchClient) Prefetch(ctx context.Context, reqs []Request) {
	if len(reqs) == 0 {
		return
	}
	if c.maxPrompts > 0 && len(reqs) > c.maxPrompts {
		c.logger.Warn("batch prefetch over max_prompts; the rest run live", "requests", len(reqs), "max_prompts", c.maxPrompts)
		reqs = reqs[:c.maxPrompts]
	}

	if len(reqs) < c.minPrompts {
		c.logger.Info("batch prefetch skipped; too few prompts to batch, running live", "requests", len(reqs), "min_prompts", c.minPrompts)
		return
	}

	start := time.Now()
	answers, err := c.runner.run(ctx, reqs)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			// Shutdown, not a failure: unseen items are fetched again after
			// the restart and nothing is lost.
			c.logger.Info("batch prefetch interrupted by shutdown; prompts run live", "requests", len(reqs), "error", err)
			return
		}
		c.logger.Warn("batch prefetch failed; prompts run live", "requests", len(reqs), "duration", time.Since(start).Round(time.Second), "error", err)
		return
	}

	c.mu.Lock()
	for key, text := range answers {
		c.answers[key] = text
	}
	c.requested += len(reqs)
	c.mu.Unlock()
	c.logger.Info("batch prefetch finished", "requests", len(reqs), "answered", len(answers), "duration", time.Since(start).Round(time.Second))
}

// answer returns the prefetched text for req and notes that it was used.
func (c *PrefetchClient) answer(req Request) (string, bool) {
	key := requestKey(req.vertexRequest())
	c.mu.Lock()
	defer c.mu.Unlock()
	text, ok := c.answers[key]
	if ok {
		c.served[key] = struct{}{}
	}
	return text, ok
}

func (c *PrefetchClient) Cached(req Request, out any) bool {
	text, ok := c.answer(req)
	return ok && decodeInto(text, out) == nil
}

func (c *PrefetchClient) Generate(ctx context.Context, prompt, system string) (string, error) {
	if text, ok := c.answer(Request{Prompt: prompt, System: system}); ok {
		return text, nil
	}
	return c.live.Generate(ctx, prompt, system)
}

func (c *PrefetchClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	req := Request{Prompt: prompt, System: system, JSON: true}
	if text, ok := c.answer(req); ok {
		err := decodeInto(text, out)
		if err == nil {
			return nil
		}
		// A malformed batch answer must not cost the item; ask the live model.
		c.logger.Warn("prefetched answer unusable; asking the live model", "error", err)
	}
	return c.live.GenerateJSON(ctx, prompt, system, out)
}

// GenerateStructured is always live: structured answers are not batched.
func (c *PrefetchClient) GenerateStructured(ctx context.Context, prompt, system string, schema *Schema, out any) error {
	return c.live.GenerateStructured(ctx, prompt, system, schema, out)
}

// Release drops the cache and reports how much of what was paid for got used.
func (c *PrefetchClient) Release() {
	c.mu.Lock()
	requested, answered, served := c.requested, len(c.answers), len(c.served)
	c.answers = make(map[string]string)
	c.served = make(map[string]struct{})
	c.requested = 0
	c.mu.Unlock()

	if requested > 0 {
		c.logger.Info("batch prefetch released", "requested", requested, "answered", answered, "served", served, "unused", answered-served)
	}
}

// decodeInto decodes a JSON answer into out the way a live GenerateJSON call
// does, but only touches out when the answer decodes, so a failed attempt
// leaves nothing behind for the live retry to inherit.
func decodeInto(text string, out any) error {
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return unmarshalJSON(text, out)
	}
	fresh := reflect.New(v.Elem().Type())
	if err := unmarshalJSON(text, fresh.Interface()); err != nil {
		return err
	}
	v.Elem().Set(fresh.Elem())
	return nil
}
