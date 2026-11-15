package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	// Schema identifies the expected decoded JSON shape in the persistent cache.
	// GenerateJSON keeps its existing wire format; schema-constrained generation uses GenerateStructured.
	Schema   *Schema
	Metadata CallMetadata
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
	model      string
	store      CacheStore
	pending    map[string]error

	mu        sync.Mutex
	answers   map[string]string
	served    map[string]struct{}
	requested int
}

var _ Prefetcher = (*PrefetchClient)(nil)

// NewPrefetchClient wraps live. At most maxPrompts requests go into one batch;
// the rest run live.
func NewPrefetchClient(live Client, batch *VertexBatch, maxPrompts int, logger *slog.Logger) *PrefetchClient {
	c := newPrefetchClient(live, batch, maxPrompts, logger)
	if cached, ok := live.(*cachedClient); ok {
		c.WithCache(cached.model, cached.store)
		if store, ok := cached.store.(BatchJobStore); ok {
			batch.WithJobStore(store)
		}
	}
	return c
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
		logger:     loggerOrDefault(logger),
		pending:    make(map[string]error),
		answers:    make(map[string]string),
		served:     make(map[string]struct{}),
	}
}

// WithCache shares decoded JSON results with the online cache across rounds and restarts.
func (c *PrefetchClient) WithCache(model string, store CacheStore) *PrefetchClient {
	c.model, c.store = model, store
	return c
}

func (c *PrefetchClient) Prefetch(ctx context.Context, reqs []Request) {
	if len(reqs) == 0 {
		return
	}
	if ctx.Err() != nil {
		c.logger.Info("batch prefetch interrupted by shutdown; no requests submitted", "requests", len(reqs))
		return
	}
	// Persistent hits are removed before minimum/maximum batch-size decisions.
	missing := make([]Request, 0, len(reqs))
	seen := map[string]bool{}
	for _, r := range reqs {
		if ctx.Err() != nil {
			return
		}
		key := requestKey(r.vertexRequest())
		if seen[key] {
			continue
		}
		seen[key] = true
		rctx := WithCallMetadata(ctx, r.Metadata)
		if r.JSON {
			if text, ok := readPersistent(rctx, c.store, c.logger, c.model, persistentRequestKey(c.model, r)); ok {
				c.mu.Lock()
				c.answers[key] = text
				c.mu.Unlock()
				continue
			}
		}
		missing = append(missing, r)
	}
	if len(missing) == 0 {
		return
	}
	if c.maxPrompts > 0 && len(missing) > c.maxPrompts {
		c.logger.Warn("batch prefetch over max_prompts; the rest run live", "requests", len(missing), "max_prompts", c.maxPrompts)
		missing = missing[:c.maxPrompts]
	}
	start := time.Now()
	var answers map[string]string
	var err error
	if len(missing) < c.minPrompts {
		c.logger.Info("batch prefetch skipped; too few prompts to batch, running live", "requests", len(missing), "min_prompts", c.minPrompts)
		if recoverer, ok := c.runner.(interface {
			recover(context.Context, []Request) (map[string]string, error)
		}); ok {
			answers, err = recoverer.recover(ctx, missing)
		} else {
			return
		}
	} else {
		answers, err = c.runner.run(ctx, missing)
	}
	c.mu.Lock()
	for key, text := range answers {
		c.answers[key] = text
		delete(c.pending, key)
	}
	var pending *PendingBatchError
	if errors.As(err, &pending) {
		for _, key := range pending.Keys {
			c.pending[key] = pending
		}
	}
	c.requested += len(missing)
	c.mu.Unlock()
	if err != nil {
		if pending != nil {
			var review *BatchReviewError
			if errors.As(err, &review) {
				c.logger.Error("batch requests require review; inference blocked", "reference", review.Reference, "reason", review.Reason, "requests", len(pending.Keys), "answered", len(answers))
			} else {
				c.logger.Info("batch requests remain pending; live duplication deferred", "requests", len(pending.Keys), "answered", len(answers))
			}
			return
		}
		if ctx.Err() != nil {
			c.logger.Info("batch prefetch interrupted by shutdown; prompts run live", "requests", len(missing))
			return
		}
		c.logger.Warn("batch prefetch failed; prompts run live", "requests", len(missing), "duration", time.Since(start).Round(time.Second), "error_kind", errorKind(err))
		return
	}
	c.logger.Info("batch prefetch finished", "requests", len(missing), "answered", len(answers), "duration", time.Since(start).Round(time.Second))
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
	if !ok && req.JSON {
		text, ok = readPersistent(WithCallMetadata(context.Background(), req.Metadata), c.store, c.logger, c.model, persistentRequestKey(c.model, req))
		if ok && decodeInto(text, out) == nil {
			c.mu.Lock()
			c.answers[requestKey(req.vertexRequest())] = text
			c.mu.Unlock()
			return true
		}
		return false
	}
	if !ok || decodeInto(text, out) != nil {
		return false
	}
	c.persistDecoded(context.Background(), req, out)
	return true
}

func (c *PrefetchClient) Generate(ctx context.Context, prompt, system string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := c.pendingError(Request{Prompt: prompt, System: system}); err != nil {
		return "", err
	}
	if text, ok := c.answer(Request{Prompt: prompt, System: system}); ok {
		return text, nil
	}
	return c.live.Generate(ctx, prompt, system)
}

func (c *PrefetchClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	req := Request{Prompt: prompt, System: system, JSON: true, Schema: jsonResponseSchema(out)}
	unusableCompletedAnswer := false
	if text, ok := c.answer(req); ok {
		err := decodeInto(text, out)
		if err == nil {
			c.persistDecoded(ctx, req, out)
			return nil
		}
		// A malformed batch answer must not cost the item; ask the live model.
		c.logger.Warn("prefetched answer unusable; asking the live model", "error_kind", "decode")
		c.mu.Lock()
		delete(c.answers, requestKey(req.vertexRequest()))
		c.mu.Unlock()
		// Retain the completed association until a valid replacement is durable.
		// Deleting it now would let another pod buy a new batch while this retry runs.
		unusableCompletedAnswer = true
	}
	if !unusableCompletedAnswer {
		if err := c.pendingError(req); err != nil {
			return err
		}
	}
	if err := fillFresh(out, func(fresh any) error { return c.live.GenerateJSON(ctx, prompt, system, fresh) }); err != nil {
		return err
	}
	c.persistDecoded(ctx, req, out)
	return nil
}

// GenerateStructured is always live: structured answers are not batched.
func (c *PrefetchClient) GenerateStructured(ctx context.Context, prompt, system string, schema *Schema, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.live.GenerateStructured(ctx, prompt, system, schema, out)
}

// Release drops the cache and reports how much of what was paid for got used.
func (c *PrefetchClient) Release() {
	c.mu.Lock()
	requested, answered, served := c.requested, len(c.answers), len(c.served)
	c.pending = make(map[string]error)
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
	return fillFresh(out, func(fresh any) error { return unmarshalJSON(text, fresh) })
}
func fillFresh(out any, fill func(any) error) error {
	v := reflect.ValueOf(out)
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("model response target must be a non-nil pointer")
	}
	fresh := reflect.New(v.Elem().Type())
	if err := fill(fresh.Interface()); err != nil {
		return err
	}
	if validator, ok := fresh.Interface().(ValidatedResponse); ok {
		if err := validator.ValidateLLMResponse(); err != nil {
			return fmt.Errorf("invalid model response: %w", err)
		}
	}
	v.Elem().Set(fresh.Elem())
	return nil
}
func (c *PrefetchClient) pendingError(req Request) error {
	c.mu.Lock()
	pending := c.pending[requestKey(req.vertexRequest())]
	c.mu.Unlock()
	if pending != nil {
		return pending
	}
	// Cover requests omitted by max_prompts or callers that did not prefetch.
	if jobs, ok := c.store.(BatchJobStore); ok {
		ref, exists, err := jobs.GetBatchJob(persistentRequestKey(c.model, req))
		if exists {
			state := BatchJobReferenceState(ref)
			if state == "review_required" || state == "abandoned" {
				return reviewRequests([]Request{req}, ref, state)
			}
		}
		if exists || err != nil {
			return pendingRequests([]Request{req}, err)
		}
	}
	return nil
}
func (c *PrefetchClient) persistDecoded(ctx context.Context, req Request, out any) {
	ctx = WithCallMetadata(ctx, req.Metadata)
	if !req.JSON || c.store == nil {
		return
	}
	if req.Schema == nil {
		req.Schema = jsonResponseSchema(out)
	}
	key := persistentRequestKey(c.model, req)
	if encoded, err := json.Marshal(out); err == nil && writePersistent(ctx, c.store, c.logger, c.model, key, string(encoded)) {
		if jobs, ok := c.store.(BatchJobStore); ok {
			ref, exists, err := jobs.GetBatchJob(key)
			if err != nil {
				cacheLog(ctx, c.logger, c.model, key, "job_cleanup_error")
				return
			}
			if !exists || BatchJobReferenceState(ref) != "remote" {
				return
			}
			if err := updateOwnedBatchReference(jobs, []string{key}, ref, ""); err != nil {
				cacheLog(ctx, c.logger, c.model, key, "job_cleanup_error")
			}
		}
	}
}
