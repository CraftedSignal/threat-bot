package llm

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const smokePrompt = `Return exactly this JSON object and no other text: {"ok":true}`

// SmokeCheck verifies that a configured LLM client can complete a minimal JSON
// generation request.
func SmokeCheck(ctx context.Context, client Client) error {
	var out struct {
		OK bool `json:"ok"`
	}
	if err := client.GenerateJSON(ctx, smokePrompt, "You are a dependency health check.", &out); err != nil {
		return err
	}
	if !out.OK {
		return fmt.Errorf("unexpected health check response")
	}
	return nil
}

// HealthMonitor records the latest success/failure per configured LLM role.
type HealthMonitor struct {
	mu     sync.RWMutex
	models map[string]modelHealth
	now    func() time.Time
}

type modelHealth struct {
	Role              string
	Model             string
	LastOK            time.Time
	LastError         time.Time
	LastErrorMessage  string
	ConsecutiveErrors int
}

// HealthStatus is the aggregate dependency state exposed by readiness.
type HealthStatus struct {
	OK      bool
	Message string
	Models  []ModelStatus
}

// ModelStatus is the public status for one LLM role/model pair.
type ModelStatus struct {
	Role              string
	Model             string
	LastOK            time.Time
	LastError         time.Time
	LastErrorMessage  string
	ConsecutiveErrors int
	OK                bool
}

// NewHealthMonitor creates a dependency health monitor.
func NewHealthMonitor() *HealthMonitor {
	return &HealthMonitor{
		models: make(map[string]modelHealth),
		now:    time.Now,
	}
}

// Wrap records successes and failures for calls made through client.
func (m *HealthMonitor) Wrap(role, model string, client Client) Client {
	m.Register(role, model)
	return &trackingClient{
		role:    role,
		model:   model,
		inner:   client,
		monitor: m,
	}
}

// Register adds a model role to the readiness set.
func (m *HealthMonitor) Register(role, model string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := healthKey(role, model)
	if _, ok := m.models[key]; ok {
		return
	}
	m.models[key] = modelHealth{Role: role, Model: model}
}

// RecordOK records a successful model call.
func (m *HealthMonitor) RecordOK(role, model string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := healthKey(role, model)
	h := m.models[key]
	h.Role = role
	h.Model = model
	h.LastOK = m.now()
	h.ConsecutiveErrors = 0
	h.LastErrorMessage = ""
	m.models[key] = h
}

// RecordError records a failed model call.
func (m *HealthMonitor) RecordError(role, model string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := healthKey(role, model)
	h := m.models[key]
	h.Role = role
	h.Model = model
	h.LastError = m.now()
	if err != nil {
		h.LastErrorMessage = ErrorStatus(err)
	}
	h.ConsecutiveErrors++
	m.models[key] = h
}

// Status returns unhealthy when any registered model has not passed a smoke
// check/call yet, or when its latest event is a failure.
func (m *HealthMonitor) Status() HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.models))
	for key := range m.models {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	status := HealthStatus{OK: true}
	var problems []string
	for _, key := range keys {
		h := m.models[key]
		ms := ModelStatus{
			Role:              h.Role,
			Model:             h.Model,
			LastOK:            h.LastOK,
			LastError:         h.LastError,
			LastErrorMessage:  h.LastErrorMessage,
			ConsecutiveErrors: h.ConsecutiveErrors,
			OK:                !h.LastOK.IsZero() && !h.LastError.After(h.LastOK),
		}
		if !ms.OK {
			status.OK = false
			if h.LastOK.IsZero() && h.LastError.IsZero() {
				problems = append(problems, "not_checked")
			} else {
				problems = append(problems, "unavailable")
			}
		}
		status.Models = append(status.Models, ms)
	}

	if status.OK {
		status.Message = "ok"
	} else {
		status.Message = "unavailable"
		if len(problems) > 0 && problems[0] == "not_checked" {
			status.Message = "not_checked"
		}
	}
	return status
}

type trackingClient struct {
	role    string
	model   string
	inner   Client
	monitor *HealthMonitor
}

func (c *trackingClient) Generate(ctx context.Context, prompt, system string) (string, error) {
	resp, err := c.inner.Generate(ctx, prompt, system)
	c.record(err)
	return resp, err
}

func (c *trackingClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	err := c.inner.GenerateJSON(ctx, prompt, system, out)
	c.record(err)
	return err
}

func (c *trackingClient) GenerateStructured(ctx context.Context, prompt, system string, schema *Schema, out any) error {
	err := c.inner.GenerateStructured(ctx, prompt, system, schema, out)
	c.record(err)
	return err
}

func (c *trackingClient) record(err error) {
	// A truncated, blocked or undecodable answer is a content outcome: the
	// dependency answered. It must not flip readiness or log "unhealthy".
	var finish *FinishReasonError
	var output *OutputError
	if errors.As(err, &finish) || errors.As(err, &output) {
		return
	}
	if err != nil {
		c.monitor.RecordError(c.role, c.model, err)
		return
	}
	c.monitor.RecordOK(c.role, c.model)
}

func healthKey(role, model string) string {
	return role + "\x00" + model
}
