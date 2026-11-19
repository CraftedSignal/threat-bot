package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// l3SourceAllowlist gates which scraper sources can promote a merge to
// the L3 ("update dispatch") tier. Anything else may still mark the
// brief as updated visually but won't email subscribers, regardless of
// what changed. The list is the set of feeds we trust to be both
// authoritative and low-false-positive on KEV / exploitation /
// severity-critical signals.
var l3SourceAllowlist = map[string]struct{}{
	"nvd":                    {},
	"cisa":                   {},
	"cisa-kev":               {},
	"msrc":                   {},
	"cisco-psirt":            {},
	"ghsa":                   {},
	"mandiant":               {},
	"talos":                  {},
	"unit42":                 {},
	"volexity":               {},
	"sophos-xops":            {},
	"crowdstrike":            {},
	"microsoft-threat-intel": {},
	"google-project-zero":    {},
	// First-party sensor telemetry: the primary public source for observed
	// exploitation attempts, which CISA KEV counts as exploitation.
	"greynoise": {},
	"rapid7":    {},
	// Security newsrooms are where exploitation reports usually break
	// (Java4Shell's attempts reached the feed through SecurityWeek). A merged
	// exploitation claim must quote its source and pass grounding, and a
	// brief turns exploited once, so this adds at most a few updates a week.
	"securityweek":     {},
	"the-hacker-news":  {},
	"bleepingcomputer": {},
	"therecord":        {},
}

// dispatchPayload mirrors the feed-notifier /dispatch wire format. We
// keep this tiny and string-keyed so a schema change on the receiving
// side that adds optional fields doesn't break threat-bot's send path.
type dispatchPayload struct {
	Briefs []dispatchBrief `json:"briefs"`
}

type dispatchBrief struct {
	Slug          string   `json:"slug"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	URL           string   `json:"url"`
	Type          string   `json:"type"`
	Severity      string   `json:"severity"`
	Actors        []string `json:"actors,omitempty"`
	Vendors       []string `json:"vendors,omitempty"`
	Products      []string `json:"products,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Exploited     bool     `json:"exploited,omitempty"`
	HasPOC        bool     `json:"has_poc,omitempty"`
	IsUpdate      bool     `json:"is_update,omitempty"`
	UpdateSummary string   `json:"update_summary,omitempty"`
}

// PublicNotificationFields are the fields subscribers filter on, exactly as a
// brief's published front matter carries them. New-brief notifications read
// them from the published file (Site Deploy); update notifications must use
// the same projection, or the same subscription matches one and not the other.
type PublicNotificationFields struct {
	Slug        string   `yaml:"slug"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Type        string   `yaml:"type"`
	Severities  []string `yaml:"severities"`
	Actors      []string `yaml:"actors"`
	Vendors     []string `yaml:"vendors"`
	Products    []string `yaml:"products"`
	Tags        []string `yaml:"tags"`
	Exploited   bool     `yaml:"exploited"`
	HasPOC      bool     `yaml:"has_poc"`
}

// notificationProjector renders a draft's public notification fields. The
// publisher implements it from the front matter it publishes.
type notificationProjector interface {
	PublicNotificationFields(briefYAML string) (PublicNotificationFields, error)
}

// withPublicFields replaces the filterable fields with the published
// projection. The draft has no public type and keeps vendors, products and
// the actor under internal names, so a payload built from it alone carried an
// empty type and matched no subscription filtering on type.
func (b dispatchBrief) withPublicFields(fields PublicNotificationFields, siteURL string) dispatchBrief {
	if slug := strings.TrimSpace(fields.Slug); slug != "" {
		b.Slug = slug
		if siteURL != "" {
			b.URL = strings.TrimRight(siteURL, "/") + "/briefs/" + slug + "/"
		}
	}
	if strings.TrimSpace(fields.Title) != "" {
		b.Title = fields.Title
	}
	if strings.TrimSpace(fields.Description) != "" {
		b.Description = fields.Description
	}
	b.Type = fields.Type
	if len(fields.Severities) > 0 && strings.TrimSpace(fields.Severities[0]) != "" {
		b.Severity = fields.Severities[0]
	}
	b.Actors, b.Vendors, b.Products, b.Tags = fields.Actors, fields.Vendors, fields.Products, fields.Tags
	b.Exploited, b.HasPOC = fields.Exploited, fields.HasPOC
	return b
}

// maybeDispatchL3Update fires the notifier dispatch path for an L3
// merge event when (a) the source is in the allowlist, (b) the per-brief
// cooldown has elapsed, and (c) the notifier endpoint is configured.
// Failures are logged and swallowed — the visual update on the site is
// the primary signal; the email is a nice-to-have.
func (p *Pipeline) maybeDispatchL3Update(ctx context.Context, draftID string, summary string, sourceName string, siteURL string) {
	if p.notifierURL == "" || p.notifierToken == "" {
		return
	}
	if _, ok := l3SourceAllowlist[strings.ToLower(strings.TrimSpace(sourceName))]; !ok {
		p.logger.Info("L3 update suppressed: source not in allowlist",
			"draft_id", draftID, "source", sourceName)
		return
	}
	draft, err := p.db.GetDraft(draftID)
	if err != nil || draft == nil {
		return
	}
	cooldown := p.notifierCooldown
	if cooldown == 0 {
		cooldown = 6 * time.Hour
	}
	if draft.LastL3Dispatch != nil && time.Since(*draft.LastL3Dispatch) < cooldown {
		p.logger.Info("L3 update suppressed: cooldown",
			"draft_id", draftID,
			"last_dispatch", draft.LastL3Dispatch,
			"cooldown", cooldown)
		return
	}

	brief, err := dispatchBriefFromDraftYAML(draft.BriefYAML, summary, siteURL)
	if err != nil {
		p.logger.Warn("L3 dispatch payload build failed", "draft_id", draftID, "error", err)
		return
	}
	if projector, ok := p.publisher.(notificationProjector); ok {
		fields, err := projector.PublicNotificationFields(draft.BriefYAML)
		if err != nil {
			p.logger.Warn("L3 dispatch public projection failed; sending draft fields", "draft_id", draftID, "error", err)
		} else {
			brief = brief.withPublicFields(fields, siteURL)
		}
	}
	var lifecycle struct {
		ClaimState string `yaml:"claim_state"`
	}
	_ = yaml.Unmarshal([]byte(draft.BriefYAML), &lifecycle)
	if lifecycle.ClaimState == "disputed" || lifecycle.ClaimState == "retracted" {
		p.logger.Info("L3 update suppressed: inactive rumour lifecycle", "draft_id", draftID, "claim_state", lifecycle.ClaimState)
		return
	}

	if err := postDispatch(ctx, p.notifierURL, p.notifierToken, dispatchPayload{Briefs: []dispatchBrief{brief}}); err != nil {
		p.logger.Warn("L3 dispatch POST failed", "draft_id", draftID, "error", err)
		return
	}
	if err := p.db.RecordL3Dispatch(draftID, time.Now().UTC()); err != nil {
		p.logger.Warn("L3 dispatch stamp failed", "draft_id", draftID, "error", err)
		return
	}
	p.logger.Info("L3 update dispatched", "draft_id", draftID, "summary", summary)
}

// UpdateNotification is the update payload one draft would send, with its
// filterable fields taken from the published projection when the publisher
// provides one (it always does in production).
func UpdateNotification(draftYAML, summary, siteURL string, publisher BriefPublisher) (dispatchBrief, error) {
	brief, err := dispatchBriefFromDraftYAML(draftYAML, summary, siteURL)
	if err != nil {
		return brief, err
	}
	if projector, ok := publisher.(notificationProjector); ok {
		fields, err := projector.PublicNotificationFields(draftYAML)
		if err != nil {
			return brief, err
		}
		brief = brief.withPublicFields(fields, siteURL)
	}
	return brief, nil
}

// SendUpdateNotification posts one update notification. It is the operator
// path for re-sending an update whose original dispatch was lost or wrong;
// it bypasses the source allowlist and cooldown, which gate automatic merges.
func SendUpdateNotification(ctx context.Context, notifierURL, token string, brief dispatchBrief) error {
	if notifierURL == "" || token == "" {
		return fmt.Errorf("notifier URL and dispatch token are required")
	}
	return postDispatch(ctx, notifierURL, token, dispatchPayload{Briefs: []dispatchBrief{brief}})
}

// dispatchBriefFromDraftYAML builds the JSON payload entry from a draft. It
// reads public field names where present and the draft's internal names
// (affected_vendors, affected_products, threat_actor) otherwise. The draft has
// no public type: maybeDispatchL3Update replaces the filterable fields with
// the publisher's projection whenever one is available.
func dispatchBriefFromDraftYAML(briefYAML, summary, siteURL string) (dispatchBrief, error) {
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &fm); err != nil {
		return dispatchBrief{}, err
	}
	str := func(k string) string {
		v, _ := fm[k].(string)
		return v
	}
	strList := func(k string) []string {
		raw, _ := fm[k].([]any)
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	}
	severity := str("severity")
	if severity == "" {
		if list := strList("severities"); len(list) > 0 {
			severity = list[0]
		} else {
			severity = "medium"
		}
	}
	exploited, _ := fm["exploited"].(bool)
	hasPOC, _ := fm["has_poc"].(bool)
	firstList := func(keys ...string) []string {
		for _, key := range keys {
			if list := strList(key); len(list) > 0 {
				return list
			}
		}
		return nil
	}
	actors := strList("actors")
	if actor := strings.TrimSpace(str("threat_actor")); len(actors) == 0 && actor != "" {
		actors = []string{actor}
	}
	slug := str("slug")
	url := siteURL
	if url != "" && slug != "" {
		url = strings.TrimRight(url, "/") + "/briefs/" + slug + "/"
	}
	return dispatchBrief{
		Slug:          slug,
		Title:         str("title"),
		Description:   firstNonEmpty(str("description"), str("summary")),
		URL:           url,
		Type:          str("type"),
		Severity:      severity,
		Actors:        actors,
		Vendors:       firstList("vendors", "affected_vendors"),
		Products:      firstList("products", "affected_products"),
		Tags:          strList("tags"),
		Exploited:     exploited,
		HasPOC:        hasPOC,
		IsUpdate:      true,
		UpdateSummary: summary,
	}, nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// postDispatch is the HTTP client for the /dispatch endpoint. It retries
// retryable failures (5xx, 429, network errors) with exponential backoff
// while respecting context cancellation.
func postDispatch(ctx context.Context, baseURL, token string, payload dispatchPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/dispatch"

	client := &http.Client{Timeout: 10 * time.Second}
	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

	var lastErr error
	for attempt := 0; attempt <= len(delays); attempt++ {
		if attempt > 0 {
			if err := sleepWithContext(ctx, delays[attempt-1]); err != nil {
				return err
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return errors.New("invalid notifier endpoint")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			// Request errors can include endpoint credentials or query parameters.
			lastErr = errors.New("notifier request failed")
			if errors.Is(err, context.Canceled) {
				return context.Canceled
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return context.DeadlineExceeded
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				lastErr = errors.New("notifier request timed out")
			}
			if !isRetryableNotifierError(err) {
				return lastErr
			}
			continue
		}
		// Drain a bounded amount for connection reuse; remote bodies are never errors.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		// The response status is authoritative; Close only releases resources.
		_ = resp.Body.Close()

		if resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("notifier HTTP %d", resp.StatusCode)
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return lastErr
		}
	}
	return fmt.Errorf("notifier dispatch failed after %d attempts: %w", len(delays)+1, lastErr)
}

func isRetryableNotifierError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "temporary failure") ||
		strings.Contains(msg, "no such host")
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
