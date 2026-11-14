package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

const qualitySystemPrompt = `You are a threat intelligence analyst evaluating incoming content for a detection engineering team.

Score each item on three dimensions (1-5 scale):

- credibility: Is this from a reputable source with concrete evidence? (1=speculation/hype, 5=verified advisory with IOCs)
- actionability: Can defenders take a concrete, source-supported response? A confirmed compromise or critical vendor/CERT notice can warrant inventorying affected assets, preparing a patch, or updating trust stores before exploit details exist (3). Specific TTPs and log sources suitable for detections score 5. Product announcements, feature releases, integration/support announcements, weekly summaries, news roundups, opinion pieces, and general awareness posts score 1.
- novelty: Is this a new threat/technique or a rehash? (1=old news repeated, 5=first disclosure of new TTP)

Also provide a one-line summary of your assessment.

Respond in JSON: {"credibility": N, "actionability": N, "novelty": N, "summary": "..."}`

const qualityPrompt = `Evaluate this threat intelligence item:

Title: %s
Source: %s
Content (first 8000 chars):
%s`

type QualityScore struct {
	Credibility   float64 `json:"credibility"`
	Actionability float64 `json:"actionability"`
	Novelty       float64 `json:"novelty"`
	Summary       string  `json:"summary"`
}

func (q *QualityScore) Average() float64 {
	// Downweight novelty: supply chain and APT campaigns reuse known TTPs but
	// remain fully actionable. Credibility and actionability are the detection
	// engineering team's primary signal.
	return 0.4*q.Credibility + 0.4*q.Actionability + 0.2*q.Novelty
}

// bypassQualitySources are authoritative advisory sources whose items bypass the LLM
// quality gate. These sources have already verified exploitation before publishing,
// so the actionability floor and score threshold are irrelevant — brief assembly
// and the grounding check still run.
var bypassQualitySources = map[string]bool{
	"cisa-kev": true,
}

// An authoritative emergency notice may have no public exploit path yet.
// Preserve the notice for grounded analysis instead of letting the
// detection-focused quality rubric discard it for missing technical detail.
func isAuthoritativeSecurityNotice(item scraper.RawItem) bool {
	u, err := url.Parse(item.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || getSourceAuthority(item.Source) < 4 {
		return false
	}
	title := strings.ToLower(item.Title)
	return strings.Contains(title, "critical") || strings.Contains(title, "compromis") ||
		strings.Contains(title, "vulnerab") || strings.Contains(title, "security release") ||
		strings.Contains(title, "security advisory") || strings.Contains(title, "security incident")
}

func bypassQuality(item scraper.RawItem) bool {
	return bypassQualitySources[item.Source] || isAuthoritativeSecurityNotice(item)
}

// A single low model score must not permanently bury a fresh high-impact
// disclosure. Re-evaluate it during the first three days, then let the normal
// seen-item path end retries if no better source or model decision arrives.
func retryCriticalQualityRejection(item scraper.RawItem, now time.Time) bool {
	if item.PublishedAt.IsZero() || item.PublishedAt.After(now) || now.Sub(item.PublishedAt) > 72*time.Hour {
		return false
	}
	if getSourceAuthority(item.Source) < 3 && item.Source != "oss-security" {
		return false
	}
	title := strings.ToLower(item.Title)
	return strings.Contains(title, "critical") || strings.Contains(title, "compromis") || strings.Contains(title, "emergency")
}

type QualityGate struct {
	client         llm.Client
	fallbackClient llm.Client
	threshold      float64
	logger         *slog.Logger
}

func NewQualityGate(client llm.Client, threshold float64) *QualityGate {
	return &QualityGate{client: client, threshold: threshold}
}

func NewQualityGateWithFallback(client, fallbackClient llm.Client, threshold float64, logger *slog.Logger) *QualityGate {
	return &QualityGate{
		client:         client,
		fallbackClient: fallbackClient,
		threshold:      threshold,
		logger:         logger,
	}
}

func (g *QualityGate) Evaluate(ctx context.Context, item scraper.RawItem) (float64, bool, error) {
	if bypassQuality(item) {
		// Return max score so the confidence multiplier in the pipeline cannot push it below threshold.
		return 5.0, true, nil
	}

	req := qualityRequest(item)

	var score QualityScore
	if err := g.client.GenerateJSON(ctx, req.Prompt, req.System, &score); err != nil {
		if g.fallbackClient == nil {
			return 0, false, fmt.Errorf("quality gate LLM call: %w", err)
		}
		if g.logger != nil {
			level := slog.LevelWarn
			if llm.IsModelUnavailable(err) {
				level = slog.LevelError
			}
			g.logger.Log(ctx, level, "quality gate fast model failed; retrying primary model", "error", err)
		}
		if fallbackErr := g.fallbackClient.GenerateJSON(ctx, req.Prompt, req.System, &score); fallbackErr != nil {
			return 0, false, fmt.Errorf("quality gate fallback LLM call: %w (fast error: %v)", fallbackErr, err)
		}
	}

	return g.evaluateScore(score)
}

func qualityRequest(item scraper.RawItem) llm.Request {
	return llm.Request{Prompt: fmt.Sprintf(qualityPrompt, item.Title, item.Source, smartTruncate(item.Content, 8000)), System: qualitySystemPrompt, JSON: true}
}

func (g *QualityGate) evaluateScore(score QualityScore) (float64, bool, error) {
	avg := score.Average()
	// Hard floor: reject items with very low actionability regardless of average.
	// This filters news roundups, weekly summaries, and opinion pieces that score
	// high on credibility but have no detectable TTPs.
	if score.Actionability < 2 {
		return avg, false, nil
	}
	return avg, avg >= g.threshold, nil
}
