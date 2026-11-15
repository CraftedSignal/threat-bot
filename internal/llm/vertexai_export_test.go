package llm

import "net/http"

// NewVertexAIClientForTest exposes transport injection to external-package
// integration tests without adding a production client API or requiring ADC.
func NewVertexAIClientForTest(hc *http.Client) *VertexAIClient {
	return newVertexAIClientWithHTTP("grounding-schema-test", "global", "offline-model", hc)
}
