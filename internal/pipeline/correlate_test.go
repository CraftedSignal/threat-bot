package pipeline

import (
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
)

func TestCorrelateActorMatch(t *testing.T) {
	briefs := []correlationBrief{
		{ID: "a", ThreatActor: "APT29", Tags: []string{"russia"}},
		{ID: "b", ThreatActor: "apt29", Tags: []string{"phishing"}},
		{ID: "c", ThreatActor: "Lazarus Group", Tags: []string{"north-korea"}},
	}

	tags := correlateBriefs(context.Background(), briefs)

	// a and b share actor "apt29".
	if len(tags["a"]) == 0 || tags["a"][0] != "apt29" {
		t.Errorf("expected apt29 tag on brief a, got %v", tags["a"])
	}
	if len(tags["b"]) == 0 || tags["b"][0] != "apt29" {
		t.Errorf("expected apt29 tag on brief b, got %v", tags["b"])
	}
	// c should not get apt29.
	for _, tag := range tags["c"] {
		if tag == "apt29" {
			t.Error("brief c should not get apt29 tag")
		}
	}
}

func TestCorrelateActorSingleBriefNoTag(t *testing.T) {
	briefs := []correlationBrief{
		{ID: "a", ThreatActor: "Lazarus Group"},
	}
	tags := correlateBriefs(context.Background(), briefs)
	if len(tags["a"]) > 0 {
		t.Errorf("single brief should not get actor tag, got %v", tags["a"])
	}
}

func TestCorrelateCVEOverlap(t *testing.T) {
	briefs := []correlationBrief{
		{ID: "a", CVEs: []string{"CVE-2024-1234", "CVE-2024-5678"}},
		{ID: "b", CVEs: []string{"CVE-2024-1234"}},
		{ID: "c", CVEs: []string{"CVE-2024-9999"}},
	}

	tags := correlateBriefs(context.Background(), briefs)

	// a and b share CVE-2024-1234.
	assertHasTag(t, tags["a"], "cve-2024-1234")
	assertHasTag(t, tags["b"], "cve-2024-1234")
	// CVE-2024-5678 only in one brief — no tag.
	assertNoTag(t, tags["a"], "cve-2024-5678")
	// c has unique CVE — no tag from it.
	assertNoTag(t, tags["c"], "cve-2024-9999")
}

func TestCorrelateTTPCluster(t *testing.T) {
	briefs := []correlationBrief{
		{ID: "a", TechniqueIDs: []string{"T1059", "T1053", "T1047", "T1106"}},
		{ID: "b", TechniqueIDs: []string{"T1059", "T1053", "T1047"}},
		{ID: "c", TechniqueIDs: []string{"T1566", "T1190"}},
	}

	tags := correlateBriefs(context.Background(), briefs)

	// a and b share 3 techniques (all execution-related).
	if len(tags["a"]) == 0 {
		t.Fatal("expected TTP cluster tag on brief a")
	}
	if len(tags["b"]) == 0 {
		t.Fatal("expected TTP cluster tag on brief b")
	}
	// The tag should be "execution" (dominant tactic for T1059, T1053, T1047).
	assertHasTag(t, tags["a"], "execution")
	assertHasTag(t, tags["b"], "execution")
	// c shares <3 techniques with anyone.
	if len(tags["c"]) > 0 {
		t.Errorf("brief c should not get TTP tag, got %v", tags["c"])
	}
}

func TestCorrelateDeduplication(t *testing.T) {
	briefs := []correlationBrief{
		{ID: "a", ThreatActor: "APT29", Tags: []string{"apt29"}},
		{ID: "b", ThreatActor: "APT29", Tags: []string{}},
	}

	tags := correlateBriefs(context.Background(), briefs)

	// a already has apt29 tag — should not get it again.
	if len(tags["a"]) > 0 {
		t.Errorf("brief a already has apt29, should not get duplicate, got %v", tags["a"])
	}
	// b should get it.
	assertHasTag(t, tags["b"], "apt29")
}

// --- LLM cluster naming tests ---

type mockTagCache struct {
	tags map[string]string
}

func (m *mockTagCache) GetCorrelationTag(hash string) (string, error) {
	return m.tags[hash], nil
}

func (m *mockTagCache) SaveCorrelationTag(hash, tag string) error {
	m.tags[hash] = tag
	return nil
}

type mockLLM struct {
	response string
	err      error
}

func (m *mockLLM) Generate(_ context.Context, _, _ string) (string, error) {
	return m.response, m.err
}

func (m *mockLLM) GenerateJSON(_ context.Context, _, _ string, _ any) error {
	return nil
}

func TestClusterNamerLLM(t *testing.T) {
	cache := &mockTagCache{tags: make(map[string]string)}
	namer := &clusterNamer{
		db:  cache,
		llm: &mockLLM{response: "  credential-harvesting  "},
	}

	tag := namer.Name(context.Background(), []string{"T1003", "T1110", "T1555"})
	if tag != "credential-harvesting" {
		t.Errorf("expected credential-harvesting, got %q", tag)
	}

	// Should be cached now.
	h := hashTechniques([]string{"T1003", "T1110", "T1555"})
	if cache.tags[h] != "credential-harvesting" {
		t.Error("tag not cached")
	}
}

func TestClusterNamerCacheHit(t *testing.T) {
	ids := []string{"T1059", "T1053", "T1047"}
	h := hashTechniques(ids)
	cache := &mockTagCache{tags: map[string]string{h: "cached-tag"}}
	namer := &clusterNamer{
		db:  cache,
		llm: &mockLLM{response: "should-not-use"},
	}

	tag := namer.Name(context.Background(), ids)
	if tag != "cached-tag" {
		t.Errorf("expected cached-tag, got %q", tag)
	}
}

func TestClusterNamerFallback(t *testing.T) {
	cache := &mockTagCache{tags: make(map[string]string)}
	namer := &clusterNamer{
		db:  cache,
		llm: nil, // no LLM
	}

	tag := namer.Name(context.Background(), []string{"T1059", "T1053", "T1047"})
	if tag != "execution" {
		t.Errorf("expected execution fallback, got %q", tag)
	}
}

func TestCorrelateBriefsWithNamer(t *testing.T) {
	cache := &mockTagCache{tags: make(map[string]string)}
	namer := &clusterNamer{
		db:  cache,
		llm: &mockLLM{response: "script-execution"},
	}

	briefs := []correlationBrief{
		{ID: "a", TechniqueIDs: []string{"T1059", "T1053", "T1047"}},
		{ID: "b", TechniqueIDs: []string{"T1059", "T1053", "T1047"}},
	}

	tags := correlateBriefs(context.Background(), briefs, namer)

	assertHasTag(t, tags["a"], "script-execution")
	assertHasTag(t, tags["b"], "script-execution")
}

func TestParseBriefForCorrelation(t *testing.T) {
	yamlStr := `title: Test Brief
threat_actor: APT29
tags:
  - russia
  - phishing
references:
  - https://example.com/CVE-2024-1234
summary: This involves CVE-2024-5678
content: Some content about threats
ttps:
  - technique_id: T1059
    technique_name: Command and Scripting Interpreter
    tactic_id: TA0002
    tactic_name: Execution
  - technique_id: T1053
    subtechnique_id: T1053.005
    technique_name: Scheduled Task
    tactic_id: TA0002
    tactic_name: Execution
`

	cb := parseBriefForCorrelation("test-1", yamlStr)

	if cb.ID != "test-1" {
		t.Errorf("expected ID test-1, got %s", cb.ID)
	}
	if cb.ThreatActor != "APT29" {
		t.Errorf("expected APT29, got %s", cb.ThreatActor)
	}
	if len(cb.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(cb.Tags))
	}
	if len(cb.CVEs) != 2 {
		t.Errorf("expected 2 CVEs, got %v", cb.CVEs)
	}
	// T1053 has subtechnique T1053.005 — should use subtechnique.
	assertContains(t, cb.TechniqueIDs, "T1059")
	assertContains(t, cb.TechniqueIDs, "T1053.005")
}

func TestNormalizeTag(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"APT29", "apt29"},
		{"Lazarus Group", "lazarus-group"},
		{"some_tag", "some-tag"},
		{"  spaced  ", "spaced"},
	}
	for _, tc := range cases {
		got := normalizeTag(tc.in)
		if got != tc.want {
			t.Errorf("normalizeTag(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFallbackTTPTag(t *testing.T) {
	tag := fallbackTTPTag([]string{"T1059", "T1053", "T1047"})
	if tag != "execution" {
		t.Errorf("expected execution, got %s", tag)
	}

	tag = fallbackTTPTag([]string{"T1566", "T1190", "T1133"})
	if tag != "initial-access" {
		t.Errorf("expected initial-access, got %s", tag)
	}

	tag = fallbackTTPTag([]string{"TXXX"})
	if tag != "ttp-cluster" {
		t.Errorf("expected ttp-cluster fallback, got %s", tag)
	}
}

func TestHashTechniques(t *testing.T) {
	// Order should not matter.
	h1 := hashTechniques([]string{"T1059", "T1053", "T1047"})
	h2 := hashTechniques([]string{"T1047", "T1059", "T1053"})
	if h1 != h2 {
		t.Error("hash should be order-independent")
	}
}

// --- helpers ---

func assertHasTag(t *testing.T, tags []string, want string) {
	t.Helper()
	for _, tag := range tags {
		if tag == want {
			return
		}
	}
	t.Errorf("expected tag %q in %v", want, tags)
}

func assertNoTag(t *testing.T, tags []string, unwanted string) {
	t.Helper()
	for _, tag := range tags {
		if tag == unwanted {
			t.Errorf("did not expect tag %q in %v", unwanted, tags)
			return
		}
	}
}

func assertContains(t *testing.T, slice []string, want string) {
	t.Helper()
	for _, s := range slice {
		if s == want {
			return
		}
	}
	t.Errorf("expected %q in %v", want, slice)
}

// The technique index must tag exactly the pairs the all-pairs comparison
// tags, in the same order.
func TestCorrelateBriefsMatchesAllPairsComparison(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	pool := []string{"T1059", "T1053", "T1047", "T1106", "T1566", "T1190", "T1078", "T1021", "T1486", "T1071", "T1105", "T1027"}
	briefs := make([]correlationBrief, 300)
	for i := range briefs {
		b := correlationBrief{ID: fmt.Sprintf("b%d", i)}
		for _, tid := range pool {
			if rng.IntN(3) == 0 {
				b.TechniqueIDs = append(b.TechniqueIDs, tid)
			}
		}
		if i%50 == 0 && len(b.TechniqueIDs) > 0 {
			// Repeated technique IDs must not change which pairs are tagged.
			b.TechniqueIDs = append(b.TechniqueIDs, b.TechniqueIDs[0])
		}
		briefs[i] = b
	}

	want := make(map[string][]string)
	for i := 0; i < len(briefs); i++ {
		for j := i + 1; j < len(briefs); j++ {
			shared := intersect(briefs[i].TechniqueIDs, briefs[j].TechniqueIDs)
			if len(shared) < 3 {
				continue
			}
			tag := fallbackTTPTag(shared)
			if tag == "" {
				continue
			}
			for _, idx := range []int{i, j} {
				if !briefHasTag(briefs[idx], tag) {
					want[briefs[idx].ID] = append(want[briefs[idx].ID], tag)
				}
			}
		}
	}

	got := correlateBriefs(context.Background(), briefs)
	if len(want) == 0 {
		t.Fatal("generated briefs produced no TTP pairs; the comparison proves nothing")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("correlateBriefs tagged %d briefs, all-pairs comparison tagged %d", len(got), len(want))
	}
}
