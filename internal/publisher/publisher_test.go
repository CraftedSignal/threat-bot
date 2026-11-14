package publisher

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPublishBuffers(t *testing.T) {
	p := &Publisher{
		publicKey: testPublicKey,
		logger:    slog.Default(),
	}

	briefYAML := `id: "brief-2026-02-20-test"
slug: "2026-02-20-test"
title: "Test Brief"
summary: "A test"
content: The notice describes suspicious process activity that warrants host investigation.
severity: "high"
published_at: "2026-02-20T10:00:00Z"
`

	if err := p.Publish(briefYAML); err != nil {
		t.Fatal(err)
	}

	if len(p.pending) != 1 {
		t.Fatalf("expected 1 pending brief, got %d", len(p.pending))
	}
	if p.pending[0].ID != "brief-2026-02-20-test" {
		t.Errorf("expected buffered ID 'brief-2026-02-20-test', got %q", p.pending[0].ID)
	}
}

func TestPublishRejectsInvalidYAML(t *testing.T) {
	p := &Publisher{
		publicKey: testPublicKey,
		logger:    slog.Default(),
	}

	// Missing required ID field.
	err := p.Publish(`title: "No ID"`)
	if err == nil {
		t.Error("expected error for brief missing ID")
	}
}

func TestPublishRejectsMissingPublicationDateBeforeBuffering(t *testing.T) {
	p := &Publisher{publicKey: testPublicKey, logger: slog.Default()}
	err := p.Publish(`id: brief-undated
slug: undated
title: Undated advisory
summary: A summary
content: The advisory describes a reported issue that requires affected asset review.
severity: high
`)
	if err == nil || !strings.Contains(err.Error(), "published_at") {
		t.Fatalf("Publish error = %v, want missing published_at", err)
	}
	if len(p.pending) != 0 {
		t.Fatalf("pending briefs = %d, want none", len(p.pending))
	}
}

func TestPublishRejectsIncompleteCoreBriefBeforeBuffering(t *testing.T) {
	base := "id: brief-test\nslug: 2026-10-test\ntitle: Test advisory\nsummary: Verified notice\ncontent: The advisory describes a reported issue that requires affected asset review.\nseverity: high\npublished_at: \"2026-10-21T07:00:00Z\"\n"
	for _, tc := range []struct{ name, old, want string }{
		{"title", "title: Test advisory\n", "title"},
		{"summary", "summary: Verified notice\n", "summary"},
		{"slug", "slug: 2026-10-test\n", "slug"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Publisher{publicKey: testPublicKey, logger: slog.Default()}
			err := p.Publish(strings.Replace(base, tc.old, "", 1))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Publish error = %v, want %q", err, tc.want)
			}
			if len(p.pending) != 0 {
				t.Fatalf("pending briefs = %d, want none", len(p.pending))
			}
		})
	}
}

func TestPublishRejectsInvalidExploitationEvidenceBeforeBuffering(t *testing.T) {
	p := &Publisher{publicKey: testPublicKey, logger: slog.Default()}
	err := p.Publish(`id: brief-test
slug: 2026-10-test
title: Test advisory
summary: Verified notice
content: The advisory describes a reported issue; the exploitation status still requires validation.
severity: high
published_at: "2026-10-21T07:00:00Z"
exploitation_evidence:
  status: confirmed
`)
	if err == nil || !strings.Contains(err.Error(), "invalid exploitation status") {
		t.Fatalf("Publish error = %v, want invalid exploitation status", err)
	}
	if len(p.pending) != 0 {
		t.Fatalf("pending briefs = %d, want none", len(p.pending))
	}
}

func TestPublishRejectsInvalidPublicMarkdownBeforeBuffering(t *testing.T) {
	p := &Publisher{publicKey: testPublicKey, logger: slog.Default()}
	err := p.Publish(`id: brief-test
slug: 2026-10-test
title: Test advisory
summary: Verified Widget advisory.
content: Review affected Widget installations against the vendor advisory before applying a revision.
severity: high
published_at: "2026-10-21T07:00:00Z"
revision: 2
references: [https://vendor.example/advisory]
`)
	if err == nil || !strings.Contains(err.Error(), "brief.revision") {
		t.Fatalf("Publish error = %v, want public feed contract failure", err)
	}
	if len(p.pending) != 0 {
		t.Fatalf("pending briefs = %d, want none", len(p.pending))
	}
}

func TestPublishRejectsContradictoryFinalBrief(t *testing.T) {
	p := &Publisher{publicKey: testPublicKey, logger: slog.Default()}
	err := p.Publish(`id: brief-struts
slug: apache-struts-rce
title: "Apache Struts: File upload remote code execution"
summary: A public-facing web application vulnerability.
content: An HTTP POST to the server's upload endpoint can write a web shell.
severity: high
published_at: "2026-09-15T00:00:00Z"
ttps:
  - technique_id: T1203
    evidence: An HTTP POST to the server's file upload endpoint writes a web shell.
`)
	if err == nil || !strings.Contains(err.Error(), "T1203") {
		t.Fatalf("Publish error = %v, want contradictory technique mapping", err)
	}
	if len(p.pending) != 0 {
		t.Fatalf("pending briefs = %d, want none", len(p.pending))
	}
}

func TestFlushNewBundle(t *testing.T) {
	var mu sync.Mutex
	var gotReq contentsRequest
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch r.Method {
		case "GET":
			// Bundle doesn't exist yet.
			w.WriteHeader(http.StatusNotFound)
		case "PUT":
			gotPath = r.URL.Path
			json.NewDecoder(r.Body).Decode(&gotReq)
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"content":{"sha":"new-sha"}}`))
		}
	}))
	defer srv.Close()

	p := &Publisher{
		repoSlug:  "CraftedSignal/threat-feed",
		publicKey: testPublicKey,
		tokenFn:   func() string { return "test-token" },
		apiURL:    srv.URL,
		client:    http.DefaultClient,
		logger:    slog.Default(),
	}

	// Buffer two briefs.
	p.Publish(`id: "brief-1"
slug: "test-1"
title: "First Brief"
summary: "First"
content: The first report describes suspicious process activity for analyst investigation.
severity: "high"
published_at: "2026-02-20T10:00:00Z"
`)
	p.Publish(`id: "brief-2"
slug: "test-2"
title: "Second Brief"
summary: "Second"
content: The second report describes additional host activity that requires separate review.
severity: "medium"
published_at: "2026-02-20T11:00:00Z"
`)

	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}

	// Should have made a GET for existing bundle, then PUT the new one.
	if gotPath != "/repos/CraftedSignal/threat-feed/contents/output/bundle.json" {
		t.Errorf("unexpected PUT path: %s", gotPath)
	}

	// No SHA should be set (new file).
	if gotReq.SHA != "" {
		t.Errorf("expected no SHA for new file, got %q", gotReq.SHA)
	}

	// Commit message should mention count.
	if gotReq.Message != "chore: update threat feed bundle (2 new briefs)" {
		t.Errorf("unexpected commit message: %s", gotReq.Message)
	}

	// Verify the PUT content is a valid encrypted bundle.
	raw, err := base64.StdEncoding.DecodeString(gotReq.Content)
	if err != nil {
		t.Fatal(err)
	}
	var manifest BundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypt(&manifest, testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted.Briefs) != 2 {
		t.Fatalf("expected 2 briefs in bundle, got %d", len(decrypted.Briefs))
	}

	// Pending should be cleared.
	if len(p.pending) != 0 {
		t.Errorf("expected pending cleared, got %d", len(p.pending))
	}
}

func TestFlushMergesExistingBundle(t *testing.T) {
	// Create an existing encrypted bundle with one brief.
	existing := &BundleContent{
		Briefs: []BundleBrief{
			{ID: "existing-1", Title: "Existing Brief", Severity: "low"},
		},
	}
	existingManifest, err := Encrypt(existing, "1.0", "2026-02-20T09:00:00Z", testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	existingJSON, _ := json.Marshal(existingManifest)
	existingB64 := base64.StdEncoding.EncodeToString(existingJSON)

	var gotReq contentsRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			// Return existing bundle.
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"sha":     "existing-sha",
				"content": existingB64,
			})
		case "PUT":
			json.NewDecoder(r.Body).Decode(&gotReq)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"content":{"sha":"updated-sha"}}`))
		}
	}))
	defer srv.Close()

	p := &Publisher{
		repoSlug:  "CraftedSignal/threat-feed",
		publicKey: testPublicKey,
		tokenFn:   func() string { return "test-token" },
		apiURL:    srv.URL,
		client:    http.DefaultClient,
		logger:    slog.Default(),
	}

	p.Publish(`id: "new-1"
slug: "new-1"
title: "New Brief"
summary: "New"
content: The new report adds suspicious process observations for analyst investigation.
severity: "high"
published_at: "2026-02-20T10:00:00Z"
`)

	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}

	// SHA should be set for update.
	if gotReq.SHA != "existing-sha" {
		t.Errorf("expected SHA 'existing-sha', got %q", gotReq.SHA)
	}

	// Verify merged content.
	raw, _ := base64.StdEncoding.DecodeString(gotReq.Content)
	var manifest BundleManifest
	json.Unmarshal(raw, &manifest)
	decrypted, _ := Decrypt(&manifest, testPublicKey)

	if len(decrypted.Briefs) != 2 {
		t.Fatalf("expected 2 briefs after merge, got %d", len(decrypted.Briefs))
	}
	if decrypted.Briefs[0].ID != "existing-1" {
		t.Errorf("expected first brief 'existing-1', got %q", decrypted.Briefs[0].ID)
	}
	if decrypted.Briefs[1].ID != "new-1" {
		t.Errorf("expected second brief 'new-1', got %q", decrypted.Briefs[1].ID)
	}
}

func TestFlushNoPending(t *testing.T) {
	p := &Publisher{
		publicKey: testPublicKey,
		logger:    slog.Default(),
	}

	// Flush with nothing pending should be a no-op.
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
}

// withFastPutFileRetries shrinks putFileRetryDelays to near-zero for the
// duration of a test, restoring the original on cleanup, so 5xx-retry tests
// don't actually sleep 2s+4s.
func withFastPutFileRetries(t *testing.T) {
	t.Helper()
	orig := putFileRetryDelays
	putFileRetryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { putFileRetryDelays = orig })
}

func TestPutFileRetries5xxThenSucceeds(t *testing.T) {
	withFastPutFileRetries(t)

	var mu sync.Mutex
	attempts := 0
	var gotReqs []contentsRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()

		var req contentsRequest
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		gotReqs = append(gotReqs, req)
		mu.Unlock()

		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"internal error"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":{"sha":"new-sha"}}`))
	}))
	defer srv.Close()

	p := &Publisher{
		repoSlug:  "CraftedSignal/threat-feed",
		publicKey: testPublicKey,
		tokenFn:   func() string { return "test-token" },
		apiURL:    srv.URL,
		client:    http.DefaultClient,
		logger:    slog.Default(),
	}

	manifest := &BundleManifest{Version: "v1", Content: "ciphertext"}
	if _, err := p.putFile("output/briefs/2026.json", manifest, "old-sha", "chore: test"); err != nil {
		t.Fatalf("putFile should succeed on 3rd attempt, got error: %v", err)
	}

	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
	// Every retry must resend the identical payload (same SHA).
	for i, r := range gotReqs {
		if r.SHA != "old-sha" {
			t.Errorf("attempt %d: SHA = %q, want %q", i+1, r.SHA, "old-sha")
		}
	}
}

func TestPutFileFailsAfterMaxAttemptsOn5xx(t *testing.T) {
	withFastPutFileRetries(t)

	var mu sync.Mutex
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"internal error"}`))
	}))
	defer srv.Close()

	p := &Publisher{
		repoSlug:  "CraftedSignal/threat-feed",
		publicKey: testPublicKey,
		tokenFn:   func() string { return "test-token" },
		apiURL:    srv.URL,
		client:    http.DefaultClient,
		logger:    slog.Default(),
	}

	manifest := &BundleManifest{Version: "v1", Content: "ciphertext"}
	_, err := p.putFile("output/briefs/2026.json", manifest, "old-sha", "chore: test")
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if attempts != putFileMaxAttempts {
		t.Errorf("attempts = %d, want %d (putFileMaxAttempts)", attempts, putFileMaxAttempts)
	}
}

func TestPutFileDoesNotRetry4xx(t *testing.T) {
	withFastPutFileRetries(t)

	var mu sync.Mutex
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusConflict) // 409 — stale SHA, not transient
		w.Write([]byte(`{"message":"sha mismatch"}`))
	}))
	defer srv.Close()

	p := &Publisher{
		repoSlug:  "CraftedSignal/threat-feed",
		publicKey: testPublicKey,
		tokenFn:   func() string { return "test-token" },
		apiURL:    srv.URL,
		client:    http.DefaultClient,
		logger:    slog.Default(),
	}

	manifest := &BundleManifest{Version: "v1", Content: "ciphertext"}
	_, err := p.putFile("output/briefs/2026.json", manifest, "old-sha", "chore: test")
	if err == nil {
		t.Fatal("expected error on 409")
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (4xx must not retry)", attempts)
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error should mention 409: %v", err)
	}
}

func TestPutFileRetriesRepositoryRuleTimeout(t *testing.T) {
	withFastPutFileRetries(t)

	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"message":"Repository rule violations found\n\nThe rule did not run because of a timeout.\n\n"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":{"sha":"new-sha"}}`))
	}))
	defer srv.Close()

	p := &Publisher{
		repoSlug: "CraftedSignal/threat-feed", tokenFn: func() string { return "test-token" },
		apiURL: srv.URL, client: http.DefaultClient, logger: slog.Default(),
	}
	manifest := &BundleManifest{Version: "v1", Content: "ciphertext"}
	if _, err := p.putFile("site/static/stix/2026-10.json", manifest, "old-sha", "chore: test"); err != nil {
		t.Fatalf("putFile should retry a repository-rule timeout: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestPublishSTIXCompatibilityAliasVerifiesCommittedBlob(t *testing.T) {
	withFastPutFileRetries(t)
	expected := []byte(`{"type":"bundle","objects":[]}`)
	current := []byte(`{"type":"bundle","objects":[{"type":"identity"}]}`)
	putAttempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]string{
				"sha": gitBlobSHA(current), "content": base64.StdEncoding.EncodeToString(current),
			})
			return
		}
		putAttempts++
		var req contentsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.DecodeString(req.Content)
		if err != nil {
			t.Fatal(err)
		}
		// Simulate GitHub returning 200 while a repository rule times out and
		// leaves the branch unchanged. The second write commits normally.
		if putAttempts > 1 {
			current = decoded
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":{"sha":"accepted"}}`))
	}))
	defer srv.Close()

	p := &Publisher{repoSlug: "CraftedSignal/threat-feed", tokenFn: func() string { return "token" }, apiURL: srv.URL, client: http.DefaultClient, logger: slog.Default()}
	if err := p.publishSTIXCompatibilityAlias("site/static/stix.json", expected, "chore: refresh alias"); err != nil {
		t.Fatal(err)
	}
	if putAttempts != 2 {
		t.Fatalf("PUT attempts = %d, want 2", putAttempts)
	}
	if string(current) != string(expected) {
		t.Fatalf("committed alias = %q, want %q", current, expected)
	}
}

// Every path into the feed goes through Publish, so no invalid Sigma rule
// reaches it.
func TestPublishDropsInvalidSigmaRules(t *testing.T) {
	p := &Publisher{
		publicKey: testPublicKey,
		logger:    slog.Default(),
	}

	briefYAML := `id: "brief-2026-10-09-rules"
slug: "2026-10-09-rules"
title: "Rules"
summary: "A test"
content: Detect tool.exe process launches and review their parent process for suspicious activity.
severity: "high"
published_at: "2026-10-09T10:00:00Z"
rules:
  - title: "Valid"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: '\tool.exe'
      condition: selection
    level: high
  - title: "No condition"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: '\tool.exe'
    level: high
`
	if err := p.Publish(briefYAML); err != nil {
		t.Fatal(err)
	}
	if rules := p.pending[0].Rules; len(rules) != 1 || rules[0].Title != "Valid" {
		t.Fatalf("expected only the valid rule to be buffered, got %+v", rules)
	}
}
