package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestWriteBatchInput(t *testing.T) {
	reqs := []vertexRequest{
		Request{Prompt: "score <this> & that", System: "you score", JSON: true}.vertexRequest(),
		Request{Prompt: "plain prompt"}.vertexRequest(),
	}
	var buf bytes.Buffer
	if err := writeBatchInput(&buf, reqs); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want one per request:\n%s", len(lines), buf.String())
	}

	var first struct {
		Request vertexRequest `json:"request"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	r := first.Request
	if got := r.Contents[0].Parts[0].Text; got != "score <this> & that" || r.Contents[0].Role != "user" {
		t.Errorf("contents = %+v", r.Contents)
	}
	if r.SystemInstruction == nil || r.SystemInstruction.Parts[0].Text != "you score" {
		t.Errorf("systemInstruction = %+v", r.SystemInstruction)
	}
	if r.GenerationConfig == nil || r.GenerationConfig.ResponseMIMEType != "application/json" {
		t.Errorf("generationConfig = %+v", r.GenerationConfig)
	}

	// A plain request carries neither a system instruction nor a response type.
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[1]), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["request"]["systemInstruction"]; ok {
		t.Error("plain request has a systemInstruction")
	}
	if _, ok := raw["request"]["generationConfig"]; ok {
		t.Error("plain request has a generationConfig")
	}
}

// The request a batch line carries must be the one the live client sends.
func TestBatchRequestMatchesLiveRequest(t *testing.T) {
	var sent []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, _ = io.ReadAll(r.Body)
		fmt.Fprint(w, `{"candidates":[{"content":{"parts":[{"text":"{}"}]}}]}`)
	}))
	defer srv.Close()
	c := newVertexAIClientWithHTTP("p", "eu", "m", &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}})

	var out struct{}
	if err := c.GenerateJSON(context.Background(), "the prompt", "the system", &out); err != nil {
		t.Fatal(err)
	}
	batch := mustJSON(t, Request{Prompt: "the prompt", System: "the system", JSON: true}.vertexRequest())
	if string(sent) != batch {
		t.Fatalf("live body %s differs from batch request %s", sent, batch)
	}
}

// outputLine builds one batch output line the way Vertex writes it: the
// request echoed back with its keys in a different order, then the response.
func outputLine(t *testing.T, req vertexRequest, status, text string) string {
	t.Helper()
	encoded, _ := json.Marshal(req)
	var echo map[string]any // re-encoding a map sorts the keys
	if err := json.Unmarshal(encoded, &echo); err != nil {
		t.Fatal(err)
	}
	if cfg, ok := echo["generationConfig"].(map[string]any); ok {
		cfg["temperature"] = 0 // the echo may carry fields we never sent
	}
	line := map[string]any{"request": echo, "status": status}
	if text != "" {
		line["response"] = map[string]any{
			"candidates": []any{map[string]any{
				"content":      map[string]any{"role": "model", "parts": []any{map[string]any{"text": text, "thoughtSignature": "AY89"}}},
				"finishReason": "STOP",
			}},
			"usageMetadata": map[string]any{"promptTokenCount": 7},
		}
	}
	out, _ := json.Marshal(line)
	return string(out)
}

func keyOf(r Request) string { return requestKey(r.vertexRequest()) }

func TestCollectBatchOutput(t *testing.T) {
	quality := Request{Prompt: "quality of item 1", System: "score", JSON: true}
	extract := Request{Prompt: "extract item 1", System: "extract", JSON: true}
	broken := Request{Prompt: "item the job could not answer", System: "score", JSON: true}
	other := Request{Prompt: "somebody else's request", JSON: true}
	want := map[string]struct{}{keyOf(quality): {}, keyOf(extract): {}, keyOf(broken): {}}

	file1 := strings.Join([]string{
		outputLine(t, quality.vertexRequest(), "", `{"credibility": 4}`),
		outputLine(t, broken.vertexRequest(), "Bad Request: the input is too long", ""),
		"this line is not JSON",
		outputLine(t, other.vertexRequest(), "", `{"x": 1}`),
	}, "\n") + "\n"
	// No trailing newline on the last line of the second file.
	file2 := outputLine(t, extract.vertexRequest(), "", `{"cves": []}`)

	answers := map[string]string{}
	var tally batchTally
	for _, file := range []string{file1, file2} {
		got, err := collectBatchOutput(strings.NewReader(file), want, answers)
		if err != nil {
			t.Fatal(err)
		}
		tally.add(got)
	}

	if len(answers) != 2 || answers[keyOf(quality)] != `{"credibility": 4}` || answers[keyOf(extract)] != `{"cves": []}` {
		t.Fatalf("answers = %v, want the quality and extraction answers matched by recomputed key", answers)
	}
	if _, ok := answers[keyOf(broken)]; ok {
		t.Error("a line with an error status was stored; its request must run live")
	}
	if tally != (batchTally{answered: 2, failed: 1, unmatched: 1, malformed: 1}) {
		t.Errorf("tally = %+v", tally)
	}
}

func TestCollectBatchOutputJoinsTextPartsAndSkipsOversizeLines(t *testing.T) {
	req := Request{Prompt: "split answer", JSON: true}
	want := map[string]struct{}{keyOf(req): {}}

	split := fmt.Sprintf(`{"request":%s,"status":"","response":{"candidates":[{"content":{"parts":[{"text":"{\"a\":"},{"text":"1}"}]}}]}}`,
		mustJSON(t, req.vertexRequest()))
	huge := `{"request":{"contents":[{"parts":[{"text":"` + strings.Repeat("x", maxBatchLine) + `"}]}]}}`
	input := huge + "\n" + split + "\n"

	answers := map[string]string{}
	tally, err := collectBatchOutput(strings.NewReader(input), want, answers)
	if err != nil {
		t.Fatal(err)
	}
	if answers[keyOf(req)] != `{"a":1}` {
		t.Errorf("answers = %v, want the text parts joined", answers)
	}
	if tally.malformed != 1 || tally.answered != 1 {
		t.Errorf("tally = %+v, want the oversize line skipped and the next one read", tally)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fakeBatchAPI imitates the parts of the Vertex AI batch prediction API and
// the Cloud Storage JSON API that VertexBatch uses. Its model answers every
// uploaded request with {"answer": "<prompt>"}, and fails those whose prompt
// contains FAIL.
type fakeBatchAPI struct {
	mu            sync.Mutex
	states        []string // job states returned by successive polls; the last repeats
	polls         int
	createStatus  int // HTTP status to fail the create call with
	noOutputDir   bool
	addUnmatched  bool
	uploadName    string
	uploadBody    []byte
	uploadLength  int64
	created       batchJobRequest
	cancelled     bool
	filesAfterJob map[string]string // output objects, by name, once the job succeeded
}

const fakeJobName = "projects/123/locations/eu/batchPredictionJobs/42"

func (f *fakeBatchAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.EscapedPath()

	switch {
	case r.Method == http.MethodPost && path == "/upload/storage/v1/b/bkt/o":
		f.uploadName = r.URL.Query().Get("name")
		f.uploadLength = r.ContentLength
		f.uploadBody, _ = io.ReadAll(r.Body)
		fmt.Fprint(w, `{}`)

	case r.Method == http.MethodPost && path == "/v1/projects/p/locations/eu/batchPredictionJobs":
		if f.createStatus != 0 {
			http.Error(w, `{"error":{"message":"permission denied"}}`, f.createStatus)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&f.created)
		fmt.Fprintf(w, `{"name":%q,"state":"JOB_STATE_PENDING"}`, fakeJobName)

	case r.Method == http.MethodPost && path == "/v1/"+fakeJobName+":cancel":
		f.cancelled = true
		fmt.Fprint(w, `{}`)

	case r.Method == http.MethodGet && path == "/v1/"+fakeJobName:
		state := f.states[min(f.polls, len(f.states)-1)]
		f.polls++
		job := map[string]any{"name": fakeJobName, "state": state}
		if state == jobFailed {
			job["error"] = map[string]any{"message": "quota exceeded"}
		}
		if (state == jobSucceeded || state == jobPartiallySucceeded) && !f.noOutputDir {
			job["outputInfo"] = map[string]any{"gcsOutputDirectory": strings.TrimSuffix(f.created.OutputConfig.GCSDestination.OutputURIPrefix, "/") + "/prediction-model-1"}
			f.writeOutput()
		}
		_ = json.NewEncoder(w).Encode(job)

	case r.Method == http.MethodGet && path == "/storage/v1/b/bkt/o":
		prefix := r.URL.Query().Get("prefix")
		var names []string
		for name := range f.filesAfterJob {
			if strings.HasPrefix(name, prefix) {
				names = append(names, name)
			}
		}
		// Two pages, to cover pagination.
		sortStrings(names)
		items := func(from, to int) []map[string]string {
			var out []map[string]string
			for _, n := range names[from:to] {
				out = append(out, map[string]string{"name": n})
			}
			return out
		}
		if len(names) > 1 && r.URL.Query().Get("pageToken") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items(0, 1), "nextPageToken": "page2"})
			return
		}
		from := 0
		if r.URL.Query().Get("pageToken") != "" {
			from = 1
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items(from, len(names))})

	case r.Method == http.MethodGet && strings.HasPrefix(path, "/storage/v1/b/bkt/o/"):
		name, _ := url.PathUnescape(strings.TrimPrefix(path, "/storage/v1/b/bkt/o/"))
		content, ok := f.filesAfterJob[name]
		if !ok || r.URL.Query().Get("alt") != "media" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, content)

	default:
		http.Error(w, "unexpected "+r.Method+" "+path, http.StatusNotImplemented)
	}
}

// writeOutput lets the fake model answer the uploaded requests, spreading the
// output lines over two files and adding a file that is not output.
func (f *fakeBatchAPI) writeOutput() {
	if f.filesAfterJob != nil {
		return
	}
	dir := strings.TrimPrefix(strings.TrimSuffix(f.created.OutputConfig.GCSDestination.OutputURIPrefix, "/"), "gs://bkt/") + "/prediction-model-1/"
	var files [2][]string
	for i, line := range strings.Split(strings.TrimSpace(string(f.uploadBody)), "\n") {
		var in struct {
			Request vertexRequest `json:"request"`
		}
		_ = json.Unmarshal([]byte(line), &in)
		prompt := in.Request.Contents[0].Parts[0].Text
		status, text := "", fmt.Sprintf(`{"answer": %q}`, prompt)
		if strings.Contains(prompt, "FAIL") {
			status, text = "invalid argument", ""
		}
		files[i%2] = append(files[i%2], echoedLine(in.Request, status, text))
	}
	if f.addUnmatched {
		files[0] = append(files[0], echoedLine(Request{Prompt: "unexpected"}.vertexRequest(), "", `{"unexpected":true}`))
	}
	f.filesAfterJob = map[string]string{
		dir + "predictions-1.jsonl": strings.Join(files[0], "\n") + "\n",
		dir + "predictions-2.jsonl": strings.Join(files[1], "\n") + "\n",
		dir + "errors.txt":          "not output",
	}
}

func echoedLine(req vertexRequest, status, text string) string {
	return echoedLineWithStatusAndReason(req, status, text, "")
}

func echoedLineWithReason(req vertexRequest, text, finishReason string) string {
	return echoedLineWithStatusAndReason(req, "", text, finishReason)
}

func echoedLineWithStatusAndReason(req vertexRequest, status, text, finishReason string) string {
	encoded, _ := json.Marshal(req)
	var echo map[string]any
	_ = json.Unmarshal(encoded, &echo)
	line := map[string]any{"request": echo, "status": status}
	if text != "" {
		line["response"] = map[string]any{"candidates": []any{map[string]any{
			"content":      map[string]any{"role": "model", "parts": []any{map[string]any{"text": text}}},
			"finishReason": finishReason,
		}}}
	}
	out, _ := json.Marshal(line)
	return string(out)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func newTestBatch(api *fakeBatchAPI, pollInterval, maxWait time.Duration) (*VertexBatch, func()) {
	srv := httptest.NewServer(api)
	return &VertexBatch{
		project:      "p",
		location:     "eu",
		model:        "gemini-test",
		bucket:       "bkt",
		pollInterval: pollInterval,
		maxWait:      maxWait,
		httpClient:   &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}},
		logger:       quietLogger(),
	}, srv.Close
}

func TestVertexBatchRun(t *testing.T) {
	api := &fakeBatchAPI{states: []string{"JOB_STATE_PENDING", "JOB_STATE_QUEUED", "JOB_STATE_RUNNING", jobSucceeded}}
	batch, stop := newTestBatch(api, time.Millisecond, 5*time.Second)
	defer stop()

	a := Request{Prompt: "prompt a", System: "system", JSON: true}
	b := Request{Prompt: "prompt b", JSON: true}
	c := Request{Prompt: "prompt c"}
	failing := Request{Prompt: "FAIL this one", JSON: true}
	answers, err := batch.run(context.Background(), []Request{a, b, c, failing, a})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	for _, req := range []Request{a, b, c} {
		if got, want := answers[keyOf(req)], fmt.Sprintf(`{"answer": %q}`, req.Prompt); got != want {
			t.Errorf("answer to %q = %q, want %q", req.Prompt, got, want)
		}
	}
	if _, ok := answers[keyOf(failing)]; ok {
		t.Error("the request that failed inside the job was answered")
	}
	if len(answers) != 3 {
		t.Errorf("got %d answers, want 3", len(answers))
	}

	// Upload: one line per distinct request, streamed with a known length.
	if n := strings.Count(string(api.uploadBody), "\n"); n != 4 {
		t.Errorf("uploaded %d lines, want 4 (the repeated request is sent once):\n%s", n, api.uploadBody)
	}
	if api.uploadLength != int64(len(api.uploadBody)) {
		t.Errorf("upload Content-Length = %d, body is %d bytes", api.uploadLength, len(api.uploadBody))
	}
	if !strings.HasPrefix(api.uploadName, "input/") || !strings.HasSuffix(api.uploadName, ".jsonl") {
		t.Errorf("upload name = %q", api.uploadName)
	}

	// Create: model, input and output locations.
	if api.created.Model != "publishers/google/models/gemini-test" {
		t.Errorf("model = %q", api.created.Model)
	}
	if got := api.created.InputConfig.GCSSource.URIs; len(got) != 1 || got[0] != "gs://bkt/"+api.uploadName || api.created.InputConfig.InstancesFormat != "jsonl" {
		t.Errorf("inputConfig = %+v", api.created.InputConfig)
	}
	out := api.created.OutputConfig
	if !strings.HasPrefix(out.GCSDestination.OutputURIPrefix, "gs://bkt/output/") || out.PredictionsFormat != "jsonl" {
		t.Errorf("outputConfig = %+v", out)
	}
	if api.polls != 4 {
		t.Errorf("polled %d times, want 4 (until the job succeeded)", api.polls)
	}
	if api.cancelled {
		t.Error("a finished job was cancelled")
	}
}

func TestCollectBatchOutputRejectsNonStopFinishReason(t *testing.T) {
	req := Request{Prompt: "answer"}.vertexRequest()
	line := echoedLineWithReason(req, "{\"partial\":", "MAX_TOKENS")
	answers := map[string]string{}
	tally, err := collectBatchOutput(strings.NewReader(line+"\n"), map[string]struct{}{requestKey(req): {}}, answers)
	if err != nil {
		t.Fatal(err)
	}
	if tally.failed != 1 || tally.answered != 0 || len(answers) != 0 {
		t.Fatalf("tally = %+v, answers = %v; want failed unanswered request", tally, answers)
	}
}

func TestCollectBatchOutputCountsUnmatched(t *testing.T) {
	req := Request{Prompt: "not requested"}.vertexRequest()
	line := echoedLine(req, "", `{"ok":true}`)
	tally, err := collectBatchOutput(strings.NewReader(line+"\n"), map[string]struct{}{}, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if tally.unmatched != 1 {
		t.Fatalf("unmatched = %d, want 1", tally.unmatched)
	}
}

func TestBatchUnansweredWarningIncludesUnmatchedCount(t *testing.T) {
	api := &fakeBatchAPI{states: []string{jobSucceeded}, addUnmatched: true}
	var logs bytes.Buffer
	batch, stop := newTestBatch(api, time.Millisecond, time.Second)
	defer stop()
	batch.logger = slog.New(slog.NewTextHandler(&logs, nil))
	_, err := batch.run(context.Background(), []Request{{Prompt: "wanted"}, {Prompt: "FAIL"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "unmatched=1") {
		t.Fatalf("warning log %q does not include unmatched=1", logs.String())
	}
}

func TestBatchWarnsWhenAllRequestedAnswersArriveAlongsideUnmatchedOutput(t *testing.T) {
	api := &fakeBatchAPI{states: []string{jobSucceeded}, addUnmatched: true}
	var logs bytes.Buffer
	batch, stop := newTestBatch(api, time.Millisecond, time.Second)
	defer stop()
	batch.logger = slog.New(slog.NewTextHandler(&logs, nil))
	answers, err := batch.run(context.Background(), []Request{{Prompt: "wanted"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(answers))
	}
	if !strings.Contains(logs.String(), "unmatched=1") {
		t.Fatalf("warning log %q does not include unmatched=1 when requested answers are complete", logs.String())
	}
}

// Every way a batch can fail must come back as an error, so the caller runs
// the prompts live.
func TestVertexBatchRunFailures(t *testing.T) {
	tests := []struct {
		name    string
		api     *fakeBatchAPI
		wantErr string
	}{
		{name: "create is refused", api: &fakeBatchAPI{createStatus: http.StatusForbidden}, wantErr: "HTTP 403"},
		{name: "job fails", api: &fakeBatchAPI{states: []string{"JOB_STATE_RUNNING", jobFailed}}, wantErr: jobFailed},
		{name: "job is cancelled", api: &fakeBatchAPI{states: []string{jobCancelled}}, wantErr: jobCancelled},
		{name: "job expires", api: &fakeBatchAPI{states: []string{jobExpired}}, wantErr: jobExpired},
		{name: "job succeeds without an output directory", api: &fakeBatchAPI{states: []string{jobSucceeded}, noOutputDir: true}, wantErr: "output directory"},
		{name: "job succeeds but wrote no output", api: &fakeBatchAPI{states: []string{jobSucceeded}, filesAfterJob: map[string]string{"elsewhere.jsonl": "x"}}, wantErr: "no output"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch, stop := newTestBatch(tt.api, time.Millisecond, 5*time.Second)
			defer stop()
			_, err := batch.run(context.Background(), []Request{{Prompt: "p", JSON: true}})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want one mentioning %q", err, tt.wantErr)
			}
		})
	}
}

func TestVertexBatchPartialSuccessKeepsTheAnswersItHas(t *testing.T) {
	api := &fakeBatchAPI{states: []string{jobPartiallySucceeded}}
	batch, stop := newTestBatch(api, time.Millisecond, 5*time.Second)
	defer stop()

	ok, failing := Request{Prompt: "fine", JSON: true}, Request{Prompt: "FAIL", JSON: true}
	answers, err := batch.run(context.Background(), []Request{ok, failing})
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 || answers[keyOf(ok)] == "" {
		t.Fatalf("answers = %v, want only the request that succeeded", answers)
	}
}

// A job that outlives max_wait is cancelled, and the prompts then run live.
func TestPrefetchTimeoutCancelsJobAndFallsBackLive(t *testing.T) {
	api := &fakeBatchAPI{states: []string{"JOB_STATE_RUNNING"}}
	batch, stop := newTestBatch(api, 2*time.Millisecond, 40*time.Millisecond)
	defer stop()
	live := &fakeLive{}
	client := NewPrefetchClient(live, batch, 500, quietLogger())

	client.Prefetch(context.Background(), []Request{{Prompt: "slow", System: "s", JSON: true}})

	api.mu.Lock()
	cancelled := api.cancelled
	api.mu.Unlock()
	if !cancelled {
		t.Fatal("the job still running at max_wait was not cancelled")
	}

	var out struct{ From string }
	if err := client.GenerateJSON(context.Background(), "slow", "s", &out); err != nil {
		t.Fatal(err)
	}
	if out.From != "live" || len(live.calls) != 1 {
		t.Fatalf("out = %+v, live calls = %v; want the prompt answered live", out, live.calls)
	}
}

// Shutdown while waiting also stops the job.
func TestVertexBatchCancelsJobWhenContextEnds(t *testing.T) {
	api := &fakeBatchAPI{states: []string{"JOB_STATE_RUNNING"}}
	batch, stop := newTestBatch(api, 2*time.Millisecond, time.Minute)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := batch.run(ctx, []Request{{Prompt: "p", JSON: true}}); err == nil {
		t.Fatal("expected an error when the context ends")
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if !api.cancelled {
		t.Error("the job was left running after the context ended")
	}
}

func TestPrefetchThroughVertexBatchServesAnswersAndReleases(t *testing.T) {
	api := &fakeBatchAPI{states: []string{jobSucceeded}}
	batch, stop := newTestBatch(api, time.Millisecond, 5*time.Second)
	defer stop()
	live := &fakeLive{}
	client := NewPrefetchClient(live, batch, 500, quietLogger())

	client.Prefetch(context.Background(), []Request{{Prompt: "quality", System: "score", JSON: true}})

	var out struct{ Answer string }
	if err := client.GenerateJSON(context.Background(), "quality", "score", &out); err != nil {
		t.Fatal(err)
	}
	if out.Answer != "quality" || len(live.calls) != 0 {
		t.Fatalf("out = %+v, live calls = %v; want the batch answer with no live call", out, live.calls)
	}

	client.Release()
	if err := client.GenerateJSON(context.Background(), "quality", "score", &out); err != nil {
		t.Fatal(err)
	}
	if len(live.calls) != 1 {
		t.Fatalf("live calls after release = %v, want the prompt to run live again", live.calls)
	}
}

func TestCollectBatchOutputBoundsCachedAnswer(t *testing.T) {
	req := Request{Prompt: "hello", JSON: true}.vertexRequest()
	line := batchOutputLine{Request: req}
	line.Response.Candidates = append(line.Response.Candidates, vertexCandidate{
		Content: vertexContent{Parts: []vertexPart{{Text: strings.Repeat("x", maxBatchAnswer+1)}}}})
	raw, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	answers := map[string]string{}
	tally, err := collectBatchOutput(bytes.NewReader(raw), map[string]struct{}{requestKey(req): {}}, answers)
	if err != nil || len(answers) != 0 || tally.failed != 1 {
		t.Fatalf("answers=%d tally=%+v err=%v", len(answers), tally, err)
	}
}

// A job that already reached a terminal state cannot be cancelled; asking
// makes Vertex answer with an error that lands in the audit log.
func TestVertexBatchCancelSkipsTerminalJobs(t *testing.T) {
	for _, state := range []string{jobSucceeded, jobPartiallySucceeded, jobFailed, jobCancelled, jobExpired} {
		api := &fakeBatchAPI{states: []string{state}, noOutputDir: true}
		batch, stop := newTestBatch(api, time.Millisecond, time.Second)
		batch.cancel(context.Background(), fakeJobName)
		stop()
		api.mu.Lock()
		cancelled := api.cancelled
		api.mu.Unlock()
		if cancelled {
			t.Errorf("job in state %s was cancelled", state)
		}
	}
}

func TestVertexBatchCancelStillCancelsRunningJobs(t *testing.T) {
	api := &fakeBatchAPI{states: []string{"JOB_STATE_RUNNING"}}
	batch, stop := newTestBatch(api, time.Millisecond, time.Second)
	defer stop()
	batch.cancel(context.Background(), fakeJobName)
	api.mu.Lock()
	defer api.mu.Unlock()
	if !api.cancelled {
		t.Error("a running job was not cancelled")
	}
}
