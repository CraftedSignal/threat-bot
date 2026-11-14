package llm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxBatchRequests bounds the requests and cached responses held per pipeline chunk.
const MaxBatchRequests = 100

const (
	gcsEndpoint = "https://storage.googleapis.com"

	// maxBatchLine caps one line of batch output. A line holds the echoed
	// request and the answer, both far below this; a longer one is skipped
	// instead of buffered.
	maxBatchLine   = 1 << 20
	maxBatchAnswer = 64 << 10
	// maxBatchObjects bounds how many output files one job is read from.
	maxBatchObjects = 1000
	// maxBatchResponse bounds the JSON bodies read from the job and listing APIs.
	maxBatchResponse = 1 << 20
	cancelTimeout    = 30 * time.Second
)

// Terminal states of a Vertex AI batch prediction job. Anything else (pending,
// queued, running, cancelling) means keep waiting.
const (
	jobSucceeded          = "JOB_STATE_SUCCEEDED"
	jobPartiallySucceeded = "JOB_STATE_PARTIALLY_SUCCEEDED"
	jobFailed             = "JOB_STATE_FAILED"
	jobCancelled          = "JOB_STATE_CANCELLED"
	jobExpired            = "JOB_STATE_EXPIRED"
)

// VertexBatch answers requests through Vertex AI batch prediction, which costs
// half as much as live calls and takes minutes. Input and output travel
// through a Cloud Storage bucket.
type VertexBatch struct {
	project      string
	location     string
	model        string
	bucket       string
	pollInterval time.Duration
	maxWait      time.Duration
	httpClient   *http.Client
	logger       *slog.Logger
	store        BatchJobStore
}

var _ batchRunner = (*VertexBatch)(nil)

// NewVertexBatch creates a batch runner for model using Application Default
// Credentials. location is the Vertex AI location the jobs run in.
func NewVertexBatch(project, location, model, bucket string, pollInterval, maxWait time.Duration, logger *slog.Logger) (*VertexBatch, error) {
	if pollInterval <= 0 || maxWait <= 0 {
		return nil, fmt.Errorf("batch poll interval and max wait must be positive")
	}
	hc, err := googleHTTPClient(5 * time.Minute)
	if err != nil {
		return nil, err
	}
	return &VertexBatch{
		project:      project,
		location:     location,
		model:        model,
		bucket:       bucket,
		pollInterval: pollInterval,
		maxWait:      maxWait,
		httpClient:   hc,
		logger:       logger,
	}, nil
}

type batchJob struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
	CreateTime  time.Time `json:"createTime"`
	State       string    `json:"state"`
	Error       *struct {
		Message string `json:"message"`
	} `json:"error"`
	OutputInfo struct {
		GCSOutputDirectory string `json:"gcsOutputDirectory"`
	} `json:"outputInfo"`
}

type batchJobRequest struct {
	DisplayName  string            `json:"displayName"`
	Model        string            `json:"model"`
	InputConfig  batchInputConfig  `json:"inputConfig"`
	OutputConfig batchOutputConfig `json:"outputConfig"`
}

type batchInputConfig struct {
	InstancesFormat string `json:"instancesFormat"`
	GCSSource       struct {
		URIs []string `json:"uris"`
	} `json:"gcsSource"`
}

type batchOutputConfig struct {
	PredictionsFormat string `json:"predictionsFormat"`
	GCSDestination    struct {
		OutputURIPrefix string `json:"outputUriPrefix"`
	} `json:"gcsDestination"`
}

// run answers reqs in one batch job and returns the answer text by request
// key. Requests that fail inside the job are left out of the result.
func (b *VertexBatch) runNew(ctx context.Context, reqs []Request) (map[string]string, error) {
	ctx = withBatchCallMetadata(ctx, reqs)
	ctx, stop := context.WithTimeout(ctx, b.maxWait)
	defer stop()
	inputs := make([]vertexRequest, 0, len(reqs))
	want := make(map[string]struct{}, len(reqs))
	for _, r := range reqs {
		vr := r.vertexRequest()
		key := requestKey(vr)
		if _, dup := want[key]; dup {
			continue
		}
		want[key] = struct{}{}
		inputs = append(inputs, vr)
	}

	id, err := newJobID()
	if err != nil {
		return nil, err
	}
	inputObject := "input/" + id + ".jsonl"
	outputPrefix := "output/" + id + "/"

	if err := b.upload(ctx, inputObject, inputs); err != nil {
		return nil, fmt.Errorf("uploading batch input: %w", err)
	}
	if b.store != nil {
		if claimer, ok := b.store.(BatchJobClaimer); ok {
			claimed, err := claimer.ClaimBatchJob(b.requestKeys(reqs), creationIntentPrefix+id)
			if err != nil || !claimed {
				return nil, pendingRequests(reqs, err)
			}
		} else if err := b.store.PutBatchJob(b.requestKeys(reqs), creationIntentPrefix+id); err != nil {
			return nil, pendingRequests(reqs, err)
		}
	}
	// No create request has been attempted yet. A cancellation observed at this
	// boundary is demonstrably unsent, so release only our exact owned intent.
	// After entering create, transport cancellation is ambiguous and stays held.
	if err := ctx.Err(); err != nil {
		if b.store != nil {
			if cleanup := swapBatchReference(b.store, b.requestKeys(reqs), creationIntentPrefix+id, ""); cleanup != nil {
				return nil, pendingRequests(reqs, errors.Join(err, cleanup))
			}
		}
		return nil, err
	}
	job, err := b.create(ctx, id, "gs://"+b.bucket+"/"+inputObject, "gs://"+b.bucket+"/"+outputPrefix)
	if err != nil {
		if b.store != nil {
			var he *HTTPError
			if errors.As(err, &he) && he.StatusCode >= 400 && he.StatusCode < 500 {
				if cleanup := updateOwnedBatchReference(b.store, b.requestKeys(reqs), creationIntentPrefix+id, ""); cleanup != nil {
					return nil, pendingRequests(reqs, cleanup)
				}
			} else {
				return nil, pendingRequests(reqs, err)
			}
		}
		return nil, fmt.Errorf("creating batch job: %w", err)
	}
	b.logger.Info("batch job created", "job", job.Name, "requests", len(inputs))

	if b.store != nil {
		if err := updateOwnedBatchReference(b.store, b.requestKeys(reqs), creationIntentPrefix+id, job.Name); err != nil {
			return nil, pendingRequests(reqs, err)
		}
		return b.awaitStored(ctx, job.Name, reqs)
	}
	job, err = b.wait(ctx, job.Name)
	if err != nil {
		return nil, err
	}
	return b.collect(ctx, job, want)
}

func newJobID() (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generating batch job id: %w", err)
	}
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(suffix[:]), nil
}

// writeBatchInput writes one {"request": ...} line per request.
func writeBatchInput(w io.Writer, reqs []vertexRequest) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, r := range reqs {
		if err := enc.Encode(struct {
			Request vertexRequest `json:"request"`
		}{r}); err != nil {
			return err
		}
	}
	return nil
}

type countWriter struct{ n int64 }

func (w *countWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

// upload streams the input lines to object without holding them in memory. The
// size is counted in a first pass so the upload carries a Content-Length
// instead of relying on chunked encoding.
func (b *VertexBatch) upload(ctx context.Context, object string, inputs []vertexRequest) error {
	var size countWriter
	if err := writeBatchInput(&size, inputs); err != nil {
		return err
	}

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeBatchInput(pw, inputs)) }()
	// Closing the read side unblocks the writer if the request ends early.
	defer func() { _ = pr.Close() }()

	endpoint := fmt.Sprintf("%s/upload/storage/v1/b/%s/o?uploadType=media&name=%s", gcsEndpoint, url.PathEscape(b.bucket), url.QueryEscape(object))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, pr)
	if err != nil {
		return err
	}
	req.ContentLength = size.n
	req.Header.Set("Content-Type", "application/jsonl")

	// Not retried: the streamed body cannot be replayed.
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return &RequestError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return &HTTPError{StatusCode: resp.StatusCode, Body: string(msg)}
	}
	return nil
}

func (b *VertexBatch) host() string { return vertexAIEndpoint(b.location) }

func (b *VertexBatch) create(ctx context.Context, id, inputURI, outputPrefix string) (*batchJob, error) {
	body := batchJobRequest{
		DisplayName: batchDisplayNamePrefix + id,
		Model:       "publishers/google/models/" + b.model,
	}
	body.InputConfig.InstancesFormat = "jsonl"
	body.InputConfig.GCSSource.URIs = []string{inputURI}
	body.OutputConfig.PredictionsFormat = "jsonl"
	body.OutputConfig.GCSDestination.OutputURIPrefix = outputPrefix

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/v1/projects/%s/locations/%s/batchPredictionJobs", b.host(), b.project, b.location)
	var job batchJob
	// Not retried: a create that failed in flight may still have started a job.
	if err := b.call(ctx, http.MethodPost, endpoint, payload, false, &job); err != nil {
		return nil, err
	}
	if job.Name == "" {
		return nil, fmt.Errorf("batch job response has no name")
	}
	return &job, nil
}

// wait polls the job until it reaches a terminal state. When maxWait passes or
// ctx ends first, the job is cancelled so it stops accruing cost.
func (b *VertexBatch) wait(ctx context.Context, name string) (*batchJob, error) {
	waitCtx, stop := context.WithTimeout(ctx, b.maxWait)
	defer stop()
	ticker := time.NewTicker(b.pollInterval)
	defer ticker.Stop()

	// giveUp cancels the job and explains why waiting ended.
	giveUp := func(pollErr error) (*batchJob, error) {
		b.cancel(ctx, name)
		switch {
		case ctx.Err() != nil:
			return nil, fmt.Errorf("waiting for batch job %s: %w", name, ctx.Err())
		case waitCtx.Err() != nil:
			return nil, fmt.Errorf("batch job %s not finished after %s; cancelled", name, b.maxWait)
		}
		return nil, fmt.Errorf("polling batch job %s: %w", name, pollErr)
	}

	for {
		select {
		case <-waitCtx.Done():
			return giveUp(nil)
		case <-ticker.C:
		}

		var job batchJob
		if err := b.call(waitCtx, http.MethodGet, b.host()+"/v1/"+name, nil, true, &job); err != nil {
			return giveUp(err)
		}
		b.logger.Debug("batch job state", "job", name, "state", job.State)

		switch job.State {
		case jobSucceeded, jobPartiallySucceeded:
			return &job, nil
		case jobFailed, jobCancelled, jobExpired:
			return nil, fmt.Errorf("batch job ended %s", job.State)
		}
	}
}

// cancel stops a job that is no longer wanted, on a context that outlives a
// cancelled ctx.
func (b *VertexBatch) cancel(ctx context.Context, name string) {
	cctx, stop := context.WithTimeout(context.WithoutCancel(ctx), cancelTimeout)
	defer stop()

	// A job that already finished cannot be cancelled; asking only produces an
	// error in the audit log. If the state cannot be read, cancel anyway.
	var job batchJob
	if err := b.call(cctx, http.MethodGet, b.host()+"/v1/"+name, nil, true, &job); err == nil {
		switch job.State {
		case jobSucceeded, jobPartiallySucceeded, jobFailed, jobCancelled, jobExpired:
			b.logger.Debug("batch job already finished; not cancelling", "job", name, "state", job.State)
			return
		}
	}
	if err := b.call(cctx, http.MethodPost, b.host()+"/v1/"+name+":cancel", []byte("{}"), true, nil); err != nil {
		b.logger.Warn("cancelling batch job failed", "job", name, "error", err)
		return
	}
	if ctx.Err() != nil {
		// Shutdown: the job was cancelled on purpose; unseen items are
		// fetched again after the restart, so nothing needs attention.
		b.logger.Info("batch job cancelled on shutdown", "job", name)
		return
	}
	b.logger.Warn("batch job cancelled", "job", name)
}

// call performs a JSON request against the Vertex AI or Cloud Storage APIs.
func (b *VertexBatch) call(ctx context.Context, method, endpoint string, body []byte, retry bool, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	var resp *http.Response
	if retry {
		resp, err = retryDo(b.httpClient, req)
	} else {
		resp, err = b.httpClient.Do(req)
	}
	if err != nil {
		return &RequestError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return &HTTPError{StatusCode: resp.StatusCode, Body: string(msg)}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBatchResponse)).Decode(out); err != nil {
		return fmt.Errorf("decoding provider metadata: %w", &RequestError{Err: err})
	}
	return nil
}

// collect reads every .jsonl file the job wrote and keeps the answers to the
// requests in want.
func (b *VertexBatch) collect(ctx context.Context, job *batchJob, want map[string]struct{}) (map[string]string, error) {
	ctx = context.WithValue(ctx, batchJobTelemetryKey{}, batchJobTelemetry{Name: job.Name, CreateTime: job.CreateTime})
	dir := job.OutputInfo.GCSOutputDirectory
	bucket, prefix, ok := parseGCSURI(dir)
	if !ok {
		return nil, fmt.Errorf("batch job has no usable output directory")
	}
	objects, err := b.list(ctx, bucket, prefix+"/")
	if err != nil {
		return nil, fmt.Errorf("listing batch output: %w", err)
	}
	if len(objects) == 0 {
		return nil, fmt.Errorf("batch job %s wrote no output under %s", job.Name, dir)
	}

	answers := make(map[string]string, len(want))
	var tally batchTally
	for _, object := range objects {
		t, err := b.download(ctx, bucket, object, want, answers)
		if err != nil {
			return nil, fmt.Errorf("reading batch output %s: %w", object, err)
		}
		tally.add(t)
	}
	if tally.failed > 0 || tally.unmatched > 0 || tally.malformed > 0 || len(answers) < len(want) {
		b.logger.Warn("batch job output incomplete or unmatched; unanswered requests run live", "job", job.Name,
			"requested", len(want), "answered", len(answers), "failed", tally.failed, "unmatched", tally.unmatched, "malformed", tally.malformed)
	}
	return answers, nil
}

func parseGCSURI(uri string) (bucket, object string, ok bool) {
	rest, found := strings.CutPrefix(uri, "gs://")
	if !found {
		return "", "", false
	}
	bucket, object, _ = strings.Cut(rest, "/")
	object = strings.TrimSuffix(object, "/")
	return bucket, object, bucket != "" && object != ""
}

// list returns the names of the .jsonl objects under prefix.
func (b *VertexBatch) list(ctx context.Context, bucket, prefix string) ([]string, error) {
	var names []string
	pageToken := ""
	for {
		endpoint := fmt.Sprintf("%s/storage/v1/b/%s/o?prefix=%s", gcsEndpoint, url.PathEscape(bucket), url.QueryEscape(prefix))
		if pageToken != "" {
			endpoint += "&pageToken=" + url.QueryEscape(pageToken)
		}
		var page struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := b.call(ctx, http.MethodGet, endpoint, nil, true, &page); err != nil {
			return nil, err
		}
		for _, item := range page.Items {
			if strings.HasSuffix(item.Name, ".jsonl") {
				names = append(names, item.Name)
			}
		}
		if len(names) > maxBatchObjects {
			return nil, fmt.Errorf("more than %d output files", maxBatchObjects)
		}
		if page.NextPageToken == "" {
			return names, nil
		}
		pageToken = page.NextPageToken
	}
}

// download streams one output object through collectBatchOutput.
func (b *VertexBatch) download(ctx context.Context, bucket, object string, want map[string]struct{}, answers map[string]string) (batchTally, error) {
	endpoint := fmt.Sprintf("%s/storage/v1/b/%s/o/%s?alt=media", gcsEndpoint, url.PathEscape(bucket), url.PathEscape(object))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return batchTally{}, err
	}
	resp, err := retryDo(b.httpClient, req)
	if err != nil {
		return batchTally{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return batchTally{}, &HTTPError{StatusCode: resp.StatusCode, Body: string(msg)}
	}
	return collectBatchOutput(resp.Body, want, answers, func(key string, response vertexResponse) {
		metadata, _ := ctx.Value(batchCallMetadataKey{}).(map[string]CallMetadata)
		rctx := WithCallMetadata(ctx, metadata[key])
		_, finishErr := structuredText(response)
		logUsage(rctx, b.logger, b.model, "batch", key, response, 0, finishErr)
	})
}

// batchTally counts what became of the lines in batch output.
type batchTally struct {
	answered  int // stored in answers
	failed    int // the request failed inside the job, or the answer holds no text
	unmatched int // answers a request nobody asked for, or one already answered
	malformed int // not a JSON object, or longer than maxBatchLine
}

func (t *batchTally) add(o batchTally) {
	t.answered += o.answered
	t.failed += o.failed
	t.unmatched += o.unmatched
	t.malformed += o.malformed
}

type batchOutputLine struct {
	Request  vertexRequest   `json:"request"`
	Status   json.RawMessage `json:"status"`
	Response vertexResponse  `json:"response"`
}

// failed reports whether the line carries an error status. A successful line
// has an empty status.
func (l batchOutputLine) failed() bool {
	status := strings.TrimSpace(string(l.Status))
	return status != "" && status != `""` && status != "null"
}

// collectBatchOutput reads JSONL batch output line by line and stores the
// answer to every request in want under its key. The key is recomputed from the
// echoed request, never from raw bytes, because the echo does not keep the key
// order of the input. Lines with an error status or no answer text are not
// stored, so their requests run live.
func collectBatchOutput(r io.Reader, want map[string]struct{}, answers map[string]string, observers ...func(string, vertexResponse)) (batchTally, error) {
	var tally batchTally
	br := bufio.NewReaderSize(r, 64*1024)
	var line []byte
	oversize := false

	handle := func(raw []byte) {
		var out batchOutputLine
		if err := json.Unmarshal(raw, &out); err != nil {
			tally.malformed++
			return
		}
		if out.failed() {
			tally.failed++
			return
		}
		key := requestKey(out.Request)
		if _, wanted := want[key]; !wanted {
			tally.unmatched++
			return
		}
		if _, dup := answers[key]; dup {
			tally.unmatched++
			return
		}
		for _, observe := range observers {
			observe(key, out.Response)
		}
		text, err := structuredText(out.Response)
		if err != nil || len(text) > maxBatchAnswer {
			tally.failed++
			return
		}
		answers[key] = text
		tally.answered++
	}

	for {
		chunk, more, err := br.ReadLine()
		if err != nil {
			if err == io.EOF {
				return tally, nil
			}
			return tally, err
		}
		if !oversize {
			if len(line)+len(chunk) > maxBatchLine {
				oversize = true
				line = line[:0]
			} else {
				line = append(line, chunk...)
			}
		}
		if more {
			continue
		}
		switch {
		case oversize:
			tally.malformed++
		case len(bytes.TrimSpace(line)) > 0:
			handle(line)
		}
		line = line[:0]
		oversize = false
	}
}
