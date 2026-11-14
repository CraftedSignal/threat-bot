package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBatchRecoveryPreservesCanonicalAndLegacyCreationIdentity(t *testing.T) {
	for _, prefix := range []string{"threat-bot-prefetch-", "ti-bot-prefetch-"} {
		t.Run(prefix, func(t *testing.T) {
			const id = "20261114-120000-fixture"
			display := prefix + id
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("recovery wrote remote state: %s", r.Method)
				}
				if r.URL.Path == "/v1/projects/p/locations/eu/batchPredictionJobs" {
					if r.URL.Query().Get("filter") != `display_name="`+display+`"` {
						_, _ = fmt.Fprint(w, `{"batchPredictionJobs":[]}`)
						return
					}
					_, _ = fmt.Fprintf(w, `{"batchPredictionJobs":[{"name":%q,"displayName":%q}]}`, fakeJobName, display)
					return
				}
				_, _ = fmt.Fprintf(w, `{"name":%q,"displayName":%q}`, fakeJobName, display)
			}))
			defer srv.Close()
			intent := creationIntentPrefix + id
			store := &memoryJobs{jobs: map[string]string{"request": intent}}
			batch := reviewTestBatch(srv, store)
			job, err := batch.findCreatedJob(context.Background(), id)
			if err != nil || job == nil || job.Name != fakeJobName {
				t.Fatalf("lost existing %s job: job=%+v err=%v", prefix, job, err)
			}
			if err := batch.ReconcileBatchJob(context.Background(), []string{"request"}, intent, fakeJobName); err != nil {
				t.Fatal(err)
			}
			if store.jobs["request"] != fakeJobName {
				t.Fatal("existing paid job was not attached")
			}
		})
	}
}
