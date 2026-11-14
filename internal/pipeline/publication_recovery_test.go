package pipeline

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

type recoveryPublisher struct {
	fail            bool
	updates, drafts int
	payload         string
}

func (p *recoveryPublisher) Publish(s string) error {
	if p.fail {
		return errors.New("queue unavailable")
	}
	p.updates++
	p.payload = s
	return nil
}
func (p *recoveryPublisher) PublishDraft(s, _, _ string) error {
	if p.fail {
		return errors.New("queue unavailable")
	}
	p.drafts++
	p.payload = s
	return nil
}
func (*recoveryPublisher) Flush() error { return nil }
func TestDraftPublicationRecoverySurvivesQueueFailureAndRestart(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	draft := &storage.Draft{ID: "intent", Source: "test", Status: storage.StatusPending, BriefYAML: "candidate", CreatedAt: time.Now()}
	if err := db.CreateDraftWithPublication(draft, ""); err != nil {
		t.Fatal(err)
	}
	pub := &recoveryPublisher{fail: true}
	cfg := Config{DB: db, Publisher: pub, AutoPublish: true, Logger: quietLogger()}
	if err := New(cfg).recoverPublicationIntents(); err == nil {
		t.Fatal("queue error ignored")
	}
	intents, _ := db.ListPublicationIntents()
	if len(intents) != 1 {
		t.Fatal("durable work lost")
	}
	pub.fail = false
	if err := New(cfg).recoverPublicationIntents(); err != nil {
		t.Fatal(err)
	}
	if pub.drafts != 1 || pub.updates != 0 || pub.payload != "candidate" {
		t.Fatalf("wrong recovery: %+v", pub)
	}
	intents, _ = db.ListPublicationIntents()
	if len(intents) != 0 {
		t.Fatal("accepted intent retained")
	}
	if err := New(cfg).recoverPublicationIntents(); err != nil {
		t.Fatal(err)
	}
	if pub.drafts != 1 {
		t.Fatal("completed recovery repeated")
	}
}

type reviewSelectivePublisher struct{ queued int }

func (*reviewSelectivePublisher) ValidatePublication(s string) error {
	if s == "legacy candidate now fails current editorial policy" {
		return fmt.Errorf("brief requires editorial review: missing affected product evidence")
	}
	return nil
}
func (p *reviewSelectivePublisher) Publish(s string) error {
	if err := p.ValidatePublication(s); err != nil {
		return err
	}
	p.queued++
	return nil
}
func (p *reviewSelectivePublisher) PublishDraft(s, _, _ string) error { return p.Publish(s) }
func (*reviewSelectivePublisher) Flush() error                        { return nil }
func TestRejectedRetainedIntentDoesNotBlockIndependentPublication(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	for _, c := range []struct{ id, payload string }{{"old", "legacy candidate now fails current editorial policy"}, {"new", "validated new candidate"}} {
		if err := db.CreateDraftWithPublication(&storage.Draft{ID: c.id, Status: storage.StatusPending, BriefYAML: c.payload, CreatedAt: time.Now()}, ""); err != nil {
			t.Fatal(err)
		}
	}
	pub := &reviewSelectivePublisher{}
	p := New(Config{DB: db, Publisher: pub, AutoPublish: true, Logger: quietLogger()})
	for range 2 {
		_ = p.Process(context.Background(), nil)
	}
	if pub.queued != 1 {
		t.Fatalf("one editorially rejected retained intent blocks unrelated validated work on every run: queued=%d want1", pub.queued)
	}
}
