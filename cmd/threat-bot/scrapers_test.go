package main

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// Every source must poll at its configured interval. Registration used to
// drop the configured value for all non-Reddit sources, silently falling
// back to the registry default and hammering the feeds.
func TestRegisterScrapersHonorsConfiguredIntervals(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var cfg config.Config
	cfg.Sources.BleepingComputer = config.SourceToggle{Enabled: true, PollInterval: time.Hour}
	cfg.Sources.CCBBelgium = config.SourceToggle{Enabled: true, PollInterval: 6 * time.Hour}
	cfg.Sources.NVD = config.SourceToggle{Enabled: true} // interval unset
	cfg.Sources.RedditNetSec = config.SourceToggle{Enabled: true}
	cfg.Sources.PwnWatch = config.SourceToggle{Enabled: true, PollInterval: time.Hour}
	cfg.Sources.SOCRadar = config.SourceToggle{Enabled: true, PollInterval: 6 * time.Hour}
	cfg.Sources.GossiTheDogThreatHunting = config.SourceToggle{Enabled: true, PollInterval: 3 * time.Hour}
	cfg.Sources.GossiTheDogMastodon = config.SourceToggle{Enabled: true, PollInterval: 30 * time.Minute}

	runner := scraper.NewRunner(nil, logger, 0)
	registerScrapers(runner, &cfg, func() string { return "" }, nil, logger)

	got := runner.PollIntervals()
	want := map[string]time.Duration{
		"bleepingcomputer":          time.Hour,
		"ccb-belgium":               6 * time.Hour,
		"nvd":                       time.Hour, // conservative default when unset
		"reddit-netsec":             5 * time.Minute,
		"pwn-watch":                 time.Hour,
		"socradar":                  6 * time.Hour,
		"gossithedog-threathunting": 3 * time.Hour,
		"gossithedog-mastodon":      30 * time.Minute,
	}
	for name, interval := range want {
		if got[name] != interval {
			t.Errorf("%s poll interval = %v, want %v", name, got[name], interval)
		}
	}
}

func TestCountEnabledSourcesIncludesSOCRadar(t *testing.T) {
	var cfg config.Config
	cfg.Sources.SOCRadar.Enabled = true
	if got := countEnabledSources(&cfg); got != 1 {
		t.Fatalf("countEnabledSources() = %d, want 1", got)
	}
}

func TestRegisterScrapersRegistersBridgedSourceWithFeedURL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var cfg config.Config
	cfg.Sources.Ronin66 = config.BridgedSource{
		SourceToggle: config.SourceToggle{Enabled: true, PollInterval: 2 * time.Hour},
		FeedURL:      "https://rss.app/feeds/abc.xml",
	}

	runner := scraper.NewRunner(nil, logger, 0)
	registerScrapers(runner, &cfg, func() string { return "" }, nil, logger)

	if got := runner.PollIntervals()["ronin66"]; got != 2*time.Hour {
		t.Errorf("ronin66 poll interval = %v, want %v", got, 2*time.Hour)
	}
}

// A bridged source is inert without its feed URL, which carries a
// per-subscription token and therefore lives in config. Registering one anyway
// would log a poll failure every cycle forever.
func TestRegisterScrapersSkipsBridgedSourceWithoutFeedURL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var cfg config.Config
	cfg.Sources.Ronin66 = config.BridgedSource{
		SourceToggle: config.SourceToggle{Enabled: true, PollInterval: 2 * time.Hour},
	}

	runner := scraper.NewRunner(nil, logger, 0)
	registerScrapers(runner, &cfg, func() string { return "" }, nil, logger)

	if _, ok := runner.PollIntervals()["ronin66"]; ok {
		t.Error("ronin66 was registered with an empty feed_url, want it skipped")
	}
}

func TestRegisterScrapersSocialDiscovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var cfg config.Config
	cfg.Sources.BlueskyDiscovery = config.BlueskyDiscoveryConfig{Enabled: true, PollInterval: 2 * time.Minute}
	cfg.Sources.MastodonDiscovery = config.MastodonDiscoveryConfig{Enabled: true, Instances: []string{"https://infosec.exchange"}, PollInterval: 3 * time.Minute}
	cfg.Sources.PublicWebSocialSearch = config.PublicWebSocialSearchConfig{Enabled: true, Endpoint: "https://search.example.test", PollInterval: 4 * time.Minute}
	runner := scraper.NewRunner(nil, logger, 0)
	registerScrapers(runner, &cfg, func() string { return "" }, nil, logger)
	got := runner.PollIntervals()
	if got["bluesky-discovery"] != 2*time.Minute || got["mastodon-discovery"] != 3*time.Minute {
		t.Fatalf("discovery intervals: %v", got)
	}
	if got["public-web-social-search"] != 4*time.Minute {
		t.Fatalf("search interval: %v", got)
	}
}

// The KEV catalog main loads at startup must be refreshed by the KEV source's
// own polls, so the source registered is the one main loads it through.
func TestRegisterScrapersPollsSharedKEVSource(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var cfg config.Config
	cfg.Sources.CISAKEV = config.SourceToggle{Enabled: true, PollInterval: 6 * time.Hour}
	kev := scraper.NewCISAKEV(scraper.NewKEVCatalog())

	runner := scraper.NewRunner(nil, logger, 0)
	registerScrapers(runner, &cfg, func() string { return "" }, kev, logger)

	got, ok := runner.Scraper("cisa-kev")
	if !ok {
		t.Fatal("cisa-kev not registered")
	}
	if got != scraper.Scraper(kev) {
		t.Fatal("registered KEV source is not the one that fills the catalog")
	}
	if interval := runner.PollIntervals()["cisa-kev"]; interval != 6*time.Hour {
		t.Errorf("cisa-kev poll interval = %v, want 6h", interval)
	}
}
