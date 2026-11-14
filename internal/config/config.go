package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DB         DBConfig         `yaml:"db"`
	LLM        LLMConfig        `yaml:"llm"`
	GitHub     GitHubConfig     `yaml:"github"`
	Publish    PublishConfig    `yaml:"publish"`
	Sources    SourcesConfig    `yaml:"sources"`
	Pipeline   PipelineConfig   `yaml:"pipeline"`
	Watchlist  WatchlistConfig  `yaml:"watchlist"`
	EPSS       EPSSConfig       `yaml:"epss"`
	Notifier   NotifierConfig   `yaml:"notifier"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
}

type MonitoringConfig struct {
	PublicFeedURL string `yaml:"public_feed_url"`
	// PublicFeedPublishGrace is how long the public site may take to show a
	// brief after threat-bot pushed it before the feed counts as stale.
	PublicFeedPublishGrace  time.Duration `yaml:"public_feed_publish_grace"`
	PublicFeedCheckInterval time.Duration `yaml:"public_feed_check_interval"`
}

// NotifierConfig wires direct threat-bot → feed-notifier dispatch for
// L3 update events (KEV flip, active-exploitation, severity → critical).
// Empty URL or empty token disables the path; updates render on the
// site but don't email subscribers.
type NotifierConfig struct {
	URL           string        `yaml:"url"`
	DispatchToken string        `yaml:"dispatch_token"`
	Cooldown      time.Duration `yaml:"cooldown"` // per-brief min interval between L3 dispatches; default 6h
}

type EPSSConfig struct {
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	MinScoreDelta   float64       `yaml:"min_score_delta"`
}

type DBConfig struct {
	Path string `yaml:"path"`
}

type LLMBatchConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Bucket       string        `yaml:"bucket"`
	PollInterval time.Duration `yaml:"poll_interval"`
	MaxWait      time.Duration `yaml:"max_wait"`
	// MinPrompts is the smallest prompt set worth a batch job; smaller sets
	// run live. Default 5.
	MinPrompts int `yaml:"min_prompts"`
}

type LLMConfig struct {
	Batch       LLMBatchConfig `yaml:"batch"`
	Provider    string         `yaml:"provider"` // explicitly "ollama" or "vertexai"
	Endpoint    string         `yaml:"endpoint"`
	Model       string         `yaml:"model"`
	RepairModel string         `yaml:"repair_model"` // optional targeted grounding repair model
	FastModel   string         `yaml:"fast_model"`   // smaller model for quality gate (defaults to Model)
	Project     string         `yaml:"project"`      // GCP project ID (Vertex AI only)
	Location    string         `yaml:"location"`     // GCP region (Vertex AI only)
}

type GitHubConfig struct {
	AppID          int64  `yaml:"app_id"`
	InstallationID int64  `yaml:"installation_id"`
	PrivateKeyPath string `yaml:"private_key_path"`
}

type PublishConfig struct {
	RepoSlug      string `yaml:"repo_slug"` // owner/repository on GitHub.com
	SiteURL       string `yaml:"site_url"`
	Branch        string `yaml:"branch"`
	AuthorName    string `yaml:"author_name"`
	AuthorEmail   string `yaml:"author_email"`
	FeedPublicKey string `yaml:"feed_public_key"` // hex-encoded public compatibility key; not a confidentiality boundary
}

type SourcesConfig struct {
	BlueskyDiscovery      BlueskyDiscoveryConfig      `yaml:"bluesky_discovery"`
	MastodonDiscovery     MastodonDiscoveryConfig     `yaml:"mastodon_discovery"`
	PublicWebSocialSearch PublicWebSocialSearchConfig `yaml:"public_web_social_search"`
	SocialContext         SocialContextConfig         `yaml:"social_context"`
	SigmaHQ               SourceToggle                `yaml:"sigma_hq"`
	Elastic               SourceToggle                `yaml:"elastic"`
	SplunkESCU            SourceToggle                `yaml:"splunk_escu"`
	CISA                  SourceToggle                `yaml:"cisa"`
	DFIRReport            SourceToggle                `yaml:"dfir_report"`
	AbuseCH               AbuseCHSource               `yaml:"abuse_ch"`
	RedditNetSec          SourceToggle                `yaml:"reddit_netsec"`
	RedditBlueTeamSec     SourceToggle                `yaml:"reddit_blueteamsec"`
	RedditCybersecurity   SourceToggle                `yaml:"reddit_cybersecurity"`
	ISCStormCast          SourceToggle                `yaml:"isc_stormcast"`
	CISAKEV               SourceToggle                `yaml:"cisa_kev"`
	CCBBelgium            SourceToggle                `yaml:"ccb_belgium"`
	CIRCLMISP             SourceToggle                `yaml:"circl_misp"`
	RiskyBiz              SourceToggle                `yaml:"risky_biz"`
	RiskyBizBulletin      SourceToggle                `yaml:"risky_biz_bulletin"`
	PwnWatch              SourceToggle                `yaml:"pwn_watch"`
	// Vendor threat research blogs
	Talos                SourceToggle `yaml:"talos"`
	Mandiant             SourceToggle `yaml:"mandiant"`
	Unit42               SourceToggle `yaml:"unit42"`
	MicrosoftThreatIntel SourceToggle `yaml:"microsoft_threat_intel"`
	SophosXOps           SourceToggle `yaml:"sophos_xops"`
	Huntress             SourceToggle `yaml:"huntress"`
	ArcticWolf           SourceToggle `yaml:"arctic_wolf"`
	CheckPoint           SourceToggle `yaml:"checkpoint"`
	CrowdStrike          SourceToggle `yaml:"crowdstrike"`
	ESET                 SourceToggle `yaml:"eset"`
	Volexity             SourceToggle `yaml:"volexity"`
	Wiz                  SourceToggle `yaml:"wiz"`
	HackerNews           SourceToggle `yaml:"the_hacker_news"`
	DarkReading          SourceToggle `yaml:"dark_reading"`
	DataBreaches         SourceToggle `yaml:"databreaches"`
	HackRead             SourceToggle `yaml:"hackread"`
	RansomwareLive       SourceToggle `yaml:"ransomware_live"`
	DataBreachToday      SourceToggle `yaml:"databreachtoday"`
	KrebsBreaches        SourceToggle `yaml:"krebs_breaches"`
	Schneier             SourceToggle `yaml:"schneier"`
	Securelist           SourceToggle `yaml:"securelist"`
	OSSSec               SourceToggle `yaml:"oss_security"`
	WatchTowr            SourceToggle `yaml:"watchtowr"`
	MozillaSecurity      SourceToggle `yaml:"mozilla_security"`
	ArsSecurity          SourceToggle `yaml:"ars_security"`
	InfosecExchangeCVE   SourceToggle `yaml:"infosec_exchange_cve"`
	// National CERTs
	NCSC   SourceToggle `yaml:"ncsc_uk"`
	NCSCNL SourceToggle `yaml:"ncsc_nl"`
	ANSSI  SourceToggle `yaml:"anssi"`
	BSI    SourceToggle `yaml:"bsi"`
	CERTEU SourceToggle `yaml:"cert_eu"`
	JPCERT SourceToggle `yaml:"jpcert"`
	// Broad cybersecurity news
	BleepingComputer SourceToggle `yaml:"bleepingcomputer"`
	TheRecord        SourceToggle `yaml:"therecord"`
	SecurityWeek     SourceToggle `yaml:"securityweek"`
	// Vulnerability intelligence
	NVD  SourceToggle `yaml:"nvd"`
	GHSA SourceToggle `yaml:"ghsa"`
	// Vendor PSIRT advisory feeds
	MSRC             SourceToggle `yaml:"msrc"`
	CiscoPSIRT       SourceToggle `yaml:"cisco_psirt"`
	PaloAltoNetworks SourceToggle `yaml:"palo_alto_networks"`
	// Supply chain and vulnerability research
	Sonatype          SourceToggle `yaml:"sonatype"`
	GoogleProjectZero SourceToggle `yaml:"google_project_zero"`
	// New threat intel sources — added 2026-05-06
	// Tier 1 commercial
	SentinelLabs SourceToggle `yaml:"sentinel_labs"`
	// Tier 2 commercial
	Bitdefender            SourceToggle `yaml:"bitdefender"`
	FortiGuard             SourceToggle `yaml:"fortiguard"`
	Proofpoint             SourceToggle `yaml:"proofpoint"`
	Rapid7                 SourceToggle `yaml:"rapid7"`
	RedCanary              SourceToggle `yaml:"red_canary"`
	RecordedFuture         SourceToggle `yaml:"recorded_future"`
	Flashpoint             SourceToggle `yaml:"flashpoint"`
	Intel471               SourceToggle `yaml:"intel471"`
	GreyNoise              SourceToggle `yaml:"greynoise"`
	Cofense                SourceToggle `yaml:"cofense"`
	AnyRun                 SourceToggle `yaml:"any_run"`
	QualysThreatResearch   SourceToggle `yaml:"qualys_threat_research"`
	MalwareTrafficAnalysis SourceToggle `yaml:"malware_traffic_analysis"`
	ObjectiveSee           SourceToggle `yaml:"objective_see"`
	AttackIQ               SourceToggle `yaml:"attackiq"`
	// Government / CERT
	FBICyber SourceToggle `yaml:"fbi_cyber"`
	CCCS     SourceToggle `yaml:"cccs"`
	ACSC     SourceToggle `yaml:"acsc"`
	MSISAC   SourceToggle `yaml:"ms_isac"`
	// Independent research
	GoogleTAG SourceToggle `yaml:"google_tag"`
	// Exploit tracking
	ExploitDB SourceToggle `yaml:"exploit_db"`
	Sploitus  SourceToggle `yaml:"sploitus"`
	// Detection-focused research
	SocPrime SourceToggle `yaml:"socprime"`
	// Curated commentary published only behind a social auth wall, read via a
	// third-party bridge feed.
	Ronin66 BridgedSource `yaml:"ronin66"`
	// Kevin Beaumont (GossiTheDog) — detection content repo plus Mastodon
	// commentary. Both have first-party feeds (no bridge needed).
	GossiTheDogThreatHunting SourceToggle `yaml:"gossithedog_threathunting"`
	GossiTheDogMastodon      SourceToggle `yaml:"gossithedog_mastodon"`
}

type BlueskyDiscoveryConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Endpoint     string        `yaml:"endpoint"`
	CandidateCap int           `yaml:"candidate_cap"`
	ReadWindow   time.Duration `yaml:"read_window"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

type MastodonDiscoveryConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Instances    []string      `yaml:"instances"`
	Tags         []string      `yaml:"tags"`
	CandidateCap int           `yaml:"candidate_cap"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

type PublicWebSocialSearchConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Provider      string        `yaml:"provider"`
	Endpoint      string        `yaml:"endpoint"`
	APIKeyEnv     string        `yaml:"api_key_env"`
	APIKey        string        `yaml:"-"`
	Limit         int           `yaml:"limit"`
	ResponseLimit int64         `yaml:"response_limit"`
	PollInterval  time.Duration `yaml:"poll_interval"`
	QueryGroups   [][]string    `yaml:"query_groups"`
}

type SocialContextConfig struct {
	ResolverURLs       []string      `yaml:"resolver_urls"`
	ThreadResolverURL  string        `yaml:"thread_resolver_url"`
	OEmbedEnabled      bool          `yaml:"oembed_enabled"`
	OEmbedURL          string        `yaml:"oembed_url"`
	ThreadDepth        int           `yaml:"thread_depth"`
	ResponseLimit      int64         `yaml:"response_limit"`
	LeafDailyBudget    int           `yaml:"leaf_daily_budget"`
	ThreadDailyBudget  int           `yaml:"thread_daily_budget"`
	RequestInterval    time.Duration `yaml:"request_interval"`
	ThreadCacheEntries int           `yaml:"thread_cache_entries"`
}

type SourceToggle struct {
	Enabled      bool          `yaml:"enabled"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// BridgedSource is a SourceToggle whose feed URL comes from config rather than
// being hardcoded like every other source: bridge feeds carry a
// per-subscription token and rotate, so the URL must not live in source.
type BridgedSource struct {
	SourceToggle `yaml:",inline"`
	FeedURL      string `yaml:"feed_url"`
}

// AbuseCHSource is a SourceToggle plus the abuse.ch Auth-Key, which URLhaus
// and ThreatFox require on every request.
type AbuseCHSource struct {
	SourceToggle `yaml:",inline"`
	APIKeyEnv    string `yaml:"api_key_env"`
	APIKey       string `yaml:"-"`
}

type WatchlistConfig struct {
	Vendors      []string            `yaml:"vendors"`
	Products     []string            `yaml:"products"`
	Keywords     []string            `yaml:"keywords"`
	PlatformSync *PlatformSyncConfig `yaml:"platform_sync"`
}

type PlatformSyncConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Endpoint string        `yaml:"endpoint"`
	Interval time.Duration `yaml:"interval"`
	APIKey   string        `yaml:"api_key"`
}

type PipelineConfig struct {
	QualityThreshold float64 `yaml:"quality_threshold"`
	// MaxGroundingAttempts quarantines an item whose brief still fails the
	// grounding check after this many passes. Zero means the default (5).
	RetryBackoff           time.Duration            `yaml:"retry_backoff"` // default 15m between failed candidate retries
	MaxGroundingAttempts   int                      `yaml:"max_grounding_attempts"`
	InitialLookback        time.Duration            `yaml:"initial_lookback"`
	SourceConfidence       map[string]float64       `yaml:"source_confidence"`        // per-source confidence multiplier (0.0-1.0)
	SourceSignalThresholds map[string]int           `yaml:"source_signal_thresholds"` // opt-in deterministic pre-LLM gate by source
	AdaptivePolling        map[string]time.Duration `yaml:"adaptive_polling"`         // opt-in maximum poll interval by source
	AutoPublish            bool                     `yaml:"auto_publish"`             // auto-publish briefs that pass quality gate
	// RoundupConsolidation folds a patch-cycle vendor's monthly CVEs (Patch
	// Tuesday, Apple, Adobe, Qualcomm, ...) into one roundup brief. Default off.
	RoundupConsolidation bool `yaml:"roundup_consolidation"`
	// CampaignConsolidation folds known campaign/technique families (ClickFix,
	// Shai-Hulud) into one umbrella brief. Default off.
	CampaignConsolidation bool `yaml:"campaign_consolidation"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("config must contain exactly one YAML document")
	}
	if cfg.LLM.Endpoint == "" {
		cfg.LLM.Endpoint = "http://localhost:11434"
	}
	if cfg.Publish.Branch == "" {
		cfg.Publish.Branch = "main"
	}
	if cfg.Publish.AuthorName == "" {
		cfg.Publish.AuthorName = "threat-bot"
	}
	if cfg.Publish.AuthorEmail == "" {
		cfg.Publish.AuthorEmail = "threat-bot@users.noreply.github.com"
	}

	// Recovery remains available when new batch submission is disabled.
	if cfg.LLM.Batch.PollInterval == 0 {
		cfg.LLM.Batch.PollInterval = 30 * time.Second
	}
	if cfg.LLM.Batch.MaxWait == 0 {
		cfg.LLM.Batch.MaxWait = 15 * time.Minute
	}

	if cfg.LLM.Batch.Enabled {
		if cfg.LLM.Provider != "vertexai" || cfg.LLM.Batch.Bucket == "" {
			return nil, fmt.Errorf("LLM batch requires vertexai provider and a bucket")
		}
		if cfg.LLM.Batch.MinPrompts == 0 {
			cfg.LLM.Batch.MinPrompts = 5
		}
		if cfg.LLM.Batch.MinPrompts < 0 {
			return nil, fmt.Errorf("LLM batch min_prompts must not be negative")
		}
		if cfg.LLM.Batch.PollInterval < 0 || cfg.LLM.Batch.MaxWait < 0 {
			return nil, fmt.Errorf("LLM batch poll_interval and max_wait must be positive")
		}
	}

	// EPSS refresh defaults.
	if cfg.EPSS.RefreshInterval == 0 {
		cfg.EPSS.RefreshInterval = 24 * time.Hour
	}
	if cfg.EPSS.MinScoreDelta == 0 {
		cfg.EPSS.MinScoreDelta = 0.01
	}

	// Public feed freshness monitor defaults.
	if cfg.Monitoring.PublicFeedPublishGrace == 0 {
		cfg.Monitoring.PublicFeedPublishGrace = 45 * time.Minute
	}
	if cfg.Monitoring.PublicFeedCheckInterval == 0 {
		cfg.Monitoring.PublicFeedCheckInterval = 15 * time.Minute
	}

	// Notifier defaults.
	if cfg.Notifier.Cooldown == 0 {
		cfg.Notifier.Cooldown = 6 * time.Hour
	}
	// Allow the dispatch token to come from the environment so the
	// configmap can stay plaintext and the secret can be mounted as
	// NOTIFIER_DISPATCH_TOKEN via envFrom.
	if cfg.Notifier.DispatchToken == "" {
		cfg.Notifier.DispatchToken = strings.TrimSpace(os.Getenv("NOTIFIER_DISPATCH_TOKEN"))
	}
	if cfg.Sources.BlueskyDiscovery.Endpoint == "" {
		cfg.Sources.BlueskyDiscovery.Endpoint = "wss://jetstream2.us-east.bsky.network/subscribe"
	}
	if cfg.Sources.BlueskyDiscovery.CandidateCap == 0 {
		cfg.Sources.BlueskyDiscovery.CandidateCap = 100
	}
	if cfg.Sources.BlueskyDiscovery.ReadWindow == 0 {
		cfg.Sources.BlueskyDiscovery.ReadWindow = 20 * time.Second
	}
	if cfg.Sources.BlueskyDiscovery.PollInterval == 0 {
		cfg.Sources.BlueskyDiscovery.PollInterval = time.Minute
	}
	if len(cfg.Sources.MastodonDiscovery.Tags) == 0 {
		cfg.Sources.MastodonDiscovery.Tags = []string{"cve", "infosec", "vulnerability", "exploit", "0day", "malware"}
	}
	if cfg.Sources.MastodonDiscovery.CandidateCap == 0 {
		cfg.Sources.MastodonDiscovery.CandidateCap = 100
	}
	if cfg.Sources.MastodonDiscovery.PollInterval == 0 {
		cfg.Sources.MastodonDiscovery.PollInterval = time.Minute
	}
	if cfg.Sources.PublicWebSocialSearch.Limit == 0 {
		cfg.Sources.PublicWebSocialSearch.Limit = 25
	}
	if cfg.Sources.PublicWebSocialSearch.ResponseLimit == 0 {
		cfg.Sources.PublicWebSocialSearch.ResponseLimit = 256 << 10
	}
	if strings.EqualFold(cfg.Sources.PublicWebSocialSearch.Provider, "brave") {
		if cfg.Sources.PublicWebSocialSearch.Endpoint == "" {
			cfg.Sources.PublicWebSocialSearch.Endpoint = "https://api.search.brave.com/res/v1/web/search"
		}
		if cfg.Sources.PublicWebSocialSearch.APIKeyEnv == "" {
			cfg.Sources.PublicWebSocialSearch.APIKeyEnv = "BRAVE_SEARCH_API_KEY"
		}
		cfg.Sources.PublicWebSocialSearch.APIKey = strings.TrimSpace(os.Getenv(cfg.Sources.PublicWebSocialSearch.APIKeyEnv))
	}
	if cfg.Sources.PublicWebSocialSearch.PollInterval == 0 {
		cfg.Sources.PublicWebSocialSearch.PollInterval = time.Minute
	}
	if cfg.Sources.AbuseCH.APIKeyEnv == "" {
		cfg.Sources.AbuseCH.APIKeyEnv = "ABUSECH_AUTH_KEY"
	}
	cfg.Sources.AbuseCH.APIKey = strings.TrimSpace(os.Getenv(cfg.Sources.AbuseCH.APIKeyEnv))
	if cfg.Sources.SocialContext.ThreadDepth == 0 {
		cfg.Sources.SocialContext.ThreadDepth = 6
	}
	if cfg.Sources.SocialContext.OEmbedURL == "" {
		cfg.Sources.SocialContext.OEmbedURL = "https://publish.x.com/oembed"
	}
	if cfg.Sources.SocialContext.ResponseLimit == 0 {
		cfg.Sources.SocialContext.ResponseLimit = 256 << 10
	}
	if cfg.Sources.SocialContext.LeafDailyBudget == 0 {
		cfg.Sources.SocialContext.LeafDailyBudget = 100
	}
	if cfg.Sources.SocialContext.ThreadDailyBudget == 0 {
		cfg.Sources.SocialContext.ThreadDailyBudget = 20
	}
	if cfg.Sources.SocialContext.RequestInterval == 0 {
		cfg.Sources.SocialContext.RequestInterval = 2 * time.Second
	}
	if cfg.Sources.SocialContext.ThreadCacheEntries == 0 {
		cfg.Sources.SocialContext.ThreadCacheEntries = 512
	}

	return &cfg, nil
}
