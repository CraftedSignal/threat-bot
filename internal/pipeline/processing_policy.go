package pipeline

import "encoding/json"

// processingPolicySourceBaseline freezes the source confidence defaults that
// were part of the processing policy before release v0.2.3. Checkpoints,
// evidence keys and retry identities all hash the processing policy, so any
// change to it discards every pending candidate: held rebuilds, retained
// grounding retries and merge reviews are then re-processed and their
// grounding, repair and recheck calls are paid again.
//
// Do not edit this table. Add or retune source defaults in
// defaultSourceConfidence: they apply to new items without invalidating pending
// work. Configured confidence overrides and signal thresholds remain part of
// the policy, as deliberate operator changes. Bump processingPolicyVersion to
// re-evaluate pending work on purpose.
var processingPolicySourceBaseline = map[string]float64{
	"cisa":                   0.95,
	"cisa-kev":               0.95,
	"dfir-report":            0.90,
	"ccb-belgium":            0.85,
	"sigma-hq":               0.90,
	"elastic":                0.85,
	"splunk-escu":            0.85,
	"abuse-ch":               0.80,
	"nvd":                    0.90,
	"ghsa":                   0.85,
	"isc-stormcast":          0.70,
	"circl-misp":             0.75,
	"risky-biz":              0.80,
	"risky-biz-bulletin":     0.80,
	"pwn-watch":              0.55,
	"reddit-netsec":          0.30,
	"reddit-blueteamsec":     0.35,
	"reddit-cybersecurity":   0.25,
	"talos":                  0.85,
	"mandiant":               0.90,
	"unit42":                 0.85,
	"socradar":               0.80,
	"microsoft-threat-intel": 0.85,
	"sophos-xops":            0.80,
	"huntress":               0.80,
	"arctic-wolf":            0.80,
	"checkpoint":             0.85,
	"crowdstrike":            0.90,
	"eset":                   0.85,
	"volexity":               0.90,
	"securelist":             0.90,
	"wiz":                    0.80,
	"ncsc-uk":                0.90,
	"ncsc-nl":                0.90,
	"anssi":                  0.85,
	"bsi":                    0.85,
	"cert-eu":                0.85,
	"jpcert":                 0.80,
	"bleepingcomputer":       0.70,
	"therecord":              0.75,
	"securityweek":           0.70,
	"msrc":                   0.95,
	"cisco-psirt":            0.90,
	"palo-alto-networks":     0.90,
	"sonatype":               0.85,
	"google-project-zero":    0.95,
	"watchtowr":              0.85,
	"mozilla-security":       0.95,
	"ars-security":           0.85,
	// Tier 1 commercial
	"sentinelone-labs": 0.85,
	// Tier 2 commercial
	"bitdefender":              0.80,
	"fortiguard":               0.80,
	"proofpoint":               0.85,
	"rapid7":                   0.80,
	"red-canary":               0.80,
	"recorded-future":          0.80,
	"flashpoint":               0.75,
	"intel471":                 0.80,
	"greynoise":                0.75,
	"cofense":                  0.75,
	"any-run":                  0.70,
	"qualys-threat-research":   0.75,
	"malware-traffic-analysis": 0.75,
	"objective-see":            0.85,
	"attackiq":                 0.70,
	// Government / CERT
	"fbi-cyber": 0.90,
	"cccs":      0.85,
	"acsc":      0.85,
	"ms-isac":   0.80,
	// Independent research
	"google-tag": 0.90,
	// Ransomware victim tracking (observational — group claims, not independently verified)
	"ransomware-live": 0.70,
	// Exploit tracking
	"exploit-db": 0.80,
	"sploitus":   0.75,
	// Detection-focused research
	"socprime": 0.75,
	// Curator, not author: the content is whatever they linked to. Above the
	// reddit tier (a research company's curation, not crowd submissions), well
	// below vendor research. When the destination is already a threat-bot source
	// its own item wins on authority, so this only governs links to publishers
	// threat-bot does not follow — whose rigour is therefore unvetted.
	"ronin66": 0.60,
	// GossiTheDog (Kevin Beaumont): original detection-engineering content he
	// authored himself, same tier as elastic/splunk-escu rather than a curator
	// citing someone else's work.
	"gossithedog-threathunting": 0.80,
	// Mastodon commentary: structurally a curator+link like ronin66, but a
	// named researcher with a strong personal track record of first breaking
	// stories he then verifies himself — set above the generic curator tier.
	"gossithedog-mastodon": 0.75,
}

// processingPolicyConfig is the source-independent part of every processing
// key. Its encoding must stay byte-identical for an unchanged configuration.
func processingPolicyConfig(cfg Config) string {
	confidence := make(map[string]float64, len(processingPolicySourceBaseline)+len(cfg.TrustedSources)+len(cfg.SourceConfidence))
	for source, value := range processingPolicySourceBaseline {
		confidence[source] = value
	}
	for _, source := range cfg.TrustedSources {
		confidence[source] = 1.0
	}
	for source, value := range cfg.SourceConfidence {
		confidence[source] = value
	}
	policy, _ := json.Marshal(struct {
		Models            string
		Threshold         float64
		Confidence        map[string]float64
		Signals           map[string]int
		Roundup, Campaign bool
	}{cfg.ProcessingPolicy, cfg.QualityThreshold, confidence, cfg.SourceSignalThresholds, cfg.RoundupConsolidation, cfg.CampaignConsolidation})
	return string(policy)
}
