package main

import (
	"log/slog"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// registerScrapers wires every enabled source into the runner with its
// configured poll interval. RegisterWithInterval falls back to a
// conservative default when the config leaves the interval unset.
//
// kev is the CISA KEV source; main passes the one that fills the KEV catalog
// so each poll refreshes it. nil registers a source that keeps no catalog.
func registerScrapers(runner *scraper.Runner, cfg *config.Config, ghTokenFn func() string, kev *scraper.CISAKEV, logger *slog.Logger) {
	if cfg.Sources.BlueskyDiscovery.Enabled {
		interval := cfg.Sources.BlueskyDiscovery.PollInterval
		if interval <= 0 {
			interval = time.Minute
		}
		runner.RegisterWithInterval(scraper.NewBlueskyJetstream(cfg.Sources.BlueskyDiscovery), interval)
	}
	if cfg.Sources.MastodonDiscovery.Enabled {
		interval := cfg.Sources.MastodonDiscovery.PollInterval
		if interval <= 0 {
			interval = time.Minute
		}
		runner.RegisterWithInterval(scraper.NewMastodonTagDiscovery(cfg.Sources.MastodonDiscovery), interval)
	}
	if cfg.Sources.PublicWebSocialSearch.Enabled && cfg.Sources.PublicWebSocialSearch.Endpoint != "" {
		interval := cfg.Sources.PublicWebSocialSearch.PollInterval
		if interval <= 0 {
			interval = time.Minute
		}
		runner.RegisterWithInterval(scraper.NewPublicWebSocialSearch(cfg.Sources.PublicWebSocialSearch), interval)
	}
	if cfg.Sources.SigmaHQ.Enabled {
		runner.RegisterWithInterval(scraper.NewSigmaHQ(ghTokenFn), cfg.Sources.SigmaHQ.PollInterval)
	}
	if cfg.Sources.CISA.Enabled {
		runner.RegisterWithInterval(scraper.NewCISA(), cfg.Sources.CISA.PollInterval)
	}
	if cfg.Sources.DFIRReport.Enabled {
		runner.RegisterWithInterval(scraper.NewDFIRReport(), cfg.Sources.DFIRReport.PollInterval)
	}
	if cfg.Sources.ISCStormCast.Enabled {
		runner.RegisterWithInterval(scraper.NewISCStormCast(), cfg.Sources.ISCStormCast.PollInterval)
	}
	if cfg.Sources.RedditNetSec.Enabled {
		interval := cfg.Sources.RedditNetSec.PollInterval
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		runner.RegisterWithInterval(scraper.NewRedditNetSec(), interval)
	}
	if cfg.Sources.RedditBlueTeamSec.Enabled {
		interval := cfg.Sources.RedditBlueTeamSec.PollInterval
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		runner.RegisterWithInterval(scraper.NewRedditBlueTeamSec(), interval)
	}
	if cfg.Sources.RedditCybersecurity.Enabled {
		interval := cfg.Sources.RedditCybersecurity.PollInterval
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		runner.RegisterWithInterval(scraper.NewRedditCybersecurity(), interval)
	}
	if cfg.Sources.Elastic.Enabled {
		runner.RegisterWithInterval(scraper.NewElastic(ghTokenFn), cfg.Sources.Elastic.PollInterval)
	}
	if cfg.Sources.SplunkESCU.Enabled {
		runner.RegisterWithInterval(scraper.NewSplunkESCU(ghTokenFn), cfg.Sources.SplunkESCU.PollInterval)
	}
	if cfg.Sources.AbuseCH.Enabled {
		runner.RegisterWithInterval(scraper.NewAbuseCH(cfg.Sources.AbuseCH.APIKey), cfg.Sources.AbuseCH.PollInterval)
	}
	if cfg.Sources.CISAKEV.Enabled {
		if kev == nil {
			kev = scraper.NewCISAKEV(nil)
		}
		runner.RegisterWithInterval(kev, cfg.Sources.CISAKEV.PollInterval)
	}
	if cfg.Sources.CCBBelgium.Enabled {
		runner.RegisterWithInterval(scraper.NewCCB(), cfg.Sources.CCBBelgium.PollInterval)
	}
	if cfg.Sources.CIRCLMISP.Enabled {
		runner.RegisterWithInterval(scraper.NewCIRCLMISP(), cfg.Sources.CIRCLMISP.PollInterval)
	}
	if cfg.Sources.RiskyBiz.Enabled {
		runner.RegisterWithInterval(scraper.NewRiskyBiz(), cfg.Sources.RiskyBiz.PollInterval)
	}
	if cfg.Sources.RiskyBizBulletin.Enabled {
		runner.RegisterWithInterval(scraper.NewRiskyBizBulletin(), cfg.Sources.RiskyBizBulletin.PollInterval)
	}
	if cfg.Sources.PwnWatch.Enabled {
		runner.RegisterWithInterval(scraper.NewPwnWatch(), cfg.Sources.PwnWatch.PollInterval)
	}
	if cfg.Sources.Talos.Enabled {
		runner.RegisterWithInterval(scraper.NewTalos(), cfg.Sources.Talos.PollInterval)
	}
	if cfg.Sources.Mandiant.Enabled {
		runner.RegisterWithInterval(scraper.NewMandiant(), cfg.Sources.Mandiant.PollInterval)
	}
	if cfg.Sources.Unit42.Enabled {
		runner.RegisterWithInterval(scraper.NewUnit42(), cfg.Sources.Unit42.PollInterval)
	}
	if cfg.Sources.MicrosoftThreatIntel.Enabled {
		runner.RegisterWithInterval(scraper.NewMicrosoftThreatIntel(), cfg.Sources.MicrosoftThreatIntel.PollInterval)
	}
	if cfg.Sources.SophosXOps.Enabled {
		runner.RegisterWithInterval(scraper.NewSophosXOps(), cfg.Sources.SophosXOps.PollInterval)
	}
	if cfg.Sources.Huntress.Enabled {
		runner.RegisterWithInterval(scraper.NewHuntress(), cfg.Sources.Huntress.PollInterval)
	}
	if cfg.Sources.ArcticWolf.Enabled {
		runner.RegisterWithInterval(scraper.NewArcticWolf(), cfg.Sources.ArcticWolf.PollInterval)
	}
	if cfg.Sources.CheckPoint.Enabled {
		runner.RegisterWithInterval(scraper.NewCheckPoint(), cfg.Sources.CheckPoint.PollInterval)
	}
	if cfg.Sources.CrowdStrike.Enabled {
		runner.RegisterWithInterval(scraper.NewCrowdStrike(), cfg.Sources.CrowdStrike.PollInterval)
	}
	if cfg.Sources.ESET.Enabled {
		runner.RegisterWithInterval(scraper.NewESET(), cfg.Sources.ESET.PollInterval)
	}
	if cfg.Sources.Volexity.Enabled {
		runner.RegisterWithInterval(scraper.NewVolexity(), cfg.Sources.Volexity.PollInterval)
	}
	if cfg.Sources.Wiz.Enabled {
		runner.RegisterWithInterval(scraper.NewWiz(), cfg.Sources.Wiz.PollInterval)
	}
	if cfg.Sources.HackerNews.Enabled {
		runner.RegisterWithInterval(scraper.NewHackerNews(), cfg.Sources.HackerNews.PollInterval)
	}
	if cfg.Sources.DarkReading.Enabled {
		runner.RegisterWithInterval(scraper.NewDarkReading(), cfg.Sources.DarkReading.PollInterval)
	}
	if cfg.Sources.DataBreaches.Enabled {
		runner.RegisterWithInterval(scraper.NewDataBreaches(), cfg.Sources.DataBreaches.PollInterval)
	}
	if cfg.Sources.HackRead.Enabled {
		runner.RegisterWithInterval(scraper.NewHackRead(), cfg.Sources.HackRead.PollInterval)
	}
	if cfg.Sources.RansomwareLive.Enabled {
		runner.RegisterWithInterval(scraper.NewRansomwareLive(), cfg.Sources.RansomwareLive.PollInterval)
	}
	if cfg.Sources.DataBreachToday.Enabled {
		runner.RegisterWithInterval(scraper.NewDataBreachToday(), cfg.Sources.DataBreachToday.PollInterval)
	}
	if cfg.Sources.KrebsBreaches.Enabled {
		runner.RegisterWithInterval(scraper.NewKrebsBreaches(), cfg.Sources.KrebsBreaches.PollInterval)
	}
	if cfg.Sources.Schneier.Enabled {
		runner.RegisterWithInterval(scraper.NewSchneier(), cfg.Sources.Schneier.PollInterval)
	}
	if cfg.Sources.Securelist.Enabled {
		runner.RegisterWithInterval(scraper.NewSecurelist(), cfg.Sources.Securelist.PollInterval)
	}
	if cfg.Sources.OSSSec.Enabled {
		runner.RegisterWithInterval(scraper.NewOSSSec(), cfg.Sources.OSSSec.PollInterval)
	}
	if cfg.Sources.WatchTowr.Enabled {
		runner.RegisterWithInterval(scraper.NewWatchTowr(), cfg.Sources.WatchTowr.PollInterval)
	}
	if cfg.Sources.MozillaSecurity.Enabled {
		runner.RegisterWithInterval(scraper.NewMozillaSecurity(), cfg.Sources.MozillaSecurity.PollInterval)
	}
	if cfg.Sources.ArsSecurity.Enabled {
		runner.RegisterWithInterval(scraper.NewArsSecurity(), cfg.Sources.ArsSecurity.PollInterval)
	}
	if cfg.Sources.InfosecExchangeCVE.Enabled {
		runner.RegisterWithInterval(scraper.NewInfosecExchangeCVE(), cfg.Sources.InfosecExchangeCVE.PollInterval)
	}
	if cfg.Sources.NCSC.Enabled {
		runner.RegisterWithInterval(scraper.NewNCSC(), cfg.Sources.NCSC.PollInterval)
	}
	if cfg.Sources.NCSCNL.Enabled {
		runner.RegisterWithInterval(scraper.NewNCSCNL(), cfg.Sources.NCSCNL.PollInterval)
	}
	if cfg.Sources.ANSSI.Enabled {
		runner.RegisterWithInterval(scraper.NewANSSI(), cfg.Sources.ANSSI.PollInterval)
	}
	if cfg.Sources.BSI.Enabled {
		runner.RegisterWithInterval(scraper.NewBSI(), cfg.Sources.BSI.PollInterval)
	}
	if cfg.Sources.CERTEU.Enabled {
		runner.RegisterWithInterval(scraper.NewCERTEU(), cfg.Sources.CERTEU.PollInterval)
	}
	if cfg.Sources.JPCERT.Enabled {
		runner.RegisterWithInterval(scraper.NewJPCERT(), cfg.Sources.JPCERT.PollInterval)
	}
	if cfg.Sources.BleepingComputer.Enabled {
		runner.RegisterWithInterval(scraper.NewBleepingComputer(), cfg.Sources.BleepingComputer.PollInterval)
	}
	if cfg.Sources.TheRecord.Enabled {
		runner.RegisterWithInterval(scraper.NewTheRecord(), cfg.Sources.TheRecord.PollInterval)
	}
	if cfg.Sources.SecurityWeek.Enabled {
		runner.RegisterWithInterval(scraper.NewSecurityWeek(), cfg.Sources.SecurityWeek.PollInterval)
	}
	if cfg.Sources.NVD.Enabled {
		runner.RegisterWithInterval(scraper.NewNVD().WithLogger(logger), cfg.Sources.NVD.PollInterval)
	}
	if cfg.Sources.GHSA.Enabled {
		runner.RegisterWithInterval(scraper.NewGHSA(ghTokenFn), cfg.Sources.GHSA.PollInterval)
	}
	if cfg.Sources.MSRC.Enabled {
		runner.RegisterWithInterval(scraper.NewMSRC(), cfg.Sources.MSRC.PollInterval)
	}
	if cfg.Sources.CiscoPSIRT.Enabled {
		runner.RegisterWithInterval(scraper.NewCiscoPSIRT(), cfg.Sources.CiscoPSIRT.PollInterval)
	}
	if cfg.Sources.PaloAltoNetworks.Enabled {
		runner.RegisterWithInterval(scraper.NewPaloAltoNetworks(), cfg.Sources.PaloAltoNetworks.PollInterval)
	}
	if cfg.Sources.Sonatype.Enabled {
		runner.RegisterWithInterval(scraper.NewSonatype(), cfg.Sources.Sonatype.PollInterval)
	}
	if cfg.Sources.GoogleProjectZero.Enabled {
		runner.RegisterWithInterval(scraper.NewGoogleProjectZero(), cfg.Sources.GoogleProjectZero.PollInterval)
	}
	if cfg.Sources.SentinelLabs.Enabled {
		runner.RegisterWithInterval(scraper.NewSentinelLabs(), cfg.Sources.SentinelLabs.PollInterval)
	}
	if cfg.Sources.Bitdefender.Enabled {
		runner.RegisterWithInterval(scraper.NewBitdefender(), cfg.Sources.Bitdefender.PollInterval)
	}
	if cfg.Sources.FortiGuard.Enabled {
		runner.RegisterWithInterval(scraper.NewFortiGuard(), cfg.Sources.FortiGuard.PollInterval)
	}
	if cfg.Sources.Proofpoint.Enabled {
		runner.RegisterWithInterval(scraper.NewProofpoint(), cfg.Sources.Proofpoint.PollInterval)
	}
	if cfg.Sources.Rapid7.Enabled {
		runner.RegisterWithInterval(scraper.NewRapid7(), cfg.Sources.Rapid7.PollInterval)
	}
	if cfg.Sources.RedCanary.Enabled {
		runner.RegisterWithInterval(scraper.NewRedCanary(), cfg.Sources.RedCanary.PollInterval)
	}
	if cfg.Sources.RecordedFuture.Enabled {
		runner.RegisterWithInterval(scraper.NewRecordedFuture(), cfg.Sources.RecordedFuture.PollInterval)
	}
	if cfg.Sources.Flashpoint.Enabled {
		runner.RegisterWithInterval(scraper.NewFlashpoint(), cfg.Sources.Flashpoint.PollInterval)
	}
	if cfg.Sources.Intel471.Enabled {
		runner.RegisterWithInterval(scraper.NewIntel471(), cfg.Sources.Intel471.PollInterval)
	}
	if cfg.Sources.GreyNoise.Enabled {
		runner.RegisterWithInterval(scraper.NewGreyNoise(), cfg.Sources.GreyNoise.PollInterval)
	}
	if cfg.Sources.Cofense.Enabled {
		runner.RegisterWithInterval(scraper.NewCofense(), cfg.Sources.Cofense.PollInterval)
	}
	if cfg.Sources.AnyRun.Enabled {
		runner.RegisterWithInterval(scraper.NewAnyRun(), cfg.Sources.AnyRun.PollInterval)
	}
	if cfg.Sources.QualysThreatResearch.Enabled {
		runner.RegisterWithInterval(scraper.NewQualysThreatResearch(), cfg.Sources.QualysThreatResearch.PollInterval)
	}
	if cfg.Sources.MalwareTrafficAnalysis.Enabled {
		runner.RegisterWithInterval(scraper.NewMalwareTrafficAnalysis(), cfg.Sources.MalwareTrafficAnalysis.PollInterval)
	}
	if cfg.Sources.ObjectiveSee.Enabled {
		runner.RegisterWithInterval(scraper.NewObjectiveSee(), cfg.Sources.ObjectiveSee.PollInterval)
	}
	if cfg.Sources.AttackIQ.Enabled {
		runner.RegisterWithInterval(scraper.NewAttackIQ(), cfg.Sources.AttackIQ.PollInterval)
	}
	if cfg.Sources.FBICyber.Enabled {
		runner.RegisterWithInterval(scraper.NewFBICyber(), cfg.Sources.FBICyber.PollInterval)
	}
	if cfg.Sources.CCCS.Enabled {
		runner.RegisterWithInterval(scraper.NewCCCS(), cfg.Sources.CCCS.PollInterval)
	}
	if cfg.Sources.ACSC.Enabled {
		runner.RegisterWithInterval(scraper.NewACSC(), cfg.Sources.ACSC.PollInterval)
	}
	if cfg.Sources.MSISAC.Enabled {
		runner.RegisterWithInterval(scraper.NewMSISAC(), cfg.Sources.MSISAC.PollInterval)
	}
	if cfg.Sources.GoogleTAG.Enabled {
		runner.RegisterWithInterval(scraper.NewGoogleTAG(), cfg.Sources.GoogleTAG.PollInterval)
	}
	if cfg.Sources.ExploitDB.Enabled {
		runner.RegisterWithInterval(scraper.NewExploitDB(), cfg.Sources.ExploitDB.PollInterval)
	}
	if cfg.Sources.Sploitus.Enabled {
		runner.RegisterWithInterval(scraper.NewSploitus(), cfg.Sources.Sploitus.PollInterval)
	}
	if cfg.Sources.SocPrime.Enabled {
		runner.RegisterWithInterval(scraper.NewSocPrime(), cfg.Sources.SocPrime.PollInterval)
	}
	// An empty feed_url means no bridge subscription is configured. Registering
	// anyway would log a poll failure every cycle, so skip it instead.
	if cfg.Sources.Ronin66.Enabled && cfg.Sources.Ronin66.FeedURL != "" {
		runner.RegisterWithInterval(
			scraper.NewBridgedSocial("ronin66", cfg.Sources.Ronin66.FeedURL, "linkedin.com"),
			cfg.Sources.Ronin66.PollInterval,
		)
	}
	if cfg.Sources.GossiTheDogThreatHunting.Enabled {
		runner.RegisterWithInterval(
			scraper.NewGossiTheDogThreatHunting(ghTokenFn),
			cfg.Sources.GossiTheDogThreatHunting.PollInterval,
		)
	}
	// Mastodon exposes a native per-account RSS feed, so unlike ronin66 this
	// needs no third-party bridge or config-supplied feed_url.
	if cfg.Sources.GossiTheDogMastodon.Enabled {
		runner.RegisterWithInterval(
			scraper.NewBridgedSocial("gossithedog-mastodon", "https://cyberplace.social/@GossiTheDog.rss", "cyberplace.social"),
			cfg.Sources.GossiTheDogMastodon.PollInterval,
		)
	}
}
