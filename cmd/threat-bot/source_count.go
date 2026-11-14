package main

import (
	"github.com/craftedsignal/threat-bot/internal/config"
)

func countEnabledSources(cfg *config.Config) int {
	count := 0
	if cfg.Sources.SigmaHQ.Enabled {
		count++
	}
	if cfg.Sources.Elastic.Enabled {
		count++
	}
	if cfg.Sources.SplunkESCU.Enabled {
		count++
	}
	if cfg.Sources.CISA.Enabled {
		count++
	}
	if cfg.Sources.DFIRReport.Enabled {
		count++
	}
	if cfg.Sources.AbuseCH.Enabled {
		count++
	}
	if cfg.Sources.RedditNetSec.Enabled {
		count++
	}
	if cfg.Sources.RedditBlueTeamSec.Enabled {
		count++
	}
	if cfg.Sources.RedditCybersecurity.Enabled {
		count++
	}
	if cfg.Sources.ISCStormCast.Enabled {
		count++
	}
	if cfg.Sources.CISAKEV.Enabled {
		count++
	}
	if cfg.Sources.CCBBelgium.Enabled {
		count++
	}
	if cfg.Sources.CIRCLMISP.Enabled {
		count++
	}
	if cfg.Sources.RiskyBiz.Enabled {
		count++
	}
	if cfg.Sources.RiskyBizBulletin.Enabled {
		count++
	}
	if cfg.Sources.PwnWatch.Enabled {
		count++
	}
	if cfg.Sources.Talos.Enabled {
		count++
	}
	if cfg.Sources.Mandiant.Enabled {
		count++
	}
	if cfg.Sources.Unit42.Enabled {
		count++
	}
	if cfg.Sources.MicrosoftThreatIntel.Enabled {
		count++
	}
	if cfg.Sources.SophosXOps.Enabled {
		count++
	}
	if cfg.Sources.Huntress.Enabled {
		count++
	}
	if cfg.Sources.ArcticWolf.Enabled {
		count++
	}
	if cfg.Sources.CheckPoint.Enabled {
		count++
	}
	if cfg.Sources.CrowdStrike.Enabled {
		count++
	}
	if cfg.Sources.ESET.Enabled {
		count++
	}
	if cfg.Sources.Volexity.Enabled {
		count++
	}
	if cfg.Sources.Wiz.Enabled {
		count++
	}
	if cfg.Sources.HackerNews.Enabled {
		count++
	}
	if cfg.Sources.DarkReading.Enabled {
		count++
	}
	if cfg.Sources.DataBreaches.Enabled {
		count++
	}
	if cfg.Sources.HackRead.Enabled {
		count++
	}
	if cfg.Sources.RansomwareLive.Enabled {
		count++
	}
	if cfg.Sources.DataBreachToday.Enabled {
		count++
	}
	if cfg.Sources.KrebsBreaches.Enabled {
		count++
	}
	if cfg.Sources.Schneier.Enabled {
		count++
	}
	if cfg.Sources.Securelist.Enabled {
		count++
	}
	if cfg.Sources.OSSSec.Enabled {
		count++
	}
	if cfg.Sources.WatchTowr.Enabled {
		count++
	}
	if cfg.Sources.MozillaSecurity.Enabled {
		count++
	}
	if cfg.Sources.ArsSecurity.Enabled {
		count++
	}
	if cfg.Sources.InfosecExchangeCVE.Enabled {
		count++
	}
	if cfg.Sources.NCSC.Enabled {
		count++
	}
	if cfg.Sources.NCSCNL.Enabled {
		count++
	}
	if cfg.Sources.ANSSI.Enabled {
		count++
	}
	if cfg.Sources.BSI.Enabled {
		count++
	}
	if cfg.Sources.CERTEU.Enabled {
		count++
	}
	if cfg.Sources.JPCERT.Enabled {
		count++
	}
	if cfg.Sources.BleepingComputer.Enabled {
		count++
	}
	if cfg.Sources.TheRecord.Enabled {
		count++
	}
	if cfg.Sources.SecurityWeek.Enabled {
		count++
	}
	if cfg.Sources.NVD.Enabled {
		count++
	}
	if cfg.Sources.GHSA.Enabled {
		count++
	}
	if cfg.Sources.MSRC.Enabled {
		count++
	}
	if cfg.Sources.CiscoPSIRT.Enabled {
		count++
	}
	if cfg.Sources.PaloAltoNetworks.Enabled {
		count++
	}
	if cfg.Sources.Sonatype.Enabled {
		count++
	}
	if cfg.Sources.GoogleProjectZero.Enabled {
		count++
	}
	if cfg.Sources.SentinelLabs.Enabled {
		count++
	}
	if cfg.Sources.Bitdefender.Enabled {
		count++
	}
	if cfg.Sources.FortiGuard.Enabled {
		count++
	}
	if cfg.Sources.Proofpoint.Enabled {
		count++
	}
	if cfg.Sources.Rapid7.Enabled {
		count++
	}
	if cfg.Sources.RedCanary.Enabled {
		count++
	}
	if cfg.Sources.RecordedFuture.Enabled {
		count++
	}
	if cfg.Sources.Flashpoint.Enabled {
		count++
	}
	if cfg.Sources.Intel471.Enabled {
		count++
	}
	if cfg.Sources.GreyNoise.Enabled {
		count++
	}
	if cfg.Sources.Cofense.Enabled {
		count++
	}
	if cfg.Sources.AnyRun.Enabled {
		count++
	}
	if cfg.Sources.QualysThreatResearch.Enabled {
		count++
	}
	if cfg.Sources.MalwareTrafficAnalysis.Enabled {
		count++
	}
	if cfg.Sources.ObjectiveSee.Enabled {
		count++
	}
	if cfg.Sources.AttackIQ.Enabled {
		count++
	}
	if cfg.Sources.FBICyber.Enabled {
		count++
	}
	if cfg.Sources.CCCS.Enabled {
		count++
	}
	if cfg.Sources.ACSC.Enabled {
		count++
	}
	if cfg.Sources.MSISAC.Enabled {
		count++
	}
	if cfg.Sources.GoogleTAG.Enabled {
		count++
	}
	if cfg.Sources.ExploitDB.Enabled {
		count++
	}
	if cfg.Sources.Sploitus.Enabled {
		count++
	}
	if cfg.Sources.SocPrime.Enabled {
		count++
	}
	return count
}
