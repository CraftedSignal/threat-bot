package pipeline

import (
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestIsInformationalItem_ProductAnnouncement(t *testing.T) {
	item := scraper.RawItem{
		Title:   "CrowdStrike Falcon Next-Gen SIEM Supports Third-Party EDR Tools",
		Source:  "crowdstrike",
		Content: "CrowdStrike Falcon Next-Gen SIEM now supports third-party EDR tools and new federated search capabilities. The release highlights integrations with ExtraHop network data and Amazon S3 access through Athena federated query workflows.",
	}

	if got := isInformationalItem(item); got != "informational-product-announcement" {
		t.Fatalf("isInformationalItem() = %q, want informational-product-announcement", got)
	}
}

func TestIsInformationalItem_StrategicThreatBriefNotInformational(t *testing.T) {
	item := scraper.RawItem{
		Title:   "Mandiant tracks UNC3886 operations targeting virtualization platforms",
		Source:  "mandiant",
		Content: "Mandiant observed a threat actor using valid accounts, persistence, and data exfiltration during an espionage campaign against enterprise virtualization platforms.",
	}

	if got := isInformationalItem(item); got != "" {
		t.Fatalf("isInformationalItem() = %q, want empty", got)
	}
}

func TestIsInformationalItem_ProductAnnouncementWithCVEIsNotInformational(t *testing.T) {
	item := scraper.RawItem{
		Title:   "Cisco releases fixes for new firewall management vulnerability",
		Source:  "cisco-psirt",
		Content: "Cisco released security updates for CVE-2026-12345, a command injection vulnerability affecting firewall management interfaces.",
	}

	if got := isInformationalItem(item); got != "" {
		t.Fatalf("isInformationalItem() = %q, want empty", got)
	}
}

func TestSOCRadarUsesCommercialResearchSourceMetadata(t *testing.T) {
	if got := defaultSourceConfidence["socradar"]; got != 0.80 {
		t.Errorf("SOCRadar source confidence = %v, want 0.80", got)
	}
	if got := getSourceAuthority("socradar"); got != 3 {
		t.Errorf("SOCRadar source authority = %d, want 3", got)
	}
}
