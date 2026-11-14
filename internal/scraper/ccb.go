package scraper

// NewCCB creates a scraper for Belgian Centre for Cybersecurity advisories.
func NewCCB() *RSS {
	return NewRSS("ccb-belgium", "https://ccb.belgium.be/advisories.xml")
}
