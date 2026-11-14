package pipeline

import "testing"

func TestNVDMetaContradictsVendor(t *testing.T) {
	// Every patch-cycle vendor with a realistic CPE (vendor:product).
	cpes := map[string]string{
		"microsoft": "cpe:2.3:a:microsoft:windows:-:*:*:*:*:*:*:*",
		"adobe":     "cpe:2.3:a:adobe:acrobat:-:*:*:*:*:*:*:*",
		"apple":     "cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*",
		"oracle":    "cpe:2.3:a:oracle:mysql:-:*:*:*:*:*:*:*",
		"sap":       "cpe:2.3:a:sap:netweaver:-:*:*:*:*:*:*:*",
		"qualcomm":  "cpe:2.3:h:qualcomm:snapdragon:-:*:*:*:*:*:*:*",
		"google":    "cpe:2.3:a:google:chrome:-:*:*:*:*:*:*:*",
		"android":   "cpe:2.3:o:google:android:-:*:*:*:*:*:*:*",
		"cisco":     "cpe:2.3:o:cisco:ios:-:*:*:*:*:*:*:*",
		"siemens":   "cpe:2.3:a:siemens:simatic:-:*:*:*:*:*:*:*",
		"mozilla":   "cpe:2.3:a:mozilla:firefox:-:*:*:*:*:*:*:*",
		"atlassian": "cpe:2.3:a:atlassian:jira:-:*:*:*:*:*:*:*",
	}
	for v, cpe := range cpes {
		if !isPatchCycleVendor(v) {
			t.Errorf("%s not a patch-cycle vendor", v)
		}
		if nvdMetaContradictsVendor(&CVEMeta{CPEs: []string{cpe}}, normalizeVendorName(v)) {
			t.Errorf("CPE %s must agree with vendor %s", cpe, v)
		}
		other := "microsoft"
		if v == "microsoft" {
			other = "adobe"
		}
		if !nvdMetaContradictsVendor(&CVEMeta{CPEs: []string{cpe}}, other) {
			t.Errorf("CPE %s must contradict vendor %s", cpe, other)
		}
	}
	for v := range patchCycleVendors {
		if _, ok := cpes[v]; !ok {
			t.Errorf("patch-cycle vendor %s missing from table", v)
		}
	}
}

func TestNVDMetaCNAOnly(t *testing.T) {
	tests := []struct {
		name, cna, vendor string
		want              bool
	}{
		{"android CNA vs microsoft", "security@android.com", "microsoft", true},
		{"android CNA vs android", "security@android.com", "android", false},
		{"android CNA vs google", "security@android.com", "google", false},
		{"google CNA vs android", "security@google.com", "android", false},
		{"microsoft CNA vs android", "secure@microsoft.com", "android", true},
		{"microsoft CNA vs microsoft", "secure@microsoft.com", "microsoft", false},
		{"cisa ics", "ics-cert@hq.dhs.gov", "microsoft", false},
		{"zdi", "zdi-disclosures@trendmicro.com", "microsoft", false},
		{"github", "security-advisories@github.com", "android", false},
		{"vuldb", "cna@vuldb.com", "adobe", false},
		{"mitre", "cve@mitre.org", "microsoft", false},
		{"empty", "", "microsoft", false},
		{"talos is third party", "talos-cna@cisco.com", "microsoft", false},
		{"cisco psirt vs microsoft", "psirt@cisco.com", "microsoft", true},
		{"cisco psirt vs cisco", "psirt@cisco.com", "cisco", false},
		{"red hat coordinator is not vendor evidence", "secalert@redhat.com", "microsoft", false},
		{"debian coordinator is not vendor evidence", "security@debian.org", "microsoft", false},
		{"pineapple is not apple", "security@pineapple.com", "microsoft", false},
		{"pineapple vs apple", "security@pineapple.com", "apple", false},
		{"msrc subdomain", "secure@msrc.microsoft.com", "microsoft", false},
	}
	for _, tc := range tests {
		got := nvdMetaContradictsVendor(&CVEMeta{SourceIdentifier: tc.cna}, normalizeVendorName(tc.vendor))
		if got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestNVDMetaCPEFalseAgreement(t *testing.T) {
	tests := []struct {
		cpe, vendor string
		contradicts bool
	}{
		{"cpe:2.3:a:samsung:android:-:*:*:*:*:*:*:*", "android", true},
		{"cpe:2.3:a:mozilla:firefox_for_android:-:*:*:*:*:*:*:*", "android", true},
		{"cpe:2.3:a:microsoft:windows_subsystem_for_android:-:*:*:*:*:*:*:*", "android", true},
		{"cpe:2.3:a:jenkins:google_login:-:*:*:*:*:*:*:*", "google", true},
		{"cpe:2.3:a:acme:microsoft_teams_connector:-:*:*:*:*:*:*:*", "microsoft", true},
		{"cpe:2.3:a:acme:pineapple:-:*:*:*:*:*:*:*", "apple", true},
		{"cpe:2.3:o:google:android:-:*:*:*:*:*:*:*", "android", false},
	}
	for _, tc := range tests {
		got := nvdMetaContradictsVendor(&CVEMeta{CPEs: []string{tc.cpe}}, normalizeVendorName(tc.vendor))
		if got != tc.contradicts {
			t.Errorf("%s vs %s: got %v want %v", tc.cpe, tc.vendor, got, tc.contradicts)
		}
	}
}
