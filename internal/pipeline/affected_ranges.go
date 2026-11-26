package pipeline

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// injectAffectedRanges renders product-specific, unambiguous source scope into
// affected_products before grounding. The checker then judges the exact ranges
// its evidence states, instead of a model's transcription of them that it can
// dispute in both directions (range missing, range unsupported). Every stated
// range becomes its own "Product (range)" entry, which the public projection
// splits back into the product and its version scope.
//
// Structured ranges, from NVD configurations and from the CVE records the
// checker receives as primary evidence, are exact and take precedence over
// bounds extracted from prose. Structured sources that disagree leave the
// product unscoped, as does any uninterpretable scope; scope removed by a
// grounding repair is never reintroduced automatically.
func injectAffectedRanges(briefYAML string, item scraper.RawItem, primary primaryRecordFacts) string {
	var doc map[string]any
	if yaml.Unmarshal([]byte(briefYAML), &doc) != nil {
		return briefYAML
	}
	products := nonEmptyTrimmed(yamlStringList(doc["affected_products"]))
	scopes := map[string][]string{}
	for key, hint := range supportedProductScope(products, item.Content) {
		if hint.VulnerableRange != "" {
			scopes[key] = []string{hint.VulnerableRange}
		}
	}
	structured := map[string][]string{}
	conflicting := map[string]bool{}
	if item.Source == "nvd" || item.Source == "ghsa" {
		for _, mr := range parseAffectedRangeLines(item.Metadata["affected_ranges"]) {
			var matches []string
			for _, product := range products {
				if productMatchesRangeName(product, mr.name) {
					matches = append(matches, product)
				}
			}
			if len(matches) == 1 {
				key := scopeProductKey(matches[0])
				if prior, ok := structured[key]; ok && !sameRanges(prior, mr.ranges) {
					conflicting[key] = true
				} else {
					structured[key] = mr.ranges
				}
			}
		}
	}
	// CVE Program/CNA facts are the vendor's primary affected-version record.
	// NVD's normalized ranges can omit precision (for example, .8 versus .8.1)
	// or flatten custom release streams. Use complete primary-record ranges for
	// products they cover, while retaining NVD metadata for other products.
	for key, ranges := range primaryRecordRanges(products, primary) {
		structured[key] = ranges
		delete(conflicting, key)
	}
	for key, ranges := range structured {
		scopes[key] = ranges
	}
	for key := range conflicting {
		delete(scopes, key)
	}
	changed := applyProductRanges(doc, scopes)
	changed = addRecordProducts(doc, primary) || changed
	changed = addPrimaryScopeGaps(doc, primary) || changed
	if !changed {
		return briefYAML
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

// primaryRecordFacts are the structured CVE record facts of a brief's grounding
// evidence. Included facts reached the checker intact. Incomplete facts were
// kept out of the evidence by cross-record references or its size limit.
// Truncated reports that a record lost affected entries before any fact was
// retained, so the names of the products it covered are unknown.
type primaryRecordFacts struct {
	Included   []cnaSourceFact
	Incomplete []cnaSourceFact
	Truncated  bool
}

// cnaAffectedEntry is one retained CVE JSON 5 "affected" entry.
type cnaAffectedEntry struct {
	Vendor        string               `json:"vendor"`
	Product       string               `json:"product"`
	DefaultStatus string               `json:"defaultStatus"`
	Versions      []cnaAffectedVersion `json:"versions"`
}

type cnaAffectedVersion struct {
	Version         string          `json:"version"`
	Status          string          `json:"status"`
	LessThan        string          `json:"lessThan"`
	LessThanOrEqual string          `json:"lessThanOrEqual"`
	VersionType     string          `json:"versionType"`
	Changes         json.RawMessage `json:"changes"`
}

var exactProductVersion = regexp.MustCompile(`(?i)^` + productVersionToken + `$`)

// primaryRecordRanges returns the affected ranges the primary CVE records state
// for each brief product. A record names a product only by its exact name,
// optionally vendor-qualified, so "FortiAnalyzer" never takes the ranges of
// "FortiAnalyzer Cloud". A product gets record ranges only when every affected
// entry naming it reached the checker, renders literally and agrees: several
// packages or CVEs with different ranges need editorial branch mapping, and a
// partial rendering would omit affected versions.
func primaryRecordRanges(products []string, primary primaryRecordFacts) map[string][]string {
	if primary.Truncated {
		return nil
	}
	keys := map[string]bool{}
	for _, product := range products {
		keys[scopeProductKey(product)] = true
	}
	match := func(names ...string) string {
		for _, name := range names {
			if key := scopeProductKey(name); key != "" && keys[key] {
				return key
			}
		}
		return ""
	}
	entryKey := func(fact cnaSourceFact) (string, cnaAffectedEntry, bool) {
		var entry cnaAffectedEntry
		parsed := json.Unmarshal([]byte(fact.Text), &entry) == nil
		key := match(fact.Product)
		if key == "" && parsed {
			key = match(entry.Product, entry.Vendor+" "+entry.Product)
		}
		return key, entry, parsed
	}
	blocked := map[string]bool{}
	for _, fact := range primary.Incomplete {
		if fact.Kind != "affected" {
			continue
		}
		if key, _, _ := entryKey(fact); key != "" {
			blocked[key] = true
		}
	}
	out := map[string][]string{}
	for _, fact := range primary.Included {
		if fact.Kind != "affected" {
			continue
		}
		key, entry, parsed := entryKey(fact)
		if key == "" {
			continue
		}
		ranges, ok := entry.ranges()
		if !parsed || !ok {
			blocked[key] = true
			continue
		}
		if prior, seen := out[key]; seen && !sameRanges(prior, ranges) {
			blocked[key] = true
			continue
		}
		out[key] = ranges
	}
	for key := range blocked {
		delete(out, key)
	}
	return out
}

// unresolvedPrimaryScopeGuidance makes the renderer's conservative decision
// explicit to both assembly and grounding. Without it, a model can interpret
// Git commit bounds or an original_commit_for_fix marker as product releases,
// then spend a repair/recheck cycle on ranges the public feed cannot safely
// express. This is explanatory evidence only: it never supplies a range or a
// fixed release, and unsupported version claims remain subject to grounding.
func unresolvedPrimaryScopeGuidance(primary primaryRecordFacts) string {
	gaps := unresolvedPrimaryScopeGaps(primary, nil)
	if len(gaps) == 0 {
		return ""
	}
	for i := range gaps {
		gaps[i] = "- " + gaps[i]
	}
	return "Applicability range limitation (machine-derived; not a claim of fixed versions). Apply each line only to a brief product that matches the product named on that line; never transfer it to another product:\n" + strings.Join(gaps, "\n") + "\n"
}

func unresolvedPrimaryScopeGaps(primary primaryRecordFacts, products []string) []string {
	if primary.Truncated {
		return nil
	}
	type scopeGap struct {
		cve, product string
		reasons      map[string]bool
	}
	byScope := map[string]*scopeGap{}
	for _, fact := range primary.Included {
		if fact.Kind != "affected" {
			continue
		}
		var entry cnaAffectedEntry
		if err := json.Unmarshal([]byte(fact.Text), &entry); err != nil {
			continue
		}
		if _, ok := entry.ranges(); ok {
			continue
		}
		product := strings.TrimSpace(fact.Product)
		if product == "" {
			product = strings.TrimSpace(entry.Product)
		}
		if len(products) > 0 {
			matches := 0
			for _, target := range products {
				if productMatchesRangeName(target, product) {
					matches++
				}
			}
			if matches != 1 {
				continue
			}
		}
		key := strings.ToUpper(fact.CVEID) + "\x00" + scopeProductKey(product)
		if fact.CVEID == "" || product == "" {
			continue
		}
		gap := byScope[key]
		if gap == nil {
			gap = &scopeGap{cve: fact.CVEID, product: product, reasons: map[string]bool{}}
			byScope[key] = gap
		}
		for _, version := range entry.Versions {
			switch strings.ToLower(strings.TrimSpace(version.VersionType)) {
			case "git":
				gap.reasons["Git commit bounds"] = true
			case "original_commit_for_fix":
				gap.reasons["original_commit_for_fix markers"] = true
			}
		}
		if strings.EqualFold(strings.TrimSpace(entry.DefaultStatus), "affected") {
			gap.reasons["defaultStatus=affected with version exceptions"] = true
		}
	}
	keys := make([]string, 0, len(byScope))
	for key := range byScope {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	gaps := make([]string, 0, len(keys))
	for _, key := range keys {
		gap := byScope[key]
		reasons := make([]string, 0, len(gap.reasons))
		for reason := range gap.reasons {
			reasons = append(reasons, reason)
		}
		slices.Sort(reasons)
		if len(reasons) == 0 {
			reasons = []string{"status or bounds that require interpretation"}
		}
		gaps = append(gaps, gap.cve+" / "+gap.product+": "+strings.Join(reasons, ", ")+". The supplied primary record cannot be mapped safely to release-version ranges; verify the installed branch against current vendor guidance. Do not infer a fixed release from these bounds; a fixed release may be reported when the supplied source explicitly states it for this product and CVE.")
	}
	return gaps
}

// addPrimaryScopeGaps makes an unrenderable primary scope visible in the
// published brief's source assessment. It avoids demanding a fabricated
// semver range while preserving an explicit defender-facing limitation.
func addPrimaryScopeGaps(doc map[string]any, primary primaryRecordFacts) bool {
	products := nonEmptyTrimmed(yamlStringList(doc["affected_products"]))
	if len(products) == 0 {
		return false
	}
	gaps := unresolvedPrimaryScopeGaps(primary, products)
	if len(gaps) == 0 {
		return false
	}
	assessment, ok := doc["source_assessment"].(map[string]any)
	if !ok {
		assessment = map[string]any{}
		doc["source_assessment"] = assessment
	}
	prior := nonEmptyTrimmed(yamlStringList(assessment["gaps"]))
	changed := false
	for _, gap := range gaps {
		// Replace only the exact machine-generated legacy wording for this
		// scope. Retained candidates may already contain it, and retaining it
		// would continue to contradict an explicitly sourced solution.
		legacy := strings.Replace(gap, "Do not infer a fixed release from these bounds; a fixed release may be reported when the supplied source explicitly states it for this product and CVE.", "Do not infer a fixed release from this record.", 1)
		for i := range prior {
			if prior[i] == legacy {
				prior[i] = gap
				changed = true
			}
		}
		if !slices.Contains(prior, gap) {
			prior = append(prior, gap)
			changed = true
		}
	}
	if changed {
		assessment["gaps"] = prior
	}
	return changed
}

// maxRecordProductEntries bounds affected_products once record products are
// added. Multi-SKU records (Windows builds, PowerStore models, RHEL streams)
// name dozens of products; the remainder is summarized as one gap naming the
// record instead of being dropped silently.
const maxRecordProductEntries = 25

// recordProductOverflowSuffix ends the machine-written overflow gap, so a
// later call replaces its own stale count instead of stacking contradictions.
const recordProductOverflowSuffix = "check the record for the complete product list."

// recordProduct is one product the brief's primary CVE records name as
// affected, with the scope every retained entry for it renders.
type recordProduct struct {
	name     string
	names    []string // record product name and its vendor-qualified form
	cves     []string
	ranges   []string
	disagree bool // entries render different ranges: identity only, as for brief products
	unsafe   bool // an entry needs interpretation, or its record is incomplete
}

// recordProducts returns the affected products of the CVE records that
// reached the checker intact, in record order. A record that lost affected
// entries, or kept any of them out of the evidence, cannot list its products
// completely, so none of its products are offered.
func recordProducts(primary primaryRecordFacts) []*recordProduct {
	if primary.Truncated {
		return nil
	}
	factName := func(fact cnaSourceFact) (string, cnaAffectedEntry, bool) {
		var entry cnaAffectedEntry
		parsed := json.Unmarshal([]byte(fact.Text), &entry) == nil
		name := strings.Join(strings.Fields(fact.Product), " ")
		if name == "" {
			name = strings.Join(strings.Fields(entry.Product), " ")
		}
		return name, entry, parsed
	}
	// An affected entry kept out of the evidence leaves its record's product
	// list, and its product's scope under any record, unknown.
	incomplete, withheld := map[string]bool{}, map[string]bool{}
	for _, fact := range primary.Incomplete {
		if fact.Kind == "affected" {
			incomplete[strings.ToUpper(strings.TrimSpace(fact.CVEID))] = true
			name, _, _ := factName(fact)
			withheld[scopeProductKey(name)] = true
		}
	}
	var out []*recordProduct
	byKey := map[string]*recordProduct{}
	for _, fact := range primary.Included {
		if fact.Kind != "affected" {
			continue
		}
		name, entry, parsed := factName(fact)
		key := scopeProductKey(name)
		// The validator would rewrite a placeholder or over-long taxonomy
		// name, and the rewritten entry would no longer dedupe on re-injection.
		if key == "" || isPlaceholder(name) || len(name) > MaxTermBytes {
			continue
		}
		rp := byKey[key]
		if rp == nil {
			rp = &recordProduct{name: name, names: []string{name}}
			if vendor := strings.Join(strings.Fields(entry.Vendor), " "); vendor != "" && !isPlaceholder(vendor) {
				rp.names = append(rp.names, vendor+" "+name)
			}
			byKey[key] = rp
			out = append(out, rp)
		}
		id := strings.ToUpper(strings.TrimSpace(fact.CVEID))
		if !slices.Contains(rp.cves, id) {
			rp.cves = append(rp.cves, id)
		}
		ranges, ok := entry.ranges()
		switch {
		case id == "" || incomplete[id] || withheld[key] || !parsed || !ok:
			rp.unsafe = true
		case rp.ranges == nil:
			rp.ranges = ranges
		case !sameRanges(rp.ranges, ranges):
			rp.disagree = true
		}
	}
	return out
}

// addRecordProducts appends the record products a brief omits. The checker
// compares affected_products with every product of the primary records and
// reports each omitted SKU or stream; the writer cannot reliably transcribe
// long record lists, so repair rarely converged. Only products whose every
// entry renders are added, with the same scope a brief product of that name
// receives. Products the brief names (exactly, or by one unambiguous shorter
// or vendor-qualified form) and products a grounding repair removed are never
// added. Record order is kept; additions stop at maxRecordProductEntries.
func addRecordProducts(doc map[string]any, primary primaryRecordFacts) bool {
	candidates := recordProducts(primary)
	if len(candidates) == 0 {
		return false
	}
	products := yamlStringList(doc["affected_products"])
	listed := recordProductsListed(nonEmptyTrimmed(products), candidates)
	var pending []*recordProduct
	for _, rp := range candidates {
		if rp.unsafe || listed[rp] || recordProductBlocked(doc, rp) {
			continue
		}
		pending = append(pending, rp)
	}
	added := false
	var overflow []*recordProduct
	for i, rp := range pending {
		entries := []string{rp.name}
		if !rp.disagree {
			if rendered, ok := renderProductRanges(rp.name, rp.ranges); ok {
				entries = rendered
			}
		}
		// A product's ranges are added together: a partial range list would
		// publish an incomplete affected scope for that product.
		if len(products)+len(entries) > maxRecordProductEntries {
			overflow = pending[i:]
			break
		}
		products = append(products, entries...)
		added = true
	}
	if added {
		doc["affected_products"] = products
	}
	return setRecordProductOverflowGap(doc, overflow) || added
}

// recordProductsListed returns the record products the brief already names. A
// brief product names the record product whose name it is, exactly or
// vendor-qualified. Otherwise a looser name match counts only when it is
// unambiguous: "Tomcat" lists "Apache Tomcat", but "Windows Server 2012" does
// not list "Windows Server 2012 R2", and the family name "Windows" lists none
// of a record's Windows SKUs.
func recordProductsListed(products []string, candidates []*recordProduct) map[*recordProduct]bool {
	byKey := map[string]*recordProduct{}
	for _, c := range candidates {
		for _, name := range c.names {
			byKey[scopeProductKey(name)] = c
		}
	}
	listed := map[*recordProduct]bool{}
	for _, product := range products {
		if c := byKey[scopeProductKey(product)]; c != nil {
			listed[c] = true
			continue
		}
		var matched []*recordProduct
		for _, c := range candidates {
			for _, name := range c.names {
				if productMatchesRangeName(product, name) {
					matched = append(matched, c)
					break
				}
			}
		}
		if len(matched) == 1 {
			listed[matched[0]] = true
		}
	}
	return listed
}

func recordProductBlocked(doc map[string]any, rp *recordProduct) bool {
	for _, name := range rp.names {
		if scopeRepairBlocked(doc, name) {
			return true
		}
	}
	return false
}

// setRecordProductOverflowGap states how many record products the cap left
// out, naming each record, and replaces an earlier machine-written count.
func setRecordProductOverflowGap(doc map[string]any, overflow []*recordProduct) bool {
	gap := ""
	if len(overflow) > 0 {
		var ids []string
		for _, rp := range overflow {
			for _, id := range rp.cves {
				if !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
		slices.Sort(ids)
		records := make([]string, len(ids))
		for i, id := range ids {
			records[i] = id + " (https://cveawg.mitre.org/api/cve/" + id + ")"
		}
		noun, record := "products are", "record"
		if len(overflow) == 1 {
			noun = "product is"
		}
		if len(ids) > 1 {
			record = "records"
		}
		gap = fmt.Sprintf("%d more affected %s listed in the CVE %s %s; affected_products is capped at %d entries, so %s", len(overflow), noun, record, strings.Join(records, ", "), maxRecordProductEntries, recordProductOverflowSuffix)
	}
	assessment, ok := doc["source_assessment"].(map[string]any)
	if !ok && gap == "" {
		return false
	}
	prior := nonEmptyTrimmed(yamlStringList(assessment["gaps"]))
	kept := make([]string, 0, len(prior)+1)
	for _, line := range prior {
		if strings.HasSuffix(line, recordProductOverflowSuffix) && line != gap {
			continue
		}
		kept = append(kept, line)
	}
	if gap != "" && !slices.Contains(kept, gap) {
		kept = append(kept, gap)
	}
	if slices.Equal(kept, prior) {
		return false
	}
	if !ok {
		assessment = map[string]any{}
		doc["source_assessment"] = assessment
	}
	assessment["gaps"] = kept
	return true
}

// ranges renders the entry's affected versions literally. It refuses entries
// whose affected set needs interpretation: versions affected by default,
// unaffected or unknown entries, status changes inside a range, commit ranges,
// and bounds that are not plain version tokens, such as wildcards or URLs.
func (e cnaAffectedEntry) ranges() ([]string, bool) {
	switch strings.ToLower(strings.TrimSpace(e.DefaultStatus)) {
	case "", "unaffected", "unknown":
	default:
		return nil, false
	}
	if len(e.Versions) == 0 {
		return nil, false
	}
	var out []string
	for _, version := range e.Versions {
		r, ok := version.render()
		if !ok {
			return nil, false
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out, true
}

func (v cnaAffectedVersion) render() (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(v.Status), "affected") || strings.EqualFold(strings.TrimSpace(v.VersionType), "git") {
		return "", false
	}
	if changes := strings.TrimSpace(string(v.Changes)); changes != "" && changes != "null" && changes != "[]" {
		return "", false
	}
	from := strings.TrimSpace(v.Version)
	below, through := strings.TrimSpace(v.LessThan), strings.TrimSpace(v.LessThanOrEqual)
	open := from == "0"
	if !open && !exactProductVersion.MatchString(from) {
		return "", false
	}
	// CVE JSON 5 defines an upper limit of "*" as unbounded: "all versions
	// starting at" the lower one. F5 states every NGINX record that way, so
	// refusing it left NGINX2Shell CVE-2026-123633 unscoped and the grounding
	// checker demanded the range until the brief was quarantined. Only the
	// bare "*" is unbounded; "2.*" is a branch pattern and still refused.
	if below == "*" && through == "" || through == "*" && below == "" {
		if open {
			return "", false
		}
		return ">= " + from, true
	}
	var op, bound string
	switch {
	case below != "" && through != "":
		return "", false
	case below != "":
		op, bound = "< ", below
	case through != "":
		op, bound = "<= ", through
	case open:
		return "", false
	default:
		return "= " + from, true
	}
	if !exactProductVersion.MatchString(bound) {
		return "", false
	}
	if open {
		return op + bound, true
	}
	return ">= " + from + ", " + op + bound, true
}

func sameRanges(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, r := range a {
		if !slices.Contains(b, r) {
			return false
		}
	}
	return true
}

// applyProductRanges replaces each unscoped product entry with one
// "Product (range)" entry per range. A product the brief already scopes, or
// whose scope a grounding repair removed, keeps the brief's wording. Every
// rendered entry must split back into the original name and its range;
// otherwise the public projection would publish the range as a product name.
func applyProductRanges(doc map[string]any, scopes map[string][]string) bool {
	products := yamlStringList(doc["affected_products"])
	scoped := map[string]bool{}
	for _, product := range products {
		if productScopeSuffix.MatchString(product) {
			scoped[scopeProductKey(product)] = true
		}
	}
	out := make([]string, 0, len(products))
	changed := false
	for _, product := range products {
		key := scopeProductKey(product)
		rendered, ok := renderProductRanges(product, scopes[key])
		if !ok || scoped[key] || scopeRepairBlocked(doc, product) {
			out = append(out, product)
			continue
		}
		out = append(out, rendered...)
		changed = true
	}
	if changed {
		doc["affected_products"] = out
	}
	return changed
}

func renderProductRanges(product string, ranges []string) ([]string, bool) {
	name := strings.TrimSpace(product)
	if name == "" || len(ranges) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		entry := name + " (" + r + ")"
		if gotName, gotScope := SplitProductVersionScope(entry); gotName != name || gotScope != r {
			return nil, false
		}
		out = append(out, entry)
	}
	return out, true
}

func nonEmptyTrimmed(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

type affectedRangeLine struct {
	name   string
	ranges []string
}

// parseAffectedRangeLines parses the "product: range; range" lines of
// Metadata["affected_ranges"].
func parseAffectedRangeLines(raw string) []affectedRangeLine {
	var out []affectedRangeLine
	for _, line := range strings.Split(raw, "\n") {
		name, ranges, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		var rs []string
		for _, r := range strings.Split(ranges, ";") {
			if r = strings.TrimSpace(r); r != "" {
				rs = append(rs, r)
			}
		}
		if name = strings.TrimSpace(name); name != "" && len(rs) > 0 {
			out = append(out, affectedRangeLine{name: name, ranges: rs})
		}
	}
	return out
}

// productMatchesRangeName reports whether a brief product entry names the NVD
// "vendor product" of a range line ("diskstation manager" matches both
// "Synology DiskStation Manager" and "DiskStation Manager (DSM)").
func productMatchesRangeName(product, name string) bool {
	if i := strings.Index(product, "("); i > 0 {
		product = product[:i]
	}
	return productNameLocation(name, product) != nil || productNameLocation(product, name) != nil
}

// withRanges appends each range in add that the entry does not already carry:
// "Product" becomes "Product (r1, r2)" and "Product (r1)" becomes
// "Product (r1, r2)".
func withRanges(entry string, add []string) string {
	var missing []string
	lower := strings.ToLower(entry)
	for _, r := range add {
		if r = strings.TrimSpace(r); r != "" && !strings.Contains(lower, strings.ToLower(r)) {
			if !containsString(missing, r) {
				missing = append(missing, r)
			}
		}
	}
	if len(missing) == 0 {
		return entry
	}
	joined := strings.Join(missing, ", ")
	if strings.HasSuffix(entry, ")") {
		return strings.TrimSuffix(entry, ")") + ", " + joined + ")"
	}
	return entry + " (" + joined + ")"
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
