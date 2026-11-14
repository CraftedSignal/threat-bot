package eval

import (
	"sort"
	"strings"
)

// BaseTechniqueID strips a sub-technique suffix: T1566.001 -> T1566.
func BaseTechniqueID(id string) string {
	if i := strings.IndexByte(id, '.'); i >= 0 {
		return id[:i]
	}
	return id
}

// DocResult pairs a document's gold technique set with the predicted set.
type DocResult struct {
	Gold []string
	Pred []string
}

// TechniqueScore holds pooled counts and metrics for a single technique.
type TechniqueScore struct {
	Technique             string
	TP, FP, FN            int
	Precision, Recall, F1 float64
}

// Report is the full scoring result at one normalisation granularity.
type Report struct {
	Docs                                 int
	MicroPrecision, MicroRecall, MicroF1 float64
	MacroPrecision, MacroRecall, MacroF1 float64
	PerTechnique                         []TechniqueScore
}

func prf(tp, fp, fn int) (p, r, f float64) {
	if tp+fp > 0 {
		p = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		r = float64(tp) / float64(tp+fn)
	}
	if p+r > 0 {
		f = 2 * p * r / (p + r)
	}
	return
}

func toSet(items []string, norm func(string) string) map[string]bool {
	s := map[string]bool{}
	for _, it := range items {
		if it == "" {
			continue
		}
		s[norm(it)] = true
	}
	return s
}

// Score computes micro, macro, and per-technique precision/recall/F1 over a
// set of documents. norm normalises technique IDs before set comparison
// (identity for exact scoring, BaseTechniqueID for base scoring).
func Score(results []DocResult, norm func(string) string) Report {
	counts := map[string]*TechniqueScore{}
	get := func(tech string) *TechniqueScore {
		c := counts[tech]
		if c == nil {
			c = &TechniqueScore{Technique: tech}
			counts[tech] = c
		}
		return c
	}
	for _, dr := range results {
		gold := toSet(dr.Gold, norm)
		pred := toSet(dr.Pred, norm)
		for tech := range pred {
			if gold[tech] {
				get(tech).TP++
			} else {
				get(tech).FP++
			}
		}
		for tech := range gold {
			if !pred[tech] {
				get(tech).FN++
			}
		}
	}

	var microTP, microFP, microFN int
	var sumP, sumR, sumF float64
	techs := make([]string, 0, len(counts))
	for tech := range counts {
		techs = append(techs, tech)
	}
	sort.Strings(techs)
	per := make([]TechniqueScore, 0, len(techs))
	for _, tech := range techs {
		c := counts[tech]
		c.Precision, c.Recall, c.F1 = prf(c.TP, c.FP, c.FN)
		microTP += c.TP
		microFP += c.FP
		microFN += c.FN
		sumP += c.Precision
		sumR += c.Recall
		sumF += c.F1
		per = append(per, *c)
	}

	rep := Report{Docs: len(results), PerTechnique: per}
	rep.MicroPrecision, rep.MicroRecall, rep.MicroF1 = prf(microTP, microFP, microFN)
	if n := float64(len(techs)); n > 0 {
		rep.MacroPrecision = sumP / n
		rep.MacroRecall = sumR / n
		rep.MacroF1 = sumF / n
	}
	return rep
}
