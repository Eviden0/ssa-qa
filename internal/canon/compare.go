package canon

import (
	"fmt"
	"reflect"
	"sort"
)

// Diff is a classified comparison between two canonical reports. "Added" means
// present in B but not A, "Removed" present in A but not B, "Changed" the same
// stable key with different fields.
type Diff struct {
	RulesAdded   []string
	RulesRemoved []string
	Added        []Risk
	Removed      []Risk
	Changed      []RiskChange
}

// RiskChange pairs a risk's before/after form.
type RiskChange struct {
	Before Risk
	After  Risk
}

// Empty reports whether the two reports are canonically identical.
func (d Diff) Empty() bool {
	return len(d.RulesAdded) == 0 && len(d.RulesRemoved) == 0 &&
		len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Compare classifies a -> b.
func Compare(a, b Report) Diff {
	am := riskMap(a.Risks)
	bm := riskMap(b.Risks)
	var d Diff
	for k, rb := range bm {
		ra, ok := am[k]
		if !ok {
			d.Added = append(d.Added, rb)
			continue
		}
		if !reflect.DeepEqual(ra, rb) {
			d.Changed = append(d.Changed, RiskChange{Before: ra, After: rb})
		}
	}
	for k, ra := range am {
		if _, ok := bm[k]; !ok {
			d.Removed = append(d.Removed, ra)
		}
	}
	d.RulesAdded, d.RulesRemoved = strSetDiff(a.Rules, b.Rules)
	sort.Slice(d.Added, func(i, j int) bool { return key(d.Added[i]) < key(d.Added[j]) })
	sort.Slice(d.Removed, func(i, j int) bool { return key(d.Removed[i]) < key(d.Removed[j]) })
	sort.Slice(d.Changed, func(i, j int) bool { return key(d.Changed[i].After) < key(d.Changed[j].After) })
	return d
}

// Keys returns the stable key set of a report's risks.
func Keys(r Report) []string {
	out := make([]string, 0, len(r.Risks))
	for _, k := range riskMap(r.Risks) {
		out = append(out, key(k))
	}
	sort.Strings(out)
	return out
}

func riskMap(rs []Risk) map[string]Risk {
	m := make(map[string]Risk, len(rs))
	for _, r := range rs {
		m[key(r)] = r
	}
	return m
}

// key builds a stable, per-finding key. The feature hash alone is NOT unique:
// the engine emits the same feature hash for a rule across every file it fires
// in (e.g. the broad-exception rule matches each file identically). Keying on
// the feature hash alone would collapse distinct findings onto one map entry and
// silently hide newly added ones. Fold in file, line, and rule to disambiguate.
func key(r Risk) string {
	seed := r.FeatureHash
	if seed == "" {
		seed = r.RiskType
	}
	return fmt.Sprintf("%s\x00%s\x00%d\x00%s", seed, r.File, r.Line, r.RuleName)
}

func strSetDiff(a, b []string) (added, removed []string) {
	as, bs := set(a), set(b)
	for k := range bs {
		if _, ok := as[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range as {
		if _, ok := bs[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

func set(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}
