// Command ssa-qa is a black-box stability harness for the standalone SSA
// engine (yak-ssa). It runs versioned scan cases in an isolated environment,
// canonicalizes the reports, and checks determinism, golden drift, SARIF shape,
// and performance budgets.
//
// Usage:
//
//	ssa-qa run   [flags]   # execute cases, report determinism + perf
//	ssa-qa verify [flags]  # run + compare to goldens/allowlist (CI gate)
//	ssa-qa update-golden [flags] --confirm  # rewrite goldens from current engine
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Eviden0/ssa-qa/internal/canon"
	"github.com/Eviden0/ssa-qa/internal/harness"
)

type budgetsFile struct {
	Cases map[string]struct {
		MaxMs int `json:"max_ms"`
	} `json:"cases"`
}

type allowlistFile struct {
	Risks []struct {
		FeatureHash string `json:"feature_hash"`
		Reason      string `json:"reason"`
	} `json:"risks"`
}

type caseRun struct {
	Case         harness.Case
	Rep          canon.Report
	Durations    []time.Duration
	NonDet       bool
	NonDetDetail string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	mode := os.Args[1]
	switch mode {
	case "run", "verify", "update-golden":
	default:
		fmt.Fprintf(os.Stderr, "error: unknown mode %q (run|verify|update-golden)\n", mode)
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	root := fs.String("root", ".", "ssa-qa repo root (contains cases/, goldens/)")
	binary := fs.String("binary", defaultBinary(), "path to yak-ssa (or $SSA_QA_BINARY)")
	only := fs.String("case", "", "run only the named case (default: all)")
	timeout := fs.Duration("timeout", 5*time.Minute, "per-scan timeout")
	goldenDir := fs.String("golden-dir", "goldens", "golden directory (relative to root)")
	budgetsPath := fs.String("budgets", "budgets.json", "performance budgets (relative to root)")
	allowPath := fs.String("allowlist", "allowlist.json", "approved changes (relative to root)")
	confirm := fs.Bool("confirm", false, "update-golden: required to actually write goldens")
	_ = fs.Parse(os.Args[2:])

	rn := harness.Runner{Bin: *binary, Timeout: *timeout}
	cases, err := listCases(*root, *only)
	if err != nil {
		fatal(err)
	}
	if len(cases) == 0 {
		fatal(fmt.Errorf("no cases found under %s/cases", *root))
	}

	budgets := loadBudgets(filepath.Join(*root, *budgetsPath))
	allow := loadAllow(filepath.Join(*root, *allowPath))

	ctx := context.Background()
	failed := false
	for _, caseDir := range cases {
		run, err := executeCase(ctx, rn, caseDir)
		if err != nil {
			fmt.Printf("FAIL %s: %v\n", filepath.Base(caseDir), err)
			failed = true
			continue
		}
		name := run.Case.Name

		// Determinism / crash / schema all surface as non-det or exec error.
		if run.NonDet {
			fmt.Printf("FAIL %s: non-deterministic across runs\n%s\n", name, run.NonDetDetail)
			failed = true
		}

		perfFail := checkPerf(name, run.Durations, budgets)

		switch mode {
		case "run":
			printRunSummary(run)
		case "verify":
			failed = verifyCase(*root, *goldenDir, name, run, allow) || failed
			failed = perfFail || failed
		case "update-golden":
			if !*confirm {
				fmt.Printf("SKIP %s: update-golden requires --confirm\n", name)
				continue
			}
			if err := writeGolden(*root, *goldenDir, name, run.Rep); err != nil {
				fmt.Printf("FAIL %s: write golden: %v\n", name, err)
				failed = true
			} else {
				fmt.Printf("UPDATED %s (%d risks, hash %s)\n", name, len(run.Rep.Risks), short(run.Rep.Hash()))
			}
		default:
			fatal(fmt.Errorf("unknown mode %q (run|verify|update-golden)", mode))
		}
	}

	if failed {
		os.Exit(1)
	}
}

func executeCase(ctx context.Context, rn harness.Runner, caseDir string) (caseRun, error) {
	c, err := harness.LoadCase(caseDir)
	if err != nil {
		return caseRun{}, err
	}
	cr := caseRun{Case: c}

	if c.Incremental {
		// Two passes against the SAME home/DB: the second must be idempotent.
		home, err := os.MkdirTemp("", "ssaqa-inc-*")
		if err != nil {
			return caseRun{}, err
		}
		defer os.RemoveAll(home)
		p1, err := scanToReport(ctx, rn, c, caseDir, home)
		if err != nil {
			return caseRun{}, err
		}
		cr.Durations = append(cr.Durations, p1.Duration)
		p2, err := scanToReport(ctx, rn, c, caseDir, home)
		if err != nil {
			return caseRun{}, err
		}
		cr.Durations = append(cr.Durations, p2.Duration)
		cr.Rep = p2.Report
		if d := canon.Compare(p1.Report, p2.Report); !d.Empty() {
			cr.NonDet = true
			cr.NonDetDetail = "incremental second pass differs from first:\n" + describeDiff(d)
		}
		return cr, nil
	}

	var first *canon.Report
	for i := 0; i < c.Runs; i++ {
		home, err := os.MkdirTemp("", "ssaqa-run-*")
		if err != nil {
			return caseRun{}, err
		}
		res, err := scanToReport(ctx, rn, c, caseDir, home)
		os.RemoveAll(home)
		if err != nil {
			return caseRun{}, err
		}
		cr.Durations = append(cr.Durations, res.Duration)
		if first == nil {
			first = &res.Report
			cr.Rep = res.Report
			continue
		}
		if d := canon.Compare(*first, res.Report); !d.Empty() {
			cr.NonDet = true
			cr.NonDetDetail = describeDiff(d)
			break
		}
	}
	return cr, nil
}

type scanOut struct {
	Report   canon.Report
	Duration time.Duration
}

func scanToReport(ctx context.Context, rn harness.Runner, c harness.Case, caseDir, home string) (scanOut, error) {
	res, err := rn.Scan(ctx, c, caseDir, home)
	if err != nil {
		return scanOut{}, err
	}
	var rep canon.Report
	if c.Format == "sarif" {
		rep, err = canon.FromSarif(res.Raw, c.Program)
	} else {
		rep, err = canon.FromIrify(res.Raw)
	}
	if err != nil {
		return scanOut{}, fmt.Errorf("canonicalize %s report: %w", c.Format, err)
	}
	return scanOut{Report: rep, Duration: res.Duration}, nil
}

func verifyCase(root, goldenDir, name string, run caseRun, allow allowlistFile) bool {
	goldenPath := filepath.Join(root, goldenDir, name+".json")
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		fmt.Printf("FAIL %s: no golden at %s (run update-golden --confirm)\n", name, goldenPath)
		return true
	}
	var golden canon.Report
	if err := json.Unmarshal(raw, &golden); err != nil {
		fmt.Printf("FAIL %s: parse golden: %v\n", name, err)
		return true
	}
	d := canon.Compare(golden, run.Rep)
	if d.Empty() {
		fmt.Printf("PASS %s (%d risks, hash %s)\n", name, len(run.Rep.Risks), short(run.Rep.Hash()))
		return false
	}
	// Allowlisted feature hashes downgrade a change to a warning.
	allowed := map[string]string{}
	for _, a := range allow.Risks {
		allowed[a.FeatureHash] = a.Reason
	}
	unapproved := false
	fmt.Printf("DIFF %s: %d added, %d removed, %d changed\n",
		name, len(d.Added), len(d.Removed), len(d.Changed))
	for _, r := range d.Added {
		if reason, ok := allowed[r.FeatureHash]; ok {
			fmt.Printf("   ALLOWED added %s (%s)\n", short(r.FeatureHash), reason)
		} else {
			fmt.Printf("   ADDED   %s  %s:%d %s\n", short(r.FeatureHash), r.File, r.Line, r.RiskType)
			unapproved = true
		}
	}
	for _, r := range d.Removed {
		if reason, ok := allowed[r.FeatureHash]; ok {
			fmt.Printf("   ALLOWED removed %s (%s)\n", short(r.FeatureHash), reason)
		} else {
			fmt.Printf("   REMOVED %s  %s:%d %s\n", short(r.FeatureHash), r.File, r.Line, r.RiskType)
			unapproved = true
		}
	}
	for _, ch := range d.Changed {
		if reason, ok := allowed[ch.After.FeatureHash]; ok {
			fmt.Printf("   ALLOWED changed %s (%s)\n", short(ch.After.FeatureHash), reason)
		} else {
			fmt.Printf("   CHANGED %s\n     - %+v\n     + %+v\n", short(ch.After.FeatureHash), ch.Before, ch.After)
			unapproved = true
		}
	}
	if len(d.RulesAdded)+len(d.RulesRemoved) > 0 {
		fmt.Printf("   rule set changed: +%v -%v\n", d.RulesAdded, d.RulesRemoved)
		unapproved = true
	}
	if unapproved {
		fmt.Printf("FAIL %s: unapproved golden drift\n", name)
		return true
	}
	fmt.Printf("PASS %s: drift fully allowlisted\n", name)
	return false
}

func checkPerf(name string, durs []time.Duration, b budgetsFile) bool {
	bc, ok := b.Cases[name]
	if !ok || bc.MaxMs <= 0 || len(durs) == 0 {
		return false
	}
	var max time.Duration
	for _, d := range durs {
		if d > max {
			max = d
		}
	}
	budget := time.Duration(bc.MaxMs) * time.Millisecond
	if max > budget {
		fmt.Printf("FAIL %s: slowest run %s exceeds budget %s\n", name, max.Round(time.Millisecond), budget)
		return true
	}
	return false
}

func printRunSummary(run caseRun) {
	ds := make([]string, len(run.Durations))
	for i, d := range run.Durations {
		ds[i] = d.Round(time.Millisecond).String()
	}
	status := "DETERMINISTIC"
	if run.NonDet {
		status = "NON-DETERMINISTIC"
	}
	fmt.Printf("%s %s: %d risks, hash %s, runs=[%s]\n",
		status, run.Case.Name, len(run.Rep.Risks), short(run.Rep.Hash()), strings.Join(ds, ", "))
}

func describeDiff(d canon.Diff) string {
	var b strings.Builder
	for _, r := range d.Added {
		fmt.Fprintf(&b, "   + %s %s:%d %s\n", short(r.FeatureHash), r.File, r.Line, r.RiskType)
	}
	for _, r := range d.Removed {
		fmt.Fprintf(&b, "   - %s %s:%d %s\n", short(r.FeatureHash), r.File, r.Line, r.RiskType)
	}
	for _, ch := range d.Changed {
		fmt.Fprintf(&b, "   ~ %s\n     - %+v\n     + %+v\n", short(ch.After.FeatureHash), ch.Before, ch.After)
	}
	return strings.TrimRight(b.String(), "\n")
}

func writeGolden(root, goldenDir, name string, rep canon.Report) error {
	dir := filepath.Join(root, goldenDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".json"), rep.Bytes(), 0o644)
}

func listCases(root, only string) ([]string, error) {
	base := filepath.Join(root, "cases")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("read cases dir: %w", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if only != "" && e.Name() != only {
			continue
		}
		if _, err := os.Stat(filepath.Join(base, e.Name(), "case.json")); err != nil {
			continue
		}
		out = append(out, filepath.Join(base, e.Name()))
	}
	sort.Strings(out)
	if only != "" && len(out) == 0 {
		return nil, fmt.Errorf("case %q not found under %s", only, base)
	}
	return out, nil
}

func loadBudgets(path string) budgetsFile {
	var b budgetsFile
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &b)
	}
	return b
}

func loadAllow(path string) allowlistFile {
	var a allowlistFile
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &a)
	}
	return a
}

func defaultBinary() string {
	if v := os.Getenv("SSA_QA_BINARY"); v != "" {
		return v
	}
	return "yak-ssa"
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func usage() {
	fmt.Print(`ssa-qa: black-box stability harness for yak-ssa

  ssa-qa run           [flags]   execute cases, report determinism + perf
  ssa-qa verify        [flags]   run + diff against goldens/allowlist (CI gate)
  ssa-qa update-golden [flags] --confirm   rewrite goldens from current engine

flags: --root --binary --case --timeout --golden-dir --budgets --allowlist --confirm
`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
