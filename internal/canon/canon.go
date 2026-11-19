// Package canon turns engine scan output into a stable, comparable form.
//
// The engine's raw reports carry volatile data: per-run RuntimeId/ResultUUID
// (folded into the risk identity hash), a timestamped default program name,
// scan/report timestamps, auto-increment ids, and map iteration order. Those
// must be stripped or normalized before outputs can be diffed across runs or
// versions. The stable identity is the risk *feature* hash
// (risk_feature_hash / yaklangRiskFeatureHash), never the identity hash.
package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Report is the canonical, version-independent view of one scan.
type Report struct {
	Format        string   `json:"format"`
	EngineVersion string   `json:"engine_version"`
	Language      string   `json:"language"`
	Rules         []string `json:"rules,omitempty"`
	Risks         []Risk   `json:"risks"`
}

// Risk is one finding keyed by its stable feature hash.
type Risk struct {
	FeatureHash string   `json:"feature_hash"`
	RuleName    string   `json:"rule_name"`
	RiskType    string   `json:"risk_type"`
	Severity    string   `json:"severity"`
	Language    string   `json:"language"`
	ScanMode    string   `json:"scan_mode"`
	Line        int      `json:"line"`
	Function    string   `json:"function"`
	File        string   `json:"file"`
	CWE         []string `json:"cwe,omitempty"`
}

// Hash is the sha256 of the canonical JSON encoding.
func (r Report) Hash() string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Bytes renders the canonical JSON (pretty for golden files).
func (r Report) Bytes() []byte {
	b, _ := json.MarshalIndent(r, "", "  ")
	return append(b, '\n')
}

// FromIrify parses the engine's `irify` JSON report.
func FromIrify(raw []byte) (Report, error) {
	var doc struct {
		ReportType    string `json:"report_type"`
		EngineVersion string `json:"engine_version"`
		ProgramName   string `json:"program_name"`
		ProgramLang   string `json:"program_lang"`
		Risks         map[string]struct {
			FeatureHash string   `json:"risk_feature_hash"`
			Title       string   `json:"title"`
			Severity    string   `json:"severity"`
			RiskType    string   `json:"risk_type"`
			Language    string   `json:"language"`
			CodeSource  string   `json:"code_source_url"`
			Line        int      `json:"line"`
			Function    string   `json:"function_name"`
			RuleName    string   `json:"rule_name"`
			ScanMode    string   `json:"scan_mode"`
			CWE         []string `json:"cwe"`
		} `json:"Risks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Report{}, fmt.Errorf("parse irify json: %w", err)
	}
	// Guard against feeding a different report format (e.g. SARIF, which has no
	// report_type) into this parser: it would otherwise unmarshal to an empty
	// risk set and silently "pass".
	if doc.ReportType != "irify" {
		return Report{}, fmt.Errorf("not an irify report (report_type=%q)", doc.ReportType)
	}
	rep := Report{
		Format:        "irify",
		EngineVersion: doc.EngineVersion,
		Language:      doc.ProgramLang,
		Risks:         make([]Risk, 0, len(doc.Risks)),
	}
	for _, r := range doc.Risks {
		cwe := append([]string(nil), r.CWE...)
		sort.Strings(cwe)
		rep.Risks = append(rep.Risks, Risk{
			FeatureHash: r.FeatureHash,
			RuleName:    r.RuleName,
			RiskType:    r.RiskType,
			Severity:    r.Severity,
			Language:    r.Language,
			ScanMode:    r.ScanMode,
			Line:        r.Line,
			Function:    r.Function,
			File:        normalizeFile(r.CodeSource, doc.ProgramName),
			CWE:         cwe,
		})
	}
	sortRisks(rep.Risks)
	return rep, nil
}

// FromSarif parses the engine's SARIF 2.1.0 report. program is the forced
// program name; it is stripped from artifact URIs (see normalizeFile).
func FromSarif(raw []byte, program string) (Report, error) {
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Report{}, fmt.Errorf("parse sarif json: %w", err)
	}
	if doc.Version != "2.1.0" {
		return Report{}, fmt.Errorf("unexpected sarif version %q", doc.Version)
	}
	if len(doc.Runs) == 0 {
		return Report{}, fmt.Errorf("sarif has no runs")
	}
	rep := Report{Format: "sarif"}
	ruleSet := map[string]struct{}{}
	for _, run := range doc.Runs {
		for _, rl := range run.Tool.Driver.Rules {
			if rl.ID != "" {
				ruleSet[rl.ID] = struct{}{}
			}
		}
		for _, res := range run.Results {
			uri, line := "", 0
			if len(res.Locations) > 0 {
				pl := res.Locations[0].PhysicalLocation
				uri = pl.ArtifactLocation.URI
				line = pl.Region.StartLine
			}
			rep.Risks = append(rep.Risks, Risk{
				FeatureHash: res.PartialFingerprints["yaklangRiskFeatureHash"],
				RuleName:    res.RuleID,
				Severity:    res.Level,
				Line:        line,
				File:        normalizeFile(uri, program),
			})
		}
	}
	rep.Rules = make([]string, 0, len(ruleSet))
	for id := range ruleSet {
		rep.Rules = append(rep.Rules, id)
	}
	sort.Strings(rep.Rules)
	sortRisks(rep.Risks)
	return rep, nil
}

// sortRisks imposes a total order over all risk fields so that Go map iteration
// order can never leak into the canonical output. Ties only remain for entries
// that are byte-for-byte indistinguishable, where order is irrelevant.
func sortRisks(rs []Risk) {
	sort.Slice(rs, func(i, j int) bool { return riskLess(rs[i], rs[j]) })
}

func riskLess(a, b Risk) bool {
	switch {
	case a.FeatureHash != b.FeatureHash:
		return a.FeatureHash < b.FeatureHash
	case a.File != b.File:
		return a.File < b.File
	case a.Line != b.Line:
		return a.Line < b.Line
	case a.RuleName != b.RuleName:
		return a.RuleName < b.RuleName
	case a.RiskType != b.RiskType:
		return a.RiskType < b.RiskType
	case a.Severity != b.Severity:
		return a.Severity < b.Severity
	case a.Function != b.Function:
		return a.Function < b.Function
	case a.Language != b.Language:
		return a.Language < b.Language
	case a.ScanMode != b.ScanMode:
		return a.ScanMode < b.ScanMode
	default:
		return strings.Join(a.CWE, "\x00") < strings.Join(b.CWE, "\x00")
	}
}

// normalizeFile strips the volatile program-name prefix from a source URL,
// leaving a path relative to the scanned project root.
//
//   - irify:   /<program_name>/pkg/File.java   -> pkg/File.java
//   - sarif:   /scan-project(2026-.. 12:00:00)/pkg/File.java -> pkg/File.java
func normalizeFile(url, programName string) string {
	if url == "" {
		return ""
	}
	u := strings.TrimPrefix(url, "file://")
	u = strings.TrimPrefix(u, "/")
	parts := strings.Split(u, "/")
	if len(parts) > 1 {
		first := parts[0]
		if first == programName || strings.HasPrefix(first, "scan-project(") {
			parts = parts[1:]
		}
	}
	return path.Clean(strings.Join(parts, "/"))
}
