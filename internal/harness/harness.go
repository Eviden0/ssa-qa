// Package harness runs the black-box engine binary in an isolated environment
// and returns the raw report bytes. It never imports engine code; the only
// contract is the CLI and the report file.
package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Case is one scan configuration, loaded from cases/<name>/case.json.
type Case struct {
	Name        string   `json:"name"`
	Language    string   `json:"language"`
	Corpus      string   `json:"corpus"`      // path relative to the case dir
	Format      string   `json:"format"`      // "irify" (default) or "sarif"
	Program     string   `json:"program"`     // forced program name (stabilizes source URLs)
	Memory      bool     `json:"memory"`      // --memory (no DB persistence)
	Runs        int      `json:"runs"`        // determinism runs (default 3)
	Incremental bool     `json:"incremental"` // reuse one home/DB for two passes
	ExtraArgs   []string `json:"extraArgs"`   // appended verbatim to code-scan
}

// LoadCase reads cases/<name>/case.json.
func LoadCase(caseDir string) (Case, error) {
	raw, err := os.ReadFile(filepath.Join(caseDir, "case.json"))
	if err != nil {
		return Case{}, err
	}
	var c Case
	if err := json.Unmarshal(raw, &c); err != nil {
		return Case{}, fmt.Errorf("parse case.json: %w", err)
	}
	if c.Name == "" {
		c.Name = filepath.Base(caseDir)
	}
	if c.Format == "" {
		c.Format = "irify"
	}
	if c.Runs <= 0 {
		c.Runs = 3
	}
	if c.Program == "" {
		c.Program = "qa-" + c.Name
	}
	if c.Corpus == "" {
		c.Corpus = "corpus"
	}
	return c, nil
}

// Runner executes the engine binary.
type Runner struct {
	Bin     string        // path to yak-ssa
	Timeout time.Duration // per-scan wall-clock cap
}

// ScanResult is one engine invocation.
type ScanResult struct {
	Raw      []byte
	Duration time.Duration
	Home     string
}

// Scan runs the engine once against c, using home as YAKIT_HOME (created if
// absent). The engine's stdout/stderr go to <home>/engine.log so large logs do
// not pollute memory; only the report file is read back.
func (rn Runner) Scan(ctx context.Context, c Case, caseDir, home string) (ScanResult, error) {
	if rn.Bin == "" {
		return ScanResult{}, fmt.Errorf("engine binary path is empty")
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		return ScanResult{}, err
	}
	corpusAbs, err := filepath.Abs(filepath.Join(caseDir, c.Corpus))
	if err != nil {
		return ScanResult{}, err
	}
	outBase := filepath.Join(home, "report")

	args := []string{
		"code-scan",
		"-t", corpusAbs,
		"-l", c.Language,
		"-p", c.Program,
		"--format", c.Format,
		"-o", outBase,
		"--no-save-risk",
		"--log-level", "error",
	}
	if c.Memory {
		args = append(args, "--memory")
	}
	args = append(args, c.ExtraArgs...)

	timeout := rn.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ectx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	logPath := filepath.Join(home, "engine.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return ScanResult{}, err
	}
	defer logFile.Close()

	// cmd.Dir switches the child's cwd to caseDir before exec, so a relative
	// binary path would be re-resolved against cases/<case>/ and fail. Absolutize
	// anything path-like (including "./yak-ssa"); leave bare names (e.g.
	// "yak-ssa") intact so PATH lookup still works.
	bin := rn.Bin
	if strings.ContainsAny(bin, `/\`) {
		bin, err = filepath.Abs(bin)
		if err != nil {
			return ScanResult{}, err
		}
	}

	cmd := exec.CommandContext(ectx, bin, args...)
	cmd.Dir = caseDir
	cmd.Env = append(os.Environ(), "YAKIT_HOME="+home)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)
	if ectx.Err() == context.DeadlineExceeded {
		return ScanResult{}, fmt.Errorf("scan timed out after %s (see %s)", timeout, logPath)
	}
	if runErr != nil {
		tail, _ := os.ReadFile(logPath)
		return ScanResult{}, fmt.Errorf("engine exited with error: %w\n--- engine.log tail ---\n%s",
			runErr, tailString(tail, 2000))
	}

	raw, err := readReport(outBase)
	if err != nil {
		return ScanResult{}, err
	}
	return ScanResult{Raw: raw, Duration: dur, Home: home}, nil
}

// readReport finds the engine's report file. The engine appends an extension
// based on --format (.json for irify, .sarif for sarif), so match a prefix.
func readReport(outBase string) ([]byte, error) {
	matches, _ := filepath.Glob(outBase + "*")
	var chosen string
	for _, m := range matches {
		if filepath.Ext(m) == ".json" || filepath.Ext(m) == ".sarif" {
			chosen = m
			break
		}
	}
	if chosen == "" {
		return nil, fmt.Errorf("no report file produced (looked for %s.{json,sarif})", outBase)
	}
	return os.ReadFile(chosen)
}

func tailString(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[len(b)-n:])
}
