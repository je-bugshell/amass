// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package insert

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/afmt"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

const (
	UsageMsg    = "insert -config <config.yaml> -input <findings.json> -output <summary.json>"
	Description = "Ingest external scanner findings (naabu/dnsx-ptr/tlsx) into the assetdb"
)

// Args is the parsed flag set for `amass insert`. Filepaths are mandatory;
// Silent toggles whether we write the human-readable banner to stderr (we
// always write the summary JSON to the -output path regardless).
type Args struct {
	Help    bool
	Options struct {
		NoColor bool
		Silent  bool
	}
	Filepaths struct {
		ConfigFile string
		InputFile  string
		OutputFile string
	}
}

func NewFlagset(args *Args, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet("insert", errorHandling)

	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	fs.StringVar(&args.Filepaths.ConfigFile, "config", "",
		"Path to the YAML configuration file (selects which assetdb to write to)")
	fs.StringVar(&args.Filepaths.InputFile, "input", "",
		"Path to the findings JSON file produced by bs-asm (use '-' for stdin)")
	fs.StringVar(&args.Filepaths.OutputFile, "output", "",
		"Path where the per-asset-type summary JSON gets written (use '-' for stdout)")
	return fs
}

// Summary is the per-run, per-asset-type tally written to `-output`.
// bs-asm parses it back to surface "X new assets pushed to amass" telemetry.
type Summary struct {
	Summary   map[string]TypeCounters `json:"summary"`
	Edges     map[string]TypeCounters `json:"edges,omitempty"`
	ElapsedMS int64                   `json:"elapsed_ms"`
	Note      string                  `json:"note,omitempty"`
	// Errors captures per-record write failures so operators can diagnose
	// without grepping bs-asm logs. Capped at a small number of entries to
	// keep the summary JSON small even when a whole batch failed.
	Errors []string `json:"errors,omitempty"`
}

const maxErrorsInSummary = 32

func (s *Summary) addError(msg string) {
	if len(s.Errors) >= maxErrorsInSummary {
		return
	}
	s.Errors = append(s.Errors, msg)
}

type TypeCounters struct {
	Created int64 `json:"created"`
	Deduped int64 `json:"deduped"`
	Failed  int64 `json:"failed,omitempty"`
}

// bumpEntity records a per-asset-type counter bump. created==true for a
// freshly-written row; false for a dedup hit against an existing row.
func (s *Summary) bumpEntity(kind string, created bool) {
	if s.Summary == nil {
		s.Summary = map[string]TypeCounters{}
	}
	c := s.Summary[kind]
	if created {
		c.Created++
	} else {
		c.Deduped++
	}
	s.Summary[kind] = c
}

// bumpEdge mirrors bumpEntity but for edges.
func (s *Summary) bumpEdge(kind string, created bool) {
	if s.Edges == nil {
		s.Edges = map[string]TypeCounters{}
	}
	c := s.Edges[kind]
	if created {
		c.Created++
	} else {
		c.Deduped++
	}
	s.Edges[kind] = c
}

// bumpFailedEdge records an edge write that failed mid-pipeline. Tracked
// separately from `failed` on entity counters so operators can tell where
// the breakage was.
func (s *Summary) bumpFailedEdge(kind string) {
	if s.Edges == nil {
		s.Edges = map[string]TypeCounters{}
	}
	c := s.Edges[kind]
	c.Failed++
	s.Edges[kind] = c
}

// CLIWorkflow is the subcommand entrypoint registered in cmd/amass/main.go.
//
// SLICE 2E.2 SHIPS THIS AS SCAFFOLDING ONLY:
//   - args parsing
//   - input file load + validation (via LoadInput)
//   - config file load (so we surface bad config early)
//   - a no-op summary write
//
// SLICE 2E.3 fills in the actual asset/edge writes against the assetdb.
// Splitting the work this way means bs-asm can pin the binary in its
// Dockerfile + smoke-test the argv + summary shape before any DB rows
// are touched.
func CLIWorkflow(cmdName string, clArgs []string) {
	started := time.Now()
	var args Args

	fs := NewFlagset(&args, flag.ContinueOnError)
	usageBuf := new(bytes.Buffer)
	fs.SetOutput(usageBuf)

	var usage = func() {
		afmt.PrintBanner()
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", cmdName, UsageMsg)
		if args.Help {
			fs.PrintDefaults()
			_, _ = afmt.G.Fprintln(color.Error, usageBuf.String())
		}
	}

	if err := fs.Parse(clArgs); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if args.Help {
		usage()
		return
	}
	if args.Options.NoColor {
		color.NoColor = true
	}

	if args.Filepaths.ConfigFile == "" {
		_, _ = afmt.R.Fprintln(color.Error, "-config is required")
		os.Exit(2)
	}
	if args.Filepaths.InputFile == "" {
		_, _ = afmt.R.Fprintln(color.Error, "-input is required")
		os.Exit(2)
	}
	if args.Filepaths.OutputFile == "" {
		_, _ = afmt.R.Fprintln(color.Error, "-output is required")
		os.Exit(2)
	}

	in, err := LoadInput(args.Filepaths.InputFile)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to load input: %v\n", err)
		os.Exit(2)
	}

	// Load the namespace config so OpenGraphDatabase picks the right
	// per-org Postgres (or SQLite, in tests). This is the same code path
	// `amass enum` uses to route writes to the correct database.
	cfg := config.NewConfig()
	if err := config.AcquireConfig("", args.Filepaths.ConfigFile, cfg); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to load config: %v\n", err)
		os.Exit(2)
	}

	summary := Summary{
		Summary: map[string]TypeCounters{},
		Edges:   map[string]TypeCounters{},
	}
	// Pre-create the per-type buckets so bsapp's summary parser sees a
	// predictable shape regardless of what was actually written.
	for _, t := range []string{"fqdn", "ipaddress", "service", "tlscertificate"} {
		summary.Summary[t] = TypeCounters{}
	}
	for _, e := range []string{"ptr_record", "port_relation", "certificate"} {
		summary.Edges[e] = TypeCounters{}
	}

	// Open the assetdb. nil return means amass couldn't connect — either
	// bad creds or unreachable host. We surface as an exit 4 so bs-asm can
	// distinguish from input-shape errors (exit 2) or write failures (exit 5).
	db := tools.OpenGraphDatabase(cfg)
	if db == nil {
		summary.Note = "assetdb unreachable — config.GraphDBs primary unreachable or missing"
		summary.ElapsedMS = time.Since(started).Milliseconds()
		_ = writeSummary(args.Filepaths.OutputFile, &summary)
		_, _ = afmt.R.Fprintln(color.Error, "Failed to open the assetdb (no primary entry or connection failed)")
		os.Exit(4)
	}

	// runStart is the watermark for the freshly-created vs deduped heuristic
	// — see isFreshlyCreated in process.go. Take it AFTER the DB open so
	// connection-setup latency doesn't get counted as "before any writes."
	runStart := time.Now()
	ctx := context.Background()
	if err := processFindings(ctx, db, in, runStart, &summary); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "processFindings: %v\n", err)
		summary.Note = fmt.Sprintf("processFindings error: %v", err)
		summary.ElapsedMS = time.Since(started).Milliseconds()
		_ = writeSummary(args.Filepaths.OutputFile, &summary)
		os.Exit(5)
	}

	summary.ElapsedMS = time.Since(started).Milliseconds()
	if err := writeSummary(args.Filepaths.OutputFile, &summary); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to write summary: %v\n", err)
		os.Exit(3)
	}
}

func writeSummary(path string, s *Summary) error {
	buf, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	if path == "-" {
		_, err = os.Stdout.Write(buf)
		return err
	}
	return os.WriteFile(path, buf, 0o600)
}
