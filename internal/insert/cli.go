// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package insert

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v5/internal/afmt"
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
	Summary    map[string]TypeCounters `json:"summary"`
	Edges      map[string]TypeCounters `json:"edges,omitempty"`
	ElapsedMS  int64                   `json:"elapsed_ms"`
	Note       string                  `json:"note,omitempty"`
	Skipped    string                  `json:"skipped,omitempty"`
}

type TypeCounters struct {
	Created int64 `json:"created"`
	Deduped int64 `json:"deduped"`
	Failed  int64 `json:"failed,omitempty"`
}

// CLIWorkflow is the subcommand entrypoint registered in cmd/amass/main.go.
//
// SLICE 2E.2 SHIPS THIS AS SCAFFOLDING ONLY:
//   * args parsing
//   * input file load + validation (via LoadInput)
//   * config file load (so we surface bad config early)
//   * a no-op summary write
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

	// 2E.2 scaffolding stops here. 2E.3 will: open the assetdb via
	// tools.OpenGraphDatabase(cfg), iterate `in.Source*` records, build OAM
	// entities + edges via the helpers in normalize.go, call CreateAsset /
	// CreateEdge / CreateEntityProperty, and count results into `summary`.
	summary := Summary{
		Summary:   map[string]TypeCounters{},
		Edges:     map[string]TypeCounters{},
		ElapsedMS: time.Since(started).Milliseconds(),
		Note:      "scaffold — Slice 2E.2 does not write to assetdb yet",
	}
	// Pre-create the per-type buckets so bsapp's summary parser sees a
	// predictable shape regardless of what was in the input.
	for _, t := range []string{"fqdn", "ipaddress", "service", "tlscertificate"} {
		summary.Summary[t] = TypeCounters{}
	}
	for _, e := range []string{"dns_record_ptr", "port_relation", "certificate"} {
		summary.Edges[e] = TypeCounters{}
	}
	// Count input records so the scaffold's output is informative even
	// without DB writes.
	if in != nil {
		_ = appendInputCountsToSummary(in, &summary)
	}

	if err := writeSummary(args.Filepaths.OutputFile, &summary); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to write summary: %v\n", err)
		os.Exit(3)
	}
}

// appendInputCountsToSummary reports per-source record counts so operators
// can verify the payload structure end-to-end before 2E.3 wires up DB writes.
// Once 2E.3 lands, this becomes a sanity check that the input matches what
// actually got persisted.
func appendInputCountsToSummary(in *FindingsInput, s *Summary) error {
	if s.Summary == nil {
		s.Summary = map[string]TypeCounters{}
	}
	if s.Edges == nil {
		s.Edges = map[string]TypeCounters{}
	}
	// Pre-tallies are written into a separate "input_counts" key on the
	// summary so operators can see the raw input volume vs. the eventual
	// persistence counts (which will be 0 in this slice).
	s.Summary["input_counts"] = TypeCounters{
		Created: int64(len(in.SourceNaabu) + len(in.SourceDNSXPtr) + len(in.SourceTLSX)),
	}
	return nil
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
