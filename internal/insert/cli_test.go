// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package insert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSummary is the only side-effecting fn worth testing directly in 2E.2 —
// the rest of CLIWorkflow does flag parsing + os.Exit which is awkward to
// drive from a unit test. Slice 2E.3's DB writes will exercise the full path.

func TestWriteSummary_to_file(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "summary.json")
	s := &Summary{
		Summary:   map[string]TypeCounters{"fqdn": {Created: 3, Deduped: 1}},
		ElapsedMS: 42,
	}
	if err := writeSummary(out, s); err != nil {
		t.Fatalf("writeSummary: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var got Summary
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("parse summary: %v", err)
	}
	if got.Summary["fqdn"].Created != 3 || got.Summary["fqdn"].Deduped != 1 {
		t.Errorf("round-trip lost data: %+v", got)
	}
	if got.ElapsedMS != 42 {
		t.Errorf("elapsed_ms lost: %d", got.ElapsedMS)
	}
}

func TestSummary_bumpEntity_initializes_nil_map(t *testing.T) {
	// Defensive: caller might pass a zero-value Summary by accident; the
	// bumpers should self-heal rather than nil-panic.
	s := &Summary{}
	s.bumpEntity("fqdn", true)
	if s.Summary == nil {
		t.Fatal("Summary map should be initialized")
	}
	if s.Summary["fqdn"].Created != 1 {
		t.Errorf("expected Created=1, got %+v", s.Summary["fqdn"])
	}
}

func TestSummary_bumpEdge_initializes_nil_map(t *testing.T) {
	s := &Summary{}
	s.bumpEdge("ptr_record", false)
	if s.Edges == nil {
		t.Fatal("Edges map should be initialized")
	}
	if s.Edges["ptr_record"].Deduped != 1 {
		t.Errorf("expected Deduped=1, got %+v", s.Edges["ptr_record"])
	}
}

func TestSummary_addError_caps_at_max(t *testing.T) {
	// Defensive cap so a runaway batch doesn't bloat the summary JSON.
	s := &Summary{}
	for i := 0; i < maxErrorsInSummary*2; i++ {
		s.addError("oops")
	}
	if len(s.Errors) != maxErrorsInSummary {
		t.Errorf("Errors len = %d, want %d", len(s.Errors), maxErrorsInSummary)
	}
}

func TestSummary_json_shape_matches_documented_schema(t *testing.T) {
	// bsapp parses this JSON downstream — pin the field names so a refactor
	// doesn't silently break the contract.
	s := &Summary{
		Summary: map[string]TypeCounters{
			"fqdn": {Created: 3, Deduped: 1, Failed: 0},
		},
		Edges: map[string]TypeCounters{
			"port_relation": {Created: 4, Deduped: 1},
		},
		ElapsedMS: 312,
	}
	buf, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(buf)
	// Required top-level keys + counter sub-keys (note: `failed` is omitempty
	// when zero, so don't assert its presence here).
	for _, key := range []string{`"summary"`, `"edges"`, `"elapsed_ms"`, `"created"`, `"deduped"`} {
		if !strings.Contains(body, key) {
			t.Errorf("missing %s in marshalled summary: %s", key, body)
		}
	}
}
