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

func TestAppendInputCountsToSummary_counts_records_across_sources(t *testing.T) {
	in := &FindingsInput{
		SourceNaabu:   []NaabuRecord{{IP: "1.2.3.4", Port: 80, Protocol: "tcp"}, {IP: "1.2.3.5", Port: 443, Protocol: "tcp"}},
		SourceDNSXPtr: []DNSXPtrRecord{{IP: "1.2.3.4", PtrName: "a.example.com"}},
		SourceTLSX:    []TLSXRecord{{IP: "1.2.3.4", Port: 443, Cert: CertJSON{SerialNumberHex: "ab"}}},
	}
	s := &Summary{Summary: map[string]TypeCounters{}, Edges: map[string]TypeCounters{}}
	if err := appendInputCountsToSummary(in, s); err != nil {
		t.Fatalf("append: %v", err)
	}
	got := s.Summary["input_counts"].Created
	want := int64(2 + 1 + 1)
	if got != want {
		t.Errorf("input_counts = %d, want %d", got, want)
	}
}

func TestAppendInputCountsToSummary_initializes_nil_maps(t *testing.T) {
	// Defensive: the scaffold pre-allocates the maps before calling this,
	// but a future refactor could pass a zero-value Summary. Guard against
	// nil-map panics.
	in := &FindingsInput{SourceNaabu: []NaabuRecord{{IP: "1.2.3.4", Port: 80, Protocol: "tcp"}}}
	s := &Summary{}
	if err := appendInputCountsToSummary(in, s); err != nil {
		t.Fatalf("append: %v", err)
	}
	if s.Summary == nil || s.Edges == nil {
		t.Errorf("maps should be initialized")
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
