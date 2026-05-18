// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Integration tests for the assetdb-write path. We use SQLite (via
// asset-db's sqlite3 backend) so the tests are hermetic — no external
// Postgres required. The schema initialization is identical to what the
// per-org Postgres uses, so dedup behavior we verify here is the same
// behavior that hits production.

package insert

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oam "github.com/owasp-amass/open-asset-model"
)

// newTestDB opens an ephemeral SQLite assetdb in t.TempDir(). The Close
// happens via t.Cleanup so the file goes away with the test.
func newTestDB(t *testing.T) repository.Repository {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test-asset.db")
	store, err := assetdb.New(sqlite3.SQLite, path)
	if err != nil {
		t.Fatalf("open sqlite assetdb: %v", err)
	}
	return store
}

// emptySummary returns a Summary pre-shaped the way CLIWorkflow shapes it,
// so per-type buckets are guaranteed to exist before the writers touch them.
func emptySummary() *Summary {
	s := &Summary{
		Summary: map[string]TypeCounters{},
		Edges:   map[string]TypeCounters{},
	}
	for _, t := range []string{"fqdn", "ipaddress", "service", "tlscertificate"} {
		s.Summary[t] = TypeCounters{}
	}
	for _, e := range []string{"ptr_record", "port_relation", "certificate"} {
		s.Edges[e] = TypeCounters{}
	}
	return s
}

// --- single-source happy paths ------------------------------------------

func TestProcessFindings_dnsx_ptr_creates_ip_fqdn_and_ptr_edge(t *testing.T) {
	db := newTestDB(t)
	in := &FindingsInput{SourceDNSXPtr: []DNSXPtrRecord{
		{IP: "49.13.29.34", PtrName: "mail.bugshell.space"},
	}}
	sum := emptySummary()

	if err := processFindings(context.Background(), db, in, time.Now(), sum); err != nil {
		t.Fatalf("processFindings: %v", err)
	}
	if len(sum.Errors) > 0 {
		t.Logf("captured errors: %v", sum.Errors)
	}
	t.Logf("summary entities: %+v", sum.Summary)
	t.Logf("summary edges:    %+v", sum.Edges)

	if got := sum.Summary["ipaddress"].Created; got != 1 {
		t.Errorf("ipaddress.created = %d, want 1", got)
	}
	if got := sum.Summary["fqdn"].Created; got != 1 {
		t.Errorf("fqdn.created = %d, want 1", got)
	}
	if got := sum.Edges["ptr_record"].Created; got != 1 {
		t.Errorf("ptr_record.created = %d, want 1", got)
	}

	// Spot-check the entities actually landed by querying the same content
	// filter amass's PutAsset would use.
	ents, err := db.FindEntitiesByContent(context.Background(), oam.FQDN, time.Time{}, 1, map[string]any{"name": "mail.bugshell.space"})
	if err != nil || len(ents) != 1 {
		t.Errorf("expected 1 FQDN matching name=mail.bugshell.space, got %v / err %v", ents, err)
	}
}

func TestProcessFindings_naabu_creates_ip_service_and_port_edge(t *testing.T) {
	db := newTestDB(t)
	in := &FindingsInput{SourceNaabu: []NaabuRecord{
		{IP: "1.2.3.4", Port: 443, Protocol: "tcp",
			Attributes: map[string][]string{"Server": {"nginx/1.18.0"}}},
	}}
	sum := emptySummary()

	if err := processFindings(context.Background(), db, in, time.Now(), sum); err != nil {
		t.Fatalf("processFindings: %v", err)
	}

	if got := sum.Summary["ipaddress"].Created; got != 1 {
		t.Errorf("ipaddress.created = %d, want 1", got)
	}
	if got := sum.Summary["service"].Created; got != 1 {
		t.Errorf("service.created = %d, want 1", got)
	}
	if got := sum.Edges["port_relation"].Created; got != 1 {
		t.Errorf("port_relation.created = %d, want 1", got)
	}

	// Service ID matches our BuildService formula — independently verifies
	// the canonical-ID story works through the DB layer.
	expectedID := BuildService("1.2.3.4", "tcp", 443).ID
	ents, err := db.FindEntitiesByContent(context.Background(), oam.Service, time.Time{}, 1, map[string]any{"unique_id": expectedID})
	if err != nil || len(ents) != 1 {
		t.Errorf("expected 1 Service with the BuildService ID; got %v / err %v", ents, err)
	}
}

func TestProcessFindings_tlsx_creates_ip_service_cert_edge_and_sans(t *testing.T) {
	db := newTestDB(t)
	in := &FindingsInput{SourceTLSX: []TLSXRecord{
		{IP: "49.13.29.34", Port: 443,
			Cert: CertJSON{
				SerialNumberHex:         "0610574ef3af59da7fea70de8948a6350f61",
				IssuerCN:                "R13",
				SubjectCN:               "mail.bugshell.space",
				NotBefore:               "2026-05-11T19:58:12Z",
				NotAfter:                "2026-08-09T19:58:11Z",
				SubjectAlternativeNames: []string{"mail.bugshell.space", "autoconfig.bugshell.space"},
			}},
	}}
	sum := emptySummary()

	if err := processFindings(context.Background(), db, in, time.Now(), sum); err != nil {
		t.Fatalf("processFindings: %v", err)
	}
	if len(sum.Errors) > 0 {
		t.Logf("captured errors: %v", sum.Errors)
	}

	if got := sum.Summary["service"].Created; got != 1 {
		t.Errorf("service.created = %d, want 1", got)
	}
	if got := sum.Summary["tlscertificate"].Created; got != 1 {
		t.Errorf("tlscertificate.created = %d, want 1", got)
	}
	if got := sum.Summary["fqdn"].Created; got != 2 {
		// 2 SAN entries → 2 FQDN rows
		t.Errorf("fqdn.created = %d, want 2 (one per SAN)", got)
	}
	if got := sum.Edges["certificate"].Created; got != 1 {
		t.Errorf("certificate.created = %d, want 1", got)
	}

	// Verify the cert serial landed in big.Int decimal form — this is the
	// dedup-critical property that lets future amass-side cert writes hit
	// the same row.
	expectedDecimal, _ := HexSerialToDecimal("0610574ef3af59da7fea70de8948a6350f61")
	ents, err := db.FindEntitiesByContent(context.Background(), oam.TLSCertificate, time.Time{}, 1, map[string]any{"serial_number": expectedDecimal})
	if err != nil || len(ents) != 1 {
		t.Errorf("expected 1 TLSCertificate with serial=%s; got %v / err %v", expectedDecimal, ents, err)
	}
}

// --- idempotency: the whole point of dedup -----------------------------

func TestProcessFindings_is_idempotent_across_runs(t *testing.T) {
	db := newTestDB(t)
	in := &FindingsInput{
		SourceDNSXPtr: []DNSXPtrRecord{
			{IP: "49.13.29.34", PtrName: "mail.bugshell.space"},
		},
		SourceNaabu: []NaabuRecord{
			{IP: "49.13.29.34", Port: 443, Protocol: "tcp"},
		},
		SourceTLSX: []TLSXRecord{
			{IP: "49.13.29.34", Port: 443,
				Cert: CertJSON{
					SerialNumberHex: "deadbeef",
					IssuerCN:        "Test CA",
					SubjectCN:       "mail.bugshell.space",
					NotBefore:       "2026-01-01T00:00:00Z",
					NotAfter:        "2027-01-01T00:00:00Z",
				}},
		},
	}

	// First run — everything's a create.
	first := emptySummary()
	if err := processFindings(context.Background(), db, in, time.Now(), first); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Second run — same input, should be all dedupes.
	// Sleep a hair so the second run's runStart is clearly after the first
	// run's CreatedAt timestamps (avoids the 100ms fudge factor in
	// isFreshlyCreated false-positively counting "created").
	time.Sleep(200 * time.Millisecond)
	second := emptySummary()
	if err := processFindings(context.Background(), db, in, time.Now(), second); err != nil {
		t.Fatalf("second run: %v", err)
	}

	// Headline assertion: nothing was created on the second run.
	if got := second.Summary["ipaddress"].Created; got != 0 {
		t.Errorf("second-run ipaddress.created = %d, want 0", got)
	}
	if got := second.Summary["fqdn"].Created; got != 0 {
		t.Errorf("second-run fqdn.created = %d, want 0", got)
	}
	if got := second.Summary["service"].Created; got != 0 {
		t.Errorf("second-run service.created = %d, want 0", got)
	}
	if got := second.Summary["tlscertificate"].Created; got != 0 {
		t.Errorf("second-run tlscertificate.created = %d, want 0", got)
	}

	// And the dedup count reflects ALL three source-record touches of the
	// IP on the second run: dnsx-ptr writes it once, naabu once, tlsx once.
	// Each touch on a row that was first created in a prior run counts as
	// deduped. (Within the run, only the first touch counts as the
	// dedup-against-prior; the rest are within-run repeats counted as
	// deduped too — same column.)
	if got := second.Summary["ipaddress"].Deduped; got != 3 {
		t.Errorf("second-run ipaddress.deduped = %d, want 3 (one per source touching the IP)", got)
	}
}

// --- cross-source dedup: naabu + tlsx must share Service row -----------

func TestProcessFindings_naabu_then_tlsx_share_service_row(t *testing.T) {
	// This is the headline test for Service.ID consistency: naabu writes a
	// service on (ip, tcp, 443), then tlsx writes one on the same triple
	// (tcp is hard-coded for tlsx). Both must land on the SAME service row.
	db := newTestDB(t)
	in := &FindingsInput{
		SourceNaabu: []NaabuRecord{
			{IP: "49.13.29.34", Port: 443, Protocol: "tcp"},
		},
		SourceTLSX: []TLSXRecord{
			{IP: "49.13.29.34", Port: 443,
				Cert: CertJSON{
					SerialNumberHex: "01",
					IssuerCN:        "Test CA",
					SubjectCN:       "x.example.com",
					NotBefore:       "2026-01-01T00:00:00Z",
					NotAfter:        "2027-01-01T00:00:00Z",
				}},
		},
	}
	sum := emptySummary()
	if err := processFindings(context.Background(), db, in, time.Now(), sum); err != nil {
		t.Fatalf("processFindings: %v", err)
	}

	// Exactly ONE Service row even though two sources wrote to it.
	expectedID := BuildService("49.13.29.34", "tcp", 443).ID
	ents, err := db.FindEntitiesByContent(context.Background(), oam.Service, time.Time{}, 10, map[string]any{"unique_id": expectedID})
	if err != nil {
		t.Fatalf("query Services: %v", err)
	}
	if len(ents) != 1 {
		t.Errorf("cross-source service dedup failed: want 1 row, got %d", len(ents))
	}

	// Sanity check via summary: one create, one dedupe in the service bucket.
	if got := sum.Summary["service"].Created + sum.Summary["service"].Deduped; got != 2 {
		t.Errorf("service writes total = %d, want 2 (naabu + tlsx)", got)
	}
	if sum.Summary["service"].Created != 1 {
		t.Errorf("service.created = %d, want exactly 1 (first source wins)", sum.Summary["service"].Created)
	}
	if sum.Summary["service"].Deduped != 1 {
		t.Errorf("service.deduped = %d, want exactly 1 (second source dedupes)", sum.Summary["service"].Deduped)
	}
}

// --- input casing variation does NOT cause duplicates ------------------

func TestProcessFindings_address_and_protocol_casing_dedupe(t *testing.T) {
	// User-provided sources may not have consistent casing. naabu emits
	// lowercase IPs; PTR can come back in any case. Two records that
	// describe the SAME triple in different casings must collapse to one
	// row each (ipaddress, service) — that's the whole point of the
	// normalizers in BuildService / NormalizeIP.
	db := newTestDB(t)
	in := &FindingsInput{
		SourceNaabu: []NaabuRecord{
			{IP: "10.0.0.5", Port: 443, Protocol: "TCP"},   // upper proto
			{IP: " 10.0.0.5 ", Port: 443, Protocol: "tcp"}, // padded ip
		},
	}
	sum := emptySummary()
	if err := processFindings(context.Background(), db, in, time.Now(), sum); err != nil {
		t.Fatalf("processFindings: %v", err)
	}

	if got := sum.Summary["service"].Created; got != 1 {
		t.Errorf("service.created = %d, want 1 (casing dedup failed)", got)
	}
	if got := sum.Summary["service"].Deduped; got != 1 {
		t.Errorf("service.deduped = %d, want 1 (second variant should dedupe)", got)
	}
}

// --- SourceProperty tags attach ----------------------------------------

func TestProcessFindings_tags_entities_with_source_property(t *testing.T) {
	db := newTestDB(t)
	in := &FindingsInput{SourceNaabu: []NaabuRecord{
		{IP: "1.2.3.4", Port: 80, Protocol: "tcp"},
	}}
	sum := emptySummary()
	if err := processFindings(context.Background(), db, in, time.Now(), sum); err != nil {
		t.Fatalf("processFindings: %v", err)
	}

	// Find the IPAddress entity and inspect its tags.
	ents, err := db.FindEntitiesByContent(context.Background(), oam.IPAddress, time.Time{}, 1, map[string]any{"address": "1.2.3.4"})
	if err != nil || len(ents) != 1 {
		t.Fatalf("expected 1 IP, got %v / err %v", ents, err)
	}
	tags, err := db.FindEntityTags(context.Background(), ents[0], time.Time{}, SourceNaabu)
	if err != nil {
		t.Fatalf("get tags: %v", err)
	}
	if len(tags) != 1 {
		t.Errorf("expected 1 source tag for SourceNaabu; got %d", len(tags))
	}
}

// --- bad-record handling ------------------------------------------------

func TestProcessFindings_invalid_ip_skips_record_without_aborting(t *testing.T) {
	// A garbage IP in source_naabu must NOT abort the whole pipeline; the
	// rest of the records should still land.
	db := newTestDB(t)
	in := &FindingsInput{SourceNaabu: []NaabuRecord{
		{IP: "999.999.999.999", Port: 443, Protocol: "tcp"}, // bad
		{IP: "1.2.3.4", Port: 443, Protocol: "tcp"},          // good
	}}
	sum := emptySummary()
	if err := processFindings(context.Background(), db, in, time.Now(), sum); err != nil {
		t.Fatalf("processFindings: %v", err)
	}
	// One service should have landed (the second, good record).
	if got := sum.Summary["service"].Created; got != 1 {
		t.Errorf("service.created = %d, want 1 (only good record persisted)", got)
	}
	// The failed edge is counted so operators can see something went wrong.
	if got := sum.Edges["port_relation"].Failed; got != 1 {
		t.Errorf("port_relation.failed = %d, want 1", got)
	}
}

func TestProcessFindings_invalid_cert_serial_skips_record(t *testing.T) {
	db := newTestDB(t)
	in := &FindingsInput{SourceTLSX: []TLSXRecord{
		{IP: "1.2.3.4", Port: 443, Cert: CertJSON{
			SerialNumberHex: "not-hex!", // garbage
			IssuerCN:        "X", SubjectCN: "Y",
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
		}},
		{IP: "1.2.3.5", Port: 443, Cert: CertJSON{
			SerialNumberHex: "ab",
			IssuerCN:        "X", SubjectCN: "Y",
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
		}},
	}}
	sum := emptySummary()
	if err := processFindings(context.Background(), db, in, time.Now(), sum); err != nil {
		t.Fatalf("processFindings: %v", err)
	}
	if got := sum.Summary["tlscertificate"].Created; got != 1 {
		t.Errorf("tlscertificate.created = %d, want 1 (only the good cert)", got)
	}
}
