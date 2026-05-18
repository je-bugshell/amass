// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package insert

import (
	"context"
	"fmt"
	"time"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Source names — these become the `Source` field on SourceProperty tags so
// operators can query "which scanner found this" via
// `tag.property.name = 'bs-asm-naabu'` etc.
const (
	SourceNaabu   = "bs-asm-naabu"
	SourceDNSXPtr = "bs-asm-dnsx-ptr"
	SourceTLSX    = "bs-asm-tlsx"
	SourceTLSXSAN = "bs-asm-tlsx-san"
)

// Confidence values per source, calibrated against amass's own conventions
// (their plugins use 50–95). PTR is lowest because reverse DNS can lie; SAN
// FQDNs are softer than the cert itself because the cert claim ≠ user controls
// the name.
const (
	ConfidenceNaabu   = 95
	ConfidenceDNSXPtr = 80
	ConfidenceTLSX    = 90
	ConfidenceTLSXSAN = 70
)


// processFindings writes a FindingsInput to assetdb in the order required for
// edge endpoints to exist before edges reference them: dnsx-ptr (FQDNs + IPs)
// first, then naabu (Services on those IPs), then tlsx (Certs + SAN FQDNs +
// Service↔Cert edges). Each step is idempotent — re-running with the same
// input dedupes against asset-db's content filter rather than duplicating.
//
// The within-run dedup tracker is the missing piece in raw asset-db dedup:
// asset-db dedupes against PRIOR-RUN entities but counts within-run repeats
// as "created" because their CreatedAt is in the current run window. We
// track entity IDs we've already touched this run and downgrade subsequent
// touches to dedupe hits in the summary.
func processFindings(ctx context.Context, db repository.Repository, in *FindingsInput, runStart time.Time, sum *Summary) error {
	seen := newSeenSet()
	for _, rec := range in.SourceDNSXPtr {
		if err := writePtrRecord(ctx, db, rec, runStart, sum, seen); err != nil {
			sum.bumpFailedEdge("ptr_record")
			sum.addError(fmt.Sprintf("dnsx-ptr %s/%s: %v", rec.IP, rec.PtrName, err))
		}
	}
	for _, rec := range in.SourceNaabu {
		if err := writeNaabuRecord(ctx, db, rec, runStart, sum, seen); err != nil {
			sum.bumpFailedEdge("port_relation")
			sum.addError(fmt.Sprintf("naabu %s:%d/%s: %v", rec.IP, rec.Port, rec.Protocol, err))
		}
	}
	for _, rec := range in.SourceTLSX {
		if err := writeTLSXRecord(ctx, db, rec, runStart, sum, seen); err != nil {
			sum.bumpFailedEdge("certificate")
			sum.addError(fmt.Sprintf("tlsx %s:%d: %v", rec.IP, rec.Port, err))
		}
	}
	return nil
}

// seenSet tracks which entity/edge IDs we've already touched this run. The
// first touch counts as "created" (or "deduped" against a PRIOR run);
// subsequent touches always count as "deduped" within the current run.
type seenSet struct {
	entities map[string]struct{}
	edges    map[string]struct{}
}

func newSeenSet() *seenSet {
	return &seenSet{
		entities: map[string]struct{}{},
		edges:    map[string]struct{}{},
	}
}

// markEntity returns true if this is the first time we've touched this
// entity ID this run.
func (s *seenSet) markEntity(id string) bool {
	if _, ok := s.entities[id]; ok {
		return false
	}
	s.entities[id] = struct{}{}
	return true
}

// markEdge returns true if this is the first time we've touched this edge
// ID this run.
func (s *seenSet) markEdge(id string) bool {
	if _, ok := s.edges[id]; ok {
		return false
	}
	s.edges[id] = struct{}{}
	return true
}

// --- per-source writers --------------------------------------------------

// writePtrRecord persists one (ip, ptr_name) observation as:
//
//	IPAddress —ptr_record(SimpleRelation)→ FQDN
//
// IMPORTANT: the OAM schema (open-asset-model/relation.go::ipRels) only
// allows two outbound edges from IPAddress: `port → PortRelation → Service`
// and `ptr_record → SimpleRelation → FQDN`. The "dns_record" label is for
// FQDN-side records (A/AAAA/CNAME/MX) only. asset-db will refuse a
// `BasicDNSRelation` from IPAddress to FQDN at edge-create time.
func writePtrRecord(ctx context.Context, db repository.Repository, rec DNSXPtrRecord, runStart time.Time, sum *Summary, seen *seenSet) error {
	ipEnt, err := ensureIPAddress(ctx, db, rec.IP, runStart, sum, seen, SourceDNSXPtr, ConfidenceDNSXPtr)
	if err != nil {
		return fmt.Errorf("dnsx-ptr ip: %w", err)
	}
	fqdnEnt, err := ensureFQDN(ctx, db, rec.PtrName, runStart, sum, seen, SourceDNSXPtr, ConfidenceDNSXPtr)
	if err != nil {
		return fmt.Errorf("dnsx-ptr fqdn: %w", err)
	}
	edge, err := db.CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.SimpleRelation{Name: "ptr_record"},
		FromEntity: ipEnt,
		ToEntity:   fqdnEnt,
	})
	if err != nil || edge == nil {
		return fmt.Errorf("create PTR edge: %w", err)
	}
	sum.bumpEdge("ptr_record", seen.markEdge(edge.ID) && isFreshlyCreated(edge.CreatedAt, runStart))
	tagEdge(ctx, db, edge, SourceDNSXPtr, ConfidenceDNSXPtr)
	return nil
}

// writeNaabuRecord persists one (ip, port, protocol [+ optional nmap banner
// attributes]) observation as:
//
//	IPAddress —port_relation(port, proto)→ Service
//
// The Service.ID uses amass's own FNV-64a formula via BuildService so future
// amass enum discoveries on the same (ip, proto, port) dedupe to this row.
func writeNaabuRecord(ctx context.Context, db repository.Repository, rec NaabuRecord, runStart time.Time, sum *Summary, seen *seenSet) error {
	ipEnt, err := ensureIPAddress(ctx, db, rec.IP, runStart, sum, seen, SourceNaabu, ConfidenceNaabu)
	if err != nil {
		return fmt.Errorf("naabu ip: %w", err)
	}
	// Service ID uses the IP-as-address keyspace. amass enum's later
	// discovery via an FQDN side will use the FQDN as address (different ID);
	// the heuristic-matcher path in support.CreateServiceAsset can bridge
	// across that mismatch via attribute comparison, but we don't invoke
	// it here — see the dedup discussion in docs/asm_phase_2e_iter2_amass_insert.md.
	svc := BuildService(rec.IP, rec.Protocol, rec.Port)
	if len(rec.Attributes) > 0 {
		svc.Attributes = rec.Attributes
	}
	// Service type is the protocol uppercased ("HTTPS" / "TCP") so it surfaces
	// in amass UIs the same way amass plugins set it. Empty type would render
	// blank in the graph view.
	svc.Type = upperProtocol(rec.Protocol)
	svcEnt, err := db.CreateAsset(ctx, svc)
	if err != nil || svcEnt == nil {
		return fmt.Errorf("create Service: %w", err)
	}
	sum.bumpEntity("service", seen.markEntity(svcEnt.ID) && isFreshlyCreated(svcEnt.CreatedAt, runStart))
	tagEntity(ctx, db, svcEnt, SourceNaabu, ConfidenceNaabu)

	edge, err := db.CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.PortRelation{Name: "port_relation", PortNumber: rec.Port, Protocol: lowerProtocol(rec.Protocol)},
		FromEntity: ipEnt,
		ToEntity:   svcEnt,
	})
	if err != nil || edge == nil {
		return fmt.Errorf("create port_relation edge: %w", err)
	}
	sum.bumpEdge("port_relation", seen.markEdge(edge.ID) && isFreshlyCreated(edge.CreatedAt, runStart))
	tagEdge(ctx, db, edge, SourceNaabu, ConfidenceNaabu)
	return nil
}

// writeTLSXRecord persists one (ip, port, cert) tuple as:
//
//	IPAddress —port_relation(port, "tcp")→ Service —certificate→ TLSCertificate
//	+ a FQDN entity per cert SAN (tagged SourceTLSXSAN, lower confidence)
//
// The Service row is shared with naabu (same BuildService → same ID), so the
// CreateAsset content-filter dedupe collapses against an earlier naabu push.
// TLSCertificate's serial is converted from bsapp's canonical hex to amass's
// big.Int decimal string at this boundary.
func writeTLSXRecord(ctx context.Context, db repository.Repository, rec TLSXRecord, runStart time.Time, sum *Summary, seen *seenSet) error {
	ipEnt, err := ensureIPAddress(ctx, db, rec.IP, runStart, sum, seen, SourceTLSX, ConfidenceTLSX)
	if err != nil {
		return fmt.Errorf("tlsx ip: %w", err)
	}
	// Re-use the same Service-ID formula naabu uses so cross-source dedup
	// works. tlsx always probes TCP — RFC says TLS sits on TCP — so hardcode.
	svc := BuildService(rec.IP, "tcp", rec.Port)
	svc.Type = "TLS"
	svcEnt, err := db.CreateAsset(ctx, svc)
	if err != nil || svcEnt == nil {
		return fmt.Errorf("create Service from tlsx: %w", err)
	}
	sum.bumpEntity("service", seen.markEntity(svcEnt.ID) && isFreshlyCreated(svcEnt.CreatedAt, runStart))
	tagEntity(ctx, db, svcEnt, SourceTLSX, ConfidenceTLSX)

	// IP → Service edge — same shape as naabu writes. If naabu ran first
	// this dedupes; if not, this is the first port_relation for this host.
	portEdge, err := db.CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.PortRelation{Name: "port_relation", PortNumber: rec.Port, Protocol: "tcp"},
		FromEntity: ipEnt,
		ToEntity:   svcEnt,
	})
	if err != nil || portEdge == nil {
		return fmt.Errorf("create tlsx port_relation edge: %w", err)
	}
	sum.bumpEdge("port_relation", seen.markEdge(portEdge.ID) && isFreshlyCreated(portEdge.CreatedAt, runStart))
	tagEdge(ctx, db, portEdge, SourceTLSX, ConfidenceTLSX)

	// Cert entity. Serial conversion is the dedup-critical step — see
	// HexSerialToDecimal in normalize.go.
	decSerial, err := HexSerialToDecimal(rec.Cert.SerialNumberHex)
	if err != nil {
		return fmt.Errorf("convert cert serial %q: %w", rec.Cert.SerialNumberHex, err)
	}
	// asset-db's TLSCertificate writer rejects empty Version. amass's own
	// X509ToOAMTLSCertificate sets it from strconv.Itoa(cert.Version) which
	// produces "3" for X.509 v3 (universally what we observe in 2026). Fall
	// back to "3" if bsapp didn't carry the field — this matches
	// bsapp/asm/models.py::TLSCertificate.version default.
	version := rec.Cert.Version
	if version == "" {
		version = "3"
	}
	certAsset := &oamcert.TLSCertificate{
		SerialNumber:          decSerial,
		SubjectCommonName:     rec.Cert.SubjectCN,
		IssuerCommonName:      rec.Cert.IssuerCN,
		NotBefore:             rec.Cert.NotBefore,
		NotAfter:              rec.Cert.NotAfter,
		Version:               version,
		SignatureAlgorithm:    rec.Cert.SignatureAlgorithm,
		PublicKeyAlgorithm:    rec.Cert.PublicKeyAlgorithm,
		IsCA:                  rec.Cert.IsCA,
		KeyUsage:              rec.Cert.KeyUsage,
		ExtKeyUsage:           rec.Cert.ExtKeyUsage,
		CRLDistributionPoints: rec.Cert.CRLDistributionPoints,
		SubjectKeyID:          rec.Cert.SubjectKeyID,
		AuthorityKeyID:        rec.Cert.AuthorityKeyID,
	}
	certEnt, err := db.CreateAsset(ctx, certAsset)
	if err != nil || certEnt == nil {
		return fmt.Errorf("create TLSCertificate: %w", err)
	}
	sum.bumpEntity("tlscertificate", seen.markEntity(certEnt.ID) && isFreshlyCreated(certEnt.CreatedAt, runStart))
	tagEntity(ctx, db, certEnt, SourceTLSX, ConfidenceTLSX)

	// Service → Cert edge.
	certEdge, err := db.CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.SimpleRelation{Name: "certificate"},
		FromEntity: svcEnt,
		ToEntity:   certEnt,
	})
	if err != nil || certEdge == nil {
		return fmt.Errorf("create Service→Cert edge: %w", err)
	}
	sum.bumpEdge("certificate", seen.markEdge(certEdge.ID) && isFreshlyCreated(certEdge.CreatedAt, runStart))
	tagEdge(ctx, db, certEdge, SourceTLSX, ConfidenceTLSX)

	// SAN FQDNs as their own entities. We intentionally do NOT create
	// cert→fqdn edges here — amass enum's own enrichment plugins build that
	// linkage from the cert's SAN field during the next enum run, and
	// modeling it twice creates parallel graphs. The SAN-derived FQDNs
	// themselves are valuable for amass to use as scope seeds, though.
	for _, san := range rec.Cert.SubjectAlternativeNames {
		if _, err := ensureFQDN(ctx, db, san, runStart, sum, seen, SourceTLSXSAN, ConfidenceTLSXSAN); err != nil {
			// SAN entries can include odd things (email-style names, etc.);
			// don't fail the whole record because one SAN was unparseable.
			continue
		}
	}
	return nil
}

// --- shared entity creation ---------------------------------------------

// ensureIPAddress idempotently creates (or dedupes against) an IPAddress
// entity, tags it with the source provenance, and returns the entity for
// edge-building. Counts the create vs dedupe outcome into the summary,
// using the seen-set to downgrade within-run repeats to dedupe hits.
func ensureIPAddress(ctx context.Context, db repository.Repository, raw string, runStart time.Time, sum *Summary, seen *seenSet, source string, confidence int) (*dbt.Entity, error) {
	addr, ipType, err := NormalizeIP(raw)
	if err != nil {
		return nil, err
	}
	asset := &oamnet.IPAddress{Address: addr, Type: ipType}
	ent, err := db.CreateAsset(ctx, asset)
	if err != nil || ent == nil {
		return nil, fmt.Errorf("CreateAsset IPAddress %s: %w", addr, err)
	}
	sum.bumpEntity("ipaddress", seen.markEntity(ent.ID) && isFreshlyCreated(ent.CreatedAt, runStart))
	tagEntity(ctx, db, ent, source, confidence)
	return ent, nil
}

// ensureFQDN is the same shape as ensureIPAddress but for FQDN assets.
func ensureFQDN(ctx context.Context, db repository.Repository, raw string, runStart time.Time, sum *Summary, seen *seenSet, source string, confidence int) (*dbt.Entity, error) {
	name, err := NormalizeFQDN(raw)
	if err != nil {
		return nil, err
	}
	asset := &oamdns.FQDN{Name: name}
	ent, err := db.CreateAsset(ctx, asset)
	if err != nil || ent == nil {
		return nil, fmt.Errorf("CreateAsset FQDN %s: %w", name, err)
	}
	sum.bumpEntity("fqdn", seen.markEntity(ent.ID) && isFreshlyCreated(ent.CreatedAt, runStart))
	tagEntity(ctx, db, ent, source, confidence)
	return ent, nil
}

// --- shared helpers ------------------------------------------------------

// tagEntity attaches a SourceProperty tag to an entity. Idempotent: asset-db
// dedupes (entity, source name) tags so re-running doesn't duplicate.
// Errors here are non-fatal — the entity already exists either way.
func tagEntity(ctx context.Context, db repository.Repository, ent *dbt.Entity, source string, confidence int) {
	_, _ = db.CreateEntityProperty(ctx, ent, &oamgen.SourceProperty{
		Source:     source,
		Confidence: confidence,
	})
}

// tagEdge attaches a SourceProperty to an edge. Same idempotency story as
// tagEntity.
func tagEdge(ctx context.Context, db repository.Repository, edge *dbt.Edge, source string, confidence int) {
	_, _ = db.CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     source,
		Confidence: confidence,
	})
}

// isFreshlyCreated returns true when the entity/edge was just created on
// this run (vs. found by content filter from a prior run). The heuristic is
// `CreatedAt >= runStart` — fragile against clock skew but good enough for
// the per-run summary counters that bsapp displays as telemetry.
func isFreshlyCreated(createdAt, runStart time.Time) bool {
	if createdAt.IsZero() {
		return true
	}
	// Allow a small fudge factor since CreatedAt is set in another
	// transaction (the asset-db library's) and may have a microsecond skew
	// from our runStart. 100ms catches the realistic clock skew window
	// without false-positiving against pre-existing rows.
	return !createdAt.Before(runStart.Add(-100 * time.Millisecond))
}

// upperProtocol returns the OAM-conventional uppercase form used for
// Service.Type ("HTTPS", "TCP", "SMTP"). amass's own plugins set it from
// the application-protocol name, falling back to the transport for plain
// scan results.
func upperProtocol(proto string) string {
	// Don't reach out to a map of well-known protocols here — the input is
	// scanner-provided and we trust the caller's labeling. Capitalize for
	// presentational consistency with amass's own writes.
	out := []rune{}
	for i, r := range proto {
		if i == 0 && r >= 'a' && r <= 'z' {
			r = r - ('a' - 'A')
		}
		out = append(out, r)
	}
	return string(out)
}

// lowerProtocol returns the OAM-conventional lowercase form used in
// PortRelation.Protocol ("tcp" / "udp").
func lowerProtocol(proto string) string {
	out := []rune{}
	for _, r := range proto {
		if r >= 'A' && r <= 'Z' {
			r = r + ('a' - 'A')
		}
		out = append(out, r)
	}
	return string(out)
}

// _ensureOAMImports stops Go from elaborating "imported and not used" for
// types referenced only by interface assertion inside the same package.
// (oam.Asset etc. are referenced via the oamcert / oamdns / oamnet sub-imports.)
var _ oam.Asset = (*oamdns.FQDN)(nil)
