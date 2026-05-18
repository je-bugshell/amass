// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package insert

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// FindingsInput is the JSON shape bs-asm writes to disk and hands us via the
// `-input` flag. Each source's array is independently optional; we tolerate
// missing keys for forward/backward compatibility with bsapp's payload
// builder.
//
// The decoder is strict on per-record fields though — a record missing its
// IP or port would silently dedupe into nothing useful, so we reject those
// at decode time and surface a clear error.
type FindingsInput struct {
	SourceNaabu   []NaabuRecord   `json:"source_naabu,omitempty"`
	SourceDNSXPtr []DNSXPtrRecord `json:"source_dnsx_ptr,omitempty"`
	SourceTLSX    []TLSXRecord    `json:"source_tlsx,omitempty"`
}

// NaabuRecord = one open (ip, port, protocol) discovery from naabu.
// Attributes are the optional service-banner key/value pairs from nmap
// (which naabu calls via -nmap-cli). They feed into the OAM Service
// attributes map so amass's CreateServiceAsset heuristic can dedupe against
// future enum-discovered services on the same host:port.
type NaabuRecord struct {
	IP         string              `json:"ip"`
	Port       int                 `json:"port"`
	Protocol   string              `json:"protocol"`
	Attributes map[string][]string `json:"attributes,omitempty"`
}

// DNSXPtrRecord = one reverse-DNS observation (ip → name). bsapp has already
// filtered generic/provider names via is_generic_ptr before sending; we
// trust that filter and don't re-apply it here.
type DNSXPtrRecord struct {
	IP      string `json:"ip"`
	PtrName string `json:"ptr_name"`
}

// TLSXRecord = a TLS handshake outcome from tlsx. The cert is the canonical
// payload — we'll persist a TLSCertificate entity + a Service edge to it.
// SNI (if non-empty) is the hostname tlsx sent in the ClientHello; we don't
// currently persist it as its own entity because tlsx's bare-IP probe means
// the SNI is just a hint to coax the cert out.
type TLSXRecord struct {
	IP   string   `json:"ip"`
	Port int      `json:"port"`
	SNI  string   `json:"sni,omitempty"`
	Cert CertJSON `json:"cert"`
}

// CertJSON mirrors the bsapp-side TLSCertificate row, with one critical
// rename: bsapp stores `serial_number` as canonical hex (lowercase, no
// leading zero); we ship it as `serial_number_hex` here to make the
// units-of-measurement explicit at the wire boundary.
type CertJSON struct {
	SerialNumberHex          string   `json:"serial_number_hex"`
	IssuerCN                 string   `json:"issuer_cn"`
	SubjectCN                string   `json:"subject_cn"`
	NotBefore                string   `json:"not_before"`
	NotAfter                 string   `json:"not_after"`
	SubjectAlternativeNames  []string `json:"subject_alternative_names,omitempty"`
	FingerprintSHA256        string   `json:"fingerprint_sha256,omitempty"`
	Version                  string   `json:"version,omitempty"`
	SignatureAlgorithm       string   `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm       string   `json:"public_key_algorithm,omitempty"`
	KeyUsage                 []string `json:"key_usage,omitempty"`
	ExtKeyUsage              []string `json:"ext_key_usage,omitempty"`
	IsCA                     bool     `json:"is_ca,omitempty"`
	CRLDistributionPoints    []string `json:"crl_distribution_points,omitempty"`
	SubjectKeyID             string   `json:"subject_key_id,omitempty"`
	AuthorityKeyID           string   `json:"authority_key_id,omitempty"`
}

// LoadInput reads the findings JSON from a path (`-` for stdin). Empty input
// is a valid case — bsapp may invoke us when only some sources had data.
// We tolerate at decode time and downstream code skips empty source slices.
func LoadInput(path string) (*FindingsInput, error) {
	var data []byte
	var err error
	if path == "" {
		return nil, errors.New("input path is empty")
	}
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read input %q: %w", path, err)
	}
	if len(data) == 0 {
		// Empty file == no findings. Caller will write a stub summary.
		return &FindingsInput{}, nil
	}
	var in FindingsInput
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, fmt.Errorf("parse input %q: %w", path, err)
	}
	if err := validate(&in); err != nil {
		return nil, err
	}
	return &in, nil
}

// validate runs cheap per-record checks. We want failures HERE, not three
// levels deep inside CreateAsset where the error message wouldn't pin down
// which record was malformed.
func validate(in *FindingsInput) error {
	for i, r := range in.SourceNaabu {
		if r.IP == "" || r.Port <= 0 || r.Protocol == "" {
			return fmt.Errorf("source_naabu[%d]: requires ip + port>0 + protocol; got %+v", i, r)
		}
	}
	for i, r := range in.SourceDNSXPtr {
		if r.IP == "" || r.PtrName == "" {
			return fmt.Errorf("source_dnsx_ptr[%d]: requires ip + ptr_name; got %+v", i, r)
		}
	}
	for i, r := range in.SourceTLSX {
		if r.IP == "" || r.Port <= 0 {
			return fmt.Errorf("source_tlsx[%d]: requires ip + port>0; got %+v", i, r)
		}
		if r.Cert.SerialNumberHex == "" {
			return fmt.Errorf("source_tlsx[%d]: cert.serial_number_hex required; got %+v", i, r.Cert)
		}
	}
	return nil
}
