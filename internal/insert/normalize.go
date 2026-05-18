// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package insert implements the `amass insert` subcommand: a one-shot,
// idempotent ingester that lets external scanners (bs-asm/naabu/dnsx-ptr/tlsx)
// pre-populate the per-org assetdb with OAM entities + edges using exactly
// the same Go APIs amass's own plugins use.
//
// THIS FILE is the dedup-critical primitive layer. Every value we send to
// asset-db must match what amass would have written if it had discovered
// the same asset. There are four places that fidelity matters:
//
//  1. Service.ID  — opaque FNV-64a hash; see [BuildServiceID].
//  2. IPAddress.Address — netip.Addr canonical string; see [NormalizeIP].
//  3. Netblock.CIDR — netip.Prefix canonical string; see [NormalizeCIDR].
//  4. TLSCertificate.SerialNumber — big.Int decimal string; see [HexSerialToDecimal].
//
// All four are independently tested in normalize_test.go.
package insert

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strings"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// NormalizeIP parses any string the JSON payload might carry into netip.Addr
// canonical form. Returns (parsed addr, "IPv4"|"IPv6" type tag, error).
//
// The Type tag is what OAM stores on IPAddress entities; asset-db queries it
// in addition to address for the content filter, so passing the wrong tag
// would mis-dedupe.
func NormalizeIP(raw string) (netip.Addr, string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("invalid IP %q: %w", raw, err)
	}
	// Reject zero/unspec addresses early — they don't represent real hosts and
	// would silently dedupe against any future zero-addr write.
	if addr.IsUnspecified() {
		return netip.Addr{}, "", fmt.Errorf("refusing unspecified address %q", raw)
	}
	if addr.Is4() {
		return addr, "IPv4", nil
	}
	return addr, "IPv6", nil
}

// NormalizeCIDR parses a CIDR string into netip.Prefix canonical form.
// Returns the prefix and the "IPv4"|"IPv6" type tag.
func NormalizeCIDR(raw string) (netip.Prefix, string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, "", fmt.Errorf("invalid CIDR %q: %w", raw, err)
	}
	if prefix.Addr().Is4() {
		return prefix, "IPv4", nil
	}
	return prefix, "IPv6", nil
}

// NormalizeFQDN lowercases, trims, and strips a single trailing dot.
//
// We don't IDNA-encode or punycode here — amass enum stores names exactly as
// it observed them in DNS responses, which is typically already lowercase ASCII
// for our targets. If a UTF-8 punycode-encoded name surfaces, both sides will
// keep their xn-- form so dedup still works.
func NormalizeFQDN(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty FQDN")
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", errors.New("FQDN was only a trailing dot")
	}
	// Cheap structural validation — anything wilder than this would cause amass's
	// own DNS plugins to reject the name too, so we mirror their leniency: must
	// have at least one '.' and only RFC 1035-ish characters plus underscore +
	// wildcard.
	if !strings.ContainsRune(s, '.') {
		return "", fmt.Errorf("FQDN %q has no dot — single-label names not supported", raw)
	}
	lower := strings.ToLower(s)
	for _, c := range lower {
		switch {
		case c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '.', c == '-', c == '_', c == '*':
			// ok
		default:
			return "", fmt.Errorf("FQDN %q contains invalid character %q", raw, c)
		}
	}
	return lower, nil
}

// HexSerialToDecimal converts a TLS certificate serial number from bsapp's
// canonical lowercase-hex form (with leading zeros stripped) into the
// decimal big.Int string form that amass stores in
// TLSCertificate.SerialNumber.
//
// THIS conversion is what keeps cert dedup consistent across sources:
// amass's X509ToOAMTLSCertificate uses `cert.SerialNumber.String()` which is
// always base-10. If we pass hex to amass, the asset-db content filter
// `serial_number = ?` will never match, and we'll double-write every cert.
//
// See engine/plugins/support/normalization.go:227 for amass's encoding.
func HexSerialToDecimal(hex string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(hex))
	if s == "" {
		return "", errors.New("empty serial")
	}
	// Strip optional 0x prefix and any colons in case bsapp ever changes its
	// canonical form back to colon-hex. We want to be tolerant on input even
	// though we ourselves emit no-colon lowercase.
	s = strings.TrimPrefix(s, "0x")
	s = strings.ReplaceAll(s, ":", "")
	if s == "" {
		return "", errors.New("serial was empty after stripping prefix/colons")
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			// ok
		default:
			return "", fmt.Errorf("serial %q contains non-hex character %q", hex, c)
		}
	}
	n := new(big.Int)
	if _, ok := n.SetString(s, 16); !ok {
		return "", fmt.Errorf("serial %q failed big.Int parse", hex)
	}
	return n.String(), nil
}

// BuildService constructs the OAM Service for an (address, protocol, port)
// triple using amass's OWN identity helper from the support package. We do
// NOT hand-roll the FNV-64a hash — calling support.ServiceWithIdentifier
// guarantees the ID stays in lockstep with whatever amass plugins would emit
// for the same triple, including any future changes to the formula.
//
// Address is normalized to lowercase. Protocol is normalized to lowercase
// (amass already lowercases inside ServiceWithIdentifier but we mirror it
// here too so the canonical name we log matches the stored ID).
func BuildService(address, protocol string, port int) *oamplat.Service {
	addr := strings.ToLower(strings.TrimSpace(address))
	proto := strings.ToLower(strings.TrimSpace(protocol))
	return support.ServiceWithIdentifier(addr, proto, port)
}
