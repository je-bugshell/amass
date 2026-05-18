// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package insert

import (
	"hash/fnv"
	"math/big"
	"strings"
	"testing"
)

// ----- NormalizeIP -------------------------------------------------------

func TestNormalizeIP_v4_canonical(t *testing.T) {
	addr, typ, err := NormalizeIP("192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.String() != "192.0.2.1" {
		t.Errorf("addr = %q, want 192.0.2.1", addr.String())
	}
	if typ != "IPv4" {
		t.Errorf("type = %q, want IPv4", typ)
	}
}

func TestNormalizeIP_v6_canonical(t *testing.T) {
	addr, typ, err := NormalizeIP("2001:db8::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.String() != "2001:db8::1" {
		t.Errorf("addr = %q, want 2001:db8::1", addr.String())
	}
	if typ != "IPv6" {
		t.Errorf("type = %q, want IPv6", typ)
	}
}

func TestNormalizeIP_strips_whitespace(t *testing.T) {
	addr, _, err := NormalizeIP("  10.0.0.1  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.String() != "10.0.0.1" {
		t.Errorf("addr = %q, want 10.0.0.1", addr.String())
	}
}

func TestNormalizeIP_rejects_unspecified_zero(t *testing.T) {
	if _, _, err := NormalizeIP("0.0.0.0"); err == nil {
		t.Error("expected rejection of 0.0.0.0")
	}
	if _, _, err := NormalizeIP("::"); err == nil {
		t.Error("expected rejection of ::")
	}
}

func TestNormalizeIP_rejects_garbage(t *testing.T) {
	for _, bad := range []string{"", "not-an-ip", "999.999.999.999", "1.2.3", "1.2.3.4.5"} {
		if _, _, err := NormalizeIP(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

// ----- NormalizeCIDR -----------------------------------------------------

func TestNormalizeCIDR_v4(t *testing.T) {
	prefix, typ, err := NormalizeCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prefix.String() != "10.0.0.0/24" {
		t.Errorf("prefix = %q, want 10.0.0.0/24", prefix.String())
	}
	if typ != "IPv4" {
		t.Errorf("type = %q, want IPv4", typ)
	}
}

func TestNormalizeCIDR_v6(t *testing.T) {
	prefix, typ, err := NormalizeCIDR("2001:db8::/64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prefix.String() != "2001:db8::/64" {
		t.Errorf("prefix = %q, want 2001:db8::/64", prefix.String())
	}
	if typ != "IPv6" {
		t.Errorf("type = %q, want IPv6", typ)
	}
}

func TestNormalizeCIDR_rejects_garbage(t *testing.T) {
	for _, bad := range []string{"", "10.0.0.0", "not/even/cidr", "10.0.0.0/33"} {
		if _, _, err := NormalizeCIDR(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

// ----- NormalizeFQDN -----------------------------------------------------

func TestNormalizeFQDN_lowercases(t *testing.T) {
	got, err := NormalizeFQDN("MAIL.Bugshell.Space")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "mail.bugshell.space" {
		t.Errorf("got %q, want mail.bugshell.space", got)
	}
}

func TestNormalizeFQDN_strips_trailing_dot(t *testing.T) {
	got, err := NormalizeFQDN("example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "example.com" {
		t.Errorf("got %q, want example.com", got)
	}
}

func TestNormalizeFQDN_accepts_wildcard(t *testing.T) {
	got, err := NormalizeFQDN("*.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "*.example.com" {
		t.Errorf("got %q, want *.example.com", got)
	}
}

func TestNormalizeFQDN_accepts_punycode(t *testing.T) {
	// Punycode-encoded IDN — the xn-- prefix is RFC-canonical.
	got, err := NormalizeFQDN("xn--bcher-kva.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "xn--bcher-kva.example.com" {
		t.Errorf("got %q, want xn--bcher-kva.example.com", got)
	}
}

func TestNormalizeFQDN_rejects_garbage(t *testing.T) {
	bad := []string{
		"",
		"  ",
		".",
		"singlelabel",                 // no dot
		"has spaces .com",             // whitespace
		"!badchar.example.com",        // punctuation
		"slash/in.path.example.com",   // slash
	}
	for _, b := range bad {
		if _, err := NormalizeFQDN(b); err == nil {
			t.Errorf("expected error for %q", b)
		}
	}
}

// ----- HexSerialToDecimal ------------------------------------------------

func TestHexSerialToDecimal_roundtrip_matches_amass(t *testing.T) {
	// This is the canonical bsapp form of a Let's Encrypt cert serial (no
	// leading zero byte, lowercase hex, no colons). amass stores the same
	// number as a decimal string via big.Int.String().
	hex := "610574ef3af59da7fea70de8948a6350f61"
	got, err := HexSerialToDecimal(hex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := new(big.Int)
	want.SetString(hex, 16)
	if got != want.String() {
		t.Errorf("got %q, want %q", got, want.String())
	}
}

func TestHexSerialToDecimal_tolerates_colon_hex(t *testing.T) {
	// Belt-and-suspenders: if bsapp ever sends colon-hex by accident, accept
	// it. This is defensive — bsapp's normalize_serial currently strips
	// colons before storage.
	got1, _ := HexSerialToDecimal("06:10:57:4e")
	got2, _ := HexSerialToDecimal("0610574e")
	if got1 != got2 {
		t.Errorf("colon-hex and no-colon should yield same decimal; got %q vs %q", got1, got2)
	}
}

func TestHexSerialToDecimal_tolerates_0x_prefix(t *testing.T) {
	got1, _ := HexSerialToDecimal("0x0610574e")
	got2, _ := HexSerialToDecimal("0610574e")
	if got1 != got2 {
		t.Errorf("0x-prefix and bare should yield same decimal; got %q vs %q", got1, got2)
	}
}

func TestHexSerialToDecimal_rejects_garbage(t *testing.T) {
	for _, bad := range []string{
		"",
		"  ",
		"not-hex",
		"GHIJ",       // non-hex letters
		"0x",         // prefix with no body
	} {
		if _, err := HexSerialToDecimal(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

// ----- BuildService ------------------------------------------------------

// fnv64aHex is a local copy of amass's support.Hash64Hex so the test can
// independently compute the expected ID without importing the support
// package's exported function (which BuildService itself uses).
func fnv64aHex(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	sum := h.Sum(nil)
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(sum)*2)
	for i, b := range sum {
		out[i*2] = hexChars[b>>4]
		out[i*2+1] = hexChars[b&0x0f]
	}
	return string(out)
}

func TestBuildService_id_matches_amass_formula(t *testing.T) {
	svc := BuildService("192.0.2.1", "tcp", 443)
	wantName := "192.0.2.1:tcp:443"
	wantID := wantName + "-" + fnv64aHex(wantName)
	if svc.ID != wantID {
		t.Errorf("Service.ID = %q\n  want %q", svc.ID, wantID)
	}
}

func TestBuildService_lowercases_protocol_and_address(t *testing.T) {
	// Same (logical) target sent in two casings must produce the same ID,
	// otherwise we'd double-write services every time a different source
	// reports the same host:port:proto with different case.
	a := BuildService("MAIL.bugshell.space", "TCP", 443)
	b := BuildService("mail.bugshell.space", "tcp", 443)
	if a.ID != b.ID {
		t.Errorf("expected identical ID for different casings\n  a=%q\n  b=%q", a.ID, b.ID)
	}
}

func TestBuildService_strips_whitespace(t *testing.T) {
	a := BuildService("  1.2.3.4  ", "  tcp  ", 80)
	b := BuildService("1.2.3.4", "tcp", 80)
	if a.ID != b.ID {
		t.Errorf("expected whitespace-stripped equality\n  a=%q\n  b=%q", a.ID, b.ID)
	}
}

func TestBuildService_port_changes_id(t *testing.T) {
	a := BuildService("1.2.3.4", "tcp", 80)
	b := BuildService("1.2.3.4", "tcp", 443)
	if a.ID == b.ID {
		t.Errorf("different ports must produce different IDs; got %q == %q", a.ID, b.ID)
	}
}

func TestBuildService_id_has_expected_shape(t *testing.T) {
	svc := BuildService("1.2.3.4", "tcp", 443)
	// Format: "address:proto:port-<16-hex>"
	parts := strings.Split(svc.ID, "-")
	if len(parts) < 2 {
		t.Fatalf("ID has no hash suffix: %q", svc.ID)
	}
	hash := parts[len(parts)-1]
	if len(hash) != 16 {
		t.Errorf("hash suffix length = %d, want 16", len(hash))
	}
	for _, c := range hash {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("non-hex char in hash suffix: %q", hash)
			break
		}
	}
}
