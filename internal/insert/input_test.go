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

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "in.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	return p
}

func TestLoadInput_decodes_all_three_sources(t *testing.T) {
	body := `{
		"source_naabu": [
			{"ip": "1.2.3.4", "port": 443, "protocol": "tcp",
			 "attributes": {"Server": ["nginx"]}}
		],
		"source_dnsx_ptr": [
			{"ip": "1.2.3.4", "ptr_name": "mail.example.com"}
		],
		"source_tlsx": [
			{"ip": "1.2.3.4", "port": 443,
			 "cert": {"serial_number_hex": "deadbeef",
			          "issuer_cn": "Test CA", "subject_cn": "mail.example.com",
			          "not_before": "2026-01-01T00:00:00Z",
			          "not_after":  "2027-01-01T00:00:00Z"}}
		]
	}`
	in, err := LoadInput(writeTemp(t, body))
	if err != nil {
		t.Fatalf("LoadInput: %v", err)
	}
	if len(in.SourceNaabu) != 1 || in.SourceNaabu[0].Port != 443 {
		t.Errorf("naabu: %+v", in.SourceNaabu)
	}
	if len(in.SourceDNSXPtr) != 1 || in.SourceDNSXPtr[0].PtrName != "mail.example.com" {
		t.Errorf("dnsx_ptr: %+v", in.SourceDNSXPtr)
	}
	if len(in.SourceTLSX) != 1 || in.SourceTLSX[0].Cert.SerialNumberHex != "deadbeef" {
		t.Errorf("tlsx: %+v", in.SourceTLSX)
	}
}

func TestLoadInput_accepts_empty_object_as_no_findings(t *testing.T) {
	in, err := LoadInput(writeTemp(t, "{}"))
	if err != nil {
		t.Fatalf("LoadInput: %v", err)
	}
	if len(in.SourceNaabu) != 0 || len(in.SourceDNSXPtr) != 0 || len(in.SourceTLSX) != 0 {
		t.Errorf("expected zero records; got %+v", in)
	}
}

func TestLoadInput_accepts_empty_file_as_no_findings(t *testing.T) {
	// Treat zero bytes the same as "{}" — bsapp may shell out unconditionally
	// and the simplest payload for "nothing to push" is an empty file.
	in, err := LoadInput(writeTemp(t, ""))
	if err != nil {
		t.Fatalf("LoadInput: %v", err)
	}
	if in == nil {
		t.Fatal("expected non-nil input")
	}
}

func TestLoadInput_rejects_naabu_missing_fields(t *testing.T) {
	cases := map[string]string{
		"no ip":     `{"source_naabu": [{"port": 80, "protocol": "tcp"}]}`,
		"port zero": `{"source_naabu": [{"ip": "1.2.3.4", "port": 0, "protocol": "tcp"}]}`,
		"no proto":  `{"source_naabu": [{"ip": "1.2.3.4", "port": 80}]}`,
		"negative":  `{"source_naabu": [{"ip": "1.2.3.4", "port": -1, "protocol": "tcp"}]}`,
	}
	for name, body := range cases {
		_, err := LoadInput(writeTemp(t, body))
		if err == nil {
			t.Errorf("%s: expected error", name)
		} else if !strings.Contains(err.Error(), "source_naabu") {
			t.Errorf("%s: error should mention source_naabu, got: %v", name, err)
		}
	}
}

func TestLoadInput_rejects_dnsx_ptr_missing_fields(t *testing.T) {
	cases := map[string]string{
		"no ip":   `{"source_dnsx_ptr": [{"ptr_name": "x.example"}]}`,
		"no name": `{"source_dnsx_ptr": [{"ip": "1.2.3.4"}]}`,
	}
	for name, body := range cases {
		_, err := LoadInput(writeTemp(t, body))
		if err == nil {
			t.Errorf("%s: expected error", name)
		} else if !strings.Contains(err.Error(), "source_dnsx_ptr") {
			t.Errorf("%s: error should mention source_dnsx_ptr, got: %v", name, err)
		}
	}
}

func TestLoadInput_rejects_tlsx_missing_fields(t *testing.T) {
	cases := map[string]string{
		"no ip":     `{"source_tlsx": [{"port": 443, "cert": {"serial_number_hex": "ab"}}]}`,
		"port zero": `{"source_tlsx": [{"ip": "1.2.3.4", "port": 0, "cert": {"serial_number_hex": "ab"}}]}`,
		"no serial": `{"source_tlsx": [{"ip": "1.2.3.4", "port": 443, "cert": {"issuer_cn": "x"}}]}`,
	}
	for name, body := range cases {
		_, err := LoadInput(writeTemp(t, body))
		if err == nil {
			t.Errorf("%s: expected error", name)
		} else if !strings.Contains(err.Error(), "source_tlsx") {
			t.Errorf("%s: error should mention source_tlsx, got: %v", name, err)
		}
	}
}

func TestLoadInput_rejects_garbage_json(t *testing.T) {
	if _, err := LoadInput(writeTemp(t, "not-json")); err == nil {
		t.Error("expected error on malformed JSON")
	}
}

func TestLoadInput_rejects_missing_path(t *testing.T) {
	if _, err := LoadInput(""); err == nil {
		t.Error("expected error on empty path")
	}
}

func TestLoadInput_errors_on_unreadable_path(t *testing.T) {
	if _, err := LoadInput("/nonexistent/path/to/findings.json"); err == nil {
		t.Error("expected error on missing file")
	}
}

// JSONPort accepts int, float, and string at the wire boundary. naabu's own
// JSONL emits int but bsapp / tlsx hand us strings + the occasional 80.0 float.
func TestJSONPort_unmarshal_accepts_int_float_string(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"int", `80`, 80},
		{"string", `"443"`, 443},
		{"whole-number float", `8443.0`, 8443},
		{"int-65535-max", `65535`, 65535},
		{"string-1", `"1"`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p JSONPort
			if err := json.Unmarshal([]byte(tc.in), &p); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if int(p) != tc.want {
				t.Errorf("got %d, want %d", int(p), tc.want)
			}
		})
	}
}

func TestJSONPort_unmarshal_rejects_invalid_shapes(t *testing.T) {
	// Fractional floats lose information when coerced — reject rather than
	// silently truncate to int. Bools, arrays, and garbage strings also rejected.
	tests := []string{
		`80.5`,           // fractional
		`true`,           // bool
		`null`,           // null
		`[80]`,           // array
		`"not-a-number"`, // string that doesn't parse
		`""`,             // empty string
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			var p JSONPort
			if err := json.Unmarshal([]byte(in), &p); err == nil {
				t.Errorf("expected error for %s, got JSONPort=%d", in, int(p))
			}
		})
	}
}

func TestLoadInput_naabu_port_as_string_is_accepted(t *testing.T) {
	// bsapp's _push_findings_to_amass and tlsx_collect_data may hand us
	// `"port": "443"` as a string; the lenient JSONPort decodes it cleanly.
	tmp := t.TempDir() + "/in.json"
	body := `{"source_naabu": [{"ip": "192.0.2.1", "port": "443", "protocol": "tcp"}]}`
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := LoadInput(tmp)
	if err != nil {
		t.Fatalf("port-as-string should now decode cleanly: %v", err)
	}
	if got := int(in.SourceNaabu[0].Port); got != 443 {
		t.Errorf("port = %d, want 443", got)
	}
}

func TestLoadInput_tlsx_port_as_string_is_accepted(t *testing.T) {
	// Same regression on the tlsx side — tlsx's native JSONL has port as a
	// string and bsapp's `_tls_records_from_tlsx_content` round-trips that
	// shape unchanged, so the Go decoder must tolerate it too.
	tmp := t.TempDir() + "/in.json"
	body := `{"source_tlsx": [{"ip": "192.0.2.1", "port": "443", "cert": {"serial_number_hex": "abcd", "issuer_cn": "x", "subject_cn": "y", "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}]}`
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := LoadInput(tmp)
	if err != nil {
		t.Fatalf("tlsx port-as-string should decode cleanly: %v", err)
	}
	if got := int(in.SourceTLSX[0].Port); got != 443 {
		t.Errorf("port = %d, want 443", got)
	}
}
