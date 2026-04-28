// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import "testing"

func TestPortScheme(t *testing.T) {
	// Both probeOnePort sites and the cert-attachment guard in `store`
	// rely on this exact mapping. If the predicate ever drifts, certs
	// from follow-redirect targets start landing on the http service
	// they redirected from — which is the bug this helper fixes.
	cases := []struct {
		port int
		want string
	}{
		{80, "http"},
		{8080, "http"},
		{443, "https"},
		{8443, "https"},
		{8000, "https"},
		{22, "https"},
	}
	for _, tc := range cases {
		got := portScheme(tc.port)
		if got != tc.want {
			t.Errorf("portScheme(%d) = %q, want %q", tc.port, got, tc.want)
		}
	}
}
