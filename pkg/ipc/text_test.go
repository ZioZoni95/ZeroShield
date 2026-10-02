// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package ipc

import "testing"

func TestSafeText(t *testing.T) {
	cases := map[string]string{
		"ssh":                    "ssh",
		"/usr/bin/città":         "/usr/bin/città",
		"\x1b]52;c;ZXZpbA==\x07": `\x1b]52;c;ZXZpbA==\x07`,
		"a\nb":                   `a\x0ab`,
		"bad\xffutf8":            `bad\xffutf8`,
		"rtl\u202eexe":           `rtl\u{202e}exe`,
	}
	for in, want := range cases {
		if got := SafeText(in); got != want {
			t.Errorf("SafeText(%q) = %q, atteso %q", in, got, want)
		}
	}
}
