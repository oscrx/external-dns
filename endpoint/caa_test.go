/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package endpoint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCAARecord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		flags  uint8
		tag    string
		value  string
		want   string
	}{
		{"quoted", `0 issue "letsencrypt.org"`, 0, "issue", "letsencrypt.org", `0 issue "letsencrypt.org"`},
		{"bare", "0 issue letsencrypt.org", 0, "issue", "letsencrypt.org", `0 issue "letsencrypt.org"`},
		{
			"bare with parameters keeps everything after the semicolon",
			"0 issuewild letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1",
			0, "issuewild", "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1",
			`0 issuewild "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1"`,
		},
		{"bare empty issuer", "0 issuemail ;", 0, "issuemail", ";", `0 issuemail ";"`},
		{"quoted empty value", `0 issue ""`, 0, "issue", "", `0 issue ""`},
		{"critical flag and uppercase tag", `128 IODEF "mailto:caa@example.com"`, 128, "iodef", "mailto:caa@example.com", `128 iodef "mailto:caa@example.com"`},
		{"extra spacing", "  0   issue   \"letsencrypt.org\"  ", 0, "issue", "letsencrypt.org", `0 issue "letsencrypt.org"`},
		{"escaped quote round-trips", `0 tbs "a\"b\\c"`, 0, "tbs", `a"b\c`, `0 tbs "a\"b\\c"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			caa, err := NewCAARecord(tc.target)
			require.NoError(t, err)
			assert.Equal(t, tc.flags, caa.GetFlags())
			assert.Equal(t, tc.tag, caa.GetTag())
			assert.Equal(t, tc.value, caa.GetValue())
			assert.Equal(t, tc.want, caa.String())

			again, err := NewCAARecord(caa.String())
			require.NoError(t, err)
			assert.Equal(t, caa, again, "the canonical form must parse back to the same target")
		})
	}
}

func TestNewCAARecordRejects(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"",
		"issue letsencrypt.org",
		"256 issue letsencrypt.org",
		"-1 issue letsencrypt.org",
		"0 issue",
		"0 is-sue letsencrypt.org",
		`0 issue "letsencrypt.org`,
		`0 issue "lets"encrypt.org"`,
		"0 issue \"a\tb\"",
	} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			_, err := NewCAARecord(target)
			assert.Error(t, err)
		})
	}
}

func TestCAAEndpointValidation(t *testing.T) {
	t.Parallel()

	good := NewEndpoint("example.com", RecordTypeCAA, `0 issue "letsencrypt.org"`, "0 issuemail ;")
	require.NoError(t, good.Validate())
	assert.Equal(t, Targets{`0 issue "letsencrypt.org"`, "0 issuemail ;"}, good.Targets, "targets must not be trimmed")

	bad := NewEndpoint("example.com", RecordTypeCAA, "issue letsencrypt.org")
	assert.Error(t, bad.Validate())
}
