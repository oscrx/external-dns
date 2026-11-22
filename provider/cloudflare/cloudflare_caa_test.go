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

package cloudflare

import (
	"encoding/json"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/external-dns/endpoint"
)

const (
	caaName   = "example.com"
	caaValue  = "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1"
	caaTarget = `0 issue "` + caaValue + `"`
)

func caaRecordResponse() dns.RecordResponse {
	return dns.RecordResponse{
		Name:    caaName,
		TTL:     300,
		Type:    dns.RecordResponseTypeCAA,
		Content: caaTarget,
	}
}

// The API rejects CAA sent as content ("flags is a required data field"), so writes must send structured data.
func assertCAADataOnly(t *testing.T, body any) {
	t.Helper()

	raw, err := json.Marshal(body)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))

	assert.NotContains(t, decoded, "content", "CAA writes must not send a content field")

	data, ok := decoded["data"].(map[string]any)
	require.True(t, ok, "CAA writes must send a data object, got: %s", raw)
	assert.InDelta(t, 0, data["flags"], 0)
	assert.Equal(t, "issue", data["tag"])
	assert.Equal(t, caaValue, data["value"], "the value must be sent without quotes")
	assert.Equal(t, "CAA", decoded["type"])
	assert.Equal(t, caaName, decoded["name"])
}

func TestGetCreateDNSRecordParamCAAUsesData(t *testing.T) {
	t.Parallel()

	params, err := getCreateDNSRecordParam("zone-1", &cloudFlareChange{
		Action:         cloudFlareCreate,
		ResourceRecord: caaRecordResponse(),
	})
	require.NoError(t, err)
	assert.Equal(t, "zone-1", params.ZoneID.Value)

	body, ok := params.Body.(dns.CAARecordParam)
	require.True(t, ok, "expected a CAARecordParam body, got %T", params.Body)
	assertCAADataOnly(t, body)
}

func TestGetUpdateDNSRecordParamCAAUsesData(t *testing.T) {
	t.Parallel()

	params, err := getUpdateDNSRecordParam("zone-1", cloudFlareChange{
		Action:         cloudFlareUpdate,
		ResourceRecord: caaRecordResponse(),
	})
	require.NoError(t, err)

	body, ok := params.Body.(dns.CAARecordParam)
	require.True(t, ok, "expected a CAARecordParam body, got %T", params.Body)
	assertCAADataOnly(t, body)
}

func TestBuildBatchParamsCAAUseData(t *testing.T) {
	t.Parallel()

	post, ok := buildBatchPostParam(caaRecordResponse())
	require.True(t, ok)
	body, isCAA := post.(dns.CAARecordParam)
	require.True(t, isCAA, "expected a CAARecordParam, got %T", post)
	assertCAADataOnly(t, body)

	putParam, ok := buildBatchPutParam("record-id", caaRecordResponse())
	require.True(t, ok)
	put, isCAA := putParam.(dns.BatchPutCAARecordParam)
	require.True(t, isCAA, "expected a BatchPutCAARecordParam, got %T", putParam)
	assert.Equal(t, "record-id", put.ID.Value)
	assertCAADataOnly(t, put.CAARecordParam)
}

func TestMalformedCAATargetIsRejected(t *testing.T) {
	t.Parallel()

	bad := dns.RecordResponse{Name: caaName, TTL: 300, Type: dns.RecordResponseTypeCAA, Content: "issue letsencrypt.org"}

	_, err := getCreateDNSRecordParam("zone-1", &cloudFlareChange{ResourceRecord: bad})
	require.Error(t, err)

	_, err = getUpdateDNSRecordParam("zone-1", cloudFlareChange{ResourceRecord: bad})
	require.Error(t, err)

	_, ok := buildBatchPostParam(bad)
	assert.False(t, ok, "a malformed target must not produce a batch post")

	_, ok = buildBatchPutParam("record-id", bad)
	assert.False(t, ok, "a malformed target must not produce a batch put")

	p := &CloudFlareProvider{}
	ep := endpoint.NewEndpoint(caaName, endpoint.RecordTypeCAA, "issue letsencrypt.org")
	_, err = p.newCloudFlareChange(cloudFlareCreate, ep, ep.Targets[0], nil)
	require.Error(t, err)
}

// Without normalisation a record never compares equal to its desired target and every sync updates.
func TestEndpointTargetFromCloudflareRecordNormalisesCAA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		record dns.RecordResponse
		want   string
	}{
		{"content", dns.RecordResponse{Type: dns.RecordResponseTypeCAA, Content: caaTarget}, caaTarget},
		{"content with an empty issuer", dns.RecordResponse{Type: dns.RecordResponseTypeCAA, Content: `0 issuemail ";"`}, `0 issuemail ";"`},
		{
			"structured data wins over content",
			dns.RecordResponse{Type: dns.RecordResponseTypeCAA, Content: "stale", Data: dns.CAARecordData{Flags: 128, Tag: "ISSUEWILD", Value: "ca.example"}},
			`128 issuewild "ca.example"`,
		},
		{"unparseable is passed through", dns.RecordResponse{Type: dns.RecordResponseTypeCAA, Content: "garbage"}, "garbage"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, endpointTargetFromCloudflareRecord(tc.record))
		})
	}
}

// A bare value in the source must be rewritten to the read-back form, else the plan never settles.
func TestAdjustEndpointsCanonicalisesCAA(t *testing.T) {
	t.Parallel()

	p := &CloudFlareProvider{}
	eps, err := p.AdjustEndpoints([]*endpoint.Endpoint{
		endpoint.NewEndpoint(caaName, endpoint.RecordTypeCAA,
			"0 ISSUE "+caaValue,
			"0 issuemail ;",
			`0 iodef "mailto:caa@example.com"`,
			"not a caa target",
		),
	})
	require.NoError(t, err)
	require.Len(t, eps, 1)
	assert.Equal(t, endpoint.Targets{
		caaTarget,
		`0 issuemail ";"`,
		`0 iodef "mailto:caa@example.com"`,
		"not a caa target",
	}, eps[0].Targets)
}

func TestCAAIsReadableAndNotProxied(t *testing.T) {
	t.Parallel()

	p := &CloudFlareProvider{}
	assert.True(t, p.SupportedAdditionalRecordTypes(endpoint.RecordTypeCAA),
		"CAA must be readable or the planner never sees existing records")

	assert.True(t, recordTypeProxyNotSupported.Has(endpoint.RecordTypeCAA))
	ep := endpoint.NewEndpoint(caaName, endpoint.RecordTypeCAA, caaTarget)
	assert.False(t, shouldBeProxied(ep, true))
}
