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
	"fmt"
	"strconv"
	"strings"
)

// CAATarget is a parsed CAA target (RFC 8659): <flags> <tag> <value>.
type CAATarget struct {
	flags uint8
	tag   string
	value string
}

// NewCAARecord parses a CAA target. The value may be quoted or bare; a bare
// value is taken verbatim to the end of the target, so parameters such as
// `letsencrypt.org;accounturi=...` and the `;` of an empty issuer survive
// (a zone-file lexer would read `;` as the start of a comment).
func NewCAARecord(target string) (*CAATarget, error) {
	rest := strings.TrimSpace(target)
	flagsField, rest, _ := strings.Cut(rest, " ")
	rest = strings.TrimSpace(rest)
	tag, rest, _ := strings.Cut(rest, " ")
	value := strings.TrimSpace(rest)

	flags, err := strconv.ParseUint(flagsField, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid CAA target %q: flags %q is not an integer between 0 and 255", target, flagsField)
	}
	if !isCAATag(tag) {
		return nil, fmt.Errorf("invalid CAA target %q: tag %q must be letters and digits (RFC 8659 section 4.1)", target, tag)
	}
	if value == "" {
		return nil, fmt.Errorf("invalid CAA target %q: value is empty, quote an empty value as \"\"", target)
	}
	if strings.HasPrefix(value, `"`) {
		value, err = unquoteCAAValue(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CAA target %q: %w", target, err)
		}
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return nil, fmt.Errorf("invalid CAA target %q: value contains a control character", target)
		}
	}

	return &CAATarget{flags: uint8(flags), tag: strings.ToLower(tag), value: value}, nil
}

// NewCAATargetFromFields builds a CAATarget from split fields, as returned by a provider API.
func NewCAATargetFromFields(flags uint8, tag, value string) *CAATarget {
	return &CAATarget{flags: flags, tag: strings.ToLower(tag), value: value}
}

func isCAATag(tag string) bool {
	if tag == "" {
		return false
	}
	for _, r := range tag {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// unquoteCAAValue strips the surrounding quotes and the \" and \\ escapes.
func unquoteCAAValue(quoted string) (string, error) {
	if len(quoted) < 2 || !strings.HasSuffix(quoted, `"`) {
		return "", fmt.Errorf("value %s has no closing quote", quoted)
	}
	inner := quoted[1 : len(quoted)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case c == '\\' && i+1 < len(inner):
			i++
			b.WriteByte(inner[i])
		case c == '\\':
			return "", fmt.Errorf("value %s ends in a lone backslash", quoted)
		case c == '"':
			return "", fmt.Errorf("value %s has an unescaped quote inside", quoted)
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// GetFlags returns the CAA flags field (RFC 8659 section 4.1).
func (c *CAATarget) GetFlags() uint8 { return c.flags }

// GetTag returns the CAA property tag, lowercased (tags are case-insensitive).
func (c *CAATarget) GetTag() string { return c.tag }

// GetValue returns the CAA property value without quotes.
func (c *CAATarget) GetValue() string { return c.value }

// String renders the target in canonical presentation format, with the value quoted.
func (c *CAATarget) String() string {
	value := strings.ReplaceAll(c.value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return fmt.Sprintf(`%d %s "%s"`, c.flags, c.tag, value)
}

func (t Targets) validateCAARecord() error {
	for _, target := range t {
		if _, err := NewCAARecord(target); err != nil {
			return err
		}
	}
	return nil
}
