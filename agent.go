package samesame

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dunglas/httpsfv"
)

// Signature-Agent member types (protocol draft Section 5.5).
const (
	AgentTypeDirectory = "directory"
	AgentTypeJWKSURI   = "jwks_uri"
	AgentTypeCIMD      = "cimd"
)

var (
	ErrMalformedSignatureAgent = errors.New("samesame: malformed Signature-Agent header")
	ErrUnsupportedAgentType    = errors.New("samesame: unsupported Signature-Agent member type")
	ErrInvalidAgentMember      = errors.New("samesame: invalid Signature-Agent member")
)

// AgentMember is one member of a Signature-Agent header.
type AgentMember struct {
	// Key is the dictionary member key. It is empty for the legacy string
	// form of the header.
	Key string

	// Type is the member's type parameter, AgentTypeDirectory when absent.
	Type string

	// Value is the URI string exactly as sent.
	Value string

	// Identifier is the URL a verifier resolves for this member. It is nil
	// when the member must be ignored; Err then says why.
	Identifier *url.URL

	Err error
}

// SignatureAgent is a parsed Signature-Agent header.
type SignatureAgent struct {
	// Legacy is true when the header used the deprecated single String Item
	// form. Its one member then has an empty Key.
	Legacy bool

	Members map[string]AgentMember
}

// ParseSignatureAgent parses the Signature-Agent header in h. It returns nil
// and no error when the header is absent. Members that are well-formed
// structured fields but unusable (wrong scheme, not an origin, unsupported
// type) are kept with Identifier nil and Err set, so callers can report why a
// signature could not be attributed.
func ParseSignatureAgent(h http.Header) (*SignatureAgent, error) {
	values := h.Values(HeaderSignatureAgent)
	if len(values) == 0 {
		return nil, nil
	}

	// Protocol draft Section 5.2.1: a String Item begins with a double quote
	// while a Dictionary member key does not.
	if strings.HasPrefix(strings.TrimLeft(values[0], " \t"), `"`) {
		item, err := httpsfv.UnmarshalItem(values)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedSignatureAgent, err)
		}

		return &SignatureAgent{
			Legacy:  true,
			Members: map[string]AgentMember{"": parseAgentItem("", item)},
		}, nil
	}

	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedSignatureAgent, err)
	}

	result := &SignatureAgent{Members: make(map[string]AgentMember, len(dict.Names()))}
	for _, key := range dict.Names() {
		m, _ := dict.Get(key)

		item, ok := m.(httpsfv.Item)
		if !ok {
			result.Members[key] = AgentMember{
				Key: key,
				Err: fmt.Errorf("%w: member is an inner list, not a String", ErrInvalidAgentMember),
			}
			continue
		}

		result.Members[key] = parseAgentItem(key, item)
	}

	return result, nil
}

// Member returns the member a signature covers. For the dictionary form, key
// is the ;key= parameter of the covered signature-agent component. For the
// legacy form, the component has no key and the single member is returned.
func (sa *SignatureAgent) Member(key string) (AgentMember, bool) {
	if sa == nil {
		return AgentMember{}, false
	}
	if sa.Legacy != (key == "") {
		return AgentMember{}, false
	}

	m, ok := sa.Members[key]
	return m, ok
}

func parseAgentItem(key string, item httpsfv.Item) AgentMember {
	result := AgentMember{Key: key, Type: AgentTypeDirectory}

	value, ok := item.Value.(string)
	if !ok {
		result.Err = fmt.Errorf("%w: value is not a String", ErrInvalidAgentMember)
		return result
	}
	result.Value = value

	if item.Params != nil {
		if t, ok := item.Params.Get("type"); ok {
			tok, ok := t.(httpsfv.Token)
			if !ok {
				result.Err = fmt.Errorf("%w: type parameter is not a Token", ErrInvalidAgentMember)
				return result
			}
			result.Type = string(tok)
		}
	}

	// Protocol draft Section 5.2.1: a verifier that does not support a type
	// MUST ignore the member and MUST NOT infer the mechanism.
	if result.Type != AgentTypeDirectory {
		result.Err = fmt.Errorf("%w: %q", ErrUnsupportedAgentType, result.Type)
		return result
	}

	id, err := directoryIdentifier(value)
	if err != nil {
		result.Err = err
		return result
	}
	result.Identifier = id

	return result
}

// directoryIdentifier checks that value is the ASCII serialization of an https
// origin (protocol draft Section 5.5; a "/" path is also accepted) and returns
// the well-known directory URL for that origin.
func directoryIdentifier(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAgentMember, err)
	}

	switch {
	case u.Scheme != "https":
		return nil, fmt.Errorf("%w: scheme must be https, got %q", ErrInvalidAgentMember, u.Scheme)
	case u.Opaque != "", u.Host == "":
		return nil, fmt.Errorf("%w: %q has no host", ErrInvalidAgentMember, value)
	case u.User != nil:
		return nil, fmt.Errorf("%w: %q has userinfo", ErrInvalidAgentMember, value)
	case u.Path != "" && u.Path != "/":
		return nil, fmt.Errorf("%w: %q is not an origin (has a path)", ErrInvalidAgentMember, value)
	case u.RawQuery != "" || u.ForceQuery:
		return nil, fmt.Errorf("%w: %q is not an origin (has a query)", ErrInvalidAgentMember, value)
	case u.Fragment != "" || strings.Contains(value, "#"):
		return nil, fmt.Errorf("%w: %q is not an origin (has a fragment)", ErrInvalidAgentMember, value)
	}

	origin := "https://" + u.Host
	if strings.TrimSuffix(value, "/") != origin {
		return nil, fmt.Errorf("%w: %q is not the ASCII serialization of an origin", ErrInvalidAgentMember, value)
	}
	if u.Port() == "443" {
		return nil, fmt.Errorf("%w: %q includes the default port", ErrInvalidAgentMember, value)
	}
	for _, r := range u.Host {
		if r > 0x7f || ('A' <= r && r <= 'Z') {
			return nil, fmt.Errorf("%w: host in %q is not lowercase ASCII", ErrInvalidAgentMember, value)
		}
	}

	return &url.URL{Scheme: "https", Host: u.Host, Path: WellKnownPath}, nil
}
