package samesame

import (
	"errors"
	"net/http"
	"testing"
)

func TestParseSignatureAgent(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		header     []string
		err        error
		wantNil    bool
		wantLegacy bool
		memberKey  string
		wantID     string // expected identifier; empty means the member is ignored
		wantErr    error  // expected AgentMember.Err
	}{
		{
			name:    "absent",
			wantNil: true,
		},
		{
			name:      "E.2.1 dictionary form",
			header:    []string{`agent2="https://signature-agent.test"`},
			memberKey: "agent2",
			wantID:    "https://signature-agent.test/.well-known/http-message-signatures-directory",
		},
		{
			name:       "E.2.2 legacy string form",
			header:     []string{`"https://signature-agent.test"`},
			wantLegacy: true,
			memberKey:  "",
			wantID:     "https://signature-agent.test/.well-known/http-message-signatures-directory",
		},
		{
			name:      "explicit directory type",
			header:    []string{`sig1="https://signature-agent.test";type=directory`},
			memberKey: "sig1",
			wantID:    "https://signature-agent.test/.well-known/http-message-signatures-directory",
		},
		{
			name:      "trailing slash is accepted",
			header:    []string{`sig1="https://signature-agent.test/"`},
			memberKey: "sig1",
			wantID:    "https://signature-agent.test/.well-known/http-message-signatures-directory",
		},
		{
			name:      "non-default port",
			header:    []string{`sig1="https://signature-agent.test:8443"`},
			memberKey: "sig1",
			wantID:    "https://signature-agent.test:8443/.well-known/http-message-signatures-directory",
		},
		{
			name:      "second member of several",
			header:    []string{`a="https://a.test", b="https://b.test"`},
			memberKey: "b",
			wantID:    "https://b.test/.well-known/http-message-signatures-directory",
		},
		{
			name:      "split across header lines",
			header:    []string{`a="https://a.test"`, `b="https://b.test"`},
			memberKey: "b",
			wantID:    "https://b.test/.well-known/http-message-signatures-directory",
		},
		{
			name:      "jwks_uri type is ignored",
			header:    []string{`sig1="https://signature-agent.test/jwks.json";type=jwks_uri`},
			memberKey: "sig1",
			wantErr:   ErrUnsupportedAgentType,
		},
		{
			name:      "cimd type is ignored",
			header:    []string{`sig1="https://signature-agent.test/card";type=cimd`},
			memberKey: "sig1",
			wantErr:   ErrUnsupportedAgentType,
		},
		{
			name:      "unknown type is ignored",
			header:    []string{`sig1="https://signature-agent.test";type=magic`},
			memberKey: "sig1",
			wantErr:   ErrUnsupportedAgentType,
		},
		{
			name:      "type as string is invalid",
			header:    []string{`sig1="https://signature-agent.test";type="directory"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "http scheme",
			header:    []string{`sig1="http://signature-agent.test"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "data URI",
			header:    []string{`sig1="data:application/http-message-signatures-directory+json;utf8,{}"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "full well-known URL is not an origin",
			header:    []string{`sig1="https://signature-agent.test/.well-known/http-message-signatures-directory"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "query",
			header:    []string{`sig1="https://signature-agent.test?x=1"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "empty query",
			header:    []string{`sig1="https://signature-agent.test?"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "fragment",
			header:    []string{`sig1="https://signature-agent.test#x"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "userinfo",
			header:    []string{`sig1="https://user@signature-agent.test"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "uppercase host",
			header:    []string{`sig1="https://Signature-Agent.test"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "default port",
			header:    []string{`sig1="https://signature-agent.test:443"`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "token value",
			header:    []string{`sig1=signature-agent`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:      "inner list value",
			header:    []string{`sig1=("https://signature-agent.test")`},
			memberKey: "sig1",
			wantErr:   ErrInvalidAgentMember,
		},
		{
			name:   "not a structured field",
			header: []string{`sig1="unterminated`},
			err:    ErrMalformedSignatureAgent,
		},
		{
			name:   "legacy form not a structured field",
			header: []string{`"https://a.test" trailing`},
			err:    ErrMalformedSignatureAgent,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := http.Header{}
			for _, v := range tt.header {
				h.Add(HeaderSignatureAgent, v)
			}

			sa, err := ParseSignatureAgent(h)
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Logf("want: %v", tt.err)
					t.Logf("got:  %v", err)
					t.Error("got wrong error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSignatureAgent: %v", err)
			}
			if tt.wantNil {
				if sa != nil {
					t.Errorf("want nil, got %+v", sa)
				}
				return
			}

			if sa.Legacy != tt.wantLegacy {
				t.Errorf("legacy: want %v, got %v", tt.wantLegacy, sa.Legacy)
			}

			m, ok := sa.Member(tt.memberKey)
			if !ok {
				t.Fatalf("no member %q in %+v", tt.memberKey, sa.Members)
			}

			if tt.wantErr != nil {
				if !errors.Is(m.Err, tt.wantErr) {
					t.Logf("want: %v", tt.wantErr)
					t.Logf("got:  %v", m.Err)
					t.Error("got wrong member error")
				}
				if m.Identifier != nil {
					t.Errorf("ignored member has identifier %s", m.Identifier)
				}
				return
			}

			if m.Err != nil {
				t.Fatalf("member error: %v", m.Err)
			}
			if got := m.Identifier.String(); got != tt.wantID {
				t.Logf("want: %s", tt.wantID)
				t.Logf("got:  %s", got)
				t.Error("wrong identifier")
			}
		})
	}
}

func TestSignatureAgentMemberForm(t *testing.T) {
	t.Parallel()

	dict := &SignatureAgent{Members: map[string]AgentMember{"a": {Key: "a"}}}
	legacy := &SignatureAgent{Legacy: true, Members: map[string]AgentMember{"": {}}}

	for _, tt := range []struct {
		name string
		sa   *SignatureAgent
		key  string
		want bool
	}{
		{name: "dictionary keyed", sa: dict, key: "a", want: true},
		{name: "dictionary unkeyed component", sa: dict, key: "", want: false},
		{name: "dictionary missing key", sa: dict, key: "b", want: false},
		{name: "legacy unkeyed component", sa: legacy, key: "", want: true},
		{name: "legacy keyed component", sa: legacy, key: "a", want: false},
		{name: "nil header", sa: nil, key: "a", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, ok := tt.sa.Member(tt.key); ok != tt.want {
				t.Errorf("want %v, got %v", tt.want, ok)
			}
		})
	}
}

func FuzzParseSignatureAgent(f *testing.F) {
	for _, seed := range []string{
		`agent2="https://signature-agent.test"`,
		`"https://signature-agent.test"`,
		`sig1="https://signature-agent.test/jwks.json";type=jwks_uri`,
		`a="https://a.test", b=("x")`,
		`sig1="https://[::1]:8443"`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		sa, err := ParseSignatureAgent(http.Header{HeaderSignatureAgent: []string{value}})
		if err != nil {
			return
		}
		for _, m := range sa.Members {
			if (m.Identifier == nil) == (m.Err == nil) {
				t.Fatalf("member %+v must have exactly one of Identifier and Err", m)
			}
			if m.Identifier != nil && m.Identifier.Scheme != "https" {
				t.Fatalf("non-https identifier %s", m.Identifier)
			}
		}
	})
}
