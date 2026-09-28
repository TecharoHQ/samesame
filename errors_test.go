package samesame

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteChallenge(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		opts    ChallengeOptions
		want    string
		wantErr bool
	}{
		{
			name: "defaults",
			want: `sig1=("@authority" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"`,
		},
		{
			name: "label and nonce",
			opts: ChallengeOptions{Label: "sig2", Nonce: "abc"},
			want: `sig2=("@authority" "signature-agent";key="sig2");created;expires;tag="web-bot-auth";nonce="abc"`,
		},
		{
			name:    "bad label",
			opts:    ChallengeOptions{Label: "Sig"},
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			err := WriteChallenge(w, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Fatalf("WriteChallenge: %v", err)
			}
			if got := w.Header().Get("Accept-Signature"); got != tt.want {
				t.Logf("want: %s", tt.want)
				t.Logf("got:  %s", got)
				t.Error("wrong Accept-Signature")
			}
		})
	}
}

func TestStatusCodeAndOutcome(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name        string
		err         error
		wantStatus  int
		wantOutcome Outcome
	}{
		{name: "nil", err: nil, wantStatus: http.StatusOK, wantOutcome: OutcomeVerified},
		{name: "malformed", err: invalid("", ErrMalformedSignature), wantStatus: http.StatusBadRequest, wantOutcome: OutcomeInvalid},
		{name: "malformed agent", err: invalid("", fmt.Errorf("%w: x", ErrMalformedSignatureAgent)), wantStatus: http.StatusBadRequest, wantOutcome: OutcomeInvalid},
		{name: "replay", err: invalid("sig1", ErrReplay), wantStatus: http.StatusTooManyRequests, wantOutcome: OutcomeInvalid},
		{name: "bad signature", err: invalid("sig1", ErrBadSignature), wantStatus: http.StatusForbidden, wantOutcome: OutcomeInvalid},
		{name: "unknown key", err: unverified("sig1", ErrKeyUnknown), wantStatus: http.StatusForbidden, wantOutcome: OutcomeUnverified},
		{name: "foreign error", err: errors.New("boom"), wantStatus: http.StatusForbidden, wantOutcome: OutcomeUnverified},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := StatusCode(tt.err); got != tt.wantStatus {
				t.Errorf("status: want %d, got %d", tt.wantStatus, got)
			}
			if got := OutcomeOf(tt.err); got != tt.wantOutcome {
				t.Errorf("outcome: want %s, got %s", tt.wantOutcome, got)
			}
		})
	}
}
