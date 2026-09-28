package samesame

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/dunglas/httpsfv"
)

// Outcome is the result of verifying a request (protocol draft Appendix C.1).
type Outcome int

const (
	// OutcomeUnverified means the verifier could not get enough information
	// to decide: the request is unsigned, discovery failed, or the key is
	// unknown. It is neither proof of identity nor proof of forgery.
	OutcomeUnverified Outcome = iota

	// OutcomeInvalid means a signature, its covered components, its key, or
	// its freshness failed to verify.
	OutcomeInvalid

	// OutcomeVerified means a signature verified.
	OutcomeVerified
)

func (o Outcome) String() string {
	switch o {
	case OutcomeUnverified:
		return "unverified"
	case OutcomeInvalid:
		return "invalid"
	case OutcomeVerified:
		return "verified"
	default:
		return fmt.Sprintf("Outcome(%d)", int(o))
	}
}

// Errors wrapped by VerifyError. Use errors.Is to check for them.
var (
	ErrNoSignature        = errors.New("samesame: no web-bot-auth signature")
	ErrMalformedSignature = errors.New("samesame: malformed signature headers")
	ErrInsecureTransport  = errors.New("samesame: signature sent over plaintext HTTP")
	ErrProfile            = errors.New("samesame: signature does not follow the web-bot-auth profile")
	ErrNotYetValid        = errors.New("samesame: signature created in the future")
	ErrExpired            = errors.New("samesame: signature expired")
	ErrValidityTooLong    = errors.New("samesame: signature validity window too long")
	ErrBadSignature       = errors.New("samesame: signature does not verify")
	ErrKeyUnknown         = errors.New("samesame: signing key unknown")
	ErrDiscovery          = errors.New("samesame: key discovery failed")
	ErrNonceRequired      = errors.New("samesame: signature has no nonce")
	ErrReplay             = errors.New("samesame: nonce already used")
	ErrNonceStore         = errors.New("samesame: nonce store unavailable")
	ErrTooManySignatures  = errors.New("samesame: too many signatures")
)

// VerifyError describes why a request did not verify.
type VerifyError struct {
	Outcome Outcome
	Label   string // signature label, empty when not specific to one
	Err     error
}

func (e *VerifyError) Error() string {
	if e.Label == "" {
		return fmt.Sprintf("%s: %v", e.Outcome, e.Err)
	}
	return fmt.Sprintf("%s: signature %q: %v", e.Outcome, e.Label, e.Err)
}

func (e *VerifyError) Unwrap() error { return e.Err }

func (e *VerifyError) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("outcome", e.Outcome.String()),
		slog.String("label", e.Label),
		slog.String("err", e.Err.Error()),
	)
}

func unverified(label string, err error) *VerifyError {
	return &VerifyError{Outcome: OutcomeUnverified, Label: label, Err: err}
}

func invalid(label string, err error) *VerifyError {
	return &VerifyError{Outcome: OutcomeInvalid, Label: label, Err: err}
}

// OutcomeOf returns the outcome carried by err: OutcomeVerified for nil,
// the VerifyError's outcome, or OutcomeUnverified for any other error.
func OutcomeOf(err error) Outcome {
	if err == nil {
		return OutcomeVerified
	}
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve.Outcome
	}
	return OutcomeUnverified
}

// StatusCode suggests an HTTP status code for rejecting a request that failed
// with err (protocol draft Sections 5.3 and 5.4): 400 for unparseable
// signature headers, 429 for a replayed nonce, and 403 otherwise. Whether to
// reject an unverified request at all is the caller's policy.
func StatusCode(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrMalformedSignature), errors.Is(err, ErrMalformedSignatureAgent):
		return http.StatusBadRequest
	case errors.Is(err, ErrReplay):
		return http.StatusTooManyRequests
	default:
		return http.StatusForbidden
	}
}

// ChallengeOptions controls the Accept-Signature header WriteChallenge sends.
type ChallengeOptions struct {
	// Label is the requested signature label and Signature-Agent member key.
	// Defaults to DefaultLabel.
	Label string

	// Nonce, when set, asks the agent to sign with this exact nonce. The
	// caller is responsible for remembering and checking it.
	Nonce string
}

// WriteChallenge sets an Accept-Signature header asking for a web-bot-auth
// signature (protocol draft Section 5.3). It does not write a status code;
// use StatusCode.
func WriteChallenge(w http.ResponseWriter, opts ChallengeOptions) error {
	if opts.Label == "" {
		opts.Label = DefaultLabel
	}
	if !isSFKey(opts.Label) {
		return fmt.Errorf("samesame: label %q is not a structured field key", opts.Label)
	}

	agent := httpsfv.NewItem("signature-agent")
	agent.Params.Add("key", opts.Label)

	components := httpsfv.InnerList{
		Items:  []httpsfv.Item{httpsfv.NewItem("@authority"), agent},
		Params: httpsfv.NewParams(),
	}
	components.Params.Add("created", true)
	components.Params.Add("expires", true)
	components.Params.Add("tag", TagWebBotAuth)
	if opts.Nonce != "" {
		components.Params.Add("nonce", opts.Nonce)
	}

	dict := httpsfv.NewDictionary()
	dict.Add(opts.Label, components)

	value, err := httpsfv.Marshal(dict)
	if err != nil {
		return fmt.Errorf("samesame: can't serialize Accept-Signature: %w", err)
	}

	w.Header().Set("Accept-Signature", value)
	return nil
}
