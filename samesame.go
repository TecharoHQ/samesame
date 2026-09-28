// Package samesame implements Web Bot Auth: HTTP Message Signatures (RFC 9421)
// as profiled by draft-meunier-web-bot-auth-architecture, plus the key
// directory and Signature-Agent header from
// draft-meunier-http-message-signatures-directory.
package samesame

const (
	// TagWebBotAuth is the signature tag agents use to sign requests.
	TagWebBotAuth = "web-bot-auth"

	// TagDirectory is the signature tag directory servers use to sign
	// directory responses.
	TagDirectory = "http-message-signatures-directory"

	// MediaTypeDirectory is the media type of a key directory.
	MediaTypeDirectory = "application/http-message-signatures-directory+json"

	// WellKnownPath is where a key directory is served on an origin.
	WellKnownPath = "/.well-known/http-message-signatures-directory"

	// HeaderSignatureAgent names the header that points to an agent's key
	// directory.
	HeaderSignatureAgent = "Signature-Agent"
)
