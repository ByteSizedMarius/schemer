package schemer

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrUnsupportedOS is returned by Wait and Run on every OS but Windows.
var ErrUnsupportedOS = errors.New("schemer: scheme registration is unimplemented on this OS")

// ErrStateMismatch reports a callback whose state is not this session's.
var ErrStateMismatch error = errStateMismatch

// ErrNoCode reports a callback that carried neither a code nor an error.
var ErrNoCode error = errNoCode

// ErrInProgress is returned by Wait and Run while another login holds the scheme.
var ErrInProgress = errors.New("schemer: another login for this scheme is in progress")

// Unlike the exported vars, these constants cannot be reassigned by an importer.
const (
	errStateMismatch callbackError = "schemer: state mismatch"
	errNoCode        callbackError = "schemer: callback has no code"
)

type callbackError string

func (e callbackError) Error() string { return string(e) }

// AuthError is an error the authorization server reported on the callback.
type AuthError struct {
	Code        string
	Description string
}

// Byte caps on the AuthError fields built from a callback.
const (
	maxErrorCode        = 128
	maxErrorDescription = 1024
)

func newAuthError(code, desc string) *AuthError {
	return &AuthError{
		Code:        truncate(cleanText(code), maxErrorCode),
		Description: truncate(cleanText(desc), maxErrorDescription),
	}
}

// Error leaves out control, format, line separator and paragraph separator runes.
func (e *AuthError) Error() string {
	code, desc := cleanText(e.Code), cleanText(e.Description)
	if desc == "" {
		return "schemer: " + code
	}
	return "schemer: " + code + ": " + desc
}

func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return -1
		}
		return r
	}, s)
}

// truncate returns the longest whole-rune prefix of s within n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
