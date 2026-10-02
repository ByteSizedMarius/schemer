package schemer

import (
	"errors"
	"strings"
	"unicode"
)

// ErrUnsupportedOS is returned by Wait and Run on every OS but Windows.
var ErrUnsupportedOS = errors.New("schemer: scheme registration is unimplemented on this OS")

// ErrStateMismatch reports a callback whose state is not this session's.
var ErrStateMismatch = errors.New("schemer: state mismatch")

// ErrNoCode reports a callback that carried neither a code nor an error.
var ErrNoCode = errors.New("schemer: callback has no code")

// ErrInProgress is returned by Wait and Run while another login holds the scheme.
var ErrInProgress = errors.New("schemer: another login for this scheme is in progress")

// AuthError is an error the authorization server reported on the callback.
type AuthError struct {
	Code        string
	Description string
}

// Error leaves out the control characters Code and Description may hold.
func (e *AuthError) Error() string {
	code, desc := dropControl(e.Code), dropControl(e.Description)
	if desc == "" {
		return "schemer: " + code
	}
	return "schemer: " + code + ": " + desc
}

func dropControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
