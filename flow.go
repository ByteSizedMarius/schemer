package schemer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// DefaultTimeout applies when Flow.Timeout is not positive.
const DefaultTimeout = 5 * time.Minute

// Flow describes an authorization code flow against one provider.
type Flow struct {
	ClientID     string
	AuthorizeURL string
	TokenURL     string

	// RedirectURI must carry a custom scheme, e.g. "myapp://auth/prod".
	RedirectURI string

	Scopes []string

	// Extra adds provider-specific parameters to the authorization request.
	Extra url.Values

	// DisplayName labels the scheme registration. Defaults to the scheme.
	DisplayName string

	// Timeout bounds Wait and Exchange.
	Timeout time.Duration

	// HTTPClient sends the token request.
	HTTPClient *http.Client

	registrar registrarFunc
	opener    func(rawURL string) error
}

// Token is the token endpoint's response.
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	Scope        string `json:"scope"`

	// Raw carries the response body for provider-specific fields.
	Raw json.RawMessage `json:"-"`
}

// Run returns the token from Start, Wait and Exchange together with any error from Close.
func (f Flow) Run(ctx context.Context) (tok *Token, err error) {
	s, err := f.Start()
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, s.Close()) }()

	code, err := s.Wait(ctx)
	if err != nil {
		return nil, err
	}
	return s.Exchange(ctx, code)
}

func (f Flow) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	return DefaultTimeout
}

func (f Flow) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return &http.Client{
		Timeout: f.timeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
