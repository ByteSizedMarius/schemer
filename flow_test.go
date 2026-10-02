package schemer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
)

func testFlow() Flow {
	return Flow{
		ClientID:     "client-123",
		AuthorizeURL: "https://provider.example/oauth/authorize",
		TokenURL:     "https://provider.example/oauth/token",
		RedirectURI:  "testscheme://auth/prod",
		Scopes:       []string{"ReadOrigApi", "offline"},
	}
}

func TestAuthorizeURL(t *testing.T) {
	f := testFlow()
	f.Extra = url.Values{"prompt": {"login"}, "style_id": {"bsh_hc_01"}}

	s, err := f.Start()
	if err != nil {
		t.Fatal(err)
	}

	raw := s.AuthorizeURL()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "provider.example" || u.Path != "/oauth/authorize" {
		t.Errorf("authorize endpoint = %s", u)
	}

	q := u.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             "client-123",
		"redirect_uri":          "testscheme://auth/prod",
		"code_challenge_method": "S256",
		"scope":                 "ReadOrigApi offline",
		"prompt":                "login",
		"style_id":              "bsh_hc_01",
		"state":                 s.pkce.state,
	}
	for k, v := range want {
		if got := q.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	sum := sha256.Sum256([]byte(s.pkce.verifier))
	if got, want := q.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("code_challenge = %q, want %q", got, want)
	}

	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"raw": raw, "decoded": decoded} {
		if strings.Contains(text, s.pkce.verifier) {
			t.Errorf("%s AuthorizeURL carries the code_verifier: %s", name, text)
		}
	}
}

func TestAuthorizeURLKeepsExistingQuery(t *testing.T) {
	f := testFlow()
	f.AuthorizeURL = "https://provider.example/authorize?tenant=eu"

	s, err := f.Start()
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(s.AuthorizeURL())
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("tenant"); got != "eu" {
		t.Errorf("tenant = %q, want eu", got)
	}
	if got := u.Query().Get("client_id"); got != "client-123" {
		t.Errorf("client_id = %q", got)
	}
}

func TestStartRejectsWebAndSchemelessRedirect(t *testing.T) {
	if _, err := testFlow().Start(); err != nil {
		t.Fatalf("custom-scheme RedirectURI was rejected: %v", err)
	}

	for _, redirect := range []string{"http://localhost:5000/callback", "/no-scheme", `schemer\evil://auth`} {
		f := testFlow()
		f.RedirectURI = redirect
		if _, err := f.Start(); err == nil {
			t.Errorf("RedirectURI %q was accepted", redirect)
		}
	}
}

// openBrowser launches whatever handler the AuthorizeURL scheme names.
func TestStartRejectsNonWebAuthorizeURL(t *testing.T) {
	f := testFlow()
	if _, err := f.Start(); err != nil {
		t.Fatalf("AuthorizeURL %q was rejected: %v", f.AuthorizeURL, err)
	}

	f.AuthorizeURL = "file:///C:/Windows/System32/calc.exe"
	if _, err := f.Start(); err == nil {
		t.Errorf("AuthorizeURL %q was accepted", f.AuthorizeURL)
	}
}

// RFC 6749 section 10.12 (CSRF).
func TestParseCallback(t *testing.T) {
	s, err := testFlow().Start()
	if err != nil {
		t.Fatal(err)
	}
	valid := "testscheme://auth/prod?code=the-code&state=" + s.pkce.state

	code, err := s.ParseCallback("  " + valid + "\r\n")
	if err != nil || code != "the-code" {
		t.Fatalf("ParseCallback(valid) = %q, %v, want the-code", code, err)
	}

	if _, err := s.ParseCallback("testscheme://auth/prod?code=the-code&state=somebody-elses-state"); !errors.Is(err, ErrStateMismatch) {
		t.Errorf("wrong state: err = %v, want ErrStateMismatch", err)
	}

	if code, err := s.ParseCallback("testscheme://auth/prod?code=forged"); code != "" || !errors.Is(err, ErrStateMismatch) {
		t.Errorf("missing state: ParseCallback = %q, %v, want ErrStateMismatch and no code", code, err)
	}

	if _, err := s.ParseCallback("testscheme://auth/prod?state=" + s.pkce.state); !errors.Is(err, ErrNoCode) {
		t.Errorf("missing code: err = %v, want ErrNoCode", err)
	}

	if _, err := s.ParseCallback("%zz"); err == nil {
		t.Error("unparsable URL was accepted")
	}
}

func TestExchange(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"tok","refresh_token":"rt","id_token":"idt","token_type":"Bearer","expires_in":3600,"scope":"openid offline","sub_claim":"extra"}`)
	}))
	defer srv.Close()

	f := testFlow()
	f.TokenURL = srv.URL

	s, err := f.Start()
	if err != nil {
		t.Fatal(err)
	}

	tok, err := s.Exchange(context.Background(), "the-code")
	if err != nil {
		t.Fatal(err)
	}
	got := *tok
	got.Raw = nil
	want := Token{AccessToken: "tok", RefreshToken: "rt", IDToken: "idt", TokenType: "Bearer", ExpiresIn: 3600, Scope: "openid offline"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("token = %+v, want %+v", got, want)
	}
	if !strings.Contains(string(tok.Raw), "sub_claim") {
		t.Errorf("Raw dropped provider fields: %s", tok.Raw)
	}

	wantForm := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     "client-123",
		"code":          "the-code",
		"redirect_uri":  "testscheme://auth/prod",
		"code_verifier": s.pkce.verifier,
	}
	for k, v := range wantForm {
		if got := gotForm.Get(k); got != v {
			t.Errorf("form %s = %q, want %q", k, got, v)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestExchangeUsesHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the token request bypassed the HTTPClient")
	}))
	defer srv.Close()

	var got *http.Request
	var body []byte
	f := testFlow()
	f.TokenURL = srv.URL
	f.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var err error
		got = r
		if body, err = io.ReadAll(r.Body); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"access_token":"tok"}`))}, nil
	})}
	s := start(t, f)

	tok, err := s.Exchange(context.Background(), "the-code")
	if err != nil || tok.AccessToken != "tok" {
		t.Fatalf("token = %+v, err = %v, want the transport's token", tok, err)
	}
	if got == nil {
		t.Fatal("the HTTPClient's transport saw no request")
	}
	if got.Method != http.MethodPost || got.URL.String() != f.TokenURL {
		t.Errorf("request = %s %s, want POST %s", got.Method, got.URL, f.TokenURL)
	}
	if form, err := url.ParseQuery(string(body)); err != nil || form.Get("code") != "the-code" || form.Get("code_verifier") != s.pkce.verifier {
		t.Errorf("form = %q, want the code and the session's code_verifier", body)
	}
}

func TestExchangeHonoursTimeoutWithCustomClient(t *testing.T) {
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") == "fast" {
			io.WriteString(w, `{"access_token":"tok"}`)
			return
		}
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	}))
	defer srv.Close()
	defer close(stop)

	f := testFlow()
	f.TokenURL = srv.URL
	f.HTTPClient = &http.Client{}
	f.Timeout = 100 * time.Millisecond
	s, err := f.Start()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Exchange(context.Background(), "fast"); err != nil {
		t.Fatalf("fast response: %v", err)
	}

	type result struct {
		tok *Token
		err error
	}
	done := make(chan result, 1)
	go func() {
		tok, err := s.Exchange(context.Background(), "slow")
		done <- result{tok, err}
	}()
	select {
	case r := <-done:
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Errorf("token = %+v, err = %v, want DeadlineExceeded", r.tok, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exchange ignored the 100ms Timeout")
	}
}

// tokenServer also returns a func listing the forms received so far.
func tokenServer(t *testing.T, respond func(w http.ResponseWriter, form string)) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var forms []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		forms = append(forms, string(body))
		mu.Unlock()
		respond(w, string(body))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), forms...)
	}
}

// ASVS 16.2.5.
func TestExchangeErrorsOmitVerifierAndCode(t *testing.T) {
	var mode atomic.Value
	mode.Store("ok")
	srv, forms := tokenServer(t, func(w http.ResponseWriter, form string) {
		decoded, _ := url.QueryUnescape(form)
		switch mode.Load().(string) {
		case "ok":
			io.WriteString(w, `{"access_token":"tok"}`)
		case "400 echo":
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, form)
		case "400 error_description echo":
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"invalid_request","error_description":%q}`, decoded)
		case "200 error_description echo":
			fmt.Fprintf(w, `{"error":"invalid_request","error_description":%q}`, decoded)
		}
	})
	f := testFlow()
	f.TokenURL = srv.URL
	s := start(t, f)

	const code = "SplxlOBe/ZQQYbYS+6WxSbIA="
	if tok, err := s.Exchange(context.Background(), code); err != nil || tok.AccessToken != "tok" {
		t.Fatalf("control: token = %+v, err = %v", tok, err)
	}
	if got := forms(); len(got) != 1 || !strings.Contains(got[0], s.pkce.verifier) || !strings.Contains(got[0], url.QueryEscape(code)) {
		t.Fatalf("control: token requests %q, want one carrying the code_verifier and the code", got)
	}

	secrets := map[string]string{"code_verifier": s.pkce.verifier, "code": code, "escaped code": url.QueryEscape(code)}
	for _, m := range []string{"400 echo", "400 error_description echo", "200 error_description echo"} {
		mode.Store(m)
		tok, err := s.Exchange(context.Background(), code)
		if err == nil {
			t.Errorf("%s: token = %+v, want an error", m, tok)
			continue
		}
		if !strings.Contains(err.Error(), f.ClientID) {
			t.Errorf("%s: the error does not quote the echoed request: %v", m, err)
		}
		for name, secret := range secrets {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error string carries the %s: %v", m, name, err)
			}
		}
	}
}

func TestRedirectedTokenRequestReachesNobody(t *testing.T) {
	var hits atomic.Int32
	var gotVerifier atomic.Bool
	var verifier atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body)+r.URL.RawQuery, verifier.Load().(string)) {
			gotVerifier.Store(true)
		}
		io.WriteString(w, `{"access_token":"tok"}`)
	}))
	defer target.Close()

	f := testFlow()
	f.TokenURL = target.URL
	s := start(t, f)
	verifier.Store(s.pkce.verifier)
	if tok, err := s.Exchange(context.Background(), "code"); err != nil || tok.AccessToken != "tok" || !gotVerifier.Load() {
		t.Fatalf("control: token = %+v, err = %v, verifier received = %v", tok, err, gotVerifier.Load())
	}

	hits.Store(0)
	gotVerifier.Store(false)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/next", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	f.TokenURL = origin.URL
	s = start(t, f)
	verifier.Store(s.pkce.verifier)

	tok, err := s.Exchange(context.Background(), "code")
	if err == nil {
		t.Errorf("307: token = %+v, want an error", tok)
	}
	if n := hits.Load(); n != 0 || gotVerifier.Load() {
		t.Errorf("307: the redirect target saw %d requests, verifier received = %v, want none", n, gotVerifier.Load())
	}
}

func TestExchangeFailsClosed(t *testing.T) {
	type reply struct {
		status int
		body   string
	}
	var current atomic.Value
	current.Store(reply{200, `{"access_token":"tok"}`})
	srv, _ := tokenServer(t, func(w http.ResponseWriter, _ string) {
		r := current.Load().(reply)
		w.WriteHeader(r.status)
		io.WriteString(w, r.body)
	})
	f := testFlow()
	f.TokenURL = srv.URL
	s := start(t, f)

	if tok, err := s.Exchange(context.Background(), "code"); err != nil || tok == nil || tok.AccessToken != "tok" {
		t.Fatalf("control: token = %+v, err = %v", tok, err)
	}

	for _, r := range []reply{
		{201, `{"access_token":"tok"}`},
		{200, `{"access_token":""}`},
		{200, `{"access_token":"tok"}{"access_token":"evil"}`},
	} {
		current.Store(r)
		tok, err := s.Exchange(context.Background(), "code")
		if err == nil || tok != nil {
			t.Errorf("%d %s: token = %+v, err = %v, want no token and an error", r.status, r.body, tok, err)
		}
	}
}

// ASVS 16.2.5.
func TestExchangeErrorQuotesOnlyErrorFields(t *testing.T) {
	type reply struct {
		status int
		body   string
	}
	var current atomic.Value
	current.Store(reply{200, `{"access_token":"tok"}`})
	srv, _ := tokenServer(t, func(w http.ResponseWriter, _ string) {
		r := current.Load().(reply)
		w.WriteHeader(r.status)
		io.WriteString(w, r.body)
	})
	f := testFlow()
	f.TokenURL = srv.URL
	s := start(t, f)

	const code = "the-auth-code"
	if tok, err := s.Exchange(context.Background(), code); err != nil || tok == nil || tok.AccessToken != "tok" {
		t.Fatalf("control: token = %+v, err = %v", tok, err)
	}
	exchangeError := func(r reply) string {
		t.Helper()
		current.Store(r)
		tok, err := s.Exchange(context.Background(), code)
		if err == nil {
			t.Fatalf("%d %s: token = %+v, want an error", r.status, r.body, tok)
		}
		return err.Error()
	}

	ctl := reply{502, `<html>bad gateway html</html>`}
	msg := exchangeError(ctl)
	for _, w := range []string{"502", "bad gateway html"} {
		if !strings.Contains(msg, w) {
			t.Fatalf("control: %d %s: error = %q, want it to carry %q", ctl.status, ctl.body, msg, w)
		}
	}

	secrets := []string{"AT-SECRET", "RT-SECRET", "ID-SECRET"}
	for _, c := range []struct {
		r    reply
		want []string
	}{
		{reply{500, `{"access_token":"AT-SECRET","refresh_token":"RT-SECRET"}`}, []string{"500"}},
		{reply{400, `{"error":"invalid_grant","error_description":"code expired","access_token":"AT-SECRET","id_token":"ID-SECRET"}`}, []string{"400", "invalid_grant", "code expired"}},
	} {
		msg := exchangeError(c.r)
		for _, w := range c.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%d %s: error = %q, want it to carry %q", c.r.status, c.r.body, msg, w)
			}
		}
		for _, secret := range secrets {
			if strings.Contains(msg, secret) {
				t.Errorf("%d %s: error = %q, carries the field value %s", c.r.status, c.r.body, msg, secret)
			}
		}
	}
}

func findControl(s string) (rune, bool) {
	for _, r := range s {
		if unicode.IsControl(r) {
			return r, true
		}
	}
	return 0, false
}

// CWE-150.
func TestAuthErrorDropsControlCharacters(t *testing.T) {
	ctl := (&AuthError{Code: "access_denied", Description: "user said no"}).Error()
	if r, ok := findControl(ctl); ok || !strings.Contains(ctl, "access_denied") || !strings.Contains(ctl, "user said no") {
		t.Fatalf("control: Error() = %q, control character %U found = %v", ctl, r, ok)
	}

	e := &AuthError{Code: "\x00access_denied\x7f", Description: "\tuser said no\u0085\u009b31m"}
	got := e.Error()
	if r, ok := findControl(got); ok {
		t.Errorf("AuthError{%q, %q}.Error() = %q, holds the control character %U", e.Code, e.Description, got, r)
	}
	for _, want := range []string{"access_denied", "user said no"} {
		if !strings.Contains(got, want) {
			t.Errorf("AuthError{%q, %q}.Error() = %q, want it to carry %q", e.Code, e.Description, got, want)
		}
	}

	s := start(t, testFlow())
	_, err := s.ParseCallback("testscheme://auth/prod?error=access_denied%1B%5B2J&error_description=user+said+no%0D%0A%07&state=" + s.pkce.state)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("ParseCallback = %v, want *AuthError", err)
	}
	if r, ok := findControl(err.Error()); ok {
		t.Errorf("ParseCallback error = %q, holds the control character %U", err.Error(), r)
	}
}
