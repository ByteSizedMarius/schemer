package schemer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
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

// CWE-209.
func TestParseCallbackErrorsOmitCodeAndState(t *testing.T) {
	s := start(t, testFlow())
	const code, state = "PLANTED-CODE", "PLANTED-STATE"
	if got, err := s.ParseCallback("testscheme://auth/prod?code=" + code + "&state=" + s.pkce.state); err != nil || got != code {
		t.Fatalf("control: ParseCallback = %q, %v, want %s", got, err, code)
	}

	var authErr *AuthError
	for _, c := range []struct {
		name string
		url  string
		want func(error) bool
	}{
		{"unparsable", "testscheme://auth/pr%zzod?code=" + code + "&state=" + state, func(err error) bool { return err != nil }},
		{"foreign state", "testscheme://auth/prod?code=" + code + "&state=" + state, func(err error) bool { return errors.Is(err, ErrStateMismatch) }},
		{"missing code", "testscheme://auth/prod?state=" + s.pkce.state, func(err error) bool { return errors.Is(err, ErrNoCode) }},
		{"provider error", "testscheme://auth/prod?error=access_denied&code=" + code + "&state=" + s.pkce.state, func(err error) bool { return errors.As(err, &authErr) }},
	} {
		got, err := s.ParseCallback(c.url)
		if got != "" || !c.want(err) {
			t.Errorf("%s: ParseCallback = %q, %v, want no code and the %s error", c.name, got, err, c.name)
			continue
		}
		for _, planted := range []string{code, state, s.pkce.state} {
			if strings.Contains(err.Error(), planted) {
				t.Errorf("%s: error = %q, carries %q", c.name, err, planted)
			}
		}
	}
}

// CWE-636.
func TestRejectionSurvivesNilErrorVars(t *testing.T) {
	s := start(t, testFlow())
	foreign := "testscheme://auth/prod?code=forged&state=foreign"
	noCode := "testscheme://auth/prod?state=" + s.pkce.state
	if _, err := s.ParseCallback(foreign); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("control: wrong state: err = %v, want ErrStateMismatch", err)
	}

	stateMismatch, missingCode := ErrStateMismatch, ErrNoCode
	t.Cleanup(func() { ErrStateMismatch, ErrNoCode = stateMismatch, missingCode })
	ErrStateMismatch, ErrNoCode = nil, nil

	if code, err := s.ParseCallback(foreign); code != "" || !errors.Is(err, stateMismatch) {
		t.Errorf("wrong state: ParseCallback = %q, %v, want the original ErrStateMismatch and no code", code, err)
	}
	if code, err := s.ParseCallback(noCode); code != "" || !errors.Is(err, missingCode) {
		t.Errorf("missing code: ParseCallback = %q, %v, want the original ErrNoCode", code, err)
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
	if _, err := start(t, f).Exchange(context.Background(), "fast"); err != nil {
		t.Fatalf("fast response: %v", err)
	}

	f.Timeout = 30 * time.Millisecond
	s := start(t, f)
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
		t.Fatal("Exchange ignored the 30ms Timeout")
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

func replyExchange(t *testing.T) func(status int, body, code string) (*Token, error) {
	t.Helper()
	type reply struct {
		status int
		body   string
	}
	var current atomic.Value
	srv, _ := tokenServer(t, func(w http.ResponseWriter, _ string) {
		r := current.Load().(reply)
		w.WriteHeader(r.status)
		io.WriteString(w, r.body)
	})
	f := testFlow()
	f.TokenURL = srv.URL
	s := start(t, f)
	return func(status int, body, code string) (*Token, error) {
		current.Store(reply{status, body})
		return s.Exchange(context.Background(), code)
	}
}

func TestNonPositiveTimeoutMeansDefault(t *testing.T) {
	srv, _ := tokenServer(t, func(w http.ResponseWriter, _ string) {
		io.WriteString(w, `{"access_token":"tok"}`)
	})
	f := testFlow()
	f.TokenURL = srv.URL
	f.Timeout = -time.Second
	if tok, err := start(t, f).Exchange(context.Background(), "code"); err != nil || tok.AccessToken != "tok" {
		t.Errorf("token = %+v, err = %v, want tok", tok, err)
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
			b, _ := json.Marshal(map[string]string{"error": "invalid_request", "error_description": form})
			w.WriteHeader(http.StatusBadRequest)
			w.Write(b)
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
	if !strings.Contains(msg, "502") || !strings.Contains(msg, "29") || strings.Contains(msg, "bad gateway") {
		t.Fatalf("control: %d %s: error = %q, want the status and the body length without the body", ctl.status, ctl.body, msg)
	}

	// CWE-209, CWE-532.
	trailing := reply{400, `{"error":"MARKER"}junk`}
	if msg := exchangeError(trailing); strings.Contains(msg, "MARKER") {
		t.Errorf("%d %s: error = %.200q, quotes the body", trailing.status, trailing.body, msg)
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

	// CWE-150.
	dirty := reply{400, `{"error":"inv\u202eal\u2028id\u001b_grant","error_description":"code\u202e ex\u2028pi\u001bred"}`}
	msg = exchangeError(dirty)
	if r, ok := findDropped(msg); ok || !strings.Contains(msg, "invalid_grant") || !strings.Contains(msg, "code expired") {
		t.Errorf("%d %s: error = %q, dropped rune %U found = %v, want invalid_grant and code expired", dirty.status, dirty.body, msg, r, ok)
	}
}

// CWE-209, CWE-400.
func TestExchangeReportsUndecodable200ByLength(t *testing.T) {
	exchange := replyExchange(t)
	if tok, err := exchange(http.StatusOK, `{"access_token":"tok","expires_in":3600}`, "code"); err != nil || tok.ExpiresIn != 3600 {
		t.Fatalf("control: token = %+v, err = %v", tok, err)
	}

	digits := strings.Repeat("9", 1<<20-64)
	body := `{"access_token":"tok","expires_in":` + digits + `}`
	tok, err := exchange(http.StatusOK, body, "code")
	if err == nil || tok != nil {
		t.Fatalf("number overflowing expires_in: token = %+v, err = %v, want no token and an error", tok, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "200") || !strings.Contains(msg, strconv.Itoa(len(body))) {
		t.Errorf("error = %.200q, want the status and the body length %d", msg, len(body))
	}
	if strings.Contains(msg, "expires_in") || strings.Contains(msg, digits[:16]) {
		t.Errorf("error = %.200q (%d bytes), quotes the body", msg, len(msg))
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		t.Errorf("error = %.200q, wraps the JSON decoder's error", msg)
	}
}

// ASVS 16.2.5.
func TestExchangeErrorMembersCountOnlyAsStrings(t *testing.T) {
	exchange := replyExchange(t)
	const desc = "code expired"
	body := func(errorMember string) string {
		return `{"error":` + errorMember + `,"error_description":"` + desc + `"}`
	}
	for _, c := range []struct {
		name           string
		status         int
		body           string
		quoted, absent []string
	}{
		{"400 string error", http.StatusBadRequest, body(`"invalid_grant"`), []string{"invalid_grant", desc}, nil},
		{"200 string error", http.StatusOK, body(`"invalid_grant"`), []string{"invalid_grant", desc}, nil},
		{"400 numeric error", http.StatusBadRequest, body("42"), []string{desc}, []string{"42"}},
		{"200 numeric error", http.StatusOK, body("42"), nil, []string{"42", desc}},
	} {
		tok, err := exchange(c.status, c.body, "the-auth-code")
		if err == nil || tok != nil {
			t.Errorf("%s: token = %+v, err = %v, want no token and an error", c.name, tok, err)
			continue
		}
		for _, w := range c.quoted {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error = %q, want it to carry %q", c.name, err, w)
			}
		}
		for _, a := range c.absent {
			if strings.Contains(err.Error(), a) {
				t.Errorf("%s: error = %q, carries %q", c.name, err, a)
			}
		}
	}
}

// CWE-209, CWE-532.
func TestExchangeErrorExcerptIsCutCleanAndRedacted(t *testing.T) {
	exchange := replyExchange(t)
	body := func(desc string) string {
		b, err := json.Marshal(map[string]string{"error": "invalid_grant", "error_description": desc})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	const unit = "€: "
	short := strings.TrimSpace(strings.Repeat(unit, 3))
	if _, err := exchange(http.StatusBadRequest, body(short), "code"); err == nil || !strings.Contains(err.Error(), short) {
		t.Fatalf("control: err = %v, want it to quote %q", err, short)
	}

	// The pads put the cut at every offset within the unit.
	for pad := range len(unit) {
		desc := strings.Repeat("a", pad) + strings.Repeat(unit, 2000)
		_, err := exchange(http.StatusBadRequest, body(desc), "code")
		if err == nil {
			t.Fatalf("pad %d: want an error", pad)
		}
		msg := err.Error()
		last, _ := utf8.DecodeLastRuneInString(msg)
		if !utf8.ValidString(msg) || len(msg) >= len(desc) || last == ':' || unicode.IsSpace(last) {
			t.Errorf("pad %d: error ends %q (%d bytes, valid UTF-8 = %v), want a whole-rune cut shorter than the %d-byte description, without a trailing colon or space",
				pad, msg[max(0, len(msg)-8):], len(msg), utf8.ValidString(msg), len(desc))
		}
	}

	const code = "  Q9W8E7R6T5  "
	_, err := exchange(http.StatusBadRequest, body(code), code)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") || strings.Contains(err.Error(), strings.TrimSpace(code)) {
		t.Errorf("code echoed as the description: err = %v, want invalid_grant and no code", err)
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

	bidi := &AuthError{Code: "access\u202e_denied\u2066", Description: "user\u2028 said\u2029 no"}
	got = bidi.Error()
	for _, r := range []rune{'\u202e', '\u2066', '\u2028', '\u2029'} {
		if strings.ContainsRune(got, r) {
			t.Errorf("AuthError{%q, %q}.Error() = %q, holds %U", bidi.Code, bidi.Description, got, r)
		}
	}
	for _, want := range []string{"access_denied", "user said no"} {
		if !strings.Contains(got, want) {
			t.Errorf("AuthError{%q, %q}.Error() = %q, want it to carry %q", bidi.Code, bidi.Description, got, want)
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

// findDropped returns the first control, format or line/paragraph separator rune in s.
func findDropped(s string) (rune, bool) {
	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return r, true
		}
	}
	return 0, false
}

// CWE-150, CWE-400.
func TestCallbackErrorFieldsAreCleanedAndCapped(t *testing.T) {
	s := start(t, testFlow())
	var authErr *AuthError
	_, err := s.ParseCallback("testscheme://auth/prod?error=access_denied&error_description=user+said+no&state=" + s.pkce.state)
	if !errors.As(err, &authErr) || authErr.Code != "access_denied" || authErr.Description != "user said no" {
		t.Fatalf("control: ParseCallback = %v, want *AuthError access_denied: user said no", err)
	}

	_, err = s.ParseCallback("testscheme://auth/prod?error=access%E2%80%AE_denied%1B" + strings.Repeat("a", 5000) +
		"&error_description=user+said+no%E2%80%A8" + strings.Repeat("%E2%82%AC", 5000) + "&state=" + s.pkce.state)
	if !errors.As(err, &authErr) {
		t.Fatalf("ParseCallback = %v, want *AuthError", err)
	}
	c := authErr.Code
	if r, ok := findDropped(c); ok || !strings.HasPrefix(c, "access_denieda") || len(c) > maxErrorCode {
		t.Errorf("Code = %.40q (%d bytes), dropped rune %U found = %v, want access_denieda... within %d bytes", c, len(c), r, ok, maxErrorCode)
	}
	d := authErr.Description
	if r, ok := findDropped(d); ok || !strings.HasPrefix(d, "user said no€") || len(d) > maxErrorDescription || !utf8.ValidString(d) {
		t.Errorf("Description = %.40q (%d bytes), dropped rune %U found = %v, want valid UTF-8 user said no€... within %d bytes", d, len(d), r, ok, maxErrorDescription)
	}
	if r, ok := findDropped(err.Error()); ok {
		t.Errorf("Error() holds %U", r)
	}
}
