package schemer

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

var errSessionUsed = errors.New("schemer: Wait already ran or the session is closed")

// claimHook is a test seam that runs after the Wait handler claims a callback, before it answers.
var claimHook func()

// sentHook is a test seam that runs after the Wait handler answers, before it sends the result to Wait.
var sentHook func()

// maxExcerpt caps how much of a token response an error message carries.
const maxExcerpt = 512

// Session is one login attempt.
type Session struct {
	flow     Flow
	pkce     pkce
	scheme   string
	done     chan struct{}
	stopOnce sync.Once

	mu       sync.Mutex
	closed   bool
	started  bool
	server   *http.Server
	served   chan struct{}
	portLock *os.File
	restore  func() error
}

// Start returns a Session with a fresh PKCE verifier and state.
func (f Flow) Start() (*Session, error) {
	u, err := url.Parse(f.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("schemer: parsing RedirectURI: %w", err)
	}
	switch u.Scheme {
	case "":
		return nil, fmt.Errorf("schemer: RedirectURI %q has no scheme", f.RedirectURI)
	case "http", "https":
		return nil, fmt.Errorf("schemer: RedirectURI %q uses the %s scheme, it needs a custom scheme", f.RedirectURI, u.Scheme)
	}

	a, err := url.Parse(f.AuthorizeURL)
	if err != nil {
		return nil, fmt.Errorf("schemer: parsing AuthorizeURL: %w", err)
	}
	if a.Scheme != "http" && a.Scheme != "https" {
		return nil, fmt.Errorf("schemer: AuthorizeURL %q is not an http or https URL", f.AuthorizeURL)
	}

	return &Session{flow: f, pkce: newPKCE(), scheme: u.Scheme, done: make(chan struct{})}, nil
}

// AuthorizeURL is Flow.AuthorizeURL with this session's PKCE challenge and state in the query.
func (s *Session) AuthorizeURL() string {
	q := url.Values{}
	for k, v := range s.flow.Extra {
		q[k] = v
	}
	q.Set("response_type", "code")
	q.Set("client_id", s.flow.ClientID)
	q.Set("redirect_uri", s.flow.RedirectURI)
	q.Set("code_challenge", s.pkce.challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", s.pkce.state)
	if len(s.flow.Scopes) > 0 {
		q.Set("scope", strings.Join(s.flow.Scopes, " "))
	}

	sep := "?"
	if strings.Contains(s.flow.AuthorizeURL, "?") {
		sep = "&"
	}
	return s.flow.AuthorizeURL + sep + q.Encode()
}

// Wait registers the scheme, opens AuthorizeURL and blocks until a callback carries this session's state.
func (s *Session) Wait(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("schemer: waiting for the callback: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, s.flow.timeout())
	defer cancel()

	type outcome struct {
		code string
		err  error
	}
	results := make(chan outcome, 1)

	// Wait returns the result of the first callback that carries this session's state and arrives while Wait is open.
	var (
		mu                   sync.Mutex
		open, claimed, ended bool
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !s.ownsState(q.Get("state")) {
			reject(w, errStateMismatch)
			return
		}
		code, err := s.codeFromQuery(q)
		mu.Lock()
		gone := !open || ended
		claim := !gone && !claimed
		if claim {
			claimed = true
		}
		mu.Unlock()
		if gone {
			answer(w, http.StatusGone, "")
			return
		}
		if claim {
			defer func() {
				hook := sentHook
				defer func() { results <- outcome{code: code, err: err} }()
				if hook != nil {
					hook()
				}
			}()
			if claimHook != nil {
				claimHook()
			}
		}
		if err != nil {
			reject(w, err)
		} else {
			answer(w, http.StatusOK, "ok")
		}
	})
	giveUp := func(err error) (string, error) {
		mu.Lock()
		if claimed {
			mu.Unlock()
			r := <-results
			return r.code, r.err
		}
		ended = true
		mu.Unlock()
		return "", err
	}

	if err := s.activate(mux); err != nil {
		return "", err
	}
	mu.Lock()
	open = true
	mu.Unlock()
	select {
	case <-s.done:
		return giveUp(errSessionUsed)
	case <-ctx.Done():
		return giveUp(fmt.Errorf("schemer: waiting for the callback: %w", ctx.Err()))
	default:
	}

	if err := s.open(s.AuthorizeURL()); err != nil {
		return giveUp(fmt.Errorf("schemer: opening the browser: %w", err))
	}

	select {
	case r := <-results:
		return r.code, r.err
	case <-ctx.Done():
		return giveUp(fmt.Errorf("schemer: waiting for the callback: %w", ctx.Err()))
	case <-s.done:
		return giveUp(errSessionUsed)
	}
}

// answer puts the whole response on the connection before it returns.
func answer(w http.ResponseWriter, status int, body string) {
	// Flush without a Content-Length sends the response chunked.
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	io.WriteString(w, body)
	http.NewResponseController(w).Flush()
}

// reject answers 400 with the headers and body http.Error would write.
func reject(w http.ResponseWriter, err error) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	answer(w, http.StatusBadRequest, err.Error()+"\n")
}

// ParseCallback returns the code from a callback URL obtained by hand.
func (s *Session) ParseCallback(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("schemer: parsing callback URL: %w", parseCause(err))
	}
	return s.codeFromQuery(u.Query())
}

// Exchange trades code and the PKCE verifier for a token at TokenURL.
func (s *Session) Exchange(ctx context.Context, code string) (*Token, error) {
	ctx, cancel := context.WithTimeout(ctx, s.flow.timeout())
	defer cancel()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {s.flow.ClientID},
		"code":          {code},
		"redirect_uri":  {s.flow.RedirectURI},
		"code_verifier": {s.pkce.verifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.flow.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("schemer: building the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.flow.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("schemer: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("schemer: reading the token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("schemer: token endpoint returned %d", resp.StatusCode)
		if len(body) == 0 {
			return nil, errors.New(msg)
		}
		var v any
		if json.Unmarshal(body, &v) != nil {
			return nil, fmt.Errorf("%s (non-JSON body, %d bytes)", msg, len(body))
		}
		obj, _ := v.(map[string]any)
		e, _ := obj["error"].(string)
		desc, _ := obj["error_description"].(string)
		return nil, s.tokenError(msg, e, desc, code)
	}

	var r struct {
		Token
		Error            json.RawMessage `json:"error"`
		ErrorDescription json.RawMessage `json:"error_description"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, fmt.Errorf("schemer: parsing the token response (HTTP 200, %d bytes)", len(body))
	}
	if r.AccessToken == "" {
		const msg = "schemer: the token response has no access_token"
		e := jsonString(r.Error)
		if strings.TrimSpace(cleanText(e)) == "" {
			return nil, errors.New(msg)
		}
		return nil, s.tokenError(msg, e, jsonString(r.ErrorDescription), code)
	}
	t := r.Token
	t.Raw = body
	return &t, nil
}

// Close restores the scheme registration and releases the callback listener.
func (s *Session) Close() error {
	s.stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeLocked()
}

func (s *Session) stop() {
	s.stopOnce.Do(func() { close(s.done) })
}

// activate starts the listener, takes the port lock and registers the scheme.
func (s *Session) activate(h http.Handler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.started {
		return errSessionUsed
	}
	s.started = true
	if err := s.acquireLocked(h); err != nil {
		return errors.Join(err, s.closeLocked())
	}
	return nil
}

func (s *Session) acquireLocked(h http.Handler) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("schemer: binding callback listener: %w", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	served := make(chan struct{})
	s.server, s.served = srv, served
	go func() {
		defer close(served)
		srv.Serve(ln)
	}()

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("schemer: locating this executable: %w", err)
	}
	lock, err := lockPortFile(s.scheme, ln.Addr().(*net.TCPAddr).Port)
	if err != nil {
		return err
	}
	s.portLock = lock
	restore, err := s.register(exe)
	if err != nil {
		return err
	}
	s.restore = restore
	return nil
}

func (s *Session) closeLocked() error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.stop()

	var errs []error
	if s.restore != nil {
		errs = append(errs, s.restore())
	}
	if s.portLock != nil {
		errs = append(errs, s.portLock.Close())
		// A second instance reading the port file blocks its removal on Windows.
		deadline := time.Now().Add(time.Second)
		for {
			err := os.Remove(s.portLock.Name())
			if err == nil || errors.Is(err, fs.ErrNotExist) {
				break
			}
			if time.Now().After(deadline) {
				errs = append(errs, err)
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if s.server != nil {
		errs = append(errs, s.server.Close())
		<-s.served
	}
	return errors.Join(errs...)
}

// ownsState compares in constant time, whatever the length of state.
func (s *Session) ownsState(state string) bool {
	got, want := sha256.Sum256([]byte(state)), sha256.Sum256([]byte(s.pkce.state))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func (s *Session) codeFromQuery(q url.Values) (string, error) {
	if e := q.Get("error"); e != "" {
		return "", newAuthError(e, q.Get("error_description"))
	}
	if !s.ownsState(q.Get("state")) {
		return "", errStateMismatch
	}
	code := q.Get("code")
	if code == "" {
		return "", errNoCode
	}
	return code, nil
}

func (s *Session) register(exe string) (func() error, error) {
	reg := s.flow.registrar
	if reg == nil {
		reg = registerScheme
	}
	name := s.flow.DisplayName
	if name == "" {
		name = s.scheme
	}
	return reg(s.scheme, name, exe)
}

func (s *Session) open(rawURL string) error {
	if s.flow.opener != nil {
		return s.flow.opener(rawURL)
	}
	return openBrowser(rawURL)
}

// redact replaces the verifier and code in text from the token endpoint.
func (s *Session) redact(text, code string) string {
	// In a single pass, a code that overlaps the verifier would leave part of the verifier unredacted.
	text = strings.ReplaceAll(text, s.pkce.verifier, "[redacted]")
	var pairs []string
	clean := cleanText(code)
	for _, form := range []string{code, url.QueryEscape(code), clean, strings.TrimSpace(clean)} {
		if form != "" {
			pairs = append(pairs, form, "[redacted]")
		}
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

func (s *Session) tokenError(msg, e, desc, code string) error {
	detail := excerpt(s.redact(errorText(e, desc), code))
	if detail == "" {
		return errors.New(msg)
	}
	return fmt.Errorf("%s: %s", msg, detail)
}

func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func errorText(e, desc string) string {
	var parts []string
	for _, p := range []string{e, desc} {
		if p = strings.TrimSpace(cleanText(p)); p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ": ")
}

func excerpt(s string) string {
	if len(s) > maxExcerpt {
		s = strings.TrimRightFunc(truncate(s, maxExcerpt), func(r rune) bool { return r == ':' || unicode.IsSpace(r) })
	}
	return strings.TrimSpace(s)
}
