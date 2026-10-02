package schemer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// callbackFlow sends callbackQuery through HandleCallback instead of a browser.
func callbackFlow(t *testing.T, scheme string, callbackQuery func(state string) string) (Flow, <-chan error) {
	t.Helper()

	f := testFlow()
	f.RedirectURI = scheme + "://auth/prod"
	f.Timeout = 5 * time.Second
	f.registrar = func(_, _, _ string) (func() error, error) {
		return func() error { return nil }, nil
	}
	handoff := make(chan error, 1)
	f.opener = func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		handoff <- HandleCallback(fmt.Sprintf("%s://auth/prod?%s", scheme, callbackQuery(u.Query().Get("state"))))
		return nil
	}
	t.Cleanup(func() { os.Remove(portFilePath(scheme)) })
	return f, handoff
}

// handedOff returns the HandleCallback result of an opener that ran before Wait returned.
func handedOff(t *testing.T, handoff <-chan error) error {
	t.Helper()
	select {
	case err := <-handoff:
		return err
	default:
		t.Fatal("Wait returned without calling the opener")
		return nil
	}
}

func waitWithin(t *testing.T, ctx context.Context, s *Session, d time.Duration) (string, error) {
	t.Helper()
	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := s.Wait(ctx)
		done <- result{code, err}
	}()
	select {
	case r := <-done:
		return r.code, r.err
	case <-time.After(d):
		t.Fatalf("Wait did not return within %s", d)
		return "", nil
	}
}

func start(t *testing.T, f Flow) *Session {
	t.Helper()
	s, err := f.Start()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type fakeRegistrar struct {
	registerErr error
	restoreErr  error

	registered         atomic.Int32
	restored           atomic.Int32
	portFileAtRegister atomic.Bool
	portFileAtRestore  atomic.Bool
}

func (r *fakeRegistrar) register(scheme, _, _ string) (func() error, error) {
	r.registered.Add(1)
	r.portFileAtRegister.Store(fileExists(portFilePath(scheme)))
	if r.registerErr != nil {
		return nil, r.registerErr
	}
	return func() error {
		r.restored.Add(1)
		r.portFileAtRestore.Store(fileExists(portFilePath(scheme)))
		return r.restoreErr
	}, nil
}

func validQuery(code string) func(state string) string {
	return func(state string) string { return "code=" + code + "&state=" + state }
}

type waitResult struct {
	code string
	err  error
}

func loopbackAddr(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func portFromFile(scheme string) (int, error) {
	b, err := os.ReadFile(portFilePath(scheme))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func acceptsConnections(port int) bool {
	c, err := net.DialTimeout("tcp", loopbackAddr(port), 3*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func TestWaitDeliversCode(t *testing.T) {
	f, handoff := callbackFlow(t, "schemertest-ok", validQuery("the-code"))
	s := start(t, f)
	defer s.Close()

	code, err := waitWithin(t, context.Background(), s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code != "the-code" {
		t.Errorf("code = %q, want the-code", code)
	}
	if err := handedOff(t, handoff); err != nil {
		t.Errorf("HandleCallback: %v", err)
	}
}

func TestWaitRegistersDisplayName(t *testing.T) {
	f, _ := callbackFlow(t, "schemertest-name", validQuery("the-code"))
	f.DisplayName = "Schemer Test"
	var got string
	f.registrar = func(_, displayName, _ string) (func() error, error) {
		got = displayName
		return func() error { return nil }, nil
	}
	s := start(t, f)
	defer s.Close()

	if _, err := waitWithin(t, context.Background(), s, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if got != f.DisplayName {
		t.Errorf("registrar got the display name %q, want %q", got, f.DisplayName)
	}
}

func TestWaitIgnoresForeignState(t *testing.T) {
	const scheme = "schemertest-state"
	f, handoff := callbackFlow(t, scheme, validQuery("the-code"))
	deliver := f.opener
	forged := map[string]error{}
	f.opener = func(rawURL string) error {
		for _, q := range []string{"code=forged&state=somebody-elses-state", "code=forged", "error=access_denied"} {
			forged[q] = HandleCallback(scheme + "://auth/prod?" + q)
		}
		return deliver(rawURL)
	}
	s := start(t, f)
	defer s.Close()

	code, err := waitWithin(t, context.Background(), s, 10*time.Second)
	if err != nil || code != "the-code" {
		t.Errorf("Wait = %q, %v, want the-code from the valid callback", code, err)
	}
	if err := handedOff(t, handoff); err != nil {
		t.Errorf("valid callback: HandleCallback: %v", err)
	}
	for q, err := range forged {
		if err == nil {
			t.Errorf("forged %q: HandleCallback = nil, want the rejection", q)
		}
	}
}

func TestWaitSurfacesProviderError(t *testing.T) {
	f, handoff := callbackFlow(t, "schemertest-autherr", func(state string) string {
		return "error=access_denied&error_description=user+said+no&state=" + state
	})
	s := start(t, f)
	defer s.Close()

	_, err := waitWithin(t, context.Background(), s, 10*time.Second)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want *AuthError", err)
	}
	if authErr.Code != "access_denied" || authErr.Description != "user said no" {
		t.Errorf("authErr = %+v", authErr)
	}
	if err := handedOff(t, handoff); err == nil {
		t.Error("HandleCallback = nil, want the rejection")
	}
}

func TestWaitTimesOutAndCloseCleansUp(t *testing.T) {
	const scheme = "schemertest-timeout"
	reg := &fakeRegistrar{}
	f, _ := callbackFlow(t, scheme, nil)
	f.Timeout = 20 * time.Millisecond
	f.registrar = reg.register
	f.opener = func(string) error { return nil }
	s := start(t, f)
	defer s.Close()

	began := time.Now()
	_, err := waitWithin(t, context.Background(), s, 5*time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if elapsed := time.Since(began); elapsed > 2*time.Second {
		t.Errorf("Wait took %s, want the 20ms deadline", elapsed)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reg.restored.Load() != 1 {
		t.Errorf("Close ran restore %d times, want 1", reg.restored.Load())
	}
	if fileExists(portFilePath(scheme)) {
		t.Error("port file survived Close")
	}
}

func TestWaitHonoursContextCancel(t *testing.T) {
	f, _ := callbackFlow(t, "schemertest-cancel", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.opener = func(string) error { cancel(); return nil }
	s := start(t, f)
	defer s.Close()

	if _, err := waitWithin(t, ctx, s, 10*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want Canceled", err)
	}
}

func TestConcurrentSchemesDoNotCollide(t *testing.T) {
	var wg sync.WaitGroup
	for _, scheme := range []string{"schemertest-a", "schemertest-b", "schemertest-c"} {
		want := "code-for-" + scheme
		f, _ := callbackFlow(t, scheme, validQuery(want))
		wg.Add(1)
		go func() {
			defer wg.Done()

			s, err := f.Start()
			if err != nil {
				t.Error(err)
				return
			}
			defer s.Close()

			code, err := s.Wait(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			if code != want {
				t.Errorf("%s: code = %q, want %q", scheme, code, want)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("concurrent sessions did not finish")
	}
}

func TestSecondWaitFails(t *testing.T) {
	reg := &fakeRegistrar{}
	f, handoff := callbackFlow(t, "schemertest-twice", validQuery("the-code"))
	f.registrar = reg.register
	s := start(t, f)
	defer s.Close()

	if code, err := waitWithin(t, context.Background(), s, 10*time.Second); err != nil || code != "the-code" {
		t.Fatalf("first Wait = %q, %v", code, err)
	}
	if err := handedOff(t, handoff); err != nil {
		t.Fatalf("first HandleCallback: %v", err)
	}

	if code, err := waitWithin(t, context.Background(), s, 10*time.Second); !errors.Is(err, errSessionUsed) {
		t.Errorf("second Wait = %q, %v, want errSessionUsed", code, err)
	}
	if n := reg.registered.Load(); n != 1 {
		t.Errorf("registrar called %d times, want 1", n)
	}
}

func TestWaitAfterCloseFails(t *testing.T) {
	reg := &fakeRegistrar{}
	f, _ := callbackFlow(t, "schemertest-closed", validQuery("the-code"))
	f.registrar = reg.register
	var opened atomic.Bool
	f.opener = func(string) error { opened.Store(true); return errors.New("opened after Close") }
	s := start(t, f)

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if code, err := waitWithin(t, context.Background(), s, 10*time.Second); !errors.Is(err, errSessionUsed) {
		t.Errorf("Wait after Close = %q, %v, want errSessionUsed", code, err)
	}
	if n := reg.registered.Load(); n != 0 {
		t.Errorf("registrar called %d times after Close, want 0", n)
	}
	if opened.Load() {
		t.Error("Wait after Close opened the browser")
	}
}

func TestSecondSessionOnBusySchemeGetsErrInProgress(t *testing.T) {
	const scheme = "schemertest-busy"
	first, _ := callbackFlow(t, scheme, nil)
	opened := make(chan struct{})
	first.opener = func(string) error { close(opened); return nil }
	s1 := start(t, first)
	defer s1.Close()

	type result struct {
		code string
		err  error
	}
	firstDone := make(chan result, 1)
	go func() {
		code, err := s1.Wait(context.Background())
		firstDone <- result{code, err}
	}()
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("the first session never started waiting")
	}

	reg := &fakeRegistrar{}
	second, _ := callbackFlow(t, scheme, nil)
	second.registrar = reg.register
	second.opener = func(string) error { return errors.New("the second session opened the browser") }
	s2 := start(t, second)
	defer s2.Close()

	if _, err := waitWithin(t, context.Background(), s2, 10*time.Second); !errors.Is(err, ErrInProgress) {
		t.Errorf("second Wait err = %v, want ErrInProgress", err)
	}
	if n := reg.registered.Load(); n != 0 {
		t.Errorf("second registrar called %d times, want 0", n)
	}

	if err := HandleCallback(scheme + "://auth/prod?code=first&state=" + s1.pkce.state); err != nil {
		t.Errorf("callback for the first session: %v", err)
	}
	select {
	case r := <-firstDone:
		if r.err != nil || r.code != "first" {
			t.Errorf("first Wait = %q, %v, want first", r.code, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the first session never got its callback")
	}
}

func TestWaitTakesOverStalePortFile(t *testing.T) {
	const scheme = "schemertest-stale"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stalePort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	f, handoff := callbackFlow(t, scheme, validQuery("the-code"))
	if err := os.WriteFile(portFilePath(scheme), []byte(strconv.Itoa(stalePort)), 0600); err != nil {
		t.Fatal(err)
	}
	s := start(t, f)

	code, err := waitWithin(t, context.Background(), s, 10*time.Second)
	if err != nil || code != "the-code" {
		t.Fatalf("Wait = %q, %v, want the-code", code, err)
	}
	if err := handedOff(t, handoff); err != nil {
		t.Errorf("HandleCallback: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if fileExists(portFilePath(scheme)) {
		t.Error("port file survived Close")
	}
}

func TestRunReturnsTokenWithRestoreError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"access_token":"tok"}`)
	}))
	defer srv.Close()

	restoreErr := errors.New("restore failed")
	f, _ := callbackFlow(t, "schemertest-run", validQuery("the-code"))
	f.TokenURL = srv.URL
	f.registrar = (&fakeRegistrar{restoreErr: restoreErr}).register

	type result struct {
		tok *Token
		err error
	}
	done := make(chan result, 1)
	go func() {
		tok, err := f.Run(context.Background())
		done <- result{tok, err}
	}()
	select {
	case r := <-done:
		if r.tok == nil || r.tok.AccessToken != "tok" {
			t.Errorf("token = %+v, want the exchanged token", r.tok)
		}
		if !errors.Is(r.err, restoreErr) {
			t.Errorf("err = %v, want the restore error", r.err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return")
	}
}

// trackingRegistrar records the port its session holds while registering.
type trackingRegistrar struct {
	registerErr error
	restoreErr  error

	registered atomic.Int32
	restored   atomic.Int32
	port       atomic.Int32
	alive      atomic.Bool
}

func (r *trackingRegistrar) register(scheme, _, _ string) (func() error, error) {
	r.registered.Add(1)
	if port, err := portFromFile(scheme); err == nil {
		r.port.Store(int32(port))
		r.alive.Store(acceptsConnections(port))
	}
	if r.registerErr != nil {
		return nil, r.registerErr
	}
	return func() error {
		r.restored.Add(1)
		return r.restoreErr
	}, nil
}

// exitPath is one way a session can end.
type exitPath struct {
	name    string
	setup   func(f *Flow, tr *trackingRegistrar)
	drive   func(t *testing.T, f Flow) error
	wantErr error
}

func waitThenClose(t *testing.T, f Flow, ctx context.Context) error {
	s := start(t, f)
	code, err := waitWithin(t, ctx, s, 10*time.Second)
	t.Logf("Wait = %q, %v", code, err)
	return s.Close()
}

// runExitPaths fails unless each path leaves no listener, no port file and no unrestored registration.
func runExitPaths(t *testing.T, paths []exitPath) {
	for _, c := range paths {
		t.Run(c.name, func(t *testing.T) {
			scheme := "schemertest-exit" + strings.ReplaceAll(c.name, " ", "")
			tr := &trackingRegistrar{}
			f, _ := callbackFlow(t, scheme, validQuery("the-code"))
			f.registrar = tr.register
			if c.setup != nil {
				c.setup(&f, tr)
			}

			err := c.drive(t, f)
			if c.wantErr == nil && err != nil && !strings.HasPrefix(c.name, "run") {
				t.Errorf("Close = %v, want nil", err)
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Errorf("Close = %v, want %v", err, c.wantErr)
			}

			port := int(tr.port.Load())
			if port == 0 {
				t.Fatal("control: the registrar never saw a port file")
			}
			if !tr.alive.Load() {
				t.Errorf("control: port %d refused connections while registering", port)
			}
			if acceptsConnections(port) {
				t.Errorf("port %d still accepts connections after Close", port)
			}
			if fileExists(portFilePath(scheme)) {
				t.Error("the port file survived Close")
			}
			want := tr.registered.Load()
			if tr.registerErr != nil {
				want = 0
			}
			if got := tr.restored.Load(); got != want {
				t.Errorf("restore ran %d times after %d registrations, want %d", got, tr.registered.Load(), want)
			}
		})
	}
}

func TestCloseLeavesNothingOnEveryExitPath(t *testing.T) {
	restoreErr := errors.New("restore failed")

	runExitPaths(t, []exitPath{
		{"callback", nil, func(t *testing.T, f Flow) error {
			return waitThenClose(t, f, context.Background())
		}, nil},
		{"registrar error", func(_ *Flow, tr *trackingRegistrar) {
			tr.registerErr = errors.New("registry says no")
		}, func(t *testing.T, f Flow) error {
			return waitThenClose(t, f, context.Background())
		}, nil},
		{"restore error", func(_ *Flow, tr *trackingRegistrar) {
			tr.restoreErr = restoreErr
		}, func(t *testing.T, f Flow) error {
			return waitThenClose(t, f, context.Background())
		}, restoreErr},
		{"close while waiting", nil, func(t *testing.T, f Flow) error {
			opened := make(chan struct{})
			f.opener = func(string) error { close(opened); return nil }
			s := start(t, f)
			waitDone := make(chan error, 1)
			go func() {
				_, err := s.Wait(context.Background())
				waitDone <- err
			}()
			select {
			case <-opened:
			case <-time.After(10 * time.Second):
				t.Fatal("Wait never opened the browser")
			}
			err := s.Close()
			select {
			case werr := <-waitDone:
				if !errors.Is(werr, errSessionUsed) {
					t.Errorf("Wait = %v, want errSessionUsed", werr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Wait kept waiting after Close")
			}
			return err
		}, nil},
	})
}

func TestHandleCallbackWithoutWaiter(t *testing.T) {
	if err := HandleCallback("schemertest-orphan://auth/prod?code=x&state=y"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestIsCallback(t *testing.T) {
	cases := []struct {
		args   []string
		scheme string
		want   bool
	}{
		{[]string{"tool.exe", "HCAUTH://auth/prod"}, "hcauth", true},
		{[]string{"tool.exe", "hcauth://auth/prod"}, "HCAUTH", true},
		{[]string{"tool.exe", "hcauthx://auth"}, "hcauth", false},
		{[]string{"tool.exe", "hcauth://auth"}, "", false},
		{[]string{"tool.exe"}, "hcauth", false},
	}
	for _, c := range cases {
		if got := IsCallback(c.args, c.scheme); got != c.want {
			t.Errorf("IsCallback(%q, %q) = %v", c.args, c.scheme, got)
		}
	}
}
