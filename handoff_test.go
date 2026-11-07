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
	"path/filepath"
	"runtime"
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
	path := testPortFile(t, scheme)
	t.Cleanup(func() { os.Remove(path) })
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

// testPortFile returns the port-file path of scheme, under a temp dir unless the test has set the directory.
func testPortFile(t testing.TB, scheme string) string {
	t.Helper()
	if !portDirSet {
		tempPortDir(t)
	}
	path, err := portFilePath(scheme)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

var portDirSet bool

func setPortFileDir(t testing.TB, dir func() (string, error)) {
	t.Helper()
	saved, savedSet := portFileDir, portDirSet
	t.Cleanup(func() { portFileDir, portDirSet = saved, savedSet })
	portFileDir, portDirSet = dir, true
}

func tempPortDir(t testing.TB) {
	t.Helper()
	dir := t.TempDir()
	setPortFileDir(t, func() (string, error) { return dir, nil })
}

// waitTakesOver fails unless Wait replaces whatever sits at the port-file path and Close removes the port file.
func waitTakesOver(t *testing.T, scheme string) {
	t.Helper()
	f, handoff := callbackFlow(t, scheme, validQuery("the-code"))
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
	if fileExists(testPortFile(t, scheme)) {
		t.Error("port file survived Close")
	}
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
	path, err := portFilePath(scheme)
	if err != nil {
		return nil, err
	}
	r.portFileAtRegister.Store(fileExists(path))
	if r.registerErr != nil {
		return nil, r.registerErr
	}
	return func() error {
		r.restored.Add(1)
		r.portFileAtRestore.Store(fileExists(path))
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
	path, err := portFilePath(scheme)
	if err != nil {
		return 0, err
	}
	b, err := os.ReadFile(path)
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
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := strconv.Itoa(dead.Addr().(*net.TCPAddr).Port)
	dead.Close()
	live, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	livePort := live.Addr().(*net.TCPAddr).Port
	padded := func(n int) string {
		p := strconv.Itoa(livePort)
		return p + strings.Repeat(" ", n-len(p))
	}

	path := testPortFile(t, scheme)
	if err := os.WriteFile(path, []byte(padded(64)), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readPortFile(path); err != nil || got != livePort {
		t.Fatalf("control: a 64-byte port file reads as %d, %v, want %d", got, err, livePort)
	}

	for _, c := range []struct{ name, content string }{
		{"dead port", deadPort},
		{"live port in 65 bytes", padded(65)},
	} {
		t.Run(c.name, func(t *testing.T) {
			tempPortDir(t)
			if err := os.WriteFile(testPortFile(t, scheme), []byte(c.content), 0600); err != nil {
				t.Fatal(err)
			}
			waitTakesOver(t, scheme)
		})
	}
}

// CWE-209
func TestCorruptPortFileErrorQuotesNoContent(t *testing.T) {
	const scheme = "schemertest-leak"
	if err := os.WriteFile(testPortFile(t, scheme), []byte("1234 planted-secret"), 0600); err != nil {
		t.Fatal(err)
	}

	err := HandleCallback(scheme + "://auth/prod?code=c&state=s")
	var corrupt corruptPortFile
	if !errors.As(err, &corrupt) {
		t.Fatalf("HandleCallback = %v, want the corrupt port file error", err)
	}
	if strings.Contains(err.Error(), "planted-secret") {
		t.Errorf("HandleCallback = %q quotes the port file", err)
	}
}

// CWE-400.
func TestPortFileReadIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "port")
	read := func() (int, uint64, error) {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		port, err := readPortFile(path)
		runtime.ReadMemStats(&after)
		return port, after.TotalAlloc - before.TotalAlloc, err
	}
	const port = 4242
	if err := os.WriteFile(path, []byte(strconv.Itoa(port)), 0600); err != nil {
		t.Fatal(err)
	}
	if got, grew, err := read(); err != nil || got != port || grew >= 1<<20 {
		t.Fatalf("control: readPortFile = %d, %v after allocating %d bytes, want %d under 1 MiB", got, err, grew, port)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, werr := f.WriteString(strconv.Itoa(port) + strings.Repeat(" ", 100))
	if err := errors.Join(werr, f.Truncate(64<<20), f.Close()); err != nil {
		t.Fatal(err)
	}
	_, grew, err := read()
	var corrupt corruptPortFile
	if !errors.As(err, &corrupt) {
		t.Errorf("readPortFile of a 64 MiB port file = %v, want the corrupt port file error", err)
	}
	if grew >= 1<<20 {
		t.Errorf("readPortFile of a 64 MiB port file allocated %d bytes, want under 1 MiB", grew)
	}
}

func TestPortFileDirectoryIsNeverTakenOver(t *testing.T) {
	const scheme = "schemertest-dir"
	waitTakesOver(t, scheme)
	path := testPortFile(t, scheme)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}

	reg := &fakeRegistrar{}
	f, _ := callbackFlow(t, scheme, nil)
	f.registrar = reg.register
	f.opener = func(string) error { return errors.New("opened the browser beside a directory") }
	s := start(t, f)
	defer s.Close()
	if _, err := waitWithin(t, context.Background(), s, 10*time.Second); err == nil {
		t.Error("Wait = nil, want an error")
	}
	if n := reg.registered.Load(); n != 0 {
		t.Errorf("registrar called %d times, want 0", n)
	}
	var corrupt corruptPortFile
	if err := HandleCallback(scheme + "://auth/prod?code=c&state=s"); err == nil || errors.As(err, &corrupt) {
		t.Errorf("HandleCallback = %v, want an error other than a corrupt port file", err)
	}
	if info, err := os.Lstat(path); err != nil || !info.IsDir() {
		t.Errorf("the port-file path is no longer the directory (Lstat error %v)", err)
	}
}

func TestCloseRestoresBeforeReleasingPortFile(t *testing.T) {
	reg := &fakeRegistrar{}
	f, _ := callbackFlow(t, "schemertest-hold", validQuery("the-code"))
	f.registrar = reg.register
	s := start(t, f)
	if _, err := waitWithin(t, context.Background(), s, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if !reg.portFileAtRegister.Load() {
		t.Fatal("control: the port file was missing while registering")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reg.restored.Load() != 1 || !reg.portFileAtRestore.Load() {
		t.Errorf("restore ran %d times, port file present = %v, want once with the port file present",
			reg.restored.Load(), reg.portFileAtRestore.Load())
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
			if fileExists(testPortFile(t, scheme)) {
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
		{"timeout", func(f *Flow, _ *trackingRegistrar) {
			f.Timeout = 20 * time.Millisecond
			f.opener = func(string) error { return nil }
		}, func(t *testing.T, f Flow) error {
			s := start(t, f)
			began := time.Now()
			if _, err := waitWithin(t, context.Background(), s, 5*time.Second); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Wait = %v, want DeadlineExceeded", err)
			}
			if elapsed := time.Since(began); elapsed > 2*time.Second {
				t.Errorf("Wait took %s, want the 20ms deadline", elapsed)
			}
			return s.Close()
		}, nil},
	})
}

func TestIsCallback(t *testing.T) {
	cases := []struct {
		args   []string
		scheme string
		want   bool
	}{
		{[]string{"tool.exe", "HCAUTH://auth/prod"}, "hcauth", true},
		{[]string{"tool.exe", "hcauth://auth/prod"}, "HCAUTH", true},
		{[]string{"tool.exe", "hcauth:x"}, "hcauth", true},
		{[]string{"tool.exe", "hcauthx://auth"}, "hcauth", false},
		// RFC 3986 3.1, U+212A KELVIN SIGN is not an ASCII K.
		{[]string{"tool.exe", "\u212aapp://auth"}, "kapp", false},
		{[]string{"tool.exe", "hcauth://auth"}, "", false},
		{[]string{"tool.exe"}, "hcauth", false},
	}
	for _, c := range cases {
		if got := IsCallback(c.args, c.scheme); got != c.want {
			t.Errorf("IsCallback(%q, %q) = %v", c.args, c.scheme, got)
		}
	}
}

func writePortFile(t *testing.T, scheme string, port int) {
	t.Helper()
	if err := os.WriteFile(testPortFile(t, scheme), []byte(strconv.Itoa(port)), 0600); err != nil {
		t.Fatal(err)
	}
}

func serveAtPortFile(t *testing.T, scheme string, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	writePortFile(t, scheme, srv.Listener.Addr().(*net.TCPAddr).Port)
}

func answering(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

// assertUntyped fails unless err is an error that matches no exported sentinel and is no *AuthError.
func assertUntyped(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("HandleCallback = nil, want an error")
	}
	for _, sentinel := range []error{ErrStateMismatch, ErrNoCode, ErrInProgress, ErrUnsupportedOS} {
		if errors.Is(err, sentinel) {
			t.Errorf("HandleCallback = %v, matches %v", err, sentinel)
		}
	}
	var authErr *AuthError
	if errors.As(err, &authErr) {
		t.Errorf("HandleCallback = %v, is an *AuthError", err)
	}
}

// CWE-209
func TestHandleCallbackErrorsOmitTheCallback(t *testing.T) {
	const code, state = "PLANTEDCODE4417", "PLANTEDSTATE9023"
	const query = "code=" + code + "&state=" + state
	for _, c := range []struct {
		name string
		call func(t *testing.T, scheme string) error
	}{
		{"unparsable URL", func(t *testing.T, scheme string) error {
			return HandleCallback(scheme + "://auth/%zz?" + query)
		}},
		{"no port file", func(t *testing.T, scheme string) error {
			tempPortDir(t)
			return HandleCallback(scheme + "://auth/prod?" + query)
		}},
		{"no waiter", func(t *testing.T, scheme string) error {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := ln.Addr().(*net.TCPAddr).Port
			ln.Close()
			writePortFile(t, scheme, port)
			return HandleCallback(scheme + "://auth/prod?" + query)
		}},
		{"session rejection", func(t *testing.T, scheme string) error {
			f, _ := callbackFlow(t, scheme, validQuery("the-code"))
			deliver := f.opener
			var rejected error
			f.opener = func(rawURL string) error {
				rejected = HandleCallback(scheme + "://auth/prod?" + query)
				return deliver(rawURL)
			}
			s := start(t, f)
			defer s.Close()
			if got, err := waitWithin(t, context.Background(), s, 10*time.Second); err != nil || got != "the-code" {
				t.Fatalf("control: Wait = %q, %v, want the-code", got, err)
			}
			return rejected
		}},
		{"foreign listener echoing the request", func(t *testing.T, scheme string) error {
			serveAtPortFile(t, scheme, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, r.URL.String())
			})
			return HandleCallback(scheme + "://auth/prod?" + query)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.call(t, "schemertest-leak")
			if err == nil {
				t.Fatal("HandleCallback = nil, want an error")
			}
			for _, planted := range []string{code, state} {
				if strings.Contains(err.Error(), planted) {
					t.Errorf("HandleCallback = %q carries %s", err, planted)
				}
			}
		})
	}
}

func TestHandleCallbackTypesOnlyTheSessionsRejections(t *testing.T) {
	const withCode = "code=c&state=s"
	const withError = "error=access_denied&error_description=user+said+no&state=s"
	isStateMismatch := func(err error) bool { return errors.Is(err, ErrStateMismatch) }
	isAuthError := func(err error) bool {
		var authErr *AuthError
		return errors.As(err, &authErr) && authErr.Code == "access_denied" && authErr.Description == "user said no"
	}
	for _, c := range []struct {
		name   string
		query  string
		status int
		body   string
		typed  func(error) bool
	}{
		{"400 with the session's text", withCode, http.StatusBadRequest, ErrStateMismatch.Error() + "\n", isStateMismatch},
		{"400 with another text", withCode, http.StatusBadRequest, "FOREIGNREJECTION\n", nil},
		{"500 with the session's text", withCode, http.StatusInternalServerError, ErrStateMismatch.Error() + "\n", nil},
		{"400 with ErrNoCode's text for a query with a code", withCode, http.StatusBadRequest, ErrNoCode.Error() + "\n", nil},
		{"400 with the query's own provider error", withError, http.StatusBadRequest,
			(&AuthError{Code: "access_denied", Description: "user said no"}).Error() + "\n", isAuthError},
		{"400 with another provider error", withError, http.StatusBadRequest, (&AuthError{Code: "server_error"}).Error() + "\n", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			const scheme = "schemertest-allow"
			serveAtPortFile(t, scheme, answering(c.status, c.body))
			err := HandleCallback(scheme + "://auth/prod?" + c.query)
			if c.typed != nil {
				if !c.typed(err) {
					t.Errorf("HandleCallback = %v, want the rejection %q typed", err, strings.TrimSpace(c.body))
				}
				return
			}
			assertUntyped(t, err)
			if text := strings.TrimSpace(c.body); strings.Contains(err.Error(), text) {
				t.Errorf("HandleCallback = %q quotes %q", err, text)
			}
		})
	}

	t.Run("a session's rejection of a query without code or error", func(t *testing.T) {
		f, handoff := callbackFlow(t, "schemertest-allownocode", func(state string) string { return "state=" + state })
		s := start(t, f)
		defer s.Close()
		if _, err := waitWithin(t, context.Background(), s, 10*time.Second); !errors.Is(err, ErrNoCode) {
			t.Fatalf("Wait = %v, want ErrNoCode", err)
		}
		if err := handedOff(t, handoff); !errors.Is(err, ErrNoCode) {
			t.Errorf("HandleCallback = %v, want ErrNoCode", err)
		}
	})
}

// CWE-150, CWE-400.
func TestHandleCallbackAuthErrorIsCleanedAndCapped(t *testing.T) {
	code, desc := "access\u202e_denied", strings.Repeat("a", 2*maxErrorDescription)
	f, handoff := callbackFlow(t, "schemertest-autherrcap", func(state string) string {
		return url.Values{"error": {code}, "error_description": {desc}, "state": {state}}.Encode()
	})
	s := start(t, f)
	defer s.Close()

	var authErr *AuthError
	if _, err := waitWithin(t, context.Background(), s, 10*time.Second); !errors.As(err, &authErr) {
		t.Fatalf("Wait = %v, want *AuthError", err)
	}
	err := handedOff(t, handoff)
	if !errors.As(err, &authErr) {
		t.Fatalf("HandleCallback = %.80v, want *AuthError", err)
	}
	if r, ok := findDropped(authErr.Code + authErr.Description); ok || len(authErr.Code) > maxErrorCode || len(authErr.Description) > maxErrorDescription {
		t.Errorf("HandleCallback AuthError = %.40q (%d bytes), %.40q (%d bytes), dropped rune %U found = %v, want them cleaned and within %d and %d bytes",
			authErr.Code, len(authErr.Code), authErr.Description, len(authErr.Description), r, ok, maxErrorCode, maxErrorDescription)
	}
	if want := newAuthError(code, desc); *authErr != *want {
		t.Errorf("HandleCallback AuthError = %.40q, %d-byte Description, want %.40q, %d bytes, as the session builds it",
			authErr.Code, len(authErr.Description), want.Code, len(want.Description))
	}
}

func TestHandleCallbackRefusesRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "ok")
	}))
	defer target.Close()
	const ctl = "schemertest-redirectctl"
	writePortFile(t, ctl, target.Listener.Addr().(*net.TCPAddr).Port)
	if err := HandleCallback(ctl + "://auth/prod?code=c&state=s"); err != nil || hits.Load() != 1 {
		t.Fatalf("control: HandleCallback = %v, target hits = %d, want nil and 1", err, hits.Load())
	}

	const scheme = "schemertest-redirect"
	serveAtPortFile(t, scheme, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.RequestURI(), http.StatusFound)
	})
	assertUntyped(t, HandleCallback(scheme+"://auth/prod?code=c&state=s"))
	if n := hits.Load() - 1; n != 0 {
		t.Errorf("the redirect target saw %d requests, want 0", n)
	}
}

func TestHandleCallbackSucceedsOnlyOnTheSessionsOk(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"200 ok", http.StatusOK, "ok", true},
		{"200 with another body", http.StatusOK, "okay", false},
		{"201 ok", http.StatusCreated, "ok", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			const scheme = "schemertest-okbody"
			serveAtPortFile(t, scheme, answering(c.status, c.body))
			err := HandleCallback(scheme + "://auth/prod?code=c&state=s")
			if c.ok {
				if err != nil {
					t.Errorf("HandleCallback = %v, want nil", err)
				}
				return
			}
			assertUntyped(t, err)
		})
	}
}

func TestHandleCallbackFailsWhenWaitCannotTakeIt(t *testing.T) {
	for _, c := range []struct {
		name string
		call func(t *testing.T, scheme string) error
	}{
		{"before activate finished", func(t *testing.T, scheme string) error {
			f, _ := callbackFlow(t, scheme, validQuery("the-code"))
			var s *Session
			var early error
			f.registrar = func(_, _, _ string) (func() error, error) {
				early = HandleCallback(scheme + "://auth/prod?code=early-code&state=" + s.pkce.state)
				return func() error { return nil }, nil
			}
			s = start(t, f)
			defer s.Close()
			if code, err := waitWithin(t, context.Background(), s, 10*time.Second); err != nil || code != "the-code" {
				t.Errorf("Wait = %q, %v, want the-code from the callback after the open", code, err)
			}
			return early
		}},
		{"after Wait timed out", func(t *testing.T, scheme string) error {
			f, _ := callbackFlow(t, scheme, nil)
			f.Timeout = 20 * time.Millisecond
			f.opener = func(string) error { return nil }
			s := start(t, f)
			defer s.Close()
			if _, err := waitWithin(t, context.Background(), s, 5*time.Second); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("control: Wait = %v, want DeadlineExceeded", err)
			}
			return HandleCallback(scheme + "://auth/prod?code=late-code&state=" + s.pkce.state)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			assertUntyped(t, c.call(t, "schemertest-gone"))
		})
	}
}

func TestClaimedCallbackIsWaitsResult(t *testing.T) {
	for _, c := range []struct {
		name string
		end  func(s *Session, cancel context.CancelFunc)
	}{
		{"Close", func(s *Session, _ context.CancelFunc) { s.Close() }},
		{"ctx cancel", func(_ *Session, cancel context.CancelFunc) { cancel() }},
	} {
		t.Run(c.name, func(t *testing.T) {
			const scheme = "schemertest-claim"
			claimed, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unpark := func() { releaseOnce.Do(func() { close(release) }) }
			saved := claimHook
			t.Cleanup(func() { claimHook = saved })
			t.Cleanup(unpark)
			claimHook = func() {
				close(claimed)
				<-release
			}

			f, _ := callbackFlow(t, scheme, nil)
			opened := make(chan string, 1)
			f.opener = func(rawURL string) error { opened <- rawURL; return nil }
			s := start(t, f)
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			waitDone := make(chan waitResult, 1)
			go func() {
				code, err := s.Wait(ctx)
				waitDone <- waitResult{code, err}
			}()
			var state string
			select {
			case rawURL := <-opened:
				u, err := url.Parse(rawURL)
				if err != nil {
					t.Fatal(err)
				}
				state = u.Query().Get("state")
			case <-time.After(10 * time.Second):
				t.Fatal("Wait never opened the browser")
			}
			handed := make(chan error, 1)
			go func() { handed <- HandleCallback(scheme + "://auth/prod?code=claimed-code&state=" + state) }()
			select {
			case <-claimed:
			case <-time.After(10 * time.Second):
				t.Fatal("the callback was never claimed")
			}

			c.end(s, cancel)
			select {
			case r := <-waitDone:
				t.Fatalf("Wait = %q, %v while the handler held its claim", r.code, r.err)
			case <-time.After(25 * time.Millisecond):
			}
			unpark()
			select {
			case r := <-waitDone:
				if r.err != nil || r.code != "claimed-code" {
					t.Errorf("Wait = %q, %v, want claimed-code", r.code, r.err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Wait did not return")
			}
			select {
			case <-handed:
			case <-time.After(10 * time.Second):
				t.Fatal("HandleCallback did not return")
			}
		})
	}
}

// parkBeforeSend holds the Wait handler in sentHook, between its answer and its send to Wait, until release runs or the test ends.
func parkBeforeSend(t *testing.T) (parked <-chan struct{}, release func()) {
	t.Helper()
	p, r := make(chan struct{}), make(chan struct{})
	var parkOnce, releaseOnce sync.Once
	release = func() { releaseOnce.Do(func() { close(r) }) }
	saved := sentHook
	t.Cleanup(func() { sentHook = saved })
	t.Cleanup(release)
	sentHook = func() {
		parkOnce.Do(func() { close(p) })
		<-r
	}
	return p, release
}

// handOffInBackground is an opener that runs HandleCallback with query and the session's state in its own goroutine.
func handOffInBackground(scheme, query string, handed chan<- error) func(string) error {
	return func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		go func() { handed <- HandleCallback(scheme + "://auth/prod?" + query + "state=" + u.Query().Get("state")) }()
		return nil
	}
}

// handedWhileParked waits for the handler to park in sentHook and returns the HandleCallback result while it stays parked.
func handedWhileParked(t *testing.T, parked <-chan struct{}, handed <-chan error) error {
	t.Helper()
	select {
	case <-parked:
	case <-time.After(10 * time.Second):
		t.Fatal("the Wait handler never reached sentHook")
	}
	select {
	case err := <-handed:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("HandleCallback did not return while the Wait handler sat in sentHook")
		return nil
	}
}

func TestCallbackAnswerArrivesBeforeWaitReturns(t *testing.T) {
	isAuthError := func(err error) bool {
		var authErr *AuthError
		return errors.As(err, &authErr)
	}
	for _, c := range []struct {
		name, query           string
		handed                func(error) bool
		wait                  func(code string, err error) bool
		wantHandOff, wantWait string
	}{
		{"code", "code=the-code&",
			func(err error) bool { return err == nil },
			func(code string, err error) bool { return err == nil && code == "the-code" },
			"nil", "the-code"},
		{"provider error", "error=access_denied&",
			isAuthError,
			func(code string, err error) bool { return code == "" && isAuthError(err) },
			"*AuthError", "*AuthError"},
	} {
		t.Run(c.name, func(t *testing.T) {
			const scheme = "schemertest-sent"
			parked, release := parkBeforeSend(t)
			f, _ := callbackFlow(t, scheme, nil)
			handed := make(chan error, 1)
			f.opener = handOffInBackground(scheme, c.query, handed)
			s := start(t, f)
			defer s.Close()
			waitDone := make(chan waitResult, 1)
			go func() {
				code, err := s.Wait(context.Background())
				waitDone <- waitResult{code, err}
			}()

			if err := handedWhileParked(t, parked, handed); !c.handed(err) {
				t.Errorf("HandleCallback = %v, want %s", err, c.wantHandOff)
			}
			select {
			case r := <-waitDone:
				t.Fatalf("Wait = %q, %v before the handler sent its result", r.code, r.err)
			case <-time.After(25 * time.Millisecond):
			}
			release()
			select {
			case r := <-waitDone:
				if !c.wait(r.code, r.err) {
					t.Errorf("Wait = %q, %v, want %s", r.code, r.err, c.wantWait)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Wait did not return")
			}
		})
	}
}

func TestWaitDoesNotOpenBrowserOnceCtxIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f, _ := callbackFlow(t, "schemertest-ctxdone", nil)
	f.registrar = func(_, _, _ string) (func() error, error) {
		cancel()
		return func() error { return nil }, nil
	}
	var opened atomic.Bool
	f.opener = func(string) error { opened.Store(true); return nil }
	s := start(t, f)
	defer s.Close()

	if _, err := waitWithin(t, ctx, s, 10*time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("Wait = %v, want Canceled", err)
	}
	if opened.Load() {
		t.Error("Wait opened the browser after its ctx was done")
	}
}
