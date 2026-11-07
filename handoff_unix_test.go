//go:build unix

package schemer

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"testing"
	"time"
)

// assertNonRegularTakenOver fails unless HandleCallback calls the planted port file corrupt and Wait takes it over.
func assertNonRegularTakenOver(t *testing.T, scheme string, plant func(t *testing.T, path string), mode fs.FileMode) {
	t.Helper()
	path := testPortFile(t, scheme)
	plant(t, path)
	if info, err := os.Lstat(path); err != nil || info.Mode().Type() != mode {
		t.Fatalf("control: the port-file path is not of type %v (Lstat error %v)", mode, err)
	}

	done := make(chan error, 1)
	go func() { done <- HandleCallback(scheme + "://auth/prod?code=c&state=s") }()
	select {
	case err := <-done:
		var corrupt corruptPortFile
		if !errors.As(err, &corrupt) {
			t.Errorf("HandleCallback = %v, want the corrupt port file error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleCallback did not return within 5s")
	}
	waitTakesOver(t, scheme)
}

func TestNonRegularPortFileIsTakenOver(t *testing.T) {
	assertNonRegularTakenOver(t, "schemertest-nr", func(t *testing.T, path string) {
		if out, err := exec.Command("mkfifo", "-m", "600", path).CombinedOutput(); err != nil {
			t.Fatalf("mkfifo: %v: %s", err, out)
		}
	}, fs.ModeNamedPipe)
}

func TestPortFileAppearsWithTheWholePort(t *testing.T) {
	const scheme, port = "schemertest-publish", 54321
	path := testPortFile(t, scheme)
	calls := 0
	var atHook error
	saved := portFileHook
	t.Cleanup(func() { portFileHook = saved })
	portFileHook = func() {
		calls++
		_, atHook = os.Lstat(path)
	}

	f, err := lockPortFile(scheme, port)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if calls != 1 {
		t.Fatalf("control: the hook ran %d times, want 1", calls)
	}
	if !errors.Is(atHook, fs.ErrNotExist) {
		t.Errorf("Lstat of the port file before it became readable = %v, want fs.ErrNotExist", atHook)
	}
	if got, err := readPortFile(path); err != nil || got != port {
		t.Errorf("readPortFile = %d, %v, want %d", got, err, port)
	}
}
