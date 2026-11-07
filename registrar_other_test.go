//go:build !windows

package schemer

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestWaitReturnsErrUnsupportedOS(t *testing.T) {
	const scheme = "schemertest-unsupported"
	f := testFlow()
	f.RedirectURI = scheme + "://auth/prod"
	path := testPortFile(t, scheme)
	t.Cleanup(func() { os.Remove(path) })
	s := start(t, f)
	defer s.Close()

	if _, err := waitWithin(t, context.Background(), s, 10*time.Second); !errors.Is(err, ErrUnsupportedOS) {
		t.Fatalf("err = %v, want ErrUnsupportedOS", err)
	}
	if fileExists(testPortFile(t, scheme)) {
		t.Error("Wait left a port file")
	}
}
