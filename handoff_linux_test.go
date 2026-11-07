package schemer

import (
	"io/fs"
	"net"
	"testing"
)

// readPortFile maps ENXIO, the error Linux gives for opening a socket.
func TestSocketPortFileIsTakenOver(t *testing.T) {
	assertNonRegularTakenOver(t, "schemertest-sock", func(t *testing.T, path string) {
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
	}, fs.ModeSocket)
}
