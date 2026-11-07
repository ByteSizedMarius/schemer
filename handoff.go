package schemer

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// IsCallback reports whether args[1] starts with scheme and a colon, ignoring the case of ASCII letters.
func IsCallback(args []string, scheme string) bool {
	if scheme == "" || len(args) < 2 {
		return false
	}
	arg, want := args[1], scheme+":"
	if len(arg) < len(want) {
		return false
	}
	for i := range len(want) {
		if lowerASCII(arg[i]) != lowerASCII(want[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

// maxRejection caps how much of a rejection body HandleCallback reads.
const maxRejection = 4096

// HandleCallback forwards a callback URL to the session waiting for it.
func HandleCallback(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("schemer: parsing callback URL: %w", parseCause(err))
	}
	if u.Scheme == "" {
		return errors.New("schemer: callback URL has no scheme")
	}

	path, err := portFilePath(u.Scheme)
	if err != nil {
		return err
	}
	port, err := readPortFile(path)
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?%s", port, u.RawQuery))
	if err != nil {
		return fmt.Errorf("schemer: reaching the waiting session: %w", reachCause(err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRejection))
	// "ok" is the waiting session's whole answer to a callback it accepts.
	if resp.StatusCode == http.StatusOK && err == nil && string(body) == "ok" {
		return nil
	}
	// The waiting session sends every rejection text with 400.
	if resp.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("schemer: the waiting session rejected the callback (HTTP %d)", resp.StatusCode)
	}
	text, q := strings.TrimSpace(string(body)), u.Query()
	// The rejections the waiting session can send for this query.
	own := []error{errStateMismatch}
	if e := q.Get("error"); e != "" {
		own = append(own, newAuthError(e, q.Get("error_description")))
	} else if q.Get("code") == "" {
		own = append(own, errNoCode)
	}
	for _, sent := range own {
		if text == strings.TrimSpace(sent.Error()) {
			return fmt.Errorf("schemer: the waiting session rejected the callback: %w", sent)
		}
	}
	return fmt.Errorf("schemer: the waiting session rejected the callback (HTTP %d)", resp.StatusCode)
}

// parseCause drops the URL a url.Parse error quotes.
func parseCause(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return errors.New("malformed URL")
}

// reachCause drops the client.Get error text that can quote the query.
func reachCause(err error) error {
	var op *net.OpError
	if errors.As(err, &op) {
		return op
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Timeout() {
		return errors.New("timed out")
	}
	return errors.New("no valid HTTP response")
}

var portFileDir = defaultPortFileDir

// portFileHook is a test seam that runs just before the port becomes readable.
var portFileHook func()

func portFilePath(scheme string) (string, error) {
	dir, err := portFileDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "schemer-"+strings.ToLower(scheme)+".port"), nil
}

// Windows refuses to delete the port file while the returned file is open.
func lockPortFile(scheme string, port int) (*os.File, error) {
	path, err := portFilePath(scheme)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("schemer: creating the port file directory: %w", err)
	}
	f, err := createPortFile(path, port)
	if !errors.Is(err, fs.ErrExist) {
		return f, err
	}

	inProgress := fmt.Errorf("%w (%s)", ErrInProgress, path)
	held, err := readPortFile(path)
	var corrupt corruptPortFile
	switch {
	case errors.As(err, &corrupt):
		// A corrupt port file counts as stale.
	case err != nil:
		return nil, inProgress
	default:
		if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(held)), time.Second); err == nil {
			c.Close()
			return nil, inProgress
		}
	}
	if err := os.Remove(path); err != nil {
		return nil, inProgress
	}
	f, err = createPortFile(path, port)
	if errors.Is(err, fs.ErrExist) {
		return nil, inProgress
	}
	return f, err
}

func createPortFile(path string, port int) (*os.File, error) {
	if runtime.GOOS != "windows" {
		return publishPortFile(path, port)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("schemer: creating the port file: %w", err)
	}
	if portFileHook != nil {
		portFileHook()
	}
	if _, err := f.WriteString(strconv.Itoa(port)); err != nil {
		return nil, errors.Join(fmt.Errorf("schemer: writing the port file: %w", err), f.Close(), os.Remove(path))
	}
	return f, nil
}

// publishPortFile creates path with the whole port already in it.
func publishPortFile(path string, port int) (*os.File, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return nil, fmt.Errorf("schemer: creating the port file: %w", err)
	}
	_, werr := tmp.WriteString(strconv.Itoa(port))
	if err := errors.Join(werr, tmp.Close()); err != nil {
		return nil, errors.Join(fmt.Errorf("schemer: writing the port file: %w", err), os.Remove(tmp.Name()))
	}
	if portFileHook != nil {
		portFileHook()
	}
	linkErr := os.Link(tmp.Name(), path)
	if err := os.Remove(tmp.Name()); err != nil {
		if linkErr == nil {
			err = errors.Join(err, os.Remove(path))
		}
		return nil, fmt.Errorf("schemer: removing the port file's temp name: %w", err)
	}
	if linkErr != nil {
		return nil, fmt.Errorf("schemer: publishing the port file: %w", linkErr)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("schemer: opening the port file: %w", err)
	}
	return f, nil
}

const maxPortFile = 64

func readPortFile(path string) (int, error) {
	// A plain open of a FIFO blocks until a writer opens it.
	f, err := os.OpenFile(path, os.O_RDONLY|portFileReadFlag, 0)
	if isENXIO(err) {
		// Opening a Unix socket fails with ENXIO.
		return 0, corruptPortFile{path}
	}
	if err != nil {
		return 0, fmt.Errorf("schemer: no login is waiting for this callback: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("schemer: no login is waiting for this callback: %w", err)
	}
	// A directory is never taken over as a stale port file.
	if info.IsDir() {
		return 0, fmt.Errorf("schemer: no login is waiting for this callback: %s is a directory", path)
	}
	if !info.Mode().IsRegular() {
		return 0, corruptPortFile{path}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPortFile+1))
	if err != nil {
		return 0, fmt.Errorf("schemer: no login is waiting for this callback: %w", err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if len(b) > maxPortFile || err != nil {
		return 0, corruptPortFile{path}
	}
	return port, nil
}

type corruptPortFile struct{ path string }

func (e corruptPortFile) Error() string { return "schemer: port file " + e.path + " is corrupt" }
