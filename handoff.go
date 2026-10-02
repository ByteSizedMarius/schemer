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
	"strconv"
	"strings"
	"time"
)

// IsCallback reports whether args[1] is a callback URL for scheme.
func IsCallback(args []string, scheme string) bool {
	return scheme != "" && len(args) > 1 && strings.HasPrefix(strings.ToLower(args[1]), strings.ToLower(scheme)+":")
}

// HandleCallback forwards a callback URL to the session waiting for it.
func HandleCallback(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("schemer: parsing callback URL: %w", err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("schemer: callback URL %q has no scheme", rawURL)
	}

	port, err := readPortFile(portFilePath(u.Scheme))
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?%s", port, u.RawQuery))
	if err != nil {
		return fmt.Errorf("schemer: reaching the waiting session: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("schemer: the waiting session rejected the callback: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func portFilePath(scheme string) string {
	return filepath.Join(os.TempDir(), "schemer-"+strings.ToLower(scheme)+".port")
}

// Windows refuses to delete the port file while the returned file is open.
func lockPortFile(scheme string, port int) (*os.File, error) {
	path := portFilePath(scheme)
	f, err := createPortFile(path, port)
	if !errors.Is(err, fs.ErrExist) {
		return f, err
	}

	inProgress := fmt.Errorf("%w (%s)", ErrInProgress, path)
	held, err := readPortFile(path)
	var corrupt *strconv.NumError
	switch {
	case errors.As(err, &corrupt):
		// An unparsable port file counts as stale.
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("schemer: creating the port file: %w", err)
	}
	if _, err := f.WriteString(strconv.Itoa(port)); err != nil {
		return nil, errors.Join(fmt.Errorf("schemer: writing the port file: %w", err), f.Close(), os.Remove(path))
	}
	return f, nil
}

func readPortFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("schemer: no login is waiting for this callback: %w", err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("schemer: port file %s is corrupt: %w", path, err)
	}
	return port, nil
}
