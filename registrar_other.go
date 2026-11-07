//go:build !windows

package schemer

import "os"

func defaultPortFileDir() (string, error) {
	return os.TempDir(), nil
}

func registerScheme(scheme, displayName, exePath string) (func() error, error) {
	return nil, ErrUnsupportedOS
}

func openBrowser(rawURL string) error {
	return ErrUnsupportedOS
}
