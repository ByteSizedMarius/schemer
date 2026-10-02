//go:build !windows

package schemer

func registerScheme(scheme, displayName, exePath string) (func() error, error) {
	return nil, ErrUnsupportedOS
}

func openBrowser(rawURL string) error {
	return ErrUnsupportedOS
}
