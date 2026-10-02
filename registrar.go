package schemer

type registrarFunc func(scheme, displayName, exePath string) (restore func() error, err error)
