//go:build unix

package schemer

import (
	"errors"
	"syscall"
)

const portFileReadFlag = syscall.O_NONBLOCK

func isENXIO(err error) bool { return errors.Is(err, syscall.ENXIO) }
