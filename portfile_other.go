//go:build !unix

package schemer

const portFileReadFlag = 0

func isENXIO(error) bool { return false }
