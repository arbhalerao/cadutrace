//go:build !unix

package source

import (
	"errors"
	"os"
)

// mapFile is unavailable without POSIX mmap; OpenFile falls back to a plain read
func mapFile(_ *os.File, _ int) ([]byte, func() error, error) {
	return nil, nil, errors.New("source: mmap not supported on this platform")
}
