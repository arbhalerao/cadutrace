//go:build unix

package source

import (
	"os"

	"golang.org/x/sys/unix"
)

// mapFile memory-maps the file read-only; the returned slice aliases the mapping
// and stays valid until unmap (and after the file descriptor is closed)
func mapFile(f *os.File, size int) ([]byte, func() error, error) {
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	return data, func() error { return unix.Munmap(data) }, nil
}
