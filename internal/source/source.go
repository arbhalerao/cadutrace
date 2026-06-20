package source

import "os"

// Source provides a CADU stream as an addressable byte slice
type Source interface {
	Bytes() ([]byte, error) // valid until Close
	Name() string
	Close() error
}

// FileSource exposes a CADU file as a byte slice, memory-mapped when possible
type FileSource struct {
	path   string
	data   []byte
	unmap  func() error // non-nil only when memory-mapped
	mapped bool
}

// OpenFile opens a CADU file, memory-mapping it when supported, else reading it in
func OpenFile(path string) (*FileSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() // an established mmap stays valid after the fd is closed

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if size := fi.Size(); size > 0 {
		if data, unmap, err := mapFile(f, int(size)); err == nil {
			return &FileSource{path: path, data: data, unmap: unmap, mapped: true}, nil
		}
		// mmap unsupported or failed: fall through to a plain read
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &FileSource{path: path, data: data}, nil
}

func (s *FileSource) Bytes() ([]byte, error) { return s.data, nil }
func (s *FileSource) Name() string           { return s.path }

// Mapped reports whether the file is memory-mapped (vs read into memory)
func (s *FileSource) Mapped() bool { return s.mapped }

func (s *FileSource) Close() error {
	var err error
	if s.unmap != nil {
		err = s.unmap()
		s.unmap = nil
	}
	s.data = nil
	return err
}
