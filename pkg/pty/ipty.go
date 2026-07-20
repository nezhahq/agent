package pty

type IPty interface {
	Write(p []byte) (n int, err error)
	Read(p []byte) (n int, err error)
	Getsize() (uint16, uint16, error)
	Setsize(cols, rows uint32) error
	// Close releases an in-flight Read and completes child-process cleanup before returning.
	Close() error
}
