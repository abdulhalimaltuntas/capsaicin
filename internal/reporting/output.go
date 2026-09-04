package reporting

import (
	"io"
	"os"
)

// createOutput opens name for writing. The special name "-" writes to stdout
// (and is not closed), enabling `-o -` to stream a report into a pipeline.
func createOutput(name string) (io.WriteCloser, error) {
	if name == "-" {
		return nopWriteCloser{os.Stdout}, nil
	}
	return os.Create(name)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
