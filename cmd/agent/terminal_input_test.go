package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type terminalPartialWriter struct {
	limit int
	data  bytes.Buffer
	err   error
}

func (writer *terminalPartialWriter) Write(data []byte) (int, error) {
	if writer.err != nil {
		return 0, writer.err
	}
	if len(data) > writer.limit {
		data = data[:writer.limit]
	}
	return writer.data.Write(data)
}

func TestWriteTerminalInputCompletesShortWrites(t *testing.T) {
	writer := &terminalPartialWriter{limit: 3}
	want := []byte("multi-byte 中文 terminal input")
	if err := writeTerminalInput(writer, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writer.data.Bytes(), want) {
		t.Fatalf("terminal input = %q, want %q", writer.data.Bytes(), want)
	}
}

func TestWriteTerminalInputPropagatesWriterFailure(t *testing.T) {
	want := errors.New("pty input failed")
	if err := writeTerminalInput(&terminalPartialWriter{limit: 1, err: want}, []byte("x")); !errors.Is(err, want) {
		t.Fatalf("terminal input error = %v, want %v", err, want)
	}
}

func TestWriteTerminalInputRejectsZeroProgress(t *testing.T) {
	if err := writeTerminalInput(&terminalPartialWriter{limit: 0}, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress input error = %v, want io.ErrShortWrite", err)
	}
}

func TestValidTerminalWindowSizeBounds(t *testing.T) {
	for _, valid := range []terminalWindowSize{
		{Cols: terminalMinCols, Rows: terminalMinRows},
		{Cols: 132, Rows: 43},
		{Cols: terminalMaxCols, Rows: terminalMaxRows},
	} {
		if !validTerminalWindowSize(valid) {
			t.Errorf("expected valid terminal size: %+v", valid)
		}
	}
	for _, invalid := range []terminalWindowSize{
		{},
		{Cols: 1, Rows: 24},
		{Cols: 80, Rows: 1},
		{Cols: terminalMaxCols + 1, Rows: 24},
		{Cols: 80, Rows: terminalMaxRows + 1},
	} {
		if validTerminalWindowSize(invalid) {
			t.Errorf("expected invalid terminal size: %+v", invalid)
		}
	}
}
