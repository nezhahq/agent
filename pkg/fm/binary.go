package fm

import (
	"bytes"
	"encoding/binary"
)

var (
	fileIdentifier     = []byte{0x4E, 0x5A, 0x54, 0x44} // NZTD
	fileNameIdentifier = []byte{0x4E, 0x5A, 0x46, 0x4E} // NZFN
	errorIdentifier    = []byte{0x4E, 0x45, 0x52, 0x52} // NERR
	completeIdentifier = []byte{0x4E, 0x5A, 0x55, 0x50} // NZUP
)

func AppendFileName(bin []byte, data string, isDir bool) []byte {
	buffer := bytes.NewBuffer(bin)
	appendFileName(buffer, isDir, []byte(data))
	return buffer.Bytes()
}

func Create(buffer *bytes.Buffer, path string) []byte {
	// Write identifier for TypeFileName (4 bytes)
	binary.Write(buffer, binary.BigEndian, fileNameIdentifier)

	// Write length of path (4 byte)
	binary.Write(buffer, binary.BigEndian, uint32(len(path)))

	// Write path string
	binary.Write(buffer, binary.BigEndian, []byte(path))
	return buffer.Bytes()
}

func CreateFile(buffer *bytes.Buffer, size uint64) []byte {
	// Write identifier for TypeFile (4 bytes)
	binary.Write(buffer, binary.BigEndian, fileIdentifier)

	// Write file size (8 bytes)
	binary.Write(buffer, binary.BigEndian, size)
	return buffer.Bytes()
}

func CreateErr(err error) []byte {
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, errorIdentifier)
	binary.Write(buffer, binary.BigEndian, []byte(err.Error()))

	return buffer.Bytes()
}

func appendFileName(buffer *bytes.Buffer, isDir bool, data []byte) {
	// Write file type (1 byte)
	if isDir {
		binary.Write(buffer, binary.BigEndian, byte(1))
	} else {
		binary.Write(buffer, binary.BigEndian, byte(0))
	}

	// Write the length of file name (1 byte)
	length := byte(len(data))
	binary.Write(buffer, binary.BigEndian, length)

	// Write file name
	buffer.Write(data)
}
