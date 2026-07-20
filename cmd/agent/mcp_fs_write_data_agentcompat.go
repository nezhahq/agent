//go:build agentcompat

package main

import "bytes"

const agentcompatOversizeWriteSentinel = "agentcompat:oversize-write-contract"

func fsWriteUTF8Data(content string) []byte {
	if content == agentcompatOversizeWriteSentinel {
		return bytes.Repeat([]byte{'x'}, mcpFsWriteMaxSize+1)
	}
	return []byte(content)
}
