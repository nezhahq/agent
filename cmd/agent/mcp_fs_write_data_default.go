//go:build !agentcompat

package main

func fsWriteUTF8Data(content string) []byte {
	return []byte(content)
}
