package model

const (
	_ = iota
	TaskTypeHTTPGET
	TaskTypeICMPPing
	TaskTypeTCPPing
	TaskTypeCommand
	TaskTypeTerminal
	TaskTypeUpgrade
	TaskTypeKeepalive
	TaskTypeTerminalGRPC
)

type TerminalTask struct {
	StreamID string
}
