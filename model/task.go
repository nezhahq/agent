package model

const (
	_ = iota
	TaskTypeHTTPGet
	TaskTypeICMPPing
	TaskTypeTCPPing
	TaskTypeCommand
	TaskTypeTerminal
	TaskTypeUpgrade
	TaskTypeKeepalive
	TaskTypeTerminalGRPC
	TaskTypeNAT
	TaskTypeReportHostInfoDeprecated
	TaskTypeFM
	TaskTypeReportConfig
	TaskTypeApplyConfig
	TaskTypeServerTransferApply
	TaskTypeExec
	TaskTypeFsList
	TaskTypeFsRead
	TaskTypeFsWrite
	TaskTypeFsDelete
	TaskTypeFsTransfer
)

type TerminalTask struct {
	StreamID string
}

type TaskNAT struct {
	StreamID string
	Host     string
}

type TaskFM struct {
	StreamID string
}

type ExecRequest struct {
	Cmd            string            `json:"cmd"`
	Args           []string          `json:"args,omitempty"`
	Cwd            string            `json:"cwd,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	TimeoutSeconds uint32            `json:"timeout_seconds,omitempty"`
	Stdin          string            `json:"stdin,omitempty"`
	MaxOutputBytes uint32            `json:"max_output_bytes,omitempty"`
}

type ExecResult struct {
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	DurationMs      int64  `json:"duration_ms"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	TimedOut        bool   `json:"timed_out,omitempty"`
	Error           string `json:"error,omitempty"`
}

type FsListRequest struct {
	Path       string `json:"path"`
	ShowHidden bool   `json:"show_hidden,omitempty"`
}

type FsEntry struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Size        int64  `json:"size"`
	Mode        string `json:"mode"`
	ModTimeUnix int64  `json:"mtime"`
	IsSymlink   bool   `json:"is_symlink,omitempty"`
	LinkTarget  string `json:"link_target,omitempty"`
}

type FsListResult struct {
	Entries   []FsEntry `json:"entries"`
	Truncated bool      `json:"truncated,omitempty"`
	Total     int       `json:"total,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type FsReadRequest struct {
	Path     string `json:"path"`
	Offset   int64  `json:"offset,omitempty"`
	Length   int64  `json:"length,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type FsReadResult struct {
	Content   string `json:"content"`
	Encoding  string `json:"encoding"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

type FsWriteRequest struct {
	Path          string `json:"path"`
	Content       string `json:"content"`
	Encoding      string `json:"encoding,omitempty"`
	Mode          string `json:"mode,omitempty"`
	IfMatchSHA256 string `json:"if_match_sha256,omitempty"`
	CreateDirs    bool   `json:"create_dirs,omitempty"`
}

type FsWriteResult struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Error  string `json:"error,omitempty"`
}

type FsDeleteRequest struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}

type FsDeleteResult struct {
	DeletedCount int    `json:"deleted_count"`
	Error        string `json:"error,omitempty"`
}

const (
	MCPFsTransferOpUpload   = "upload"
	MCPFsTransferOpDownload = "download"

	// MCPFsTransferMaxSize 与 dashboard 侧一致 (100MiB)；agent 同样硬拒绝
	// 任何超大请求，避免被攻击者诱导成无限读盘/写盘。
	MCPFsTransferMaxSize = 100 * 1024 * 1024
)

type FsTransferRequest struct {
	StreamID       string `json:"stream_id"`
	Op             string `json:"op"`
	Path           string `json:"path"`
	Size           int64  `json:"size,omitempty"`
	Mode           string `json:"mode,omitempty"`
	CreateDirs     bool   `json:"create_dirs,omitempty"`
	IfMatchSHA256  string `json:"if_match_sha256,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

var (
	MCPFsXferMagicUploadHdr   = []byte{0x4E, 0x5A, 0x54, 0x55} // NZTU
	MCPFsXferMagicDownloadHdr = []byte{0x4E, 0x5A, 0x54, 0x44} // NZTD
	MCPFsXferMagicOK          = []byte{0x4E, 0x5A, 0x54, 0x4F} // NZTO
	MCPFsXferMagicErr         = []byte{0x4E, 0x5A, 0x54, 0x45} // NZTE
	MCPFsXferMagicChunk       = []byte{0x4E, 0x5A, 0x54, 0x43} // NZTC
)
