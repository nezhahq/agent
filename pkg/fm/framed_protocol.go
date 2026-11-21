package fm

import (
	"encoding/binary"
	"io/fs"
)

// 带帧头的协议（版本 2）。
//
// 旧协议里文件内容是不带帧头的原始分片，对端只能靠长度猜一帧是内容还是错误，
// 下载没有结束帧，目录列表的文件名长度只有 1 字节、整个列表必须装进一帧。
// 版本 2 让 agent 发出的每一帧都以 4 字节标识开头：
//
//	NZHI + 版本(1)                               问候应答
//	NZL2 + 标志(1) + 路径长度(4) + 路径 + 条目…    目录列表的一页，标志位 0 表示最后一页
//	      条目 = 类型(1) + 文件名长度(2) + 文件名
//	NZTD + 文件大小(8)                            下载开始（与旧协议相同）
//	NZDC + 内容                                   下载的一片
//	NZDE + 已发送字节数(8)                        下载结束
//	NERR + 文本 / NZUP                            与旧协议相同
//
// 版本由对端先发问候命令（操作码 3 + 它支持的最高版本）来协商，没有问候的会话
// 一直按旧协议工作，所以旧前端不受影响；旧 agent 不认识问候命令、不会应答，
// 新前端据此回退到旧协议。上传方向的内容仍按字节数计，没有变化。
//
// 面板原样转发字节，但它的中继缓冲是 1MiB：超过的帧会被拆成两条消息。
// 所以这里的每一帧（含标识）都不超过 framedFrameMaxBytes。
const (
	framedProtocolVersion = 2
	framedFrameMaxBytes   = 1024 * 1024
)

var (
	helloIdentifier         = []byte{0x4E, 0x5A, 0x48, 0x49} // NZHI
	listingPageIdentifier   = []byte{0x4E, 0x5A, 0x4C, 0x32} // NZL2
	downloadChunkIdentifier = []byte{0x4E, 0x5A, 0x44, 0x43} // NZDC
	downloadEndIdentifier   = []byte{0x4E, 0x5A, 0x44, 0x45} // NZDE
)

const listingLastPageFlag = 0x01

func createHelloAcknowledgement(version byte) []byte {
	return append(append([]byte(nil), helloIdentifier...), version)
}

func createDownloadEnd(sentBytes uint64) []byte {
	return binary.BigEndian.AppendUint64(append([]byte(nil), downloadEndIdentifier...), sentBytes)
}

// createListingPages 把一个目录的条目切成若干页，每页不超过 framedFrameMaxBytes。
// 空目录也有一页，对端靠最后一页的标志得知列表结束。
func createListingPages(dir string, entries []fs.DirEntry) [][]byte {
	newPage := func() []byte {
		page := append(make([]byte, 0, 4096), listingPageIdentifier...)
		page = append(page, 0)
		page = binary.BigEndian.AppendUint32(page, uint32(len(dir)))
		return append(page, dir...)
	}
	emptyPageBytes := len(newPage())
	var pages [][]byte
	page := newPage()
	for _, entry := range entries {
		name := entry.Name()
		entryBytes := 1 + 2 + len(name)
		// 文件名长度字段是 2 字节；一页连一个条目都放不下的名字同样无法表示。
		if len(name) > 0xFFFF || emptyPageBytes+entryBytes > framedFrameMaxBytes {
			continue
		}
		if len(page)+entryBytes > framedFrameMaxBytes {
			pages = append(pages, page)
			page = newPage()
		}
		entryType := byte(0)
		if entry.IsDir() {
			entryType = 1
		}
		page = append(page, entryType)
		page = binary.BigEndian.AppendUint16(page, uint16(len(name)))
		page = append(page, name...)
	}
	page[len(listingPageIdentifier)] = listingLastPageFlag
	return append(pages, page)
}
