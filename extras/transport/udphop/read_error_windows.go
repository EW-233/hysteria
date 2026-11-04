package udphop

import (
	"errors"
	"golang.org/x/sys/windows"
)

// Windows会丢弃超出接收缓冲区的报文并返回此错误，下一次读取仍然有效。
func isTruncatedPacketError(err error) bool { return errors.Is(err, windows.WSAEMSGSIZE) }
