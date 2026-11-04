//go:build !windows

package udphop

import (
	"errors"
	"syscall"
)

// 非Windows平台可能用EMSGSIZE报告超长数据报，不应永久停止接收。
func isTruncatedPacketError(err error) bool { return errors.Is(err, syscall.EMSGSIZE) }
