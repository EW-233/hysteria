//go:build kex_poc

package libbox

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
)

// 使用真正的移动端注册入口检查 TUN/DNS/KEX 组合，检查配置不得发起握手。
func TestAndroidKEXProfileOffline(t *testing.T) {
	path := os.Getenv("ANDROID_KEX_CHECK_CONFIG")
	if path == "" {
		t.Skip("未提供本机配置")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("无法读取待校验配置")
	}
	var config map[string]any
	if json.Unmarshal(content, &config) != nil {
		t.Fatal("配置 JSON 无效")
	}
	nodes := config["outbounds"].([]any)
	node := nodes[0].(map[string]any)
	if _, ok := node["inet4_bind_address"]; ok {
		t.Fatal("安卓配置含桌面源地址")
	}
	if err = CheckConfig(string(content)); err != nil {
		t.Fatal("移动端配置检查失败：", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e == nil {
			accepted.Store(true)
			conn.Close()
		}
	}()
	node["https"].(map[string]any)["endpoint"] = "https://localhost:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port) + "/k"
	node["https"].(map[string]any)["entry_ip"] = "127.0.0.1"
	content, _ = json.Marshal(config)
	if err = CheckConfig(string(content)); err != nil {
		t.Fatal("回环入口配置检查失败：", err)
	}
	listener.Close()
	<-done
	if accepted.Load() {
		t.Fatal("仅检查配置却连接了握手入口")
	}
}
