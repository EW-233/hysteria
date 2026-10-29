//go:build kex_poc

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/kexpoc"
	"github.com/apernet/hysteria/core/v2/server"
	"golang.org/x/net/dns/dnsmessage"
)

// 确认密钥仅落入独占创建的文件，不泄漏到终端或覆盖旧密钥。
func TestKeygenFileOnly(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "keys.json")
	var out bytes.Buffer
	if err := keygen([]string{"-out", filename}, &out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]string
	if err = json.Unmarshal(data, &keys); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"private_key_hex", "public_key_hex", "relay_credential_hex", "access_token"} {
		if len(keys[field]) != 64 {
			t.Fatalf("字段长度错误：%s", field)
		}
		if strings.Contains(out.String(), keys[field]) {
			t.Fatalf("终端泄漏字段：%s", field)
		}
	}
	private, err := key32(keys["private_key_hex"], "private")
	if err != nil {
		t.Fatal(err)
	}
	public, err := kexpoc.PublicKey(private)
	if err != nil || keys["public_key_hex"] != hex.EncodeToString(public[:]) {
		t.Fatal("公私钥不匹配")
	}
	if err = keygen([]string{"-out", filename}, &out); err == nil {
		t.Fatal("不应覆盖现有密钥文件")
	}
	after, _ := os.ReadFile(filename)
	if !bytes.Equal(data, after) {
		t.Fatal("原密钥被修改")
	}
}

func TestConfigAndErrorsDoNotEchoSecrets(t *testing.T) {
	secret := "sensitive-sentinel-never-print"
	for _, data := range []string{"{\"" + secret + "\":true}", "{\"service_id\":\"test\",\"private_key_hex\":\"" + secret + "\"} {}", "{\"service_id\":\"" + secret} {
		filename := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(filename, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadConfig(filename)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("配置错误未脱敏：%v", err)
		}
	}
	var out bytes.Buffer
	err := run(context.Background(), []string{"client", "-unknown", secret}, &out)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(out.String(), secret) {
		t.Fatal("参数错误泄漏秘密")
	}
}

func TestRouteExclusionsAndPinnedSNI(t *testing.T) {
	udp := netip.MustParseAddr("203.0.113.7")
	ips := []netip.Addr{udp, netip.MustParseAddr("198.51.100.8"), netip.MustParseAddr("2001:db8::1")}
	v4, v6 := routeExclusions(udp, ips)
	if len(v4) != 2 || len(v6) != 1 || v4[0].Bits() != 32 || v6[0].Bits() != 128 {
		t.Fatal("入口排除路由错误")
	}
	cfg := &config{HTTPS: httpsConfig{Endpoint: "https://entry.invalid:8443/k", EntryIP: "127.0.0.1", AccessToken: strings.Repeat("t", 32)}}
	httpCfg, resolved, err := cfg.prepareHTTP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if httpCfg.TLSConfig.InsecureSkipVerify || httpCfg.TLSConfig.ServerName != "entry.invalid" || len(resolved) != 1 {
		t.Fatal("固定 IP 改变了 TLS 验证身份")
	}
	if _, err = httpCfg.DialContext(context.Background(), "tcp", "elsewhere.invalid:8443"); err == nil {
		t.Fatal("应拒绝非配置目标")
	}
	ts, err := makeTUN(&config{UDPAddress: "203.0.113.7:443"}, nil, ips)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.Inet4RouteExcludeAddress) != 2 || len(ts.Inet6RouteExcludeAddress) != 1 {
		t.Fatal("TUN 未接收入口排除路由")
	}
}

// 回环联调覆盖真正的 HTTPS、Noise、UDP path、READY 和 CLI 的 TCP/DNS 探测。
func probeFixture(t *testing.T) (*config, *atomic.Int32) {
	t.Helper()
	private, err := kexpoc.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	public, err := kexpoc.PublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	device, err := kexpoc.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	devicePub, err := kexpoc.PublicKey(device)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	addr := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	svc, err := kexpoc.NewServer(context.Background(), udp, kexpoc.ServerOptions{Handshake: kexpoc.ServerConfig{ServiceID: "cli-test", PrivateKey: private, UDPAddress: addr}, Devices: []kexpoc.Device{{PublicKey: devicePub, Policy: kexpoc.Policy{Principal: "test-device", UDPEnabled: true, RxAuto: true}}}, HY2: server.Config{IgnoreClientBandwidth: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	token := strings.Repeat("test-token", 4)
	handler, err := svc.HTTPHandler(token)
	if err != nil {
		t.Fatal(err)
	}
	count := new(atomic.Int32)
	https := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); handler.ServeHTTP(w, r) }))
	t.Cleanup(https.Close)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: https.Certificate().Raw})
	return &config{ServiceID: "cli-test", PrivateKeyHex: hex.EncodeToString(device[:]), ServerPublicKeyHex: hex.EncodeToString(public[:]), UDPAddress: addr.String(), HTTPS: httpsConfig{Endpoint: https.URL + "/k", AccessToken: token, CAPEM: string(cert), EntryIP: "127.0.0.1"}}, count
}

func TestProbeEndToEnd(t *testing.T) {
	cfg, count := probeFixture(t)
	payload := bytes.Repeat([]byte("test-data"), 8192)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer target.Close()
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		wire := make([]byte, 4096)
		n, addr, err := dns.ReadFrom(wire)
		if err != nil {
			return
		}
		var query dnsmessage.Message
		if query.Unpack(wire[:n]) != nil {
			return
		}
		query.Response = true
		query.RecursionAvailable = true
		data, err := query.Pack()
		if err == nil {
			_, _ = dns.WriteTo(data, addr)
		}
	}()
	defer func() { dns.Close(); <-done }()
	var out bytes.Buffer
	if err = runProbe(context.Background(), cfg, target.URL, dns.LocalAddr().String(), 10*time.Second, &out); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	var result probeResult
	if err = json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.TCP == nil || result.TCP.Bytes != int64(len(payload)) || !result.TCP.OK || result.UDP == nil || !result.UDP.OK {
		t.Fatalf("探测统计错误：%s", out.String())
	}
	if count.Load() != 1 {
		t.Fatalf("握手次数应为 1，实际 %d", count.Load())
	}
	for _, secret := range []string{cfg.PrivateKeyHex, cfg.HTTPS.AccessToken, cfg.HTTPS.Endpoint} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("探测输出泄漏配置")
		}
	}
}

func TestFailedAuthenticationDoesNotRetry(t *testing.T) {
	cfg, count := probeFixture(t)
	cfg.HTTPS.AccessToken = strings.Repeat("wrong-token", 4)
	var out bytes.Buffer
	if err := runProbe(context.Background(), cfg, "http://127.0.0.1:1/", "", 3*time.Second, &out); err == nil {
		t.Fatal("错误令牌不应成功")
	}
	if count.Load() != 1 {
		t.Fatalf("失败后不应重新握手，实际 %d", count.Load())
	}
	var result probeResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ConnectStage != "https_authentication" {
		t.Fatalf("阶段错误：%s", result.ConnectStage)
	}
	if !strings.Contains(out.String(), "connect_failed") || strings.Contains(out.String(), cfg.HTTPS.AccessToken) {
		t.Fatal("故障 JSON 不正确")
	}
}

type fakeClient struct{ session client.HyUDPConn }

func (c *fakeClient) TCP(string) (net.Conn, error)   { return nil, errors.New("unused") }
func (c *fakeClient) UDP() (client.HyUDPConn, error) { return c.session, nil }
func (c *fakeClient) Close() error                   { return nil }

type fakeDNS struct {
	closeOnce   sync.Once
	data        []byte
	source      string
	wrongID     bool
	wrongSource bool
	closed      chan struct{}
	block       bool
}

func (s *fakeDNS) Send(data []byte, address string) error {
	var query dnsmessage.Message
	if err := query.Unpack(data); err != nil {
		return err
	}
	query.Response = true
	if s.wrongID {
		query.ID++
	}
	s.data, _ = query.Pack()
	s.source = address
	if s.wrongSource {
		s.source = "127.0.0.2:53"
	}
	return nil
}
func (s *fakeDNS) Receive() ([]byte, string, error) {
	if s.block {
		<-s.closed
		return nil, "", net.ErrClosed
	}
	return s.data, s.source, nil
}
func (s *fakeDNS) Close() error { s.closeOnce.Do(func() { close(s.closed) }); return nil }

func TestDNSRejectsWrongResponseAndTimesOut(t *testing.T) {
	for _, mode := range []string{"id", "source", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			session := &fakeDNS{wrongID: mode == "id", wrongSource: mode == "source", block: mode == "timeout", closed: make(chan struct{})}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if _, err := probeUDP(ctx, &fakeClient{session: session}, "127.0.0.1:53"); err == nil {
				t.Fatal("不应接受错误响应或超时")
			}
		})
	}
}

// 类型链允许诊断阶段，但任何底层正文都不能进入客户端错误或 probe JSON。
func TestConnectionStageRedacted(t *testing.T) {
	secret := "secret-sentinel-should-not-appear"
	for _, stage := range []string{"https_connect", "udp_path", "ready", "business"} {
		err := &connectionFailure{cause: errors.Join(&kexpoc.ConnectionError{Stage: stage}, errors.New(secret))}
		if connectionStage(err) != stage || !strings.Contains(err.Error(), stage) || strings.Contains(err.Error(), secret) {
			t.Fatal("阶段或脱敏不正确")
		}
	}
	raw := &connectionFailure{cause: errors.New(secret)}
	if connectionStage(raw) != "" || strings.Contains(raw.Error(), secret) {
		t.Fatal("无阶段错误未脱敏")
	}
	data, err := json.Marshal(probeResult{OK: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("connect_stage")) {
		t.Fatal("空阶段应省略")
	}
}

func TestBindAddressValidation(t *testing.T) {
	for _, value := range []string{"", "127.0.0.1", "192.168.5.125", "::1", "2001:db8::1"} {
		if _, err := (&config{BindAddress: value}).bindAddress(); err != nil {
			t.Fatalf("有效绑定被拒绝：%s", value)
		}
	}
	for _, value := range []string{"localhost", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "127.0.0.1:1234", "::ffff:127.0.0.1", "fe80::1%10", "not-an-ip"} {
		if _, err := (&config{BindAddress: value}).bindAddress(); err == nil {
			t.Fatalf("应拒绝绑定：%s", value)
		}
	}
	for _, pair := range [][2]string{{"127.0.0.1", "::1"}, {"::1", "127.0.0.1"}} {
		cfg := &config{BindAddress: pair[0], HTTPS: httpsConfig{Endpoint: "https://entry.invalid/k", EntryIP: pair[1], AccessToken: strings.Repeat("t", 32)}}
		if _, _, err := cfg.prepareHTTP(context.Background()); err == nil || !strings.Contains(err.Error(), "地址族") {
			t.Fatal("HTTPS 族不匹配未拒绝")
		}
		cfg.PrivateKeyHex = strings.Repeat("01", 32)
		cfg.ServerPublicKeyHex = strings.Repeat("02", 32)
		cfg.UDPAddress = net.JoinHostPort(pair[1], "443")
		if _, _, _, err := connect(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "UDP 目标") {
			t.Fatal("UDP 族不匹配未提前拒绝")
		}
	}
}

// 显式绑定仅使用回环地址验证，不接触物理网卡、系统路由或现有 TUN。
func TestLoopbackSourceBinding(t *testing.T) {
	cfg, _ := probeFixture(t)
	cfg.BindAddress = "127.0.0.1"
	httpCfg, _, err := cfg.prepareHTTP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimSuffix(strings.TrimPrefix(cfg.HTTPS.Endpoint, "https://"), "/k")
	conn, err := httpCfg.DialContext(context.Background(), "tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.LocalAddr().(*net.TCPAddr).IP.Equal(net.ParseIP(cfg.BindAddress)) {
		t.Fatal("HTTPS 源地址未绑定")
	}
	conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, udp, _, err := connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	defer cli.Close()
	if !udp.LocalAddr().(*net.UDPAddr).IP.Equal(net.ParseIP(cfg.BindAddress)) {
		t.Fatal("UDP 源地址未绑定")
	}
	result, err := probeTCP(ctx, cli, httptestTarget(t))
	if err != nil || !result.OK {
		t.Fatal("绑定后真实 TCP 业务失败")
	}
}
func httptestTarget(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "bound") }))
	t.Cleanup(s.Close)
	return s.URL
}

type clientReadyWriter struct {
	ready chan struct{}
	once  sync.Once
}

func (w *clientReadyWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.ready) })
	return len(p), nil
}

// 建立阶段时限过去后连接和 SOCKS5 仍可用；取消父上下文必须释放监听。
func TestClientSurvivesDialTimeoutAndCleansListener(t *testing.T) {
	check, err := net.Listen("tcp4", "127.0.0.1:1089")
	if err != nil {
		t.Skip("1089 已被其它程序占用，不影响其运行")
	}
	check.Close()
	cfg, count := probeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	out := &clientReadyWriter{ready: make(chan struct{})}
	done := make(chan struct{})
	var runErr error
	go func() { runErr = runClient(ctx, cfg, false, 2*time.Second, out); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("客户端取消后未退出")
		}
	})
	select {
	case <-out.ready:
	case <-done:
		t.Fatalf("建立失败：%v", runErr)
	case <-time.After(5 * time.Second):
		t.Fatal("等待建立超时")
	}
	select {
	case <-done:
		t.Fatalf("连接被建立时限错误终止：%v", runErr)
	case <-time.After(2100 * time.Millisecond):
	}
	c, err := net.DialTimeout("tcp4", "127.0.0.1:1089", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatal("超时后 SOCKS5 不可用")
	}
	c.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("未及时退出")
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
	if count.Load() != 1 {
		t.Fatal("客户端意外重复握手")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:1089")
	if err != nil {
		t.Fatal("退出后 SOCKS5 监听未释放")
	}
	listener.Close()
}
