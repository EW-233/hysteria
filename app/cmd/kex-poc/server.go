//go:build kex_poc

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/apernet/hysteria/core/v2/kexpoc"
	"github.com/apernet/hysteria/core/v2/server"
	"golang.org/x/net/netutil"
)

// HTTPS 与 Worker 短 TLS 帧中继共用认证状态，但分别监听不同 TCP 端口。
func serve(ctx context.Context, cfg *config, out io.Writer) error {
	private, err := key32(cfg.PrivateKeyHex, "private_key_hex")
	if err != nil {
		return err
	}
	addr, err := cfg.address()
	if err != nil {
		return err
	}
	if cfg.HTTPS.Listen == "" && cfg.Relay.Listen == "" {
		return errors.New("至少配置 https.listen 或 relay.listen")
	}
	httpsPort, err := listenPort(cfg.HTTPS.Listen)
	if err != nil {
		return err
	}
	relayPort, err := listenPort(cfg.Relay.Listen)
	if err != nil {
		return err
	}
	if httpsPort != "" && httpsPort == relayPort {
		return errors.New("HTTPS 和 relay 必须使用不同的 TCP 端口")
	}
	if cfg.HTTPS.CertFile == "" || cfg.HTTPS.KeyFile == "" {
		return errors.New("服务端需要 https.cert_file 和 https.key_file")
	}
	cert, err := tls.LoadX509KeyPair(cfg.file(cfg.HTTPS.CertFile), cfg.file(cfg.HTTPS.KeyFile))
	if err != nil {
		return errors.New("加载服务端 TLS 证书或私钥失败")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	devices := make([]kexpoc.Device, 0, len(cfg.Devices))
	if len(cfg.Devices) == 0 {
		return errors.New("服务端至少需要登记一个设备")
	}
	// 当前核心在 Noise 阶段冻结带宽；同一实例的设备需使用相同带宽配置。
	policy := cfg.Devices[0]
	for _, device := range cfg.Devices {
		if device.RxAuto != policy.RxAuto || device.Rx != policy.Rx {
			return errors.New("同一服务端的设备 rx_auto/rx 必须一致")
		}
		public, err := key32(device.PublicKeyHex, "devices.public_key_hex")
		if err != nil {
			return err
		}
		devices = append(devices, kexpoc.Device{PublicKey: public, Policy: kexpoc.Policy{Principal: device.Principal, UDPEnabled: device.UDPEnabled, RxAuto: device.RxAuto, Rx: device.Rx}})
	}
	listen := cfg.UDPListen
	if listen == "" {
		listen = cfg.UDPAddress
	}
	udp, err := net.ListenPacket("udp", listen)
	if err != nil {
		return errors.New("监听服务端 UDP 失败")
	}
	defer udp.Close()
	svc, err := kexpoc.NewServer(ctx, udp, kexpoc.ServerOptions{Handshake: kexpoc.ServerConfig{ServiceID: cfg.ServiceID, PrivateKey: private, UDPAddress: addr}, Devices: devices, HY2: server.Config{IgnoreClientBandwidth: policy.RxAuto, BandwidthConfig: server.BandwidthConfig{MaxRx: policy.Rx}}})
	if err != nil {
		return errors.New("初始化 KEX 服务端失败")
	}
	defer svc.Close()
	errs := make(chan error, 2)
	if cfg.HTTPS.Listen != "" {
		handler, err := svc.HTTPHandler(cfg.HTTPS.AccessToken)
		if err != nil {
			return errors.New("创建 HTTPS handler 失败，请检查 access_token")
		}
		listener, err := net.Listen("tcp", cfg.HTTPS.Listen)
		if err != nil {
			return errors.New("监听 HTTPS 失败")
		}
		defer listener.Close()
		hs := &http.Server{Handler: handler, TLSConfig: tlsCfg, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(io.Discard, "", 0)}
		defer hs.Close()
		go func() { errs <- hs.Serve(tls.NewListener(netutil.LimitListener(listener, 64), tlsCfg)) }()
	}
	if cfg.Relay.Listen != "" {
		credential, err := key32(cfg.Relay.CredentialHex, "relay.credential_hex")
		if err != nil {
			return err
		}
		relay, err := kexpoc.NewRelay(kexpoc.RelayConfig{TLSConfig: tlsCfg, Credential: credential[:], MaxConnections: 64}, svc.Handle)
		if err != nil {
			return errors.New("初始化 TLS 帧 relay 失败")
		}
		defer relay.Close()
		listener, err := net.Listen("tcp", cfg.Relay.Listen)
		if err != nil {
			return errors.New("监听 TLS 帧 relay 失败")
		}
		defer listener.Close()
		go func() { errs <- relay.Serve(ctx, listener) }()
	}
	if err = json.NewEncoder(out).Encode(map[string]any{"ok": true, "event": "server_listening", "https_enabled": cfg.HTTPS.Listen != "", "relay_enabled": cfg.Relay.Listen != ""}); err != nil {
		return errors.New("写入状态失败")
	}
	select {
	case <-ctx.Done():
		return nil
	case <-errs:
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("HTTPS/relay 监听服务退出")
	}
}

func listenPort(address string) (string, error) {
	if address == "" {
		return "", nil
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("监听地址必须包含主机与端口")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("监听端口必须为 1 至 65535")
	}
	return strconv.Itoa(n), nil
}
