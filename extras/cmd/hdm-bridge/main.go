// hdm-bridge 启动回环地址上的短期 TCP-to-UDP 握手通路。
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/apernet/hysteria/extras/v2/bridge/tcpudp"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "本地 TCP 监听地址，仅允许回环 IP")
	target := flag.String("target", "127.0.0.1:443", "固定 HY2 UDP 回环目标")
	maxSessions := flag.Int("max-sessions", 64, "同时存在的会话上限")
	maxBytes := flag.Int64("max-bytes", 1<<20, "每会话双向合计数据报字节上限")
	lifetime := flag.Duration("lifetime", 15*time.Second, "每会话硬生命周期")
	idle := flag.Duration("idle-timeout", 5*time.Second, "每方向无数据超时")
	flag.Parse()
	a, err := net.ResolveTCPAddr("tcp", *listen)
	if err != nil || !a.IP.IsLoopback() {
		log.Fatal("监听地址必须为回环 IP")
	}
	u, err := net.ResolveUDPAddr("udp", *target)
	if err != nil || !u.IP.IsLoopback() {
		log.Fatal("目标必须为固定回环 UDP 地址")
	}
	l, err := net.ListenTCP("tcp", a)
	if err != nil {
		log.Fatal(err)
	}
	s, err := tcpudp.New(l, tcpudp.Config{Target: u, MaxSessions: *maxSessions, MaxBytes: *maxBytes, Lifetime: *lifetime, IdleTimeout: *idle})
	if err != nil {
		_ = l.Close()
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	log.Printf("本地握手桥 %s -> %s", l.Addr(), u)
	if err := s.Serve(ctx); err != nil {
		log.Fatal(err)
	}
	log.Printf("握手桥已关闭：%+v", s.Stats())
}
