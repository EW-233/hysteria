//go:build kex_poc

// kex-poc 提供独立实验入口，仅在显式启用 kex_poc 标签时构建。
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apernet/hysteria/core/v2/kexpoc"
)

var version = "dev"

const usage = `KEX 实验 CLI（所有秘密仅从 JSON 文件读取）
  kex-poc keygen -out device-key.json
  kex-poc server -config server.json
  kex-poc client -config client.json [-tun] [-timeout 20s]
  kex-poc probe -config client.json [-url https://example.com/] [-dns 1.1.1.1:53] [-timeout 20s]
  kex-poc version

client 始终监听 127.0.0.1:1089；-tun 额外启用 TUN，需要管理员权限。
probe 的 timeout 覆盖连接建立和全部探测；client 的 timeout 只限制首次连接。
程序仅创建一次连接，失败立即退出，不自动重连。
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"ok": false, "error": err.Error()})
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return errors.New("version 不接受参数")
		}
		return json.NewEncoder(out).Encode(map[string]string{"version": version, "build_tag": "kex_poc"})
	}
	if args[0] == "keygen" {
		return keygen(args[1:], out)
	}
	mode := args[0]
	if mode != "client" && mode != "server" && mode != "probe" {
		return errors.New("未知子命令，使用 help 查看用法")
	}
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	filename := flags.String("config", "", "JSON 配置文件")
	var tunMode bool
	var timeout time.Duration = 20 * time.Second
	var target, dns string
	if mode == "client" {
		flags.BoolVar(&tunMode, "tun", false, "启用 TUN")
	}
	if mode != "server" {
		flags.DurationVar(&timeout, "timeout", 20*time.Second, "连接或探测总时限")
	}
	if mode == "probe" {
		flags.StringVar(&target, "url", "https://example.com/", "经 TCP 代理请求的 URL")
		flags.StringVar(&dns, "dns", "", "经 UDP 代理查询的 DNS IP:端口")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(out, usage)
			return err
		}
		return errors.New("命令参数无效；秘密只能写入配置文件")
	}
	if flags.NArg() != 0 || *filename == "" {
		return errors.New("需要 -config 文件路径，且不接受位置参数")
	}
	if timeout <= 0 || timeout > 10*time.Minute {
		return errors.New("timeout 必须大于零且不超过 10m")
	}
	cfg, err := loadConfig(*filename)
	if err != nil {
		return err
	}
	if mode == "server" {
		return serve(ctx, cfg, out)
	}
	if mode == "probe" {
		return runProbe(ctx, cfg, target, dns, timeout, out)
	}
	return runClient(ctx, cfg, tunMode, timeout, out)
}

// 密钥文件采用独占创建，避免覆盖已有凭据；终端只输出成功状态。
func keygen(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	filename := flags.String("out", "", "密钥输出文件")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(out, usage)
			return err
		}
		return errors.New("keygen 参数无效")
	}
	if *filename == "" || flags.NArg() != 0 {
		return errors.New("keygen 需要 -out 文件路径")
	}
	private, err := kexpoc.GeneratePrivateKey()
	if err != nil {
		return errors.New("生成私钥失败")
	}
	public, err := kexpoc.PublicKey(private)
	if err != nil {
		return errors.New("生成公钥失败")
	}
	var credential, token [32]byte
	if _, err = rand.Read(credential[:]); err != nil {
		return errors.New("生成 relay 凭据失败")
	}
	if _, err = rand.Read(token[:]); err != nil {
		return errors.New("生成 HTTPS 令牌失败")
	}
	data, err := json.MarshalIndent(map[string]string{
		"private_key_hex": hex.EncodeToString(private[:]), "public_key_hex": hex.EncodeToString(public[:]),
		"relay_credential_hex": hex.EncodeToString(credential[:]), "access_token": hex.EncodeToString(token[:]),
	}, "", "  ")
	if err != nil {
		return errors.New("编码密钥文件失败")
	}
	f, err := os.OpenFile(*filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("无法创建密钥文件，文件可能已存在")
	}
	_, writeErr := f.Write(append(data, '\n'))
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("写入密钥文件失败，请检查输出文件")
	}
	_, err = fmt.Fprintln(out, "{\"ok\":true,\"event\":\"keygen_written\"}")
	return err
}
