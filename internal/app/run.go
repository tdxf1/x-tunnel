package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/uuid"
)

func SetBuildInfo(version, commit, date string) {
	buildVersion = version
	buildCommit = commit
	buildDate = date
}

func Main() {
	flag.Parse()

	if showVersion {
		fmt.Println(versionString())
		return
	}
	if configFile != "" {
		if err := loadConfigFile(configFile, visitedFlags()); err != nil {
			log.Fatalf("[配置] 读取配置文件失败: %v", err)
		}
	}
	if listenAddr == "" {
		flag.Usage()
		return
	}
	startup, err := validateStartupConfig()
	if err != nil {
		log.Fatalf("[配置] %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if metricsAddr != "" {
		go runMetricsServer(ctx, metricsAddr)
	}

	ipStrategy = startup.IPStrategy
	if ips != "" {
		log.Printf("[客户端] IP 访问策略: %s (code: %d)", ips, ipStrategy)
	}

	// ================= 服务端模式 =================
	if startup.IsServer {
		if token == "" {
			log.Printf("[服务端] 警告: 未配置 token，v2 ChannelInit 不会校验 HMAC proof")
		}
		log.Printf("[服务端] protocol=v2-only")
		targetPolicy = startup.TargetPolicy
		socks5Config = startup.SOCKS5Config
		if socks5Config != nil {
			log.Printf("[服务端] 使用SOCKS5前置代理: %s", socks5Config.Host)
			if socks5Config.Username != "" {
				log.Printf("[服务端] SOCKS5代理认证已启用")
			}
		} else {
			log.Printf("[服务端] 直连模式（未配置SOCKS5代理）")
		}
		runWebSocketServer(ctx, startup.ServerListen, startup.SourceCIDRs)
		return
	}

	// ================= 客户端模式 =================
	if token == "" {
		log.Printf("[客户端] 警告: 未配置 token，将发送空 token 的 v2 ChannelInit proof")
	}
	log.Printf("[客户端] protocol=v2-only")
	fallback = startup.Client.Fallback
	udpBlockPorts = startup.Client.UDPBlockPorts
	if frontProxyEnabled() {
		log.Printf("[客户端] WebSocket 前置代理已启用: type=%s server=%s", websocketFrontProxyConfig.Type, websocketFrontProxyConfig.Server)
		if startup.Client.ForwardScheme == "wss" && !fallback {
			log.Printf("[客户端] 警告: WebSocket 前置代理只代理隧道 TCP 连接，ECH DNS 查询仍会直连；如前置代理要求完整链路，请启用 fallback")
		}
	}

	if startup.Client.ForwardScheme == "wss" {
		if insecure {
			if startup.Client.AutoFallback {
				log.Printf("[客户端] wss 模式且启用不校验证书（insecure）：已自动禁用 ECH（fallback）")
			} else {
				log.Printf("[客户端] wss 模式且启用不校验证书（insecure）")
			}
		}
		if !fallback {
			if err := prepareECHContext(ctx); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				log.Fatalf("[客户端] 获取 ECH 公钥失败: %v", err)
			}
		} else {
			log.Printf("[客户端] fallback 模式已启用：禁用 ECH，使用标准 TLS 1.3")
		}
	} else {
		if insecure {
			log.Printf("[客户端] ws 模式已忽略 insecure 参数")
		}
		if fallback {
			log.Printf("[客户端] ws 模式已忽略 fallback/ECH 参数")
		}
	}

	clientID = uuid.NewString()
	log.Printf("[客户端] 客户端ID: %s", clientID)

	echPool = NewECHPool(forwardAddr, connectionNum, startup.TargetIPs, clientID)
	echPool.Start(ctx)

	var wg sync.WaitGroup
	for _, listenerRule := range startup.Listeners {
		rule := listenerRule.Raw
		switch listenerRule.Scheme {
		case "tcp":
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runTCPListener(ctx, r)
			}(rule)
		case "socks5":
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runSOCKS5Listener(ctx, r)
			}(rule)
		case "http":
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runHTTPListener(ctx, r)
			}(rule)
		default:
			log.Printf("[客户端] 忽略未知协议的监听地址: %s", rule)
		}
	}
	wg.Wait()
}
