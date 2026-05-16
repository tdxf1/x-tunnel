package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const typeHTTPS = 65
const maxDNSMessageSize = 65535

func prepareECH() error {
	return prepareECHContext(context.Background())
}

func prepareECHContext(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		log.Printf("[客户端] DNS查询 ECH: %s -> %s", dnsServer, echDomain)
		echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
		if err != nil {
			log.Printf("[客户端] DNS 查询失败: %v，重试...", err)
			if err := waitECHRetry(ctx); err != nil {
				return err
			}
			continue
		}
		if echBase64 == "" {
			log.Printf("[客户端] 未找到 ECH 参数，重试...")
			if err := waitECHRetry(ctx); err != nil {
				return err
			}
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(echBase64)
		if err != nil {
			log.Printf("[客户端] ECH Base64 解码失败: %v，重试...", err)
			if err := waitECHRetry(ctx); err != nil {
				return err
			}
			continue
		}
		echListMu.Lock()
		echList = raw
		echListMu.Unlock()
		log.Printf("[客户端] ECHConfigList 长度: %d 字节", len(raw))
		return nil
	}
}

func waitECHRetry(ctx context.Context) error {
	timer := time.NewTimer(cfg.ECHRetryDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func refreshECH() error {
	if fallback {
		return nil
	}

	refreshMu.Lock()
	defer refreshMu.Unlock()
	log.Printf("[客户端] 刷新 ECH 配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	if fallback {
		return nil, nil
	}
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置尚未加载")
	}
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	cfgTLS := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH")
		},
		RootCAs: roots,
	}
	if err := applyClientCertificate(cfgTLS); err != nil {
		return nil, err
	}
	return cfgTLS, nil
}

func buildStandardTLSConfig(serverName string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	cfgTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: insecure, // 修正：fallback/标准TLS也要支持 -insecure
	}
	if err := applyClientCertificate(cfgTLS); err != nil {
		return nil, err
	}
	return cfgTLS, nil
}

func applyClientCertificate(cfgTLS *tls.Config) error {
	if clientCertFile == "" && clientKeyFile == "" {
		return nil
	}
	if err := validateCertificatePair(clientCertFile, clientKeyFile); err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return fmt.Errorf("加载客户端证书失败: %w", err)
	}
	cfgTLS.Certificates = append(cfgTLS.Certificates, cert)
	return nil
}

func loadCertPoolFromFile(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("没有找到可用 PEM CA 证书")
	}
	return pool, nil
}

func configureServerClientAuth(cfgTLS *tls.Config) error {
	if clientCAFile == "" {
		return nil
	}
	pool, err := loadCertPoolFromFile(clientCAFile)
	if err != nil {
		return err
	}
	cfgTLS.ClientAuth = tls.RequireAndVerifyClientCert
	cfgTLS.ClientCAs = pool
	return nil
}

func buildUnifiedTLSConfig(serverName string) (*tls.Config, error) {
	if fallback {
		return buildStandardTLSConfig(serverName)
	}
	ech, e := getECHList()
	if e != nil {
		return nil, e
	}
	cfgTLS, err := buildTLSConfigWithECH(serverName, ech)
	if err != nil {
		return nil, err
	}
	cfgTLS.InsecureSkipVerify = insecure
	return cfgTLS, nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	if strings.HasPrefix(dnsServer, "http://") || strings.HasPrefix(dnsServer, "https://") {
		return queryDoH(domain, dnsServer)
	}
	return queryDNSUDP(domain, dnsServer)
}

func queryDNSUDP(domain, dnsServer string) (string, error) {
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}

	query, err := buildDNSQuery(domain, typeHTTPS)
	if err != nil {
		return "", err
	}

	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		return "", fmt.Errorf("连接 DNS 服务器失败: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(cfg.DNSQueryTimeout))

	if _, err = conn.Write(query); err != nil {
		return "", fmt.Errorf("发送查询失败: %v", err)
	}

	response := make([]byte, maxDNSMessageSize)
	n, err := conn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", fmt.Errorf("DNS 查询超时")
		}
		return "", fmt.Errorf("读取 DNS 响应失败: %v", err)
	}
	return parseDNSResponse(response[:n])
}

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	dnsQuery, err := buildDNSQuery(domain, typeHTTPS)
	if err != nil {
		return "", err
	}
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	client := &http.Client{Timeout: cfg.DNSQueryTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 状态码: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessageSize+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxDNSMessageSize {
		return "", fmt.Errorf("DNS 响应过大")
	}
	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) ([]byte, error) {
	domain = normalizeDNSName(domain)
	if err := validateDNSName(domain); err != nil {
		return nil, err
	}
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00)
	query = append(query, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query, nil
}

func normalizeDNSName(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func validateDNSName(domain string) error {
	if domain == "" {
		return fmt.Errorf("DNS 域名不能为空")
	}
	if len(domain) > 253 {
		return fmt.Errorf("DNS 域名过长")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return fmt.Errorf("DNS 域名包含空标签")
		}
		if len(label) > 63 {
			return fmt.Errorf("DNS 标签 %q 过长", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("DNS 标签 %q 不能以连字符开头或结尾", label)
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return fmt.Errorf("DNS 标签 %q 包含非法字符", label)
		}
	}
	return nil
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("响应过短")
	}
	if binary.BigEndian.Uint16(response[0:2]) != 1 {
		return "", fmt.Errorf("DNS 事务 ID 不匹配")
	}
	if response[2]&0x80 == 0 {
		return "", fmt.Errorf("DNS 消息不是响应")
	}
	if rcode := response[3] & 0x0F; rcode != 0 {
		return "", fmt.Errorf("DNS 响应错误码: %d", rcode)
	}
	if qdcount := binary.BigEndian.Uint16(response[4:6]); qdcount != 1 {
		return "", fmt.Errorf("DNS 问题数无效: %d", qdcount)
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("无答案记录")
	}
	offset := 12
	next, err := skipDNSName(response, offset)
	if err != nil {
		return "", err
	}
	offset = next
	if offset+4 > len(response) {
		return "", fmt.Errorf("DNS 问题区越界")
	}
	qtype := binary.BigEndian.Uint16(response[offset : offset+2])
	qclass := binary.BigEndian.Uint16(response[offset+2 : offset+4])
	if qtype != typeHTTPS || qclass != 1 {
		return "", fmt.Errorf("DNS 问题区类型无效")
	}
	offset += 4
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			return "", fmt.Errorf("DNS 答案记录越界")
		}
		next, err := skipDNSName(response, offset)
		if err != nil {
			return "", err
		}
		offset = next
		if offset+10 > len(response) {
			return "", fmt.Errorf("DNS 答案记录越界")
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			return "", fmt.Errorf("DNS 答案数据越界")
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)
		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func skipDNSName(message []byte, offset int) (int, error) {
	if offset < 0 || offset >= len(message) {
		return 0, fmt.Errorf("DNS 名称越界")
	}
	next := -1
	seen := make(map[int]struct{})
	for {
		if offset >= len(message) {
			return 0, fmt.Errorf("DNS 名称越界")
		}
		if _, ok := seen[offset]; ok {
			return 0, fmt.Errorf("DNS 压缩指针循环")
		}
		seen[offset] = struct{}{}

		length := int(message[offset])
		switch length & 0xC0 {
		case 0x00:
			if length == 0 {
				offset++
				if next != -1 {
					return next, nil
				}
				return offset, nil
			}
			offset++
			if offset+length > len(message) {
				return 0, fmt.Errorf("DNS 名称越界")
			}
			offset += length
		case 0xC0:
			if offset+1 >= len(message) {
				return 0, fmt.Errorf("DNS 压缩指针越界")
			}
			pointer := int(message[offset]&0x3F)<<8 | int(message[offset+1])
			if pointer >= len(message) {
				return 0, fmt.Errorf("DNS 压缩指针越界")
			}
			if next == -1 {
				next = offset + 2
			}
			offset = pointer
		default:
			return 0, fmt.Errorf("DNS 名称标签类型无效")
		}
	}
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	next, err := skipDNSName(data, offset)
	if err != nil {
		return ""
	}
	offset = next
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== WebSocket 服务端 ========================
