package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ======================== SOCKS5 辅助函数 ========================

func parseSOCKS5Addr(addr string) (*SOCKS5Config, error) {
	addr = strings.TrimPrefix(addr, "socks5://")
	config := &SOCKS5Config{}

	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		auth := parts[0]
		config.Host = strings.TrimSpace(parts[1])
		if auth == "" || config.Host == "" || !strings.Contains(auth, ":") {
			return nil, fmt.Errorf("认证格式必须是 user:pass@host:port")
		}
		authParts := strings.SplitN(auth, ":", 2)
		config.Username = authParts[0]
		config.Password = authParts[1]
		if config.Username == "" || config.Password == "" {
			return nil, fmt.Errorf("用户名和密码不能为空")
		}
		if err := validateSOCKS5AuthLength(config.Username, config.Password); err != nil {
			return nil, err
		}
	} else {
		config.Host = strings.TrimSpace(addr)
	}
	return config, nil
}

func validateSOCKS5AuthLength(username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("SOCKS5 用户名和密码长度必须不超过 255 字节")
	}
	return nil
}

func dialViaSocks5(network, addr string) (net.Conn, error) {
	if socks5Config == nil {
		return net.DialTimeout(network, addr, cfg.DialTimeout)
	}
	proxyConn, err := net.DialTimeout("tcp", socks5Config.Host, cfg.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("连接SOCKS5代理失败: %v", err)
	}
	if err := socks5Handshake(proxyConn, socks5Config); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("SOCKS5握手失败: %v", err)
	}
	if err := socks5Connect(proxyConn, addr); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT失败: %v", err)
	}
	return proxyConn, nil
}

func socks5Handshake(conn net.Conn, config *SOCKS5Config) error {
	var methods []byte
	if config.Username != "" && config.Password != "" {
		methods = []byte{0x02}
	} else {
		methods = []byte{0x00}
	}
	greeting := make([]byte, 2+len(methods))
	greeting[0], greeting[1] = 0x05, byte(len(methods))
	copy(greeting[2:], methods)

	if err := writeAll(conn, greeting); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x05 {
		return fmt.Errorf("SOCKS 版本错误: %d", response[0])
	}
	switch response[1] {
	case 0x00:
		if !bytes.Contains(methods, []byte{0x00}) {
			return fmt.Errorf("服务器选择了未提供的认证方法: %d", response[1])
		}
		return nil
	case 0x02:
		if !bytes.Contains(methods, []byte{0x02}) {
			return fmt.Errorf("服务器选择了未提供的认证方法: %d", response[1])
		}
		return socks5UserPassAuthSrv(conn, config.Username, config.Password)
	case 0xFF:
		return errors.New("服务器不接受认证")
	default:
		return fmt.Errorf("认证方法错误: %d", response[1])
	}
}

func socks5UserPassAuthSrv(conn net.Conn, username, password string) error {
	if err := validateSOCKS5AuthLength(username, password); err != nil {
		return err
	}
	authReq := make([]byte, 3+len(username)+len(password))
	authReq[0], authReq[1] = 0x01, byte(len(username))
	copy(authReq[2:], username)
	authReq[2+len(username)] = byte(len(password))
	copy(authReq[3+len(username):], password)

	if err := writeAll(conn, authReq); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x01 {
		return fmt.Errorf("SOCKS5 用户名密码认证响应版本错误: %d", response[0])
	}
	if response[1] != 0x00 {
		return errors.New("认证失败")
	}
	return nil
}

func socks5Connect(conn net.Conn, addr string) error {
	if err := validateHostPort(addr); err != nil {
		return err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	var request []byte
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = make([]byte, 10)
			request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x01
			copy(request[4:8], ip4)
			request[8], request[9] = byte(port>>8), byte(port)
		} else {
			request = make([]byte, 22)
			request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x04
			copy(request[4:20], ip)
			request[20], request[21] = byte(port>>8), byte(port)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("域名过长")
		}
		request = make([]byte, 7+len(host))
		request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x03
		request[4] = byte(len(host))
		copy(request[5:], host)
		request[5+len(host)], request[6+len(host)] = byte(port>>8), byte(port)
	}

	if err := writeAll(conn, request); err != nil {
		return err
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x05 {
		return fmt.Errorf("SOCKS5 CONNECT响应版本错误: %d", response[0])
	}
	if response[2] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT响应 RSV 必须为 0")
	}
	if response[1] != 0x00 {
		return fmt.Errorf("状态码: %d", response[1])
	}
	switch response[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
			return err
		}
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])+2)); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.ReadFull(conn, make([]byte, 18)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("地址类型无效: %d", response[3])
	}
	return nil
}

// ======================== UDP Relayer (服务端用) ========================

type UDPRelayer interface {
	Read(buffer []byte) (int, string, error)
	Write(data []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

type DirectUDPRelayer struct {
	conn   *net.UDPConn
	target *net.UDPAddr
}

func (d *DirectUDPRelayer) Read(buffer []byte) (int, string, error) {
	n, addr, err := d.conn.ReadFromUDP(buffer)
	if addr == nil {
		return n, "", err
	}
	return n, addr.String(), err
}
func (d *DirectUDPRelayer) Write(data []byte) (int, error) {
	return writeUDPDatagram(d.conn, data, d.target)
}
func (d *DirectUDPRelayer) SetReadDeadline(t time.Time) error { return d.conn.SetReadDeadline(t) }
func (d *DirectUDPRelayer) Close() error                      { return d.conn.Close() }

type udpDatagramWriter interface {
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

func writeUDPDatagram(w udpDatagramWriter, data []byte, addr *net.UDPAddr) (int, error) {
	if w == nil {
		return 0, errors.New("UDP writer 未初始化")
	}
	if addr == nil {
		return 0, errors.New("UDP 目标地址为空")
	}
	n, err := w.WriteToUDP(data, addr)
	if n > len(data) {
		return n, io.ErrShortWrite
	}
	if err != nil {
		return n, err
	}
	if n != len(data) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

type SOCKS5UDPRelay struct {
	tcpConn    net.Conn
	udpConn    *net.UDPConn
	relayAddr  *net.UDPAddr
	targetAddr *net.UDPAddr
	mu         sync.Mutex
	closed     bool
}

func newSOCKS5UDPRelay(targetAddr string) (*SOCKS5UDPRelay, error) {
	if socks5Config == nil {
		return nil, errors.New("SOCKS5配置为空")
	}
	tcpConn, err := net.DialTimeout("tcp", socks5Config.Host, cfg.DialTimeout)
	if err != nil {
		return nil, err
	}
	if err := socks5Handshake(tcpConn, socks5Config); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if err := writeSOCKS5UDPAssociate(tcpConn); err != nil {
		tcpConn.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if resp[0] != 0x05 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE响应版本错误: %d", resp[0])
	}
	if resp[2] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE响应 RSV 必须为 0")
	}
	if resp[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE拒绝: %d", resp[1])
	}
	var relayHost string
	switch resp[3] {
	case 0x01:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(tcpConn, ipBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayHost = net.IP(ipBuf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(tcpConn, lenBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		if lenBuf[0] == 0 {
			tcpConn.Close()
			return nil, fmt.Errorf("UDP ASSOCIATE域名不能为空")
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(tcpConn, domainBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayHost = string(domainBuf)
	case 0x04:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(tcpConn, ipBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayHost = net.IP(ipBuf).String()
	default:
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE地址类型无效: %d", resp[3])
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, portBuf); err != nil {
		tcpConn.Close()
		return nil, err
	}
	relayPort := int(portBuf[0])<<8 | int(portBuf[1])
	if relayPort == 0 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE端口必须在 1-65535 之间")
	}

	if relayHost == "0.0.0.0" || relayHost == "::" {
		h, _, _ := net.SplitHostPort(socks5Config.Host)
		relayHost = h
	}
	rAddr, errResolve := net.ResolveUDPAddr("udp", net.JoinHostPort(relayHost, strconv.Itoa(relayPort)))
	if errResolve != nil {
		tcpConn.Close()
		return nil, errResolve
	}

	tAddr, errResolve := net.ResolveUDPAddr("udp", targetAddr)
	if errResolve != nil {
		tcpConn.Close()
		return nil, errResolve
	}

	localUDP, errListen := net.ListenUDP("udp", nil)
	if errListen != nil {
		tcpConn.Close()
		return nil, errListen
	}

	log.Printf("[服务端UDP] SOCKS5 UDP中继: %s -> %s", rAddr, targetAddr)
	return &SOCKS5UDPRelay{
		tcpConn:    tcpConn,
		udpConn:    localUDP,
		relayAddr:  rAddr,
		targetAddr: tAddr,
	}, nil
}

func writeSOCKS5UDPAssociate(w io.Writer) error {
	return writeAll(w, []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (r *SOCKS5UDPRelay) Write(data []byte) (int, error) {
	if r == nil || r.udpConn == nil || r.relayAddr == nil || r.targetAddr == nil {
		return 0, errors.New("SOCKS5 UDP relay 未初始化")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errors.New("closed")
	}
	pkt := buildSOCKS5UDPPacketData(r.targetAddr, data)
	return writeUDPDatagram(r.udpConn, pkt, r.relayAddr)
}

func (r *SOCKS5UDPRelay) Read(buffer []byte) (int, string, error) {
	if r == nil || r.udpConn == nil {
		return 0, "", errors.New("SOCKS5 UDP relay 未初始化")
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return 0, "", errors.New("closed")
	}
	tmpPtr := bufPool.Get().(*[]byte)
	tmp := *tmpPtr
	defer bufPool.Put(tmpPtr)

	n, _, err := r.udpConn.ReadFromUDP(tmp)
	if err != nil {
		return 0, "", err
	}
	srcAddr, payload, err := parseSOCKS5UDPResp(tmp[:n])
	if err != nil {
		return 0, "", err
	}
	if len(payload) > len(buffer) {
		return 0, "", fmt.Errorf("SOCKS5 UDP payload length %d exceeds buffer length %d", len(payload), len(buffer))
	}
	copy(buffer, payload)
	return len(payload), srcAddr, nil
}

func (r *SOCKS5UDPRelay) SetReadDeadline(t time.Time) error {
	if r == nil || r.udpConn == nil {
		return errors.New("SOCKS5 UDP relay 未初始化")
	}
	return r.udpConn.SetReadDeadline(t)
}

func (r *SOCKS5UDPRelay) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	_ = r.udpConn.Close()
	_ = r.tcpConn.Close()
	return nil
}

func buildSOCKS5UDPPacketData(target *net.UDPAddr, data []byte) []byte {
	packet := []byte{0x00, 0x00, 0x00}
	packet = appendSOCKS5UDPAddr(packet, target.IP.String(), target.Port)
	packet = append(packet, data...)
	return packet
}

func parseSOCKS5UDPResp(packet []byte) (string, []byte, error) {
	addr, offset, err := parseSOCKS5UDPFrameAddr(packet)
	if err != nil {
		return "", nil, err
	}
	return addr, packet[offset:], nil
}

// ======================== ECH 相关（客户端） ========================
