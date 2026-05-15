package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLocalTunnelIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const body = "x-tunnel integration payload\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")

	binPath := filepath.Join(t.TempDir(), "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	wsAddr := freeTCPAddr(t)
	socksAddr := freeTCPAddr(t)
	tcpAddr := freeTCPAddr(t)
	httpProxyAddr := freeTCPAddr(t)

	serverLog := filepath.Join(t.TempDir(), "server.log")
	clientLog := filepath.Join(t.TempDir(), "client.log")
	badClientLog := filepath.Join(t.TempDir(), "bad-client.log")

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "ws://"+wsAddr+"/tunnel",
		"-token", "integration-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wsAddr)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "socks5://"+socksAddr+",tcp://"+tcpAddr+"/"+targetAddr+",http://"+httpProxyAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "integration-token",
		"-n", "1",
	)
	defer stopProcess(client)
	waitTCP(t, ctx, socksAddr)
	waitTCP(t, ctx, tcpAddr)
	waitTCP(t, ctx, httpProxyAddr)
	waitLogContains(t, ctx, clientLog, "协议协商成功")
	waitLogContains(t, ctx, serverLog, "协议协商成功")

	assertBody(t, "tcp forward", fetchHTTP(t, "http://"+tcpAddr+"/payload"), body)
	assertBody(t, "http proxy", fetchViaHTTPProxy(t, httpProxyAddr, "http://"+targetAddr+"/payload"), body)
	assertBody(t, "http connect", fetchViaHTTPConnect(t, httpProxyAddr, targetAddr, "/payload"), body)
	assertBody(t, "socks5", fetchViaSOCKS5(t, socksAddr, targetAddr, "/payload"), body)

	badClient := startXTunnel(t, ctx, binPath, badClientLog,
		"-l", "socks5://"+freeTCPAddr(t),
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "wrong-token",
		"-n", "1",
	)
	defer stopProcess(badClient)
	waitLogContains(t, ctx, badClientLog, "认证失败")
	waitLogContains(t, ctx, serverLog, "Token 认证失败")
}

func startXTunnel(t *testing.T, ctx context.Context, binPath, logPath string, args ...string) *exec.Cmd {
	t.Helper()
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start x-tunnel %v: %v", args, err)
	}
	return cmd
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitTCP(t *testing.T, ctx context.Context, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tcp %s did not open: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitLogContains(t *testing.T, ctx context.Context, path, needle string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, _ := os.ReadFile(path)
		if bytes.Contains(raw, []byte(needle)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log %s did not contain %q\n%s", path, needle, raw)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context ended while waiting for log %q: %v", needle, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func fetchHTTP(t *testing.T, rawURL string) string {
	t.Helper()
	resp, err := http.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	return readOKBody(t, resp)
}

func fetchViaHTTPProxy(t *testing.T, proxyAddr, rawURL string) string {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("proxy GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	return readOKBody(t, resp)
}

func fetchViaHTTPConnect(t *testing.T, proxyAddr, targetAddr, path string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial HTTP proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, targetAddr)
	return readHTTPResponseBody(t, br)
}

func fetchViaSOCKS5(t *testing.T, proxyAddr, targetAddr, path string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("read SOCKS5 greeting: %v", err)
	}
	if !bytes.Equal(greeting, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 greeting = %v", greeting)
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse target port: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write SOCKS5 connect: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read SOCKS5 connect response: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("SOCKS5 connect status = %d", resp[1])
	}

	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, targetAddr)
	return readHTTPResponseBody(t, bufio.NewReader(conn))
}

func readOKBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(raw)
}

func readHTTPResponseBody(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	defer resp.Body.Close()
	return readOKBody(t, resp)
}

func assertBody(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s body = %q, want %q", label, got, want)
	}
}
