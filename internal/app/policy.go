package app

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"x-tunnel/internal/netaddr"
)

func parseIPStrategy(s string) byte {
	strategy, err := parseIPStrategyStrict(s)
	if err != nil {
		return IPStrategyDefault
	}
	return strategy
}

func parseIPStrategyStrict(s string) (byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	switch s {
	case "":
		return IPStrategyDefault, nil
	case "4":
		return IPStrategyIPv4Only, nil
	case "6":
		return IPStrategyIPv6Only, nil
	case "4,6":
		return IPStrategyPv4Pv6, nil
	case "6,4":
		return IPStrategyPv6Pv4, nil
	default:
		return IPStrategyDefault, fmt.Errorf("仅支持空值、4、6、4,6 或 6,4")
	}
}

func validateIPStrategyValue(strategy byte) error {
	switch strategy {
	case IPStrategyDefault, IPStrategyIPv4Only, IPStrategyIPv6Only, IPStrategyPv4Pv6, IPStrategyPv6Pv4:
		return nil
	default:
		return fmt.Errorf("IP 策略无效: %d", strategy)
	}
}

func validateECHLookupConfig(domain, server string) error {
	if _, err := buildDNSQuery(domain, typeHTTPS); err != nil {
		return fmt.Errorf("ech 域名无效: %w", err)
	}
	server = strings.TrimSpace(server)
	if server == "" {
		return fmt.Errorf("dns 服务器不能为空")
	}
	if strings.HasPrefix(server, "http://") || strings.HasPrefix(server, "https://") {
		u, err := url.Parse(server)
		if err != nil {
			return fmt.Errorf("dns DoH URL 无效: %w", err)
		}
		if u.Host == "" {
			return fmt.Errorf("dns DoH URL 必须包含 host")
		}
		if u.User != nil {
			return fmt.Errorf("dns DoH URL 不能包含 userinfo")
		}
		defaultPort := "443"
		if strings.EqualFold(u.Scheme, "http") {
			defaultPort = "80"
		}
		if _, err := normalizeHTTPProxyAuthority(u.Host, defaultPort); err != nil {
			return fmt.Errorf("dns DoH URL host 无效: %w", err)
		}
		return nil
	}
	if strings.Contains(server, "://") {
		return fmt.Errorf("dns 只支持 http(s) DoH URL 或 UDP host[:port]")
	}
	udpAddr := server
	if !strings.Contains(udpAddr, ":") {
		udpAddr += ":53"
	}
	if err := validateHostPort(udpAddr); err != nil {
		return fmt.Errorf("dns UDP 地址无效: %w", err)
	}
	return nil
}

func parseTargetPolicy(allowRaw, denyRaw, allowHostRaw, denyHostRaw string) (*TargetPolicy, error) {
	allow, err := parseCIDRList(allowRaw)
	if err != nil {
		return nil, fmt.Errorf("allow-target: %w", err)
	}
	deny, err := parseCIDRList(denyRaw)
	if err != nil {
		return nil, fmt.Errorf("deny-target: %w", err)
	}
	allowHosts, err := parseHostPatternList(allowHostRaw)
	if err != nil {
		return nil, fmt.Errorf("allow-host: %w", err)
	}
	denyHosts, err := parseHostPatternList(denyHostRaw)
	if err != nil {
		return nil, fmt.Errorf("deny-host: %w", err)
	}
	return &TargetPolicy{Allow: allow, Deny: deny, AllowHosts: allowHosts, DenyHosts: denyHosts}, nil
}

func parseCIDRList(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("CIDR %q 解析失败: %w", item, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func parseSourceCIDRs(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("至少需要一个 CIDR")
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			return nil, fmt.Errorf("CIDR 不能为空")
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("CIDR %q 解析失败: %w", item, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func parseHostPatternList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var patterns []string
	for _, part := range strings.Split(raw, ",") {
		item := normalizeTargetHost(part)
		if item == "" {
			continue
		}
		if err := validateHostPattern(item); err != nil {
			return nil, err
		}
		patterns = append(patterns, item)
	}
	return patterns, nil
}

func normalizeTargetHost(host string) string {
	return netaddr.NormalizeTargetHost(host)
}

func validateHostPattern(pattern string) error {
	if strings.Contains(pattern, ":") {
		return fmt.Errorf("host pattern %q 不能包含端口", pattern)
	}
	if strings.Contains(pattern, "*") {
		if !strings.HasPrefix(pattern, "*.") || strings.Count(pattern, "*") != 1 {
			return fmt.Errorf("host pattern %q 只支持前缀通配符 *.example.com", pattern)
		}
		pattern = strings.TrimPrefix(pattern, "*.")
	}
	if net.ParseIP(pattern) != nil {
		return fmt.Errorf("host pattern %q 是 IP，目标 IP 请使用 CIDR 策略", pattern)
	}
	if !validHostname(pattern) {
		return fmt.Errorf("host pattern %q 不是合法主机名", pattern)
	}
	return nil
}

func validHostname(host string) bool {
	return netaddr.ValidHostname(host)
}

func validateHostnameOrIP(host string) error {
	return netaddr.ValidateHostnameOrIP(host)
}

func (p *TargetPolicy) Allows(target string) (bool, string) {
	if p == nil || len(p.Allow) == 0 && len(p.Deny) == 0 && len(p.AllowHosts) == 0 && len(p.DenyHosts) == 0 {
		return true, ""
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false, fmt.Sprintf("目标地址格式无效: %v", err)
	}
	host = normalizeTargetHost(host)
	ip := net.ParseIP(host)
	if ip == nil {
		for _, pattern := range p.DenyHosts {
			if hostPatternMatches(pattern, host) {
				return false, fmt.Sprintf("目标主机 %s 命中 deny-host %s", host, pattern)
			}
		}
		if len(p.AllowHosts) == 0 {
			if len(p.Allow) > 0 {
				return false, "目标是域名，无法证明其属于 allow-target CIDR"
			}
			return true, ""
		}
		for _, pattern := range p.AllowHosts {
			if hostPatternMatches(pattern, host) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("目标主机 %s 未命中 allow-host", host)
	}
	for _, n := range p.Deny {
		if n.Contains(ip) {
			return false, fmt.Sprintf("目标 %s 命中 deny-target %s", ip, n)
		}
	}
	if len(p.Allow) == 0 {
		if len(p.AllowHosts) > 0 {
			return false, fmt.Sprintf("目标 %s 未命中 allow-target；allow-host 不适用于 IP 目标", ip)
		}
		return true, ""
	}
	for _, n := range p.Allow {
		if n.Contains(ip) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("目标 %s 未命中 allow-target", ip)
}

func hostPatternMatches(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

func ensureTargetAllowed(target string) error {
	if targetPolicy == nil {
		return nil
	}
	if ok, reason := targetPolicy.Allows(target); !ok {
		return errors.New(reason)
	}
	return nil
}

func validateSmuxStreamTarget(target string) error {
	if err := validateHostPort(target); err != nil {
		return fmt.Errorf("目标地址无效: %w", err)
	}
	return nil
}
