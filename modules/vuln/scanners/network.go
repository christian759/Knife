package scanners

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NetworkFinding represents a discovered open port or service
type NetworkFinding struct {
	Port           int    `json:"port"`
	Service        string `json:"service"`
	State          string `json:"state"`
	Endpoint       string `json:"endpoint"`
	Protocol       string `json:"protocol,omitempty"`
	Banner         string `json:"banner,omitempty"`
	Category       string `json:"category,omitempty"`
	PrivEscPath    bool   `json:"priv_esc_path,omitempty"`
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	Proof          string `json:"proof,omitempty"`
}

// NetworkScanner performs port and service discovery
type NetworkScanner struct {
	Target     string
	Hosts      []string
	Ports      []int
	Workers    int
	Timeout    time.Duration
	Findings   []NetworkFinding
	findingsMu sync.Mutex
}

// NetworkScanOptions controls behavior of the dedicated infrastructure scanner.
type NetworkScanOptions struct {
	Profile  string        // infrastructure | web | hybrid
	Ports    []int         // optional explicit override
	Timeout  time.Duration // optional, default 2s
	Workers  int           // optional, falls back to constructor workers
	DeepScan bool          // if true, expand to broader nmap-like top range
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner(target string, workers int, intensity int) *NetworkScanner {
	return NewNetworkScannerWithOptions(target, workers, intensity, NetworkScanOptions{})
}

// NewNetworkScannerWithOptions creates a new network scanner with dedicated options.
func NewNetworkScannerWithOptions(target string, workers int, intensity int, opts NetworkScanOptions) *NetworkScanner {
	// Extract host from URL if necessary
	host := target
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err == nil {
			host = u.Hostname()
		}
	}

	if workers <= 0 {
		workers = 10
	}

	if intensity < 1 {
		intensity = 1
	}

	profile := strings.ToLower(strings.TrimSpace(opts.Profile))
	if profile == "" {
		profile = "infrastructure"
	}

	ports := profilePorts(profile, intensity, opts.DeepScan)
	if len(opts.Ports) > 0 {
		ports = opts.Ports
	}

	timeout := 2 * time.Second
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	if opts.Workers > 0 {
		workers = opts.Workers
	}

	hosts := resolveHosts(host)
	if len(hosts) == 0 {
		hosts = []string{host}
	}

	return &NetworkScanner{
		Target:   host,
		Hosts:    hosts,
		Ports:    uniquePorts(ports),
		Workers:  workers,
		Timeout:  timeout,
		Findings: []NetworkFinding{},
	}
}

func profilePorts(profile string, intensity int, deepScan bool) []int {
	webPorts := []int{80, 443, 3000, 5000, 5601, 7001, 7002, 8000, 8080, 8081, 8443, 8888}
	infraPorts := []int{21, 22, 23, 25, 53, 110, 143, 445, 587, 993, 995, 2375, 2376, 2379, 2380, 3306, 3389, 5432, 5900, 6379, 6443, 9200, 11211, 15672, 27017}
	extraPorts := []int{9090, 10000}
	deepPorts := append(expandPortRange(1, 1024), 1025, 1080, 1433, 1521, 1883, 2049, 3128, 4444, 6378, 7000, 7443, 7777, 8880, 9000, 9443, 27018, 49152, 50000)

	switch profile {
	case "web":
		if intensity > 3 {
			webPorts = append(webPorts, extraPorts...)
		}
		if deepScan || intensity >= 5 {
			return append(webPorts, deepPorts...)
		}
		return webPorts
	case "hybrid", "mixed", "all":
		ports := append(webPorts, infraPorts...)
		if intensity > 3 {
			ports = append(ports, extraPorts...)
		}
		if deepScan || intensity >= 5 {
			ports = append(ports, deepPorts...)
		}
		return ports
	case "infrastructure", "infra":
		fallthrough
	default:
		ports := append([]int{80, 443, 8080, 8443}, infraPorts...)
		if intensity > 3 {
			ports = append(ports, extraPorts...)
		}
		if deepScan || intensity >= 5 {
			ports = append(ports, deepPorts...)
		}
		return ports
	}
}

func expandPortRange(start, end int) []int {
	if start < 1 || end < start {
		return nil
	}
	out := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		out = append(out, p)
	}
	return out
}

func resolveHosts(target string) []string {
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}
	}

	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return []string{target}
	}

	out := make([]string, 0, len(ips))
	seen := map[string]struct{}{}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			s := ipv4.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			continue
		}
		s := ip.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return []string{target}
	}
	return out
}

func uniquePorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// ParseNetworkPorts parses CSV and ranges like "22,80,443,8000-8010".
func ParseNetworkPorts(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var out []int
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			bounds := strings.SplitN(token, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", token)
			}
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port %q: %w", bounds[0], err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port %q: %w", bounds[1], err)
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid range %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				out = append(out, p)
			}
			continue
		}

		p, err := strconv.Atoi(token)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", token, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port out of range: %d", p)
		}
		out = append(out, p)
	}

	return uniquePorts(out), nil
}

// Run executes the network scan
func (ns *NetworkScanner) Run() {
	type job struct {
		host string
		port int
	}
	jobs := make(chan job, len(ns.Ports)*max(1, len(ns.Hosts)))
	var wg sync.WaitGroup

	for i := 0; i < ns.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				ns.scanPort(j.host, j.port)
			}
		}()
	}

	for _, host := range ns.Hosts {
		for _, port := range ns.Ports {
			jobs <- job{host: host, port: port}
		}
	}
	close(jobs)

	wg.Wait()
}

func (ns *NetworkScanner) scanPort(host string, port int) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, ns.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	finding := NetworkFinding{
		Port:           port,
		State:          "open",
		Service:        ns.getServiceName(port),
		Endpoint:       address,
		Protocol:       "tcp",
		Category:       ns.getCategory(port),
		Risk:           ns.defaultRisk(port),
		Recommendation: ns.defaultRecommendation(port),
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	banner := make([]byte, 256)
	if n, err := conn.Read(banner); err == nil && n > 0 {
		finding.Banner = strings.TrimSpace(string(banner[:n]))
		finding.Proof = "passive banner read"
	}

	if probe, proof := ns.probeService(port, address); probe != "" {
		finding.Banner = joinEvidence(finding.Banner, probe)
		finding.Proof = joinEvidence(finding.Proof, proof)
	}

	if portRisk, rec, proof, signal, isPrivEsc := ns.assessPortExposure(port, address); signal != "" {
		if riskRank(portRisk) > riskRank(finding.Risk) {
			finding.Risk = portRisk
		}
		if rec != "" {
			finding.Recommendation = rec
		}
		finding.Banner = joinEvidence(finding.Banner, signal)
		finding.Proof = joinEvidence(finding.Proof, proof)
		finding.PrivEscPath = finding.PrivEscPath || isPrivEsc
	}

	ns.addFinding(finding)
}

func (ns *NetworkScanner) assessPortExposure(port int, address string) (risk, rec, proof, signal string, privEsc bool) {
	if ns.isTLSPort(port) {
		if tlsRisk, tlsRec, tlsProof, tlsSignal := ns.assessTLSPolicy(address); tlsRisk != "" {
			return tlsRisk, tlsRec, tlsProof, tlsSignal, false
		}
	}

	switch port {
	case 2375:
		status, body, _, err := ns.httpRequest("http", address, "GET", "/version")
		if err == nil && status == http.StatusOK {
			return "Critical (Unauthenticated Docker API exposed)",
				"Disable Docker remote API or require mTLS and strict host firewalling.",
				"GET /version on Docker API",
				snippet(body, 120),
				true
		}
	case 2376:
		status, body, _, err := ns.httpRequest("https", address, "GET", "/version")
		if err == nil && status == http.StatusOK {
			return "High (Docker TLS API reachable)",
				"Enforce client-certificate auth and restrict API to trusted management hosts.",
				"GET /version on Docker TLS API",
				snippet(body, 120),
				true
		}
	case 6379:
		redisSignal, redisProof, unauth := ns.probeRedis(address)
		if redisSignal != "" {
			if unauth {
				return "Critical (Redis appears exposed without auth)",
					"Bind Redis to localhost/private network, require auth, and disable dangerous commands.",
					redisProof,
					redisSignal,
					true
			}
			return "High (Redis exposed on network)",
				"Restrict Redis to private interfaces and enforce authentication.",
				redisProof,
				redisSignal,
				true
		}
	case 9200:
		status, body, hdr, err := ns.httpRequest("http", address, "GET", "/")
		if err == nil && status == http.StatusOK {
			server := strings.TrimSpace(hdr.Get("Server"))
			signal := "Elasticsearch API reachable"
			if server != "" {
				signal = signal + " server=" + server
			}
			return "Critical (Elasticsearch API exposed)",
				"Enable authentication/TLS and restrict access to trusted internal IP ranges.",
				"GET / on Elasticsearch",
				signal + " | " + snippet(body, 120),
				true
		}
	case 6443:
		status, body, _, err := ns.httpRequest("https", address, "GET", "/version")
		if err == nil && (status == http.StatusOK || status == http.StatusForbidden || status == http.StatusUnauthorized) {
			return "High (Kubernetes API reachable)",
				"Restrict Kubernetes API with network policies, mTLS, and strict RBAC.",
				"GET /version on Kubernetes API",
				snippet(body, 120),
				true
		}
	}

	if ns.isWebPort(port) {
		if risk, rec, proof, signal := ns.assessWebExposure(address, port); risk != "" {
			return risk, rec, proof, signal, false
		}
	}

	if ns.isRemoteAdminPort(port) {
		return "High (Remote administration service exposed)",
			"Restrict administration interfaces to VPN/jump-host and enforce MFA/allowlists.",
			"service classification",
			ns.getServiceName(port) + " endpoint detected",
			true
	}

	return "", "", "", "", false
}

func (ns *NetworkScanner) assessWebExposure(address string, port int) (risk, rec, proof, signal string) {
	schemes := ns.webProbeSchemes(port)

	for _, scheme := range schemes {
		status, _, hdr, err := ns.httpRequest(scheme, address, "OPTIONS", "/")
		if err != nil || status == 0 {
			continue
		}
		allow := strings.ToUpper(hdr.Get("Allow"))
		if allow != "" {
			riskyMethods := []string{"PUT", "DELETE", "TRACE", "CONNECT"}
			for _, m := range riskyMethods {
				if strings.Contains(allow, m) {
					return "High (Risky HTTP methods enabled on web service)",
						"Disable unsafe HTTP methods unless strictly required and authenticated.",
						"OPTIONS / method discovery",
						"allow=" + allow
				}
			}
		}
	}

	sensitivePaths := []string{"/admin", "/actuator", "/server-status", "/.git/config"}
	for _, scheme := range schemes {
		for _, p := range sensitivePaths {
			status, body, _, err := ns.httpRequest(scheme, address, "GET", p)
			if err != nil {
				continue
			}
			if status == http.StatusOK || status == http.StatusUnauthorized || status == http.StatusForbidden {
				risk := "Medium (Sensitive web management endpoint exposed)"
				rec := "Restrict sensitive endpoints by IP/authentication and disable debug/admin pages in production."
				if p == "/.git/config" && status == http.StatusOK {
					risk = "Critical (Exposed .git/config on web root)"
					rec = "Block VCS metadata from web root and rotate any exposed secrets immediately."
				}
				return risk, rec, "sensitive endpoint probe", fmt.Sprintf("%s %s => %d %s", scheme, p, status, snippet(body, 80))
			}
		}
	}

	return "", "", "", ""
}

func (ns *NetworkScanner) addFinding(f NetworkFinding) {
	ns.findingsMu.Lock()
	defer ns.findingsMu.Unlock()
	ns.Findings = append(ns.Findings, f)
}

func (ns *NetworkScanner) getServiceName(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25, 587:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 2375:
		return "Docker API"
	case 2376:
		return "Docker TLS API"
	case 2379, 2380:
		return "etcd"
	case 3000:
		return "Web Dashboard"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 5601:
		return "Kibana"
	case 5900:
		return "VNC"
	case 6379:
		return "Redis"
	case 6443:
		return "Kubernetes API"
	case 7001, 7002:
		return "WebLogic"
	case 8000, 8080, 8081, 8443, 8888:
		return "HTTP-Alt"
	case 9090:
		return "Prometheus"
	case 9200:
		return "Elasticsearch"
	case 11211:
		return "Memcached"
	case 15672:
		return "RabbitMQ Management"
	case 27017:
		return "MongoDB"
	default:
		return "unknown"
	}
}

func (ns *NetworkScanner) getCategory(port int) string {
	switch {
	case ns.isWebPort(port):
		return "web"
	case ns.isRemoteAdminPort(port):
		return "remote-admin"
	case port == 3306 || port == 5432 || port == 6379 || port == 9200 || port == 27017 || port == 11211:
		return "data-service"
	case port == 2375 || port == 2376 || port == 2379 || port == 2380 || port == 6443 || port == 15672:
		return "management-plane"
	default:
		return "network-service"
	}
}

func (ns *NetworkScanner) isWebPort(port int) bool {
	switch port {
	case 80, 443, 3000, 5000, 5601, 7001, 7002, 8000, 8080, 8081, 8443, 8888, 9090, 15672:
		return true
	default:
		return false
	}
}

func (ns *NetworkScanner) isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 6443, 2376, 993, 995:
		return true
	default:
		return false
	}
}

func (ns *NetworkScanner) isRemoteAdminPort(port int) bool {
	switch port {
	case 22, 23, 3389, 5900:
		return true
	default:
		return false
	}
}

func (ns *NetworkScanner) webProbeSchemes(port int) []string {
	switch port {
	case 443, 8443:
		return []string{"https", "http"}
	default:
		return []string{"http", "https"}
	}
}

func (ns *NetworkScanner) probeService(port int, address string) (signal, proof string) {
	switch port {
	case 22:
		return ns.probeSSH(address)
	case 25, 587:
		return ns.probeSMTP(address)
	case 3306:
		return ns.probeMySQL(address)
	case 5432:
		return ns.probePostgres(address)
	}

	if ns.isWebPort(port) {
		for _, scheme := range ns.webProbeSchemes(port) {
			status, _, hdr, err := ns.httpRequest(scheme, address, "HEAD", "/")
			if err != nil || status == 0 {
				continue
			}
			server := strings.TrimSpace(hdr.Get("Server"))
			if server != "" {
				return fmt.Sprintf("%s status=%d server=%s", strings.ToUpper(scheme), status, server), "HEAD / web probe"
			}
			return fmt.Sprintf("%s status=%d", strings.ToUpper(scheme), status), "HEAD / web probe"
		}
	}

	if port == 443 {
		if tlsSignal := ns.probeTLS(address); tlsSignal != "" {
			return tlsSignal, "TLS handshake"
		}
	}

	return "", ""
}

func (ns *NetworkScanner) probeSSH(address string) (signal, proof string) {
	conn, err := net.DialTimeout("tcp", address, ns.Timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", ""
	}
	b := strings.TrimSpace(string(buf[:n]))
	if strings.HasPrefix(strings.ToUpper(b), "SSH-") {
		return b, "SSH banner"
	}
	return "", ""
}

func (ns *NetworkScanner) probeSMTP(address string) (signal, proof string) {
	conn, err := net.DialTimeout("tcp", address, ns.Timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", ""
	}
	banner := strings.TrimSpace(string(buf[:n]))
	_, _ = conn.Write([]byte("EHLO knife.local\r\n"))
	n2, _ := conn.Read(buf)
	if n2 > 0 {
		return banner + " | " + snippet(strings.TrimSpace(string(buf[:n2])), 120), "SMTP EHLO"
	}
	return banner, "SMTP banner"
}

func (ns *NetworkScanner) probeMySQL(address string) (signal, proof string) {
	conn, err := net.DialTimeout("tcp", address, ns.Timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return "", ""
	}
	// MySQL handshake: 4-byte packet header then protocol/version string.
	payload := buf[4:n]
	if len(payload) < 2 {
		return "", ""
	}
	versionEnd := strings.IndexByte(string(payload[1:]), 0x00)
	if versionEnd <= 0 {
		return "mysql handshake detected", "MySQL initial handshake"
	}
	version := string(payload[1 : 1+versionEnd])
	return "mysql version=" + version, "MySQL initial handshake"
}

func (ns *NetworkScanner) probePostgres(address string) (signal, proof string) {
	conn, err := net.DialTimeout("tcp", address, ns.Timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103) // SSLRequest
	if _, err := conn.Write(req); err != nil {
		return "", ""
	}
	resp := make([]byte, 1)
	n, err := conn.Read(resp)
	if err != nil || n != 1 {
		return "", ""
	}
	if resp[0] == 'S' {
		return "postgres SSL enabled", "PostgreSQL SSLRequest"
	}
	if resp[0] == 'N' {
		return "postgres SSL not enabled", "PostgreSQL SSLRequest"
	}
	return "", ""
}

func (ns *NetworkScanner) probeTLS(address string) string {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ns.Target,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: ns.Timeout}, "tcp", address, cfg)
	if err != nil {
		return ""
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "TLS handshake succeeded"
	}
	cert := state.PeerCertificates[0]
	return fmt.Sprintf("TLS CN=%s issuer=%s", cert.Subject.CommonName, cert.Issuer.CommonName)
}

func (ns *NetworkScanner) assessTLSPolicy(address string) (risk, rec, proof, signal string) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ns.Target,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: ns.Timeout}, "tcp", address, cfg)
	if err != nil {
		return "", "", "", ""
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version > 0 && state.Version < tls.VersionTLS12 {
		return "High (Outdated TLS version accepted)",
			"Disable TLS 1.0/1.1 and enforce TLS 1.2+ with modern ciphers.",
			"TLS handshake policy check",
			fmt.Sprintf("negotiated_tls=%s", tlsVersionName(state.Version))
	}
	if len(state.PeerCertificates) == 0 {
		return "", "", "", ""
	}
	cert := state.PeerCertificates[0]
	if time.Until(cert.NotAfter) <= 0 {
		return "High (Expired TLS certificate)",
			"Rotate and renew server certificates immediately.",
			"TLS certificate validation",
			fmt.Sprintf("cert_expired_on=%s cn=%s", cert.NotAfter.Format(time.RFC3339), cert.Subject.CommonName)
	}
	if time.Until(cert.NotAfter) < (30 * 24 * time.Hour) {
		return "Medium (TLS certificate near expiry)",
			"Renew TLS certificate before expiry to avoid outages and trust warnings.",
			"TLS certificate validation",
			fmt.Sprintf("cert_expires_on=%s cn=%s", cert.NotAfter.Format(time.RFC3339), cert.Subject.CommonName)
	}
	if cert.Issuer.String() == cert.Subject.String() {
		return "Medium (Self-signed TLS certificate in use)",
			"Use CA-issued certificates for production-facing services.",
			"TLS certificate issuer check",
			fmt.Sprintf("self_signed_cn=%s", cert.Subject.CommonName)
	}
	return "", "", "", ""
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func (ns *NetworkScanner) probeRedis(address string) (signal, proof string, unauthenticated bool) {
	conn, err := net.DialTimeout("tcp", address, ns.Timeout)
	if err != nil {
		return "", "", false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("INFO\r\n")); err != nil {
		return "", "", false
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", "", false
	}
	resp := strings.ToUpper(string(buf[:n]))
	if strings.Contains(resp, "REDIS_VERSION") {
		return "redis INFO exposed", "INFO command", true
	}
	if strings.Contains(resp, "NOAUTH") {
		return "redis requires authentication", "INFO command", false
	}
	return "", "", false
}

func (ns *NetworkScanner) httpRequest(scheme, address, method, path string) (status int, body string, headers http.Header, err error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   ns.Timeout + time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	targetURL := fmt.Sprintf("%s://%s%s", scheme, address, path)
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("User-Agent", "knife-network-scanner/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 1024)
	data, _ := io.ReadAll(limited)
	return resp.StatusCode, strings.TrimSpace(string(data)), resp.Header.Clone(), nil
}

func joinEvidence(existing, extra string) string {
	existing = strings.TrimSpace(existing)
	extra = strings.TrimSpace(extra)
	if existing == "" {
		return extra
	}
	if extra == "" {
		return existing
	}
	return existing + " | " + extra
}

func riskRank(risk string) int {
	normalized := strings.ToLower(risk)
	switch {
	case strings.Contains(normalized, "critical"):
		return 4
	case strings.Contains(normalized, "high"):
		return 3
	case strings.Contains(normalized, "medium"):
		return 2
	case strings.Contains(normalized, "low"):
		return 1
	default:
		return 0
	}
}

func (ns *NetworkScanner) defaultRisk(port int) string {
	switch port {
	case 23:
		return "High (plaintext remote access)"
	case 22, 3389, 5900:
		return "High (remote administration exposed)"
	case 21, 25, 110, 143, 445:
		return "Medium (legacy/auth-sensitive service exposed)"
	case 2375:
		return "Critical (Docker API exposure can lead to host takeover)"
	case 6379, 9200, 27017, 3306, 5432, 11211:
		return "High (data service exposed)"
	case 587:
		return "Medium (mail service exposure; verify relay and auth policy)"
	case 80, 443, 8080, 8443, 8000, 8081, 8888, 3000, 5000:
		return "Medium (web attack surface exposed)"
	default:
		return "Medium (open network service)"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (ns *NetworkScanner) defaultRecommendation(port int) string {
	switch port {
	case 22, 23, 3389, 5900:
		return "Restrict to VPN/jump-host and approved IP allowlist."
	case 2375, 2376, 2379, 2380, 6443:
		return "Do not expose management-plane services publicly; enforce mTLS, RBAC, and firewall rules."
	case 6379, 9200, 27017, 3306, 5432, 11211:
		return "Bind to private interfaces and enforce strong authentication."
	case 80, 443, 8080, 8443, 8000, 8081, 8888, 3000, 5000:
		return "Run authenticated web testing and verify patch/WAF/TLS posture."
	default:
		return "Confirm business need, then firewall or disable if unnecessary."
	}
}
