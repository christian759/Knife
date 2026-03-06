package vuln

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NetworkFinding represents a discovered open port or service
type NetworkFinding struct {
	Port     int    `json:"port"`
	Service  string `json:"service"`
	State    string `json:"state"`
	Banner   string `json:"banner,omitempty"`
}

// NetworkScanner performs port and service discovery
type NetworkScanner struct {
	Target     string
	Ports      []int
	Workers    int
	Timeout    time.Duration
	Findings   []NetworkFinding
	findingsMu sync.Mutex
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner(target string, workers int, intensity int) *NetworkScanner {
	// Extract host from URL if necessary
	host := target
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err == nil {
			host = u.Hostname()
		}
	}

	// Default ports to scan
	commonPorts := []int{21, 22, 23, 25, 53, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017}
	
	if intensity > 3 {
		// Add more ports for higher intensity
		morePorts := []int{110, 143, 445, 993, 995, 3389, 5900, 8000, 8001, 8081, 9000, 9200}
		commonPorts = append(commonPorts, morePorts...)
	}

	return &NetworkScanner{
		Target:   host,
		Ports:    commonPorts,
		Workers:  workers,
		Timeout:  2 * time.Second,
		Findings: []NetworkFinding{},
	}
}

// Run executes the network scan
func (ns *NetworkScanner) Run() {
	ports := make(chan int, len(ns.Ports))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < ns.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				ns.scanPort(port)
			}
		}()
	}

	// Enqueue ports
	for _, port := range ns.Ports {
		ports <- port
	}
	close(ports)

	wg.Wait()
}

func (ns *NetworkScanner) scanPort(port int) {
	address := fmt.Sprintf("%s:%d", ns.Target, port)
	conn, err := net.DialTimeout("tcp", address, ns.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	finding := NetworkFinding{
		Port:    port,
		State:   "open",
		Service: ns.getServiceName(port),
	}

	// Try to grab banner (read-only, non-blocking)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	banner := make([]byte, 256)
	n, err := conn.Read(banner)
	if err == nil && n > 0 {
		finding.Banner = strings.TrimSpace(string(banner[:n]))
	}

	ns.addFinding(finding)
}

func (ns *NetworkScanner) addFinding(f NetworkFinding) {
	ns.findingsMu.Lock()
	defer ns.findingsMu.Unlock()
	ns.Findings = append(ns.Findings, f)
}

func (ns *NetworkScanner) getServiceName(port int) string {
	switch port {
	case 21: return "FTP"
	case 22: return "SSH"
	case 23: return "Telnet"
	case 25: return "SMTP"
	case 53: return "DNS"
	case 80: return "HTTP"
	case 110: return "POP3"
	case 143: return "IMAP"
	case 443: return "HTTPS"
	case 445: return "SMB"
	case 993: return "IMAPS"
	case 995: return "POP3S"
	case 3306: return "MySQL"
	case 3389: return "RDP"
	case 5432: return "PostgreSQL"
	case 5900: return "VNC"
	case 6379: return "Redis"
	case 8000, 8080, 8081: return "HTTP-Alt"
	case 9000: return "Portainer/FastCGI"
	case 9200: return "Elasticsearch"
	case 27017: return "MongoDB"
	default: return "unknown"
	}
}

// ConvertNetworkFinding converts NetworkFinding to UnifiedFinding
func ConvertNetworkFinding(f NetworkFinding, target string) UnifiedFinding {
	return UnifiedFinding{
		Type:      "Network Service",
		Name:      fmt.Sprintf("Open Port: %d (%s)", f.Port, f.Service),
		URL:       target,
		Severity:  "Medium",
		Timestamp: time.Now(),
		Evidence:  fmt.Sprintf("Status: %s, Banner: %s", f.State, f.Banner),
	}
}
