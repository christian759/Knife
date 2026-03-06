package scanners

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FindingFile describes a discovered sensitive file/directory
type FindingFile struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Path      string `json:"path"`
	Status    string `json:"status"`
	Evidence  string `json:"evidence"`
	Timestamp string `json:"timestamp"`
}

// FilesScanner discovers sensitive files and directories
type FilesScanner struct {
	Target   string
	Client   *http.Client
	Findings []FindingFile
	Paths    []string
}

// NewFilesScanner creates a new sensitive files scanner
func NewFilesScanner(target string) *FilesScanner {
	return &FilesScanner{
		Target: target,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects to avoid false positives
			},
		},
		Paths: []string{
			".git/config",
			".env",
			".aws/credentials",
			"config.php",
			"config.php.bak",
			"config.json",
			"wp-config.php",
			"wp-config.php.bak",
			"web.config",
			".htaccess",
			"composer.json",
			"package.json",
			"phpinfo.php",
			"info.php",
			"server-status",
			"server-info",
			"robots.txt",
			"sitemap.xml",
			".svn/entries",
			".gitignore",
			"backup.sql",
			"dump.sql",
			"database.sql",
			"db.sql",
			"docker-compose.yml",
			"Dockerfile",
		},
	}
}

// Run executes the sensitive files scan
func (s *FilesScanner) Run() {
	baseURL, err := url.Parse(s.Target)
	if err != nil {
		return
	}
	
	// Normalize base URL to have no trailing slash for easier joining
	base := strings.TrimSuffix(baseURL.String(), "/")

	for _, path := range s.Paths {
		testURL := fmt.Sprintf("%s/%s", base, path)
		resp, err := s.Client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			// Basic check for interesting content
			s.Findings = append(s.Findings, FindingFile{
				Type:      "Sensitive File Discovered",
				URL:       testURL,
				Path:      path,
				Status:    "Found (200 OK)",
				Evidence:  fmt.Sprintf("Exposed path: /%s", path),
				Timestamp: time.Now().Format(time.RFC3339),
			})
		} else if resp.StatusCode == http.StatusForbidden {
			s.Findings = append(s.Findings, FindingFile{
				Type:      "Sensitive Directory Listing Restricted",
				URL:       testURL,
				Path:      path,
				Status:    "Restricted (403 Forbidden)",
				Evidence:  fmt.Sprintf("Protected path: /%s", path),
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}
}

func (s *FilesScanner) GetFindings() []FindingFile {
	return s.Findings
}
