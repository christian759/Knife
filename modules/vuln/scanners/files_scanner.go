package scanners

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// FindingFile describes a discovered sensitive file/directory
type FindingFile struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Path       string `json:"path"`
	Status     string `json:"status"`
	StatusCode int    `json:"status_code"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
	Timestamp  string `json:"timestamp"`
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
			".git/HEAD",
			".git/logs/HEAD",
			".env",
			".env.local",
			".env.production",
			".env.dev",
			".env.backup",
			".env.example",
			".aws/credentials",
			".docker/config.json",
			".npmrc",
			".pypirc",
			"id_rsa",
			"id_rsa.pub",
			"config.php",
			"config.php.bak",
			"config.json",
			"appsettings.json",
			"application.properties",
			"application.yml",
			"wp-config.php",
			"wp-config.php.bak",
			"web.config",
			".htaccess",
			"composer.json",
			"package.json",
			"yarn.lock",
			"pnpm-lock.yaml",
			"phpinfo.php",
			"info.php",
			"server-status",
			"server-info",
			"robots.txt",
			"sitemap.xml",
			".svn/entries",
			".gitignore",
			"swagger.json",
			"openapi.json",
			".well-known/security.txt",
			"backup.sql",
			"dump.sql",
			"database.sql",
			"db.sql",
			"docker-compose.yml",
			"Dockerfile",
			"kubeconfig",
			".DS_Store",
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
	notFoundSig := s.captureNotFoundSignature(base)

	for _, path := range s.Paths {
		testURL := fmt.Sprintf("%s/%s", base, path)
		resp, err := s.Client.Get(testURL)
		if err != nil {
			continue
		}
		body := readSnippet(resp.Body, 4096)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			confidence, evidence, ok := assessFileExposure(path, body, resp.Header.Get("Content-Type"), notFoundSig, resp.StatusCode)
			if !ok {
				continue
			}
			s.Findings = append(s.Findings, FindingFile{
				Type:       "Sensitive File Discovered",
				URL:        testURL,
				Path:       path,
				Status:     "Found (200 OK)",
				StatusCode: resp.StatusCode,
				Confidence: confidence,
				Evidence:   evidence,
				Timestamp:  time.Now().Format(time.RFC3339),
			})
		} else if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			s.Findings = append(s.Findings, FindingFile{
				Type:       "Sensitive Path Access Restricted",
				URL:        testURL,
				Path:       path,
				Status:     fmt.Sprintf("Restricted (%d)", resp.StatusCode),
				StatusCode: resp.StatusCode,
				Confidence: "Medium",
				Evidence:   fmt.Sprintf("Path exists but requires authorization: /%s", path),
				Timestamp:  time.Now().Format(time.RFC3339),
			})
		}
	}
}

func (s *FilesScanner) GetFindings() []FindingFile {
	return s.Findings
}

type notFoundSignature struct {
	statusCode int
	bodyNorm   string
}

func (s *FilesScanner) captureNotFoundSignature(base string) notFoundSignature {
	randomPath := fmt.Sprintf("%s/__knife_not_found_probe__%d__", base, time.Now().UnixNano())
	resp, err := s.Client.Get(randomPath)
	if err != nil {
		return notFoundSignature{}
	}
	body := readSnippet(resp.Body, 2048)
	resp.Body.Close()
	return notFoundSignature{
		statusCode: resp.StatusCode,
		bodyNorm:   normalizeForComparison(body),
	}
}

func assessFileExposure(path, body, contentType string, nf notFoundSignature, statusCode int) (string, string, bool) {
	bodyNorm := normalizeForComparison(body)
	if nf.statusCode != 0 && statusCode == nf.statusCode && bodyNorm == nf.bodyNorm {
		return "", "", false
	}
	if looksLikeNotFound(body) {
		return "", "", false
	}

	path = strings.ToLower(path)
	contentType = strings.ToLower(contentType)

	signatures := map[string][]string{
		".git/config":            {"[core]", "[remote"},
		".git/head":              {"ref: refs/heads"},
		".env":                   {"db_", "secret", "api_key", "app_key", "password"},
		"wp-config.php":          {"db_name", "db_user", "db_password"},
		"config.php":             {"<?php", "define(", "$"},
		"appsettings.json":       {"connectionstrings", "jwt", "secret"},
		"application.properties": {"spring.datasource", "password=", "username="},
		"composer.json":          {"\"require\"", "\"name\""},
		"package.json":           {"\"dependencies\"", "\"scripts\"", "\"name\""},
		"docker-compose.yml":     {"services:", "version:"},
		"swagger.json":           {"\"openapi\"", "\"paths\""},
		"openapi.json":           {"\"openapi\"", "\"paths\""},
		"robots.txt":             {"user-agent", "disallow"},
		"sitemap.xml":            {"<urlset", "<sitemapindex"},
	}

	for k, sigs := range signatures {
		if strings.Contains(path, k) {
			for _, sig := range sigs {
				if strings.Contains(bodyNorm, strings.ToLower(sig)) {
					return "High", fmt.Sprintf("Matched content signature %q at /%s", sig, path), true
				}
			}
			return "Medium", fmt.Sprintf("File path is sensitive and content differs from not-found baseline: /%s", path), true
		}
	}

	if strings.Contains(contentType, "text/plain") || strings.Contains(contentType, "application/json") || strings.Contains(contentType, "application/xml") || strings.Contains(contentType, "text/xml") {
		return "Medium", fmt.Sprintf("Potential sensitive file exposed at /%s (content-type=%s)", path, contentType), true
	}
	return "Low", fmt.Sprintf("Potential sensitive path responded 200 OK at /%s", path), true
}

func readSnippet(r io.Reader, limit int64) string {
	if r == nil {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return ""
	}
	return string(b)
}

func normalizeForComparison(s string) string {
	spaceRe := regexp.MustCompile(`\s+`)
	s = strings.ToLower(strings.TrimSpace(s))
	s = spaceRe.ReplaceAllString(s, " ")
	if len(s) > 800 {
		return s[:800]
	}
	return s
}

func looksLikeNotFound(body string) bool {
	body = strings.ToLower(body)
	indicators := []string{
		"404 not found",
		"page not found",
		"the requested url was not found",
		"cannot get /",
		"doesn't exist",
	}
	for _, ind := range indicators {
		if strings.Contains(body, ind) {
			return true
		}
	}
	return false
}
