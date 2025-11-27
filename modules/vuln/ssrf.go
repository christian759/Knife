package vuln

func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "SSRF",
		Param:   "url",
		Payload: "http://127.0.0.1:80",
		Match:   `Server|Apache|nginx|Bad Request`,
		Method:  "GET",
	})
}
