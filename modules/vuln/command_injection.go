package vuln

func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "Command Injection",
		Param:   "ip",
		Payload: "127.0.0.1; cat /etc/passwd",
		Match:   `root:x:0:0`,
		Method:  "GET",
	})
}
