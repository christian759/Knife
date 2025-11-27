package vuln

func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "LFI",
		Param:   "file",
		Payload: "../../../../etc/passwd",
		Match:   `root:x:0:0`,
		Method:  "GET",
	})
}
