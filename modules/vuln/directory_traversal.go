package vuln

func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "Directory Traversal",
		Param:   "path",
		Payload: "../../../../etc/passwd",
		Match:   `root:x:0:0`,
		Method:  "GET",
	})
}
