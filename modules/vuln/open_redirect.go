package vuln

func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "Open Redirect",
		Param:   "next",
		Payload: "//evil.com",
		Match:   `evil\.com`,
		Method:  "GET",
	})
}
