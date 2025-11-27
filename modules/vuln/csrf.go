package vuln

func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "CSRF",
		Param:   "",
		Payload: "",
		Match:   `Set-Cookie`,
		Method:  "GET",
	})
}
