package vuln

func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "RCE (Basic)",
		Param:   "cmd",
		Payload: "echo knife",
		Match:   `knife`,
		Method:  "GET",
	})
}
