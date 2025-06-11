package recon

import (
	"fmt"
	"net/http"
)

var socialsite = map[string]string{
	"facebook":  "https://web.facebook.com/",
	"twitter":   "https://x.com/",
	"github":    "https://github.com/",
	"tiktok":    "https://www.tiktok.com/@",
	"youtube":   "https://www.youtube/@",
	"instagram": "https://www.instagram/",
	"twitch":    "https://www.twitch.tv/",
	"medium":    "https://medium.com/@",
	"linkedin":  "https://www.linkedin.com/in/",
	"threads":   "https://www.threads.com/",
}

func search_user(user string) {
	fmt.Println("Found: ")
	for name, site := range socialsite {
		trialsite := site + user
		_, err := http.Get(trialsite)
		if err != nil {
			panic(err)
		} else {
			fmt.Printf("%s: %s \n", name, trialsite)
		}
	}
}
