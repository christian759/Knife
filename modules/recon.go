package modules

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gocolly/colly"
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

// searching for users in various web
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

// presently it only support google and duckduckgo
func dorksearching(word string, websites []string, strict bool, engine string) map[string]string {
	results := make(map[string]string)

	for _, site := range websites {
		// Build the query
		var query string
		if strict {
			query = fmt.Sprintf("site:%s \"%s\"", site, word)
		} else {
			query = fmt.Sprintf("site:%s %s", site, word)
		}
		escapedQuery := url.QueryEscape(query)

		// Choose search engine
		var searchURL string
		if engine == "google" {
			searchURL = fmt.Sprintf("https://www.google.com/search?q=%s", escapedQuery)
		} else {
			searchURL = fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", escapedQuery)
		}

		// Create collector
		c := colly.NewCollector(
			colly.UserAgent("Mozilla/5.0"),
		)

		// Extract result links
		c.OnHTML("a", func(e *colly.HTMLElement) {
			href := e.Attr("href")

			if engine == "google" && strings.HasPrefix(href, "/url?q=") {
				cleaned := strings.Split(strings.TrimPrefix(href, "/url?q="), "&")[0]
				if strings.HasPrefix(cleaned, "http") {
					results[query] = cleaned
				}
			}

			if engine == "duck" && strings.Contains(e.Attr("class"), "result__a") {
				href := e.Attr("href")
				if strings.HasPrefix(href, "http") {
					results[query] = href
				}
			}
		})

		// Visit search URL
		err := c.Visit(searchURL)
		if err != nil {
			log.Println("Failed to fetch:", err)
			continue
		}
	}

	return results

}
