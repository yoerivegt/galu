package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
)

// for httpx's weird input requirement.
// returns a map split with spaces as a string, like "google.com tesla.com yahoo.com".
// input: map[string]bool, output: string
func mapToString(m map[string]bool) string {
	var result string
	for key := range m {
		// Add space if result is not empty
		if result != "" {
			result += " "
		}
		result += key
	}
	return result
}

// return the list from stdin
// input: nothing, output: map[string]bool
func stdinput() map[string]bool {
	var allUrls = make(map[string]bool)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		allUrls[scanner.Text()] = true
	}
	return allUrls
}

// filter a url, by only returning the subdomain name
// input: string, output: string
func filterURL(url string) string {

	//remove parameters
	url = strings.Split(url, "?")[0]

	// remove http
	if strings.Contains(url, "://") {
		url = strings.Split(url, "://")[1]
	}

	// remove path
	url = strings.Split(url, "/")[0]
	url = strings.Split(url, "\\")[0]

	if strings.Contains(url, "@") {
		// remove anything before @ sign
		url = strings.Split(url, "@")[1]
	}

	// remove port
	url = strings.Split(url, ":")[0]

	return url
}

// run httpx on all the filtered domains, return the live ones
// input: map[string]bool, output: map[string]bool
func getLiveDomains(allFilteredDomains map[string]bool) map[string]bool {
	// change the allFilteredDomains map to a data type httpx accepts

	// run httpx on all the filtered domains
	result := make(map[string]bool)

	domainSlice := strings.Split(mapToString(allFilteredDomains), " ")

	// httpx options
	gologger.DefaultLogger.SetMaxLevel(-1) // don't output anything
	options := runner.Options{
		Methods:         "GET",
		Timeout:         5,
		Threads:         60,
		Silent:          true,
		RandomAgent:     true,
		Retries:         3,
		InputTargetHost: goflags.StringSlice(domainSlice),
		OnResult: func(r runner.Result) {
			// handle error
			if r.Err != nil {
				return
			}
			// if result exists, is not empty, and doesn't have a space
			if r.Input != "" && r.Input != " " {
				// if doesn't already exist in map
				if !result[r.Input] {
					// add filtered domain to map
					result[filterURL(r.URL)] = true
				}
			}

		},
	}

	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	// return all of the filtered domains as a map
	return result

}

// return all the entries from the list with the live domains to stdout
// input: map[string]bool, map[string]bool , ouput: map[string]bool
func returnLiveURLS(allLiveDomains map[string]bool, stdin map[string]bool) map[string]bool {
	var allLiveURLS = make(map[string]bool)
	for url := range stdin {
		for liveDomain := range allLiveDomains {
			if strings.Contains(url, "://"+liveDomain) {
				allLiveURLS[url] = true
			}
		}
	}

	return allLiveURLS
}

// start
func main() {
	stdin := stdinput()

	// filter all the URL's
	var allFilteredDomains = make(map[string]bool)
	for obj := range stdin {
		allFilteredDomains[filterURL(obj)] = true
	}

	// get all the live domains
	allLiveDomains := getLiveDomains(allFilteredDomains)

	// get all the live URL's, according to the live domains
	allLiveURLS := returnLiveURLS(allLiveDomains, stdin)

	// print everything out
	for obj := range allLiveURLS {
		fmt.Println(obj) // print all the live urls
	}
}
