/*
reads in subdomains from stdin
attempts to identify misconfigured cloudfront instances
in future, more checks will be added.
*/
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/cybercdh/isaws/awschecker"
	"github.com/gookit/color"
)

var concurrency int
var verbose bool

func main() {

	flag.IntVar(&concurrency, "c", 20, "set the concurrency level")
	flag.BoolVar(&verbose, "v", false, "Show hostname with the corresponding IP")

	flag.Parse()

	var wg sync.WaitGroup
	subdomains := make(chan string, concurrency)

	// Call GetAWSPrefixes to fetch AWS IP ranges
	prefixes, err := awschecker.GetAWSPrefixes()
	if err != nil {
		log.Fatalf("Error fetching AWS prefixes: %v", err)
	}

	// Start a fixed number of goroutines to handle subdomains
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker(subdomains, &wg, prefixes)
	}

	// Read subdomains from stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		subdomain := scanner.Text()
		subdomains <- subdomain
	}

	close(subdomains)
	wg.Wait()
}

// startsWithHTTP checks if the subdomain starts with http:// or https://
func startsWithHTTP(subdomain string) bool {
	return strings.HasPrefix(subdomain, "http://") || strings.HasPrefix(subdomain, "https://")
}

func worker(subdomains <-chan string, wg *sync.WaitGroup, prefixes []awschecker.Prefix) {

	defer wg.Done()

	for subdomain := range subdomains {

		// get IP addresses for the subdomain
		IPs, err := net.LookupIP(subdomain)
		if err != nil {
			continue
		}

		// for each IP, check if it's in the AWS range
		for _, ip := range IPs {
			matchingPrefixes, err := awschecker.IsAWSIPAddress(ip, prefixes)
			if err != nil {
				continue
			}

			// if this is an AWS IP then check the subdomain for Cloudfront issue
			if len(matchingPrefixes) > 0 {
				checkSubdomain(subdomain, wg)
			}

		}

	}
}

// checkSubdomain makes an HTTP GET request to the subdomain and checks the response.
func checkSubdomain(subdomain string, wg *sync.WaitGroup) {

	// Correctly ensure subdomain starts with http:// or https://
	if !startsWithHTTP(subdomain) {
		subdomain = "http://" + subdomain
	}

	resp, err := http.Get(subdomain)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// debugging
	if verbose {
		fmt.Printf("%s,%d\n", subdomain, resp.StatusCode)
	}

	// Check if the response status code is 403 Forbidden
	if resp.StatusCode == http.StatusForbidden {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			if verbose {
				fmt.Printf("Error reading response body for %s: %v\n", subdomain, err)
			}
			return
		}
		bodyString := string(bodyBytes)

		// Check for specific error messages in the response body, if necessary
		if strings.Contains(bodyString, "Bad request") {
			if verbose {
				color.Green.Println("Potential CloudFront misconfiguration found:", subdomain)
			} else {
				fmt.Println(subdomain)
			}

		}
	}
}
