package main

import (
	"compress/bzip2"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quay/goval-parser/oval"
)

const (
	defURL = "https://security.access.redhat.com/data/oval/v2/RHEL9/openshift-4-including-unpatched.oval.xml.bz2"
	defCVE = "CVE-2022-1996"
	defDur = 5 * time.Minute
)

func envOrDefStr(key string, def string) string {
	if val := os.Getenv(key); val != "" {
		log.Printf("%s found: %s", key, val)
		return val
	}

	log.Printf("%s not found, using default: %s", key, def)
	return def
}

func envOrDefDur(key string, def time.Duration) time.Duration {
	if valStr := os.Getenv(key); valStr != "" {
		val, err := time.ParseDuration(valStr)
		if err != nil {
			log.Printf("Error parsing %s, using default %s, err: %v", key, def, err)
			return def
		}
		log.Printf("%s found: %s", key, val)
		return val
	}

	log.Printf("%s not found, using default %s", key, def)
	return def
}

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func main() {
	dur := envOrDefDur("OC_DUR", defDur)
	cveID := envOrDefStr("OC_CVE", defCVE)
	url := envOrDefStr("OC_OVAL_URL", defURL)

	log.Printf("Every %v polling for %v from %v", dur, cveID, url)

	ticker := time.NewTicker(dur)
	defer ticker.Stop()

	tick := func() {
		if err := dump(url, cveID); err != nil {
			log.Printf("FAIL: %v", err)
		}
	}

	tick()
	for range ticker.C {
		tick()
	}
}

func dump(url, cveID string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code %v returned from %s", resp.StatusCode, url)
	}

	bzipReader := bzip2.NewReader(resp.Body)

	var root oval.Root
	err = xml.NewDecoder(bzipReader).Decode(&root)
	if err != nil {
		return err
	}

	for _, def := range root.Definitions.Definitions {
		if len(def.References) == 0 {
			continue
		}
		cve := strings.TrimSpace(def.References[0].RefID)
		if cve != cveID {
			continue
		}

		title := def.Title
		if strings.Contains(strings.ToLower(title), "unaffected") {
			continue
		}

		log.Printf("%v: %v\n", cve, def.Advisory.AffectedCPEList)
	}

	return nil
}
