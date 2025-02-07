package main

import (
	"compress/bzip2"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quay/goval-parser/oval"
)

const (
	defDur = 10 * time.Minute
)

var defaultConfig = Config{
	Sources: map[string]string{
		"0": "https://security.access.redhat.com/data/oval/v2/RHEL9/openshift-4-including-unpatched.oval.xml.bz2",
		"1": "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9-including-unpatched.oval.xml.bz2",
	},
	Vulns: map[string][]string{
		"0": {"CVE-2022-1996"},
		"1": {"RHSA-2024:10244"},
	},
}

type Config struct {
	// Sources maps an arbitrary id to a URL representing an OVAL source.
	Sources map[string]string `json:"sources,omitempty"`
	// Vulns maps a source id to a list of vulns.
	Vulns map[string][]string `json:"vulns,omitempty"`
}

type Vuln struct {
	SourceID string   `json:"source,omitempty"`
	IDs      []string `json:"ids,omitempty"`
}

func (c Config) String() string {
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf("error converting config to string: %v", err)
	}

	return fmt.Sprint(string(b))
}

func loadConfig(configPath string) Config {
	if configPath == "" {
		return defaultConfig
	}

	// TODO: load file from configPath
	return defaultConfig
}

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

	cfg := loadConfig("")

	log.Printf("Polling every %v using config: %v", dur, cfg.String())

	ticker := time.NewTicker(dur)
	defer ticker.Stop()

	tick := func() {
		if err := dump(cfg); err != nil {
			log.Printf("FAIL: %v", err)
		}
	}

	tick()
	for range ticker.C {
		tick()
	}
}

func dump(cfg Config) error {
	srcIDs := []string{}
	for id := range cfg.Sources {
		srcIDs = append(srcIDs, id)
	}
	sort.Strings(srcIDs)
	for _, srcID := range srcIDs {
		srcUrl := cfg.Sources[srcID]
		vulnsToCPE, err := gather(cfg, srcID)
		if err != nil {
			return fmt.Errorf("pulling data for source %q: %w", srcUrl, err)
		}

		var vulnIDs []string
		for vuln := range vulnsToCPE {
			vulnIDs = append(vulnIDs, vuln)
		}
		sort.Strings(vulnIDs)

		for _, vulnID := range vulnIDs {
			cpes := vulnsToCPE[vulnID]

			log.Printf("src:%q, vuln:%q, cpes:%q\n", srcID, vulnID, cpes)
		}
	}

	return nil
}

func gather(cfg Config, sourceID string) (map[string]string, error) {
	url := cfg.Sources[sourceID]
	vulnsList := cfg.Vulns[sourceID]

	// vulnMap holds CVE/RHSAs from which to pull CPEs for
	vulnMap := make(map[string]string)
	for _, v := range vulnsList {
		vulnMap[v] = ""
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid status code %v returned from %s", resp.StatusCode, url)
	}

	bzipReader := bzip2.NewReader(resp.Body)

	var root oval.Root
	err = xml.NewDecoder(bzipReader).Decode(&root)
	if err != nil {
		return nil, err
	}

	for _, def := range root.Definitions.Definitions {
		if len(def.References) == 0 {
			continue
		}
		cve := strings.TrimSpace(def.References[0].RefID)
		v, ok := vulnMap[cve]
		if !ok {
			continue
		}

		title := def.Title
		if strings.Contains(strings.ToLower(title), "unaffected") {
			continue
		}

		base := ""
		if v != "" {
			base = fmt.Sprintf("%s,", v)
		}
		vulnMap[cve] = fmt.Sprintf("%s%s", base, strings.Join(def.Advisory.AffectedCPEList, ","))
	}

	return vulnMap, nil
}
