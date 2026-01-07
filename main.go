package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// --- Configuration Structs ---

type Config struct {
	ServerPort     string    `json:"server_port"`
	RefreshMinutes int       `json:"refresh_interval_minutes"`
	MaxLines       int       `json:"max_lines"`
	AdminUser      string    `json:"admin_user"`
	AdminPass      string    `json:"admin_pass"`
	Sources        Sources   `json:"sources"`
	Whitelist      Whitelist `json:"whitelist"`
}

type Sources struct {
	IncludeIPv6   bool     `json:"include_ipv6"` // New Flag
	IncludeAWS    bool     `json:"include_aws"`
	IncludeAzure  bool     `json:"include_azure"`
	IncludeGCP    bool     `json:"include_gcp"`
	IncludeOracle bool     `json:"include_oracle"`
	IncludeLinode bool     `json:"include_linode"`
	HighRiskASNs  []string `json:"high_risk_asns"`
	GenericASNs   []string `json:"generic_asns"`
}

type Whitelist struct {
	Comment string   `json:"_comment"` // Instructions for the user
	ASNs    []string `json:"asns"`
	CIDRs   []string `json:"cidrs"`
}

// --- Global State ---

var (
	currentConfig Config
	configMutex   sync.RWMutex
	currentEDL    []string // The final processed list in memory
	edlMutex      sync.RWMutex
	lastRefresh   time.Time
	droppedCount  int
	cache         *CacheManager
)

const configFile = "config.json"

// --- Main Entry Point ---

func main() {
	// Define a command-line flag
	// Usage: ./aggregator -output="edl_list.txt"
	outputFlag := flag.String("output", "", "Path to output text file. If set, runs once and exits.")
	flag.Parse()

	setupLogging()

	// Initialize Cache
	cache = NewCacheManager("cache_data")

	// 1. Load Config
	if err := loadConfig(); err != nil {
		log.Println("Config file not found or invalid, creating default...")
		createDefaultConfig()
		if err := loadConfig(); err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	// --- CLI MODE CHECK ---
	if *outputFlag != "" {
		log.Printf("CLI Mode detected. Generating list to: %s", *outputFlag)
		
		// Run the job once synchronously
		runAggregation()

		// Write the result to the specified file
		f, err := os.Create(*outputFlag)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		defer f.Close()

		edlMutex.RLock()
		for _, line := range currentEDL {
			fmt.Fprintln(f, line)
		}
		edlMutex.RUnlock()

		log.Println("Success. Exiting.")
		return // Exit the program
	}
	// ----------------------

	log.Printf("Server Mode. Max Lines: %d", currentConfig.MaxLines)

	// 2. Start Background Scheduler
	go scheduler()

	// 3. Start Web Server
	http.HandleFunc("/edl", handleEDL)
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/admin/logs", handleLogs)
	http.HandleFunc("/api/refresh", handleRefresh)

	log.Printf("Starting Server on %s...", currentConfig.ServerPort)
	log.Fatal(http.ListenAndServe(currentConfig.ServerPort, nil))
}

func setupLogging() {
	// Ensure logs directory exists
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		os.Mkdir("logs", 0755)
	}

	logFile := &lumberjack.Logger{
		Filename:   filepath.Join("logs", "aggregator.log"),
		MaxSize:    10,   // megabytes
		MaxBackups: 3,    // files
		MaxAge:     28,   // days
		Compress:   true, // disabled by default
	}

	// Write to both Standard Output (Console) and the File
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// --- Cache Manager ---

type CacheManager struct {
	Dir string
	mu  sync.Mutex
}

func NewCacheManager(dir string) *CacheManager {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.Mkdir(dir, 0755)
	}
	return &CacheManager{Dir: dir}
}

// Save stores a list of CIDR strings
func (cm *CacheManager) Save(key string, data []string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Don't overwrite cache with empty data
	if len(data) == 0 {
		return nil
	}

	filePath := filepath.Join(cm.Dir, key+".json")
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(data)
}

// Load retrieves CIDR strings
func (cm *CacheManager) Load(key string) ([]string, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	filePath := filepath.Join(cm.Dir, key+".json")
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data []string
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}

// --- Core Aggregation Logic ---

func runAggregation() {
	configMutex.RLock()
	cfg := currentConfig
	configMutex.RUnlock()

	log.Println("Starting Aggregation Job...")
	start := time.Now()

	var priorityCIDRs []*net.IPNet
	var standardCIDRs []*net.IPNet
	
	var pMu sync.Mutex 
	var sMu sync.Mutex 
	var wg sync.WaitGroup

	// --- FETCH HELPER ---
	executeFetch := func(name string, target *[]*net.IPNet, mu *sync.Mutex, fetchFunc func() ([]*net.IPNet, error)) {
		defer wg.Done()

		// 1. Try Live Fetch
		cidrs, err := fetchFunc()

		// 2. Success? 
		if err == nil && len(cidrs) > 0 {
			// --- NEW: IPv6 Filtering (Before Caching) ---
			// We filter BEFORE caching so we don't fill the disk with IPv6 data we don't want.
			if !cfg.Sources.IncludeIPv6 {
				cidrs = filterIPv4(cidrs)
			}
			// --------------------------------------------

			var strList []string
			for _, c := range cidrs {
				strList = append(strList, c.String())
			}
			if serr := cache.Save(name, strList); serr != nil {
				log.Printf("[%s] Warning: Failed to save cache: %v", name, serr)
			}
			
			log.Printf("Fetched %s: %d (Live)", name, len(cidrs))
			
			mu.Lock()
			*target = append(*target, cidrs...)
			mu.Unlock()
			return
		}

		// 3. Failure? Load from Cache
		log.Printf("[%s] Fetch failed or empty (Err: %v). Attempting cache...", name, err)
		cachedStrs, cerr := cache.Load(name)
		if cerr != nil {
			log.Printf("[%s] CRITICAL: Cache load failed: %v", name, cerr)
			return
		}

		var cachedCIDRs []*net.IPNet
		for _, s := range cachedStrs {
			_, n, err := net.ParseCIDR(s)
			if err == nil {
				cachedCIDRs = append(cachedCIDRs, n)
			}
		}

		// --- NEW: IPv6 Filtering (After Cache Load) ---
		// We filter AFTER loading too, in case the cache file was created 
		// back when IPv6 was enabled.
		if !cfg.Sources.IncludeIPv6 {
			cachedCIDRs = filterIPv4(cachedCIDRs)
		}
		// ----------------------------------------------

		log.Printf("Fetched %s: %d (FROM CACHE)", name, len(cachedCIDRs))
		
		mu.Lock()
		*target = append(*target, cachedCIDRs...)
		mu.Unlock()
	}

	// --- 1. FETCH STANDARD SOURCES ---
	if cfg.Sources.IncludeAWS {
		wg.Add(1)
		go executeFetch("AWS", &standardCIDRs, &sMu, fetchAWS)
	}
	if cfg.Sources.IncludeGCP {
		wg.Add(1)
		go executeFetch("GCP", &standardCIDRs, &sMu, fetchGCP)
	}
	if cfg.Sources.IncludeAzure {
		wg.Add(1)
		go executeFetch("Azure", &standardCIDRs, &sMu, fetchAzure)
	}
	if cfg.Sources.IncludeOracle {
		wg.Add(1)
		go executeFetch("Oracle", &standardCIDRs, &sMu, fetchOracle)
	}
	if cfg.Sources.IncludeLinode {
		wg.Add(1)
		go executeFetch("Linode", &standardCIDRs, &sMu, fetchLinode)
	}

	asnSemaphore := make(chan struct{}, 2)

	for _, asn := range cfg.Sources.GenericASNs {
		if isWhitelisted(asn, cfg.Whitelist.ASNs) {
			log.Printf("Skipping Whitelisted ASN: %s", asn)
			continue
		}
		wg.Add(1)
		currentASN := asn
		go func() {
			asnSemaphore <- struct{}{}
			executeFetch("ASN_"+currentASN, &standardCIDRs, &sMu, func() ([]*net.IPNet, error) {
				return fetchASN(currentASN)
			})
			<-asnSemaphore
		}()
	}

	// --- 2. FETCH HIGH RISK SOURCES ---
	for _, asn := range cfg.Sources.HighRiskASNs {
		if isWhitelisted(asn, cfg.Whitelist.ASNs) {
			log.Printf("Skipping Whitelisted HighRisk ASN: %s", asn)
			continue
		}
		wg.Add(1)
		currentASN := asn
		go func() {
			asnSemaphore <- struct{}{}
			executeFetch("ASN_"+currentASN, &priorityCIDRs, &pMu, func() ([]*net.IPNet, error) {
				return fetchASN(currentASN)
			})
			<-asnSemaphore
		}()
	}

	wg.Wait()
	log.Printf("Raw Counts -> Priority: %d, Standard: %d", len(priorityCIDRs), len(standardCIDRs))

	// --- 3. PROCESSING ---
	var whiteCIDRs []*net.IPNet
	for _, s := range cfg.Whitelist.CIDRs {
		_, n, err := net.ParseCIDR(s)
		if err == nil {
			whiteCIDRs = append(whiteCIDRs, n)
		}
	}

	pFiltered := filterWhitelist(priorityCIDRs, whiteCIDRs)
	pOptimized := mergeCIDRs(pFiltered)

	sFiltered := filterWhitelist(standardCIDRs, whiteCIDRs)
	sOptimized := mergeCIDRs(sFiltered)

	log.Printf("Optimized Counts -> Priority: %d, Standard: %d", len(pOptimized), len(sOptimized))

	// --- 4. COMBINE ---
	finalList := []string{}
	for _, n := range pOptimized {
		finalList = append(finalList, n.String())
	}
	for _, n := range sOptimized {
		finalList = append(finalList, n.String())
	}

	// --- 5. TRUNCATE ---
	dropped := 0
	if len(finalList) > cfg.MaxLines {
		dropped = len(finalList) - cfg.MaxLines
		finalList = finalList[:cfg.MaxLines]
		log.Printf("WARNING: List exceeded limit of %d. Truncated %d standard entries.", cfg.MaxLines, dropped)
	}

	// --- 6. UPDATE STATE ---
	edlMutex.Lock()
	currentEDL = finalList
	lastRefresh = time.Now()
	droppedCount = dropped
	edlMutex.Unlock()

	log.Printf("Job Complete in %s. Final Count: %d. Dropped: %d", time.Since(start), len(finalList), dropped)
}

// Helper for the loop
func isWhitelisted(asn string, whitelist []string) bool {
	for _, w := range whitelist {
		if w == asn {
			return true
		}
	}
	return false
}

// --- Data Fetchers ---

// fetchASN tries RADb -> NTT -> RIPE Stat -> Error (Cache)
func fetchASN(asn string) ([]*net.IPNet, error) {
	// 1. Try Primary Whois (RADb)
	cidrs, err := queryWhoisServer("whois.radb.net:43", asn)
	if err == nil && len(cidrs) > 0 {
		return cidrs, nil
	}

	// 2. Try Secondary Whois (NTT)
	log.Printf("ASN %s: RADb failed. Trying NTT...", asn)
	cidrs, err = queryWhoisServer("rr.ntt.net:43", asn)
	if err == nil && len(cidrs) > 0 {
		return cidrs, nil
	}

	// 3. Failover: RIPE Stat API (HTTP/JSON)
	// This is the "Nuclear Option" when Port 43 is blocked.
	log.Printf("ASN %s: Whois blocked. Switching to RIPE Stat API (HTTPS)...", asn)
	cidrs, err = fetchRipeStat(asn)
	if err == nil && len(cidrs) > 0 {
		return cidrs, nil
	}

	return nil, fmt.Errorf("all sources (RADb, NTT, RIPE) failed for ASN %s", asn)
}

// fetchRipeStat queries the RIPE NCC API over HTTPS
func fetchRipeStat(asn string) ([]*net.IPNet, error) {
	// Documentation: https://stat.ripe.net/docs/data_api#announced-prefixes
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)
	
	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// JSON Structure for RIPE Stat
	type RipeData struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}

	var result RipeData
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var cidrs []*net.IPNet
	for _, p := range result.Data.Prefixes {
		_, n, err := net.ParseCIDR(p.Prefix)
		if err == nil {
			cidrs = append(cidrs, n)
		}
	}
	
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no prefixes found in RIPE API")
	}

	return cidrs, nil
}

// queryWhoisServer handles raw TCP Whois queries
func queryWhoisServer(server, asn string) ([]*net.IPNet, error) {
	conn, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// -i origin: filter by ASN
	// -T route,route6: only route objects
	fmt.Fprintf(conn, "-i origin -T route,route6 AS%s\n", asn)

	var cidrs []*net.IPNet
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lowerLine := strings.ToLower(line)

		// Parse "route: 1.2.3.0/24"
		if strings.HasPrefix(lowerLine, "route:") || strings.HasPrefix(lowerLine, "route6:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				_, n, err := net.ParseCIDR(parts[1])
				if err == nil {
					cidrs = append(cidrs, n)
				}
			}
		}
	}
	
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no prefixes returned")
	}
	return cidrs, nil
}

func fetchAWS() ([]*net.IPNet, error) {
	url := "https://ip-ranges.amazonaws.com/ip-ranges.json"
	type AWSIP struct {
		Prefix string `json:"ip_prefix"`
	}
	type AWSData struct {
		Prefixes []AWSIP `json:"prefixes"`
	}
	var data AWSData
	if err := getJSON(url, &data); err != nil {
		return nil, err
	}
	var out []*net.IPNet
	for _, p := range data.Prefixes {
		if _, n, err := net.ParseCIDR(p.Prefix); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

func fetchGCP() ([]*net.IPNet, error) {
	url := "https://www.gstatic.com/ipranges/cloud.json"
	type GCPPrefix struct {
		IPv4 string `json:"ipv4Prefix"`
		IPv6 string `json:"ipv6Prefix"`
	}
	type GCPData struct {
		Prefixes []GCPPrefix `json:"prefixes"`
	}
	var data GCPData
	if err := getJSON(url, &data); err != nil {
		return nil, err
	}
	var out []*net.IPNet
	for _, p := range data.Prefixes {
		s := p.IPv4
		if s == "" {
			s = p.IPv6
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

func fetchAzure() ([]*net.IPNet, error) {
	scrapeURL := "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
	
	// Increased timeout significantly for Azure
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", scrapeURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	re := regexp.MustCompile(`https://download\.microsoft\.com/download/.*?/ServiceTags_Public_.*?\.json`)
	match := re.FindString(bodyString)
	
	if match == "" {
		return nil, fmt.Errorf("azure JSON URL not found in scrape page")
	}

	log.Printf("Found Azure JSON URL: %s", match)

	type AzureVal struct {
		Properties struct {
			AddressPrefixes []string `json:"addressPrefixes"`
		} `json:"properties"`
	}
	type AzureData struct {
		Values []AzureVal `json:"values"`
	}
	
	// Need a custom getJSON here because we need the longer context
	reqJSON, _ := http.NewRequestWithContext(ctx, "GET", match, nil)
	respJSON, err := client.Do(reqJSON)
	if err != nil {
		return nil, err
	}
	defer respJSON.Body.Close()

	var data AzureData
	if err := json.NewDecoder(respJSON.Body).Decode(&data); err != nil {
		return nil, err
	}
	
	var out []*net.IPNet
	for _, v := range data.Values {
		for _, prefix := range v.Properties.AddressPrefixes {
			if _, n, err := net.ParseCIDR(prefix); err == nil {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

func fetchOracle() ([]*net.IPNet, error) {
	url := "https://docs.oracle.com/iaas/tools/public_ip_ranges.json"
	type OracleCIDR struct {
		Cidr string `json:"cidr"`
	}
	type OracleRegion struct {
		Cidrs []OracleCIDR `json:"cidrs"`
	}
	type OracleData struct {
		Regions []OracleRegion `json:"regions"`
	}
	var data OracleData
	if err := getJSON(url, &data); err != nil {
		return nil, err
	}
	var out []*net.IPNet
	for _, r := range data.Regions {
		for _, c := range r.Cidrs {
			if _, n, err := net.ParseCIDR(c.Cidr); err == nil {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

func fetchLinode() ([]*net.IPNet, error) {
	url := "https://geoip.linode.com/"
	client := http.Client{Timeout: 60 * time.Second}
	
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out []*net.IPNet
	scanner := bufio.NewScanner(resp.Body)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			if _, n, err := net.ParseCIDR(parts[0]); err == nil {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

// --- Logic Helpers ---

func filterWhitelist(inputs []*net.IPNet, whitelist []*net.IPNet) []*net.IPNet {
	var keep []*net.IPNet

	for _, in := range inputs {
		// Start with the current block as the only fragment
		fragments := []*net.IPNet{in}

		for _, w := range whitelist {
			var nextPassFragments []*net.IPNet
			
			for _, frag := range fragments {
				// Capture the prefix lengths (e.g., 24 for a /24)
				wOnes, _ := w.Mask.Size()
				fragOnes, _ := frag.Mask.Size()

				// Case 1: Whitelist completely covers this fragment -> Drop fragment
				// Logic: If Whitelist contains the IP AND has a smaller/equal prefix length (meaning it's a larger or equal block)
				if w.Contains(frag.IP) && wOnes <= fragOnes {
					continue 
				}

				// Case 2: Fragment completely covers Whitelist -> "Punch a hole" (Split)
				if frag.Contains(w.IP) {
					subFragments := excludeCIDR(frag, w)
					
					// --- LOGGING THE IMPACT ---
					increase := len(subFragments) - 1
					log.Printf("[Whitelist Impact] Puncturing %s with %s created %d sub-blocks (Net List Increase: +%d lines)", 
						frag.String(), w.String(), len(subFragments), increase)
					// --------------------------

					nextPassFragments = append(nextPassFragments, subFragments...)
					continue
				}

				// Case 3: No overlap -> Keep as is
				nextPassFragments = append(nextPassFragments, frag)
			}
			fragments = nextPassFragments
		}
		keep = append(keep, fragments...)
	}
	return keep
}

func filterIPv4(cidrs []*net.IPNet) []*net.IPNet {
	var v4 []*net.IPNet
	for _, cidr := range cidrs {
		// To4() returns nil if the IP is not a valid IPv4 address
		if cidr.IP.To4() != nil {
			v4 = append(v4, cidr)
		}
	}
	return v4
}

// excludeCIDR removes the 'remove' range from the 'base' range, 
// returning the remaining CIDR blocks.
func excludeCIDR(base, remove *net.IPNet) []*net.IPNet {
	// If the ranges are identical, return nothing
	if base.IP.Equal(remove.IP) && bytes.Equal(base.Mask, remove.Mask) {
		return nil
	}

	// Recursive splitting
	var result []*net.IPNet
	
	// Split base into two halves (left and right)
	left, right, err := splitCIDR(base)
	if err != nil {
		// If we can't split (e.g. it's already a /32 or /128), we can't subtract further.
		// This edge case implies we are trying to exclude a single IP from a single IP,
		// which is handled by the identity check above, or invalid input.
		return nil
	}

	// Check which half contains the 'remove' target
	if left.Contains(remove.IP) {
		// Keep the Right side (it's safe)
		result = append(result, right)
		// Recurse on the Left side
		result = append(result, excludeCIDR(left, remove)...)
	} else if right.Contains(remove.IP) {
		// Keep the Left side (it's safe)
		result = append(result, left)
		// Recurse on the Right side
		result = append(result, excludeCIDR(right, remove)...)
	} else {
		// 'remove' is in neither? This shouldn't happen if base.Contains(remove) was checked
		// by the caller, but safely returning both is the fallback.
		result = append(result, left, right)
	}

	return result
}

// splitCIDR takes a CIDR and returns its two sub-halves.
// e.g., 10.0.0.0/16 -> 10.0.0.0/17 and 10.0.128.0/17
func splitCIDR(n *net.IPNet) (*net.IPNet, *net.IPNet, error) {
	ones, bits := n.Mask.Size()
	if ones >= bits {
		return nil, nil, fmt.Errorf("cannot split /%d", bits)
	}

	// Create the new mask (one bit tighter)
	newMask := net.CIDRMask(ones+1, bits)

	// Left Child: IP is the same, just tighter mask
	left := &net.IPNet{
		IP:   make(net.IP, len(n.IP)),
		Mask: newMask,
	}
	copy(left.IP, n.IP)

	// Right Child: IP has the (ones)th bit flipped to 1
	right := &net.IPNet{
		IP:   make(net.IP, len(n.IP)),
		Mask: newMask,
	}
	copy(right.IP, n.IP)

	// Helper to flip the bit. 
	// The 'ones' variable is the index of the bit we want to flip (0-indexed from MSB).
	// For example, splitting a /16 (ones=16). We want to flip the 17th bit (index 16).
	// Byte index = 16 / 8 = 2. Bit remainder = 16 % 8 = 0.
	byteIdx := ones / 8
	bitIdx := 7 - (ones % 8) // High bit is 7, low bit is 0
	
	// Set the bit
	right.IP[byteIdx] |= (1 << bitIdx)

	return left, right, nil
}

func mergeCIDRs(cidrs []*net.IPNet) []*net.IPNet {
	if len(cidrs) == 0 {
		return nil
	}
	sort.Slice(cidrs, func(i, j int) bool {
		return bytes.Compare(cidrs[i].IP, cidrs[j].IP) < 0
	})
	var merged []*net.IPNet
	current := cidrs[0]
	for i := 1; i < len(cidrs); i++ {
		next := cidrs[i]
		if current.Contains(next.IP) {
			continue 
		}
		merged = append(merged, current)
		current = next
	}
	merged = append(merged, current)
	return merged
}

func getJSON(url string, target interface{}) error {
	client := http.Client{Timeout: 60 * time.Second} 
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}

// --- Web Handlers ---

func handleEDL(w http.ResponseWriter, r *http.Request) {
	edlMutex.RLock()
	defer edlMutex.RUnlock()

	w.Header().Set("Content-Type", "text/plain")
	for _, line := range currentEDL {
		fmt.Fprintln(w, line)
	}
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		return
	}

	if r.Method == "POST" {
		newJson := r.FormValue("config")
		var newConfig Config
		if err := json.Unmarshal([]byte(newJson), &newConfig); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), 400)
			return
		}

		configMutex.Lock()
		currentConfig = newConfig
		configMutex.Unlock()
		saveConfig()

		go runAggregation()
		time.Sleep(1 * time.Second)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	configMutex.RLock()
	configBytes, _ := json.MarshalIndent(currentConfig, "", "  ")
	configMutex.RUnlock()

	edlMutex.RLock()
	status := fmt.Sprintf("Last Refresh: %s | Total IPs: %d | Dropped (Limit): %d",
		lastRefresh.Format(time.RFC3339), len(currentEDL), droppedCount)
	edlMutex.RUnlock()

	html := `
	<html>
	<head><title>EDL Admin</title>
	<style>
		body{font-family:sans-serif; padding:20px; max-width: 900px; margin: auto; background-color: #f9f9f9;} 
		textarea{width:100%; height:400px; font-family:monospace; border:1px solid #ccc; padding:10px; border-radius: 4px;}
		button{padding:10px 20px; font-size:16px; background:#007bff; color:white; border:none; cursor:pointer; border-radius: 4px;}
		button:hover{background:#0056b3;}
		.status{background:#e8f4f8; padding:15px; border-left: 5px solid #007bff; margin-bottom:20px; border-radius: 4px;}
		.info-box { background: #fff3cd; border: 1px solid #ffeeba; padding: 15px; margin-bottom: 20px; border-radius: 4px; color: #856404; }
		.toolbar { margin-bottom: 20px; }
		.btn-secondary { background: #6c757d; text-decoration: none; padding: 10px 20px; color: white; border-radius: 4px; display: inline-block; }
		.btn-secondary:hover { background: #5a6268; }
		code { background: #eee; padding: 2px 5px; border-radius: 3px; }
	</style>
	</head>
	<body>
		<h1>EDL Aggregator Admin</h1>
		
		<div class="status"><b>Status:</b> ` + status + `</div>

		<div class="toolbar">
			<a href="/admin/logs" target="_blank" class="btn-secondary">📄 View Logs</a>
			<a href="/admin/logs?download=true" class="btn-secondary">⬇️ Download Logs</a>
		</div>

		<div class="info-box">
			<h3>ℹ️ Whitelisting Strategy: Precise vs. Buffer</h3>
			<p>When you whitelist an IP that resides inside a blocked range, the system must "shatter" the large block into smaller pieces to isolate your IP. This increases the total line count of the EDL.</p>
			<ul>
				<li><b>Precise (Expensive):</b> Whitelisting a single <code>/32</code> inside a <code>/16</code> block can create <b>15-30 new lines</b>. Use this only when you must strictly block neighbors.</li>
				<li><b>Buffer (Efficient):</b> Whitelisting a <code>/24</code> (256 IPs) around your target creates significantly fewer fragments (usually <b>2-8 lines</b>). Use this to save space if you trust the neighbor IPs.</li>
			</ul>
			<p><i>Check the logs after refreshing to see the "Net List Increase" count for your whitelists.</i></p>
		</div>

		<form method="POST">
			<label><b>Configuration (JSON):</b></label><br>
			<textarea name="config">` + string(configBytes) + `</textarea><br><br>
			<button type="submit">Save & Refresh List</button>
		</form>
	</body>
	</html>
	`
	w.Write([]byte(html))
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		return
	}
	go runAggregation()
	w.Write([]byte("Refresh triggered"))
}

// --- Internal Helpers ---

func scheduler() {
	runAggregation()
	for {
		configMutex.RLock()
		interval := currentConfig.RefreshMinutes
		configMutex.RUnlock()
		if interval < 1 {
			interval = 60
		}
		time.Sleep(time.Duration(interval) * time.Minute)
		runAggregation()
	}
}

func createDefaultConfig() {
	defaultCfg := Config{
		ServerPort:     ":8080",
		RefreshMinutes: 60,
		MaxLines:       100000,
		AdminUser:      "admin",
		AdminPass:      "changeme",
		Sources: Sources{
			IncludeIPv6:   false, // Default to IPv4 ONLY
			IncludeAWS:    true,
			IncludeAzure:  true,
			IncludeGCP:    true,
			IncludeOracle: true,
			IncludeLinode: true,
			HighRiskASNs:  []string{"200373"},
			GenericASNs:   []string{"212238", "9009", "60068", "52393"},
		},
		Whitelist: Whitelist{
			Comment: "STRATEGY TIP: Whitelisting a /32 (Precise) inside a large block creates many fragments. Whitelisting a /24 (Buffer) creates fewer fragments.",
			ASNs:    []string{"15169"}, 
			CIDRs:   []string{"1.2.3.4/32"},
		},
	}
	currentConfig = defaultCfg
	saveConfig()
}

func loadConfig() error {
	f, err := os.Open(configFile)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(&currentConfig)
}

func saveConfig() {
	configMutex.RLock()
	defer configMutex.RUnlock()

	f, err := os.Create(configFile)
	if err != nil {
		// If we can't save, we should probably log it, 
		// but for now we just return to avoid crashing.
		return 
	}
	defer f.Close()

	// Create an encoder that writes to the file
	encoder := json.NewEncoder(f)
	
	// SetIndent("", "  ") tells it to use 2 spaces for indentation
	// making it human-readable (Pretty Print)
	encoder.SetIndent("", "  ")
	
	encoder.Encode(currentConfig)
}

func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	configMutex.RLock()
	user, pass := currentConfig.AdminUser, currentConfig.AdminPass
	configMutex.RUnlock()
	u, p, ok := r.BasicAuth()
	if !ok || u != user || p != pass {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", 401)
		return false
	}
	return true
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		return
	}

	// Make sure we use the same path defined in setupLogging
	logPath := filepath.Join("logs", "aggregator.log")

	// Check if file exists before trying to serve it
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		http.Error(w, "Log file not found (has the app started?)", 404)
		return
	}

	// Logic: If ?download=true, force the browser to save the file.
	// Otherwise, just show it as text in the browser window.
	if r.URL.Query().Get("download") == "true" {
		w.Header().Set("Content-Disposition", "attachment; filename=aggregator.log")
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}

	http.ServeFile(w, r, logPath)
}