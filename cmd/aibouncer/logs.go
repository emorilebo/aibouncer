package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/emorilebo/aibouncer"
)

// logEntry is the part of a combined-format access log line that aibouncer needs.
type logEntry struct {
	ip        netip.Addr
	target    string
	referer   string
	userAgent string
}

// parseCombinedLine parses the NCSA combined log format used by nginx and Apache:
//
//	203.0.113.9 - - [14/Oct/2026:10:00:00 +0000] "GET /p?x=1 HTTP/1.1" 200 512 "https://ref/" "UA"
func parseCombinedLine(line string) (logEntry, bool) {
	var entry logEntry
	host, rest, ok := strings.Cut(line, " ")
	if !ok {
		return entry, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return entry, false
	}
	entry.ip = addr.Unmap()

	open := strings.IndexByte(rest, '[')
	closing := strings.IndexByte(rest, ']')
	if open < 0 || closing < open {
		return entry, false
	}
	fields, ok := quotedFields(rest[closing+1:])
	if !ok || len(fields) < 3 {
		return entry, false
	}
	request := strings.Fields(fields[0])
	if len(request) >= 2 {
		entry.target = request[1]
	}
	entry.referer = fields[1]
	entry.userAgent = fields[2]
	if entry.referer == "-" {
		entry.referer = ""
	}
	return entry, true
}

// quotedFields returns the double-quoted strings in s, honouring backslash escapes.
func quotedFields(s string) ([]string, bool) {
	var fields []string
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		var b strings.Builder
		i++
		for ; i < len(s) && s[i] != '"'; i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			b.WriteByte(s[i])
		}
		if i >= len(s) {
			return fields, false
		}
		fields = append(fields, b.String())
	}
	return fields, true
}

type agentStats struct {
	Agent        string            `json:"agent"`
	ID           string            `json:"id"`
	Operator     string            `json:"operator"`
	Purpose      aibouncer.Purpose `json:"purpose"`
	Requests     int               `json:"requests"`
	Verified     int               `json:"verified"`
	Unverifiable int               `json:"unverifiable"`
	Spoofed      int               `json:"spoofed"`
	SpoofedIPs   int               `json:"spoofed_ips"`
	spoofedSet   map[netip.Addr]bool
}

type logReport struct {
	Lines         int            `json:"lines"`
	Unparsed      int            `json:"unparsed"`
	AIRequests    int            `json:"ai_requests"`
	Agents        []*agentStats  `json:"agents"`
	Referrals     map[string]int `json:"ai_referrals"`
	ReferralTotal int            `json:"ai_referral_total"`
}

func cmdLogs(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("logs", stderr)
	offline := fs.Bool("offline", false, "use the embedded IP snapshot and skip DNS")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	maxAge := fs.Duration("max-age", 0, "treat IP data older than this as stale (default 168h)")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: aibouncer logs [-offline] [-json] FILE...   (use - for stdin; .gz files are decompressed)")
		return exitUsage
	}

	catalog := aibouncer.DefaultCatalog()
	verifier := newVerifier(ctx, *offline, *maxAge, stderr)
	report := &logReport{Referrals: map[string]int{}}
	stats := map[string]*agentStats{}
	type claim struct {
		agent *aibouncer.Agent
		ip    netip.Addr
	}
	claims := map[claim]int{}

	for _, name := range fs.Args() {
		if err := scanLog(name, func(entry logEntry) {
			if agent, ok := catalog.Identify(entry.userAgent); ok {
				claims[claim{agent, entry.ip}]++
				return
			}
			if referral, ok := detectReferral(catalog, entry); ok {
				report.Referrals[referral.Assistant]++
				report.ReferralTotal++
			}
		}, report); err != nil {
			fmt.Fprintf(stderr, "aibouncer: %s: %v\n", name, err)
			return exitInconclusive
		}
	}

	// Verify each distinct (agent, IP) pair once, in parallel; reverse DNS can be slow.
	var mu sync.Mutex
	work := make(chan claim)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range work {
				result := verifier.VerifyIP(ctx, c.agent, c.ip)
				count := claims[c]
				mu.Lock()
				s := stats[c.agent.ID]
				if s == nil {
					s = &agentStats{Agent: c.agent.Name, ID: c.agent.ID, Operator: c.agent.Operator, Purpose: c.agent.Purpose, spoofedSet: map[netip.Addr]bool{}}
					stats[c.agent.ID] = s
				}
				s.Requests += count
				switch result.Verdict {
				case aibouncer.Verified:
					s.Verified += count
				case aibouncer.Spoofed:
					s.Spoofed += count
					s.spoofedSet[c.ip] = true
				default:
					s.Unverifiable += count
				}
				mu.Unlock()
			}
		}()
	}
	for c := range claims {
		work <- c
	}
	close(work)
	wg.Wait()

	spoofed := 0
	for _, s := range stats {
		s.SpoofedIPs = len(s.spoofedSet)
		report.AIRequests += s.Requests
		spoofed += s.Spoofed
		report.Agents = append(report.Agents, s)
	}
	sort.Slice(report.Agents, func(i, j int) bool {
		if report.Agents[i].Requests != report.Agents[j].Requests {
			return report.Agents[i].Requests > report.Agents[j].Requests
		}
		return report.Agents[i].Agent < report.Agents[j].Agent
	})

	if *asJSON {
		writeJSON(stdout, report)
	} else {
		printLogReport(stdout, report)
	}
	if spoofed > 0 {
		return exitFinding
	}
	return exitOK
}

func detectReferral(catalog *aibouncer.Catalog, entry logEntry) (aibouncer.Referral, bool) {
	r := &http.Request{Header: http.Header{}}
	if u, err := url.ParseRequestURI(entry.target); err == nil {
		r.URL = u
	}
	if entry.referer != "" {
		r.Header.Set("Referer", entry.referer)
	}
	return catalog.DetectReferral(r)
}

func scanLog(name string, visit func(logEntry), report *logReport) error {
	var reader io.Reader
	if name == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		reader = f
		if strings.HasSuffix(name, ".gz") {
			gz, err := gzip.NewReader(f)
			if err != nil {
				return err
			}
			defer gz.Close()
			reader = gz
		}
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		report.Lines++
		entry, ok := parseCombinedLine(line)
		if !ok {
			report.Unparsed++
			continue
		}
		visit(entry)
	}
	return scanner.Err()
}

func printLogReport(w io.Writer, report *logReport) {
	fmt.Fprintf(w, "%d log lines, %d unparsed (expected: combined log format)\n\n", report.Lines, report.Unparsed)
	if len(report.Agents) == 0 {
		fmt.Fprintln(w, "No AI crawler requests found.")
	} else {
		fmt.Fprintf(w, "AI crawler requests: %d\n", report.AIRequests)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
		fmt.Fprintln(tw, "AGENT\tOPERATOR\tPURPOSE\tREQUESTS\tVERIFIED\tUNVERIFIABLE\tSPOOFED\tSPOOFING IPS\t")
		for _, s := range report.Agents {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t\n", s.Agent, s.Operator, s.Purpose, s.Requests, s.Verified, s.Unverifiable, s.Spoofed, s.SpoofedIPs)
		}
		tw.Flush()
	}
	fmt.Fprintln(w)
	if report.ReferralTotal == 0 {
		fmt.Fprintln(w, "No human visits referred by AI assistants found.")
		return
	}
	fmt.Fprintf(w, "Human visits referred by AI assistants: %d (a lower bound: many apps strip referrers)\n", report.ReferralTotal)
	names := make([]string, 0, len(report.Referrals))
	for name := range report.Referrals {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if report.Referrals[names[i]] != report.Referrals[names[j]] {
			return report.Referrals[names[i]] > report.Referrals[names[j]]
		}
		return names[i] < names[j]
	})
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, name := range names {
		fmt.Fprintf(tw, "  %s\t%d\n", name, report.Referrals[name])
	}
	tw.Flush()
}
