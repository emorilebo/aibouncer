package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/emorilebo/aibouncer"
	"github.com/emorilebo/aibouncer/robotstxt"
)

func cmdVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	userAgent := fs.String("ua", "", "User-Agent header of the request")
	agentID := fs.String("agent", "", "agent ID (see `aibouncer agents`), instead of -ua")
	offline := fs.Bool("offline", false, "use the embedded IP snapshot and skip DNS")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	maxAge := fs.Duration("max-age", 0, "treat IP data older than this as stale (default 168h)")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 || (*userAgent == "") == (*agentID == "") {
		fmt.Fprintln(stderr, "usage: aibouncer verify [-offline] [-json] (-ua UA | -agent ID) IP")
		return exitUsage
	}
	addr, err := netip.ParseAddr(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "aibouncer: %q is not an IP address\n", fs.Arg(0))
		return exitUsage
	}

	catalog := aibouncer.DefaultCatalog()
	var agent *aibouncer.Agent
	var found bool
	if *agentID != "" {
		agent, found = catalog.Agent(*agentID)
	} else {
		agent, found = catalog.Identify(*userAgent)
	}
	if !found {
		fmt.Fprintln(stdout, "not a known AI agent")
		return exitInconclusive
	}

	result := newVerifier(ctx, *offline, *maxAge, stderr).VerifyIP(ctx, agent, addr)
	if *asJSON {
		writeJSON(stdout, map[string]any{"agent": agent.ID, "ip": addr.String(), "verdict": result.Verdict, "method": result.Method, "reason": result.Reason})
	} else {
		fmt.Fprintf(stdout, "%s (%s, %s) from %s: %s\n  %s\n", agent.Name, agent.Operator, agent.Purpose, addr, strings.ToUpper(result.Verdict.String()), result.Reason)
	}
	switch result.Verdict {
	case aibouncer.Verified:
		return exitOK
	case aibouncer.Spoofed:
		return exitFinding
	default:
		return exitInconclusive
	}
}

func cmdRobots(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("robots", stderr)
	path := fs.String("path", "/", "URL path to check")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: aibouncer robots [-path /] [-json] URL|FILE")
		return exitUsage
	}

	source := fs.Arg(0)
	file, availability, err := loadRobots(ctx, source)
	if err != nil {
		fmt.Fprintf(stderr, "aibouncer: %v\n", err)
		return exitInconclusive
	}

	type row struct {
		Agent    string                   `json:"agent"`
		Token    string                   `json:"robots_token"`
		Operator string                   `json:"operator"`
		Purpose  aibouncer.Purpose        `json:"purpose"`
		Behavior aibouncer.RobotsBehavior `json:"robots_txt_behavior"`
		Allowed  bool                     `json:"allowed"`
		Rule     string                   `json:"rule"`
	}
	var rows []row
	blocked := 0
	for _, agent := range aibouncer.DefaultCatalog().Agents {
		if agent.RobotsToken == "" {
			continue
		}
		r := row{Agent: agent.Name, Token: agent.RobotsToken, Operator: agent.Operator, Purpose: agent.Purpose, Behavior: agent.RobotsTxt}
		switch availability {
		case robotstxt.AllowAll:
			r.Allowed, r.Rule = true, "robots.txt unavailable (4xx): no restrictions"
		case robotstxt.DisallowAll:
			r.Allowed, r.Rule = false, "robots.txt unreachable (5xx/network): crawlers must assume full disallow"
		default:
			match := file.Check(agent.RobotsToken, *path)
			r.Allowed = match.Allowed
			switch {
			case match.Rule == nil:
				r.Rule = "no matching rule"
			case match.Explicit:
				r.Rule = fmt.Sprintf("%s: %s (User-agent: %s)", ruleKind(match.Rule.Allow), match.Rule.Pattern, agent.RobotsToken)
			default:
				r.Rule = fmt.Sprintf("%s: %s (User-agent: *)", ruleKind(match.Rule.Allow), match.Rule.Pattern)
			}
		}
		if !r.Allowed {
			blocked++
		}
		rows = append(rows, r)
	}

	if *asJSON {
		writeJSON(stdout, map[string]any{"source": source, "path": *path, "agents": rows})
	} else {
		fmt.Fprintf(stdout, "robots.txt: %s   path: %s\n\n", source, *path)
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "AGENT\tOPERATOR\tPURPOSE\tACCESS\tDECIDED BY")
		for _, r := range rows {
			access := "allowed"
			if !r.Allowed {
				access = "BLOCKED"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Token, r.Operator, r.Purpose, access, r.Rule)
		}
		tw.Flush()
		fmt.Fprintf(stdout, "\n%d of %d AI crawlers blocked for %s.\n", blocked, len(rows), *path)
		fmt.Fprintln(stdout, "Purposes: training = model training data; search = AI search/answer index; user = fetches a page a person asked about.")
		fmt.Fprintln(stdout, "Note: operators document that some user-initiated fetchers may ignore robots.txt (see `aibouncer agents`).")
	}
	if blocked > 0 {
		return exitFinding
	}
	return exitOK
}

func ruleKind(allow bool) string {
	if allow {
		return "Allow"
	}
	return "Disallow"
}

// loadRobots reads robots.txt from a local file, or fetches /robots.txt for a URL or host name.
func loadRobots(ctx context.Context, source string) (*robotstxt.File, robotstxt.Availability, error) {
	if info, err := os.Stat(source); err == nil && !info.IsDir() {
		data, err := os.ReadFile(source)
		if err != nil {
			return nil, 0, err
		}
		return robotstxt.Parse(data), robotstxt.ApplyRules, nil
	}

	if !strings.Contains(source, "://") {
		source = "https://" + source
	}
	u, err := url.Parse(source)
	if err != nil || u.Host == "" {
		return nil, 0, fmt.Errorf("%q is neither a file nor a URL", source)
	}
	robotsURL := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/robots.txt"}).String()

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "aibouncer/"+aibouncer.Version+" (+https://github.com/emorilebo/aibouncer)")
	client := &http.Client{CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("more than 5 redirects") // RFC 9309 section 2.3.1.2
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("could not fetch %s: %w (crawlers treat an unreachable robots.txt as disallow-all)", robotsURL, err)
	}
	defer resp.Body.Close()
	availability := robotstxt.StatusPolicy(resp.StatusCode)
	if availability != robotstxt.ApplyRules {
		return &robotstxt.File{}, availability, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, robotstxt.MaxSize))
	if err != nil {
		return nil, 0, err
	}
	return robotstxt.Parse(data), robotstxt.ApplyRules, nil
}

func cmdRobotsGen(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("robots-gen", stderr)
	block := fs.String("block", "training", "comma-separated purposes to block: training,search,user,agent,other")
	blockAgents := fs.String("block-agent", "", "comma-separated agent IDs to block")
	allowAgents := fs.String("allow-agent", "", "comma-separated agent IDs to allow (overrides -block)")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	catalog := aibouncer.DefaultCatalog()
	policy := aibouncer.Policy{Purposes: map[aibouncer.Purpose]aibouncer.Action{}, Agents: map[string]aibouncer.Action{}}
	valid := map[aibouncer.Purpose]bool{aibouncer.PurposeTraining: true, aibouncer.PurposeSearch: true,
		aibouncer.PurposeUser: true, aibouncer.PurposeAgent: true, aibouncer.PurposeOther: true}
	for _, p := range splitList(*block) {
		if !valid[aibouncer.Purpose(p)] {
			fmt.Fprintf(stderr, "aibouncer: unknown purpose %q\n", p)
			return exitUsage
		}
		policy.Purposes[aibouncer.Purpose(p)] = aibouncer.Block
	}
	for list, action := range map[string]aibouncer.Action{*blockAgents: aibouncer.Block, *allowAgents: aibouncer.Allow} {
		for _, id := range splitList(list) {
			if _, ok := catalog.Agent(id); !ok {
				fmt.Fprintf(stderr, "aibouncer: unknown agent %q (see `aibouncer agents`)\n", id)
				return exitUsage
			}
			policy.Agents[id] = action
		}
	}
	fmt.Fprint(stdout, policy.RobotsTxt(catalog))
	return exitOK
}

func cmdSnapshot(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("snapshot", stderr)
	output := fs.String("o", "", "write to FILE instead of stdout")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	verifier := aibouncer.NewVerifier()
	refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := verifier.Refresh(refreshCtx); err != nil {
		fmt.Fprintf(stderr, "aibouncer: refresh failed, snapshot not written:\n  %s\n", strings.ReplaceAll(err.Error(), "\n", "\n  "))
		return exitInconclusive
	}
	snapshot := verifier.Snapshot()
	snapshot.FetchedAt = time.Now().UTC().Truncate(time.Second)

	tw := tabwriter.NewWriter(stderr, 0, 0, 2, ' ', 0)
	for _, s := range verifier.Status() {
		fmt.Fprintf(tw, "%d\tprefixes\t%s\n", s.Prefixes, s.URL)
	}
	tw.Flush()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "aibouncer: %v\n", err)
		return exitInconclusive
	}
	data = append(data, '\n')
	if *output == "" {
		_, _ = stdout.Write(data)
		return exitOK
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "aibouncer: %v\n", err)
		return exitInconclusive
	}
	return exitOK
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func writeJSON(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return exitInconclusive
	}
	return exitOK
}
