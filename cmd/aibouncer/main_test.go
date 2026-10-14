package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const noExpiry = "876000h"

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseCombinedLine(t *testing.T) {
	line := `132.196.86.5 - - [14/Oct/2026:10:00:00 +0000] "GET /blog/post?utm_source=chatgpt.com HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (compatible; \"quoted\" GPTBot/1.4)"`
	entry, ok := parseCombinedLine(line)
	if !ok {
		t.Fatal("line did not parse")
	}
	if entry.ip.String() != "132.196.86.5" || entry.target != "/blog/post?utm_source=chatgpt.com" || entry.referer != "" ||
		entry.userAgent != `Mozilla/5.0 (compatible; "quoted" GPTBot/1.4)` {
		t.Errorf("entry = %+v", entry)
	}
	for _, bad := range []string{"", "garbage", `not-an-ip - - [x] "GET / HTTP/1.1" 200 1 "-" "ua"`, `1.2.3.4 - - [x] "GET / HTTP/1.1" 200 1 "-" "unterminated`} {
		if _, ok := parseCombinedLine(bad); ok {
			t.Errorf("parseCombinedLine(%q) should fail", bad)
		}
	}
}

// The GPTBot and ClaudeBot addresses below are in the operators' published lists embedded in the
// snapshot; 81.2.69.160 and 203.0.113.0/24 are not in anyone's. Offline tests pin -max-age so the
// embedded snapshot never counts as stale.
const fixtureLog = `132.196.86.5 - - [14/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot"
132.196.86.5 - - [14/Oct/2026:10:00:01 +0000] "GET /about HTTP/1.1" 200 512 "-" "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot"
81.2.69.160 - - [14/Oct/2026:10:00:02 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "Mozilla/5.0 (compatible; GPTBot/1.4)"
34.11.34.31 - - [14/Oct/2026:10:00:03 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
203.0.113.7 - - [14/Oct/2026:10:00:04 +0000] "GET / HTTP/1.1" 200 512 "-" "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"
203.0.113.8 - - [14/Oct/2026:10:00:05 +0000] "GET /post?utm_source=chatgpt.com HTTP/2.0" 200 512 "-" "Mozilla/5.0 (iPhone) Safari/604.1"
203.0.113.9 - - [14/Oct/2026:10:00:06 +0000] "GET /post HTTP/2.0" 200 512 "https://www.perplexity.ai/search/abc" "Mozilla/5.0 (Windows NT 10.0) Chrome/141.0"
203.0.113.10 - - [14/Oct/2026:10:00:07 +0000] "GET /post HTTP/2.0" 200 512 "https://www.google.com/" "Mozilla/5.0 (Windows NT 10.0) Chrome/141.0"
this line is not a log line
`

func TestLogsReport(t *testing.T) {
	path := writeFile(t, "access.log", fixtureLog)
	stdout, stderr, code := runCLI(t, "logs", "-offline", "-max-age", noExpiry, "-json", path)
	if code != exitFinding {
		t.Fatalf("exit code %d, want %d (a spoofed GPTBot is a finding); stderr: %s", code, exitFinding, stderr)
	}
	var report logReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if report.Lines != 9 || report.Unparsed != 1 || report.AIRequests != 5 || report.ReferralTotal != 2 {
		t.Errorf("totals = %+v", report)
	}
	byID := map[string]*agentStats{}
	for _, s := range report.Agents {
		byID[s.ID] = s
	}
	if s := byID["openai-gptbot"]; s == nil || s.Requests != 3 || s.Verified != 2 || s.Spoofed != 1 || s.SpoofedIPs != 1 {
		t.Errorf("GPTBot stats = %+v", s)
	}
	if s := byID["anthropic-claudebot"]; s == nil || s.Verified != 1 {
		t.Errorf("ClaudeBot stats = %+v", s)
	}
	if s := byID["meta-externalagent"]; s == nil || s.Unverifiable != 1 {
		t.Errorf("Meta stats = %+v", s)
	}
	if report.Referrals["ChatGPT"] != 1 || report.Referrals["Perplexity"] != 1 {
		t.Errorf("referrals = %v", report.Referrals)
	}
}

func TestLogsTextOutput(t *testing.T) {
	path := writeFile(t, "access.log", fixtureLog)
	stdout, _, _ := runCLI(t, "logs", "-offline", "-max-age", noExpiry, path)
	for _, want := range []string{"AI crawler requests: 5", "GPTBot", "Human visits referred by AI assistants: 2", "ChatGPT"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output missing %q:\n%s", want, stdout)
		}
	}
}

func TestRobotsFromFile(t *testing.T) {
	path := writeFile(t, "robots.txt", "User-agent: GPTBot\nUser-agent: Google-Extended\nDisallow: /\n\nUser-agent: *\nAllow: /\n")
	stdout, _, code := runCLI(t, "robots", "-json", path)
	if code != exitFinding {
		t.Errorf("exit code %d, want %d when crawlers are blocked", code, exitFinding)
	}
	var result struct {
		Agents []struct {
			Token   string `json:"robots_token"`
			Allowed bool   `json:"allowed"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	blocked := map[string]bool{}
	for _, a := range result.Agents {
		if !a.Allowed {
			blocked[a.Token] = true
		}
	}
	if len(blocked) != 2 || !blocked["GPTBot"] || !blocked["Google-Extended"] {
		t.Errorf("blocked = %v", blocked)
	}

	open := writeFile(t, "robots.txt", "User-agent: *\nDisallow:\n")
	if _, _, code := runCLI(t, "robots", open); code != exitOK {
		t.Errorf("open robots.txt: exit %d", code)
	}
}

func TestRobotsGen(t *testing.T) {
	stdout, _, code := runCLI(t, "robots-gen", "-block", "training", "-allow-agent", "openai-gptbot")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"User-agent: ClaudeBot\n", "User-agent: Google-Extended\n", "User-agent: Applebot-Extended\n", "Disallow: /\n"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "User-agent: GPTBot\n") {
		t.Error("-allow-agent should exempt GPTBot")
	}
	if _, _, code := runCLI(t, "robots-gen", "-block", "mining"); code != exitUsage {
		t.Errorf("unknown purpose: exit %d", code)
	}
	if _, _, code := runCLI(t, "robots-gen", "-block-agent", "nobody"); code != exitUsage {
		t.Errorf("unknown agent: exit %d", code)
	}
}

func TestVerifyOffline(t *testing.T) {
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"verify", "-offline", "-max-age", noExpiry, "-ua", "GPTBot/1.4", "132.196.86.5"}, exitOK, "VERIFIED"},
		{[]string{"verify", "-offline", "-max-age", noExpiry, "-agent", "openai-gptbot", "81.2.69.160"}, exitFinding, "SPOOFED"},
		{[]string{"verify", "-offline", "-agent", "meta-externalagent", "203.0.113.1"}, exitInconclusive, "UNVERIFIABLE"},
		{[]string{"verify", "-offline", "-ua", "Mozilla/5.0 Safari", "203.0.113.1"}, exitInconclusive, "not a known AI agent"},
	}
	for _, tc := range cases {
		stdout, _, code := runCLI(t, tc.args...)
		if code != tc.code || !strings.Contains(stdout, tc.want) {
			t.Errorf("%v: exit %d, output %q; want %d and %q", tc.args, code, stdout, tc.code, tc.want)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"nope"},
		{"verify", "1.2.3.4"},
		{"verify", "-ua", "GPTBot", "-agent", "openai-gptbot", "1.2.3.4"},
		{"verify", "-ua", "GPTBot", "not-an-ip"},
		{"robots"},
		{"logs"},
		{"agents", "-bogus"},
	} {
		if _, _, code := runCLI(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
	if stdout, _, code := runCLI(t, "version"); code != exitOK || !strings.HasPrefix(stdout, "aibouncer ") {
		t.Errorf("version: %d %q", code, stdout)
	}
}

func TestAgentsJSON(t *testing.T) {
	stdout, _, code := runCLI(t, "agents", "-json")
	if code != exitOK {
		t.Fatal(code)
	}
	var agents []map[string]any
	if err := json.Unmarshal([]byte(stdout), &agents); err != nil || len(agents) < 30 {
		t.Errorf("agents -json: %v, %d entries", err, len(agents))
	}
}
