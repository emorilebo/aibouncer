package robotstxt

import (
	"strings"
	"testing"
	"time"
)

// The example from RFC 9309 section 5.1.
const rfcExample = `User-Agent: *
Disallow: *.gif$
Disallow: /example/
Allow: /publications/

User-Agent: foobot
Disallow:/
Allow:/example/page.html
Allow:/example/allowed.gif

User-Agent: barbot
User-Agent: bazbot
Disallow: /example/page.html

User-Agent: quxbot
`

func TestRFC9309Example(t *testing.T) {
	f := Parse([]byte(rfcExample))
	cases := []struct {
		agent, path string
		want        bool
	}{
		{"foobot", "/example/page.html", true},
		{"foobot", "/example/allowed.gif", true},
		{"foobot", "/example/other.html", false},
		{"foobot", "/", false},
		{"FOOBOT", "/", false}, // product tokens match case-insensitively
		{"barbot", "/example/page.html", false},
		{"bazbot", "/example/page.html", false},
		{"barbot", "/example/other.html", true}, // barbot does not inherit the * rules
		{"quxbot", "/example/", true},           // an empty group allows everything
		{"otherbot", "/example/", false},
		{"otherbot", "/image.gif", false},
		{"otherbot", "/image.gif?size=2", true}, // '$' anchors to the end
		{"otherbot", "/publications/x", true},
		{"otherbot", "/robots.txt", true},
	}
	for _, c := range cases {
		if got := f.Allowed(c.agent, c.path); got != c.want {
			t.Errorf("Allowed(%q, %q) = %v, want %v", c.agent, c.path, got, c.want)
		}
	}
}

func TestLongestMatchWinsAndAllowWinsTies(t *testing.T) {
	f := Parse([]byte("User-agent: GPTBot\nAllow: /example/page/\nDisallow: /example/page/disallowed.gif\nDisallow: /tie\nAllow: /tie\n"))
	if f.Allowed("GPTBot", "/example/page/disallowed.gif") {
		t.Error("longer disallow should win")
	}
	if !f.Allowed("GPTBot", "/example/page/ok.html") {
		t.Error("allow should apply")
	}
	if !f.Allowed("GPTBot", "/tie") {
		t.Error("allow should win an equal-length tie")
	}
}

func TestRepeatedGroupsAreMerged(t *testing.T) {
	f := Parse([]byte("User-agent: ClaudeBot\nDisallow: /a\n\nUser-agent: *\nDisallow: /\n\nUser-agent: claudebot\nDisallow: /b\n"))
	m := f.Check("ClaudeBot", "/b/c")
	if m.Allowed || !m.Explicit {
		t.Errorf("Check = %+v, want disallowed and explicit", m)
	}
	if !f.Allowed("ClaudeBot", "/c") {
		t.Error("ClaudeBot has its own group, so the * group must not apply")
	}
}

func TestVersionedUserAgentValue(t *testing.T) {
	f := Parse([]byte("User-agent: Googlebot/2.1\nDisallow: /private\n"))
	if f.Allowed("Googlebot", "/private/x") {
		t.Error("value with a version suffix should match its product token")
	}
}

func TestTokensWithDigits(t *testing.T) {
	f := Parse([]byte("User-agent: AI2Bot\nDisallow: /\n\nUser-agent: *\nAllow: /\n"))
	if m := f.Check("AI2Bot", "/"); m.Allowed || !m.Explicit {
		t.Errorf("AI2Bot: %+v, want an explicit disallow", m)
	}
	if !f.Allowed("AI", "/") {
		t.Error("a group for AI2Bot must not capture a crawler called AI")
	}
}

func TestWildcardFallbackIsNotExplicit(t *testing.T) {
	f := Parse([]byte("User-agent: *\nDisallow: /\n"))
	m := f.Check("PerplexityBot", "/")
	if m.Allowed || m.Explicit || m.Rule == nil || m.Rule.Pattern != "/" {
		t.Errorf("Check = %+v", m)
	}
}

func TestNoRobotsMeansAllowed(t *testing.T) {
	if !Parse(nil).Allowed("GPTBot", "/anything") {
		t.Error("empty file must allow everything")
	}
}

func TestCommentsBOMAndLineEndings(t *testing.T) {
	data := "\xEF\xBB\xBFUser-agent: CCBot # Common Crawl\r\nDisallow: /secret # keep out\rSitemap: https://example.com/sitemap.xml\n"
	f := Parse([]byte(data))
	if f.Allowed("CCBot", "/secret/plans") {
		t.Error("rule should apply despite comments, BOM and mixed line endings")
	}
	if len(f.Sitemaps) != 1 || f.Sitemaps[0] != "https://example.com/sitemap.xml" {
		t.Errorf("Sitemaps = %v", f.Sitemaps)
	}
}

func TestRulesBeforeUserAgentAreIgnored(t *testing.T) {
	f := Parse([]byte("Disallow: /\nUser-agent: *\nAllow: /\n"))
	if !f.Allowed("anybot", "/x") {
		t.Error("orphan rules must not apply")
	}
}

func TestEmptyDisallowAllowsEverything(t *testing.T) {
	f := Parse([]byte("User-agent: *\nDisallow:\n"))
	if !f.Allowed("GPTBot", "/") {
		t.Error("empty Disallow means nothing is disallowed")
	}
}

func TestPercentEncodingNormalisation(t *testing.T) {
	f := Parse([]byte("User-agent: *\nDisallow: /foo/bar/ツ\nDisallow: /%62%61%7A\nDisallow: /q%3fx\n"))
	cases := []struct {
		path string
		want bool
	}{
		{"/foo/bar/%E3%83%84", false}, // UTF-8 rule vs percent-encoded path
		{"/foo/bar/%e3%83%84", false}, // hex case does not matter
		{"/baz", false},               // %62%61%7A is "baz": unreserved, decoded
		{"/q%3Fx", false},             // reserved escapes stay escaped, case-normalised
		{"/q?x", true},                // ...and do not match the literal reserved character
	}
	for _, c := range cases {
		if got := f.Allowed("anybot", c.path); got != c.want {
			t.Errorf("Allowed(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestWildcards(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/", "/anything", true},
		{"/*.php", "/index.php", true},
		{"/*.php", "/dir/index.php?x=1", true},
		{"/*.php$", "/index.php?x=1", false},
		{"/fish*", "/fish.html", true},
		{"/fish*", "/Fish.html", false}, // paths are case-sensitive
		{"/*/admin$", "/a/b/admin", true},
		{"/a*b*c", "/aXXbYYc/rest", true},
		{"/a*b*c$", "/aXXbYYc/rest", false},
		{"*", "/", true},
	}
	for _, c := range cases {
		if got := matchPattern(c.pattern, c.path); got != c.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestHostilePatternIsFast(t *testing.T) {
	pattern := "/" + strings.Repeat("*a", 40) + "*b"
	path := "/" + strings.Repeat("a", 5000)
	start := time.Now()
	if matchPattern(pattern, path) {
		t.Fatal("must not match")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("pathological pattern took %v", elapsed)
	}
}

func TestMaxSize(t *testing.T) {
	data := strings.Repeat("# padding\n", MaxSize/10) + "User-agent: *\nDisallow: /\n"
	if !Parse([]byte(data)).Allowed("GPTBot", "/") {
		t.Error("rules beyond MaxSize must be ignored")
	}
}

func TestStatusPolicy(t *testing.T) {
	cases := map[int]Availability{200: ApplyRules, 204: ApplyRules, 404: AllowAll, 403: AllowAll, 410: AllowAll, 500: DisallowAll, 503: DisallowAll, 0: DisallowAll}
	for code, want := range cases {
		if got := StatusPolicy(code); got != want {
			t.Errorf("StatusPolicy(%d) = %v, want %v", code, got, want)
		}
	}
}

func FuzzParseAndCheck(f *testing.F) {
	f.Add([]byte(rfcExample), "foobot", "/example/page.html")
	f.Add([]byte("User-agent: *\nDisallow: /*a*$\n"), "x", "/aaa")
	f.Fuzz(func(t *testing.T, data []byte, agent, path string) {
		file := Parse(data)
		_ = file.Check(agent, path)
	})
}
