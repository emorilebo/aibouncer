package aibouncer

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestEmbeddedCatalogIsConsistent(t *testing.T) {
	c := DefaultCatalog()
	if len(c.Agents) < 30 {
		t.Fatalf("catalog has %d agents, expected the researched set", len(c.Agents))
	}
	validPurpose := map[Purpose]bool{PurposeTraining: true, PurposeSearch: true, PurposeUser: true, PurposeAgent: true, PurposeOther: true}
	validRobots := map[RobotsBehavior]bool{RobotsHonors: true, RobotsHonorsByDefault: true, RobotsMayIgnoreUserInitiated: true,
		RobotsGenerallyIgnores: true, RobotsControlTokenOnly: true, RobotsUnspecified: true}
	seenTokens := map[string]string{}

	for _, a := range c.Agents {
		if !validPurpose[a.Purpose] {
			t.Errorf("%s: invalid purpose %q", a.ID, a.Purpose)
		}
		if !validRobots[a.RobotsTxt] {
			t.Errorf("%s: invalid robots_txt %q", a.ID, a.RobotsTxt)
		}
		if !strings.HasPrefix(a.Docs, "https://") {
			t.Errorf("%s: docs URL %q must be https", a.ID, a.Docs)
		}
		for _, u := range a.IPRanges {
			if !strings.HasPrefix(u, "https://") {
				t.Errorf("%s: IP range URL %q must be https", a.ID, u)
			}
		}
		for _, cidr := range a.CIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				t.Errorf("%s: bad CIDR %q", a.ID, cidr)
			}
		}
		for _, suffix := range a.ReverseDNS {
			if suffix == "googleusercontent.com" {
				t.Errorf("%s: googleusercontent.com is customer-controlled and must not verify anything", a.ID)
			}
		}
		if a.RobotsOnly && len(a.UserAgentTokens) > 0 {
			t.Errorf("%s: robots-only tokens never appear in User-Agent headers", a.ID)
		}
		if len(a.UserAgentTokens) == 0 && a.RobotsToken == "" && a.WebBotAuth == nil {
			t.Errorf("%s: no way to identify this agent", a.ID)
		}
		for _, token := range a.UserAgentTokens {
			if other, dup := seenTokens[strings.ToLower(token)]; dup {
				t.Errorf("token %q used by both %s and %s", token, other, a.ID)
			}
			seenTokens[strings.ToLower(token)] = a.ID
		}
	}
}

func TestIdentify(t *testing.T) {
	c := DefaultCatalog()
	cases := []struct {
		userAgent string
		wantID    string
	}{
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot", "openai-gptbot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.3; +https://openai.com/searchbot", "openai-oai-searchbot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "anthropic-claudebot"},
		{"Mozilla/5.0 (compatible; Claude-SearchBot/1.0)", "anthropic-claude-searchbot"},
		{"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "google-googlebot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36", "microsoft-bingbot"},
		{"meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", "meta-externalagent"},
		{"Mozilla/5.0 (compatible; Diffbot-User/0.1)", "diffbot-diffbot-user"},
		{"perplexitybot", "perplexity-perplexitybot"}, // case-insensitive
	}
	for _, tc := range cases {
		agent, ok := c.Identify(tc.userAgent)
		if !ok || agent.ID != tc.wantID {
			got := "<none>"
			if ok {
				got = agent.ID
			}
			t.Errorf("Identify(%q) = %s, want %s", tc.userAgent, got, tc.wantID)
		}
	}

	for _, ua := range []string{
		"",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		"Mozilla/5.0 (compatible; Googlebot-Image/1.0)", // a different Google crawler, not Googlebot
		"NotGPTBotAtAll/1.0",
		"Mozilla/5.0 (compatible; MyGPTBot2/1.0)",
	} {
		if agent, ok := c.Identify(ua); ok {
			t.Errorf("Identify(%q) = %s, want no match", ua, agent.ID)
		}
	}
}

func TestRobotsOnlyTokensAreNotIdentified(t *testing.T) {
	c := DefaultCatalog()
	if agent, ok := c.Identify("Mozilla/5.0 (compatible; Google-Extended)"); ok {
		t.Errorf("Google-Extended is a robots.txt token only, but Identify returned %s", agent.ID)
	}
	if agent, ok := c.ByRobotsToken("google-extended"); !ok || agent.Purpose != PurposeTraining {
		t.Error("ByRobotsToken should find Google-Extended as a training control token")
	}
}

func TestLoadCatalogValidation(t *testing.T) {
	if _, err := LoadCatalog([]byte(`{"agents":[{"id":"a","name":"A"},{"id":"a","name":"B"}]}`)); err == nil {
		t.Error("duplicate IDs must be rejected")
	}
	if _, err := LoadCatalog([]byte(`{"agents":[{"id":"","name":"A"}]}`)); err == nil {
		t.Error("missing ID must be rejected")
	}
	if _, err := LoadCatalog([]byte(`{`)); err == nil {
		t.Error("invalid JSON must be rejected")
	}
	c, err := LoadCatalog([]byte(`{"agents":[{"id":"x","name":"X","purpose":"training","user_agent_tokens":["XBot"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := c.Identify("hello XBot/1"); !ok || a.ID != "x" {
		t.Error("custom catalog should identify its own agents")
	}
}

func TestDetectReferral(t *testing.T) {
	c := DefaultCatalog()
	cases := []struct {
		url, referer string
		want         string
		signal       string
	}{
		{"/post?utm_source=chatgpt.com", "", "ChatGPT", "utm_source"},
		{"/post?utm_source=ChatGPT.com&utm_medium=x", "https://example.org/", "ChatGPT", "utm_source"},
		{"/post", "https://www.perplexity.ai/search?q=go", "Perplexity", "referer"},
		{"/post", "https://gemini.google.com/app", "Gemini", "referer"},
		{"/post", "https://x.com/i/grok?conversation=1", "Grok", "referer"},
		{"/post", "https://claude.ai/chat/abc", "Claude", "referer"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", tc.url, nil)
		if tc.referer != "" {
			r.Header.Set("Referer", tc.referer)
		}
		ref, ok := c.DetectReferral(r)
		if !ok || ref.Assistant != tc.want || ref.Signal != tc.signal {
			t.Errorf("DetectReferral(%s, %s) = %+v, %v; want %s via %s", tc.url, tc.referer, ref, ok, tc.want, tc.signal)
		}
	}

	for _, referer := range []string{"https://x.com/elonmusk", "https://notperplexity.ai/", "https://google.com/search", "not a url", ""} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Referer", referer)
		if ref, ok := c.DetectReferral(r); ok {
			t.Errorf("Referer %q matched %+v", referer, ref)
		}
	}
}
