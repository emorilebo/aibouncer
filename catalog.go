package aibouncer

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Purpose describes why an AI agent fetches pages, as stated by its operator.
type Purpose string

// Purposes, as described in each operator's documentation.
const (
	// PurposeTraining crawlers collect content that may be used to train models.
	PurposeTraining Purpose = "training"
	// PurposeSearch crawlers index content so it can appear in AI search results and answers.
	PurposeSearch Purpose = "search"
	// PurposeUser fetchers retrieve a page because a person asked an assistant to, right now.
	PurposeUser Purpose = "user"
	// PurposeAgent is an autonomous browser acting on a person's behalf.
	PurposeAgent Purpose = "agent"
	// PurposeOther covers documented AI-adjacent crawlers that fit none of the above.
	PurposeOther Purpose = "other"
)

// RobotsBehavior is how an agent treats robots.txt, according to its operator.
type RobotsBehavior string

// Robots.txt behaviours, as documented by operators.
const (
	RobotsHonors                 RobotsBehavior = "honors"
	RobotsHonorsByDefault        RobotsBehavior = "honors_by_default"
	RobotsMayIgnoreUserInitiated RobotsBehavior = "may_ignore_user_initiated"
	RobotsGenerallyIgnores       RobotsBehavior = "generally_ignores"
	RobotsControlTokenOnly       RobotsBehavior = "control_token_only"
	RobotsUnspecified            RobotsBehavior = "unspecified"
)

// WebBotAuth describes an agent that signs its requests with HTTP Message Signatures (RFC 9421)
// following the Web Bot Auth architecture.
type WebBotAuth struct {
	// SignatureAgent is the documented value of the Signature-Agent request header, if any.
	SignatureAgent string `json:"signature_agent,omitempty"`
	// KeyDirectory is the URL of the operator's public key directory.
	KeyDirectory string `json:"key_directory"`
	// Experimental is true when the operator says not every request is signed.
	Experimental bool `json:"experimental,omitempty"`
}

// Agent is an AI crawler, fetcher or browsing agent documented by its operator.
type Agent struct {
	// ID is a stable identifier such as "openai-gptbot". Use it in Policy.Agents.
	ID string `json:"id"`
	// Name is the operator's name for the agent, e.g. "GPTBot".
	Name     string  `json:"name"`
	Operator string  `json:"operator"`
	Purpose  Purpose `json:"purpose"`
	// UserAgentTokens appear in the User-Agent header of the agent's requests.
	UserAgentTokens []string `json:"user_agent_tokens,omitempty"`
	// RobotsToken is the product token to use in robots.txt.
	RobotsToken string `json:"robots_token,omitempty"`
	// RobotsOnly is true for control tokens such as Google-Extended that never appear in a
	// User-Agent header; they only work through robots.txt.
	RobotsOnly bool           `json:"robots_only,omitempty"`
	RobotsTxt  RobotsBehavior `json:"robots_txt"`
	// IPRanges are URLs of the operator's published IP range lists.
	IPRanges []string `json:"ip_ranges,omitempty"`
	// SharedIPRanges are published lists that also cover the operator's cloud customers (for
	// example Google's user-triggered-fetchers.json). A match makes a claim plausible, not proven,
	// and yields Unverifiable unless reverse DNS confirms it.
	SharedIPRanges []string `json:"shared_ip_ranges,omitempty"`
	// CIDRs are prefixes stated directly in the operator's documentation.
	CIDRs []string `json:"cidrs,omitempty"`
	// ReverseDNS lists domains for forward-confirmed reverse DNS verification.
	ReverseDNS []string    `json:"reverse_dns,omitempty"`
	WebBotAuth *WebBotAuth `json:"web_bot_auth,omitempty"`
	// Docs is the operator's documentation page the entry was taken from.
	Docs string `json:"docs"`
}

// Verifiable reports whether the operator publishes any way to verify the agent beyond its
// User-Agent header.
func (a *Agent) Verifiable() bool {
	return len(a.IPRanges) > 0 || len(a.SharedIPRanges) > 0 || len(a.CIDRs) > 0 || len(a.ReverseDNS) > 0 || a.WebBotAuth != nil
}

// ReferralSource describes how human visits from an AI assistant can be recognised.
type ReferralSource struct {
	Assistant string `json:"assistant"`
	// Hosts are Referer hosts, optionally with a path prefix such as "x.com/i/grok".
	Hosts []string `json:"hosts"`
	// UTMSources are utm_source query values the assistant adds to outbound links.
	UTMSources []string `json:"utm_sources,omitempty"`
	// Evidence is "official" when the operator documents it, "reputable-observed" when it comes
	// from an independently maintained list.
	Evidence string `json:"evidence"`
}

// Catalog is a set of known AI agents and AI referral sources.
type Catalog struct {
	// Generated is the date the embedded data was researched (YYYY-MM-DD).
	Generated string           `json:"generated"`
	Agents    []Agent          `json:"agents"`
	Referrals []ReferralSource `json:"referrals"`

	byID     map[string]*Agent
	byToken  []tokenEntry // sorted longest token first
	byRobots map[string]*Agent
}

type tokenEntry struct {
	token string // lower-case
	agent *Agent
}

//go:embed catalog.json
var catalogJSON []byte

var defaultCatalog = mustLoadCatalog(catalogJSON)

// DefaultCatalog returns the embedded catalog of AI agents. Every entry links to the operator
// documentation it was taken from. The returned value is shared; do not modify it.
func DefaultCatalog() *Catalog { return defaultCatalog }

// LoadCatalog parses a catalog in the same JSON format as the embedded one, so you can extend
// or replace the defaults without waiting for a release.
func LoadCatalog(data []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("aibouncer: parse catalog: %w", err)
	}
	if err := c.index(); err != nil {
		return nil, err
	}
	return &c, nil
}

func mustLoadCatalog(data []byte) *Catalog {
	c, err := LoadCatalog(data)
	if err != nil {
		panic(err)
	}
	return c
}

func (c *Catalog) index() error {
	c.byID = make(map[string]*Agent, len(c.Agents))
	c.byRobots = make(map[string]*Agent, len(c.Agents))
	c.byToken = nil
	for i := range c.Agents {
		agent := &c.Agents[i]
		if agent.ID == "" || agent.Name == "" {
			return fmt.Errorf("aibouncer: catalog entry %d has no id or name", i)
		}
		if _, dup := c.byID[agent.ID]; dup {
			return fmt.Errorf("aibouncer: duplicate agent id %q", agent.ID)
		}
		c.byID[agent.ID] = agent
		if agent.RobotsToken != "" {
			c.byRobots[strings.ToLower(agent.RobotsToken)] = agent
		}
		for _, token := range agent.UserAgentTokens {
			if token == "" {
				return fmt.Errorf("aibouncer: agent %q has an empty user-agent token", agent.ID)
			}
			c.byToken = append(c.byToken, tokenEntry{token: strings.ToLower(token), agent: agent})
		}
	}
	sort.SliceStable(c.byToken, func(i, j int) bool { return len(c.byToken[i].token) > len(c.byToken[j].token) })
	return nil
}

// Agent returns the agent with the given ID.
func (c *Catalog) Agent(id string) (*Agent, bool) {
	agent, ok := c.byID[id]
	return agent, ok
}

// ByRobotsToken returns the agent that uses the given robots.txt product token.
func (c *Catalog) ByRobotsToken(token string) (*Agent, bool) {
	agent, ok := c.byRobots[strings.ToLower(token)]
	return agent, ok
}

// Identify returns the agent whose token appears in the User-Agent header. Tokens match
// case-insensitively and only as whole words, so "Diffbot" does not match "Diffbot-User" and
// "Googlebot" does not match "Googlebot-Image". When several tokens match, the longest wins.
//
// Identification alone proves nothing: anyone can send "GPTBot" in a header. Use a [Verifier]
// to check the claim.
func (c *Catalog) Identify(userAgent string) (*Agent, bool) {
	if userAgent == "" {
		return nil, false
	}
	lower := strings.ToLower(userAgent)
	for _, entry := range c.byToken {
		if containsWord(lower, entry.token) {
			return entry.agent, true
		}
	}
	return nil, false
}

func containsWord(haystack, word string) bool {
	for offset := 0; ; {
		i := strings.Index(haystack[offset:], word)
		if i < 0 {
			return false
		}
		start := offset + i
		end := start + len(word)
		if (start == 0 || !isTokenByte(haystack[start-1])) && (end == len(haystack) || !isTokenByte(haystack[end])) {
			return true
		}
		offset = start + 1
	}
}

func isTokenByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}
