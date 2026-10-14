# aibouncer

**Check AI crawlers' IDs at the door.** aibouncer is a dependency-free Go middleware and CLI that
identifies GPTBot, ClaudeBot, PerplexityBot, Googlebot and 30 other AI crawlers and agents,
**verifies they are who they claim to be** (official IP lists, reverse DNS, and Web Bot Auth
signatures), blocks impostors, enforces your AI crawling policy, and measures the human traffic
ChatGPT, Perplexity and friends send you.

[![Go Reference](https://pkg.go.dev/badge/github.com/emorilebo/aibouncer.svg)](https://pkg.go.dev/github.com/emorilebo/aibouncer)
[![CI](https://github.com/emorilebo/aibouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/emorilebo/aibouncer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/emorilebo/aibouncer)](https://github.com/emorilebo/aibouncer/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Anyone can type `GPTBot` into a User-Agent header. Scrapers do it all the time: it's cheaper
than a fake mustache and it works on more websites. aibouncer asks for ID.

```go
bouncer := aibouncer.New(aibouncer.WithPolicy(aibouncer.Policy{
	Purposes: map[aibouncer.Purpose]aibouncer.Action{aibouncer.PurposeTraining: aibouncer.Block},
}))
go bouncer.Verifier().Run(ctx, 12*time.Hour, nil) // keep the operators' IP lists fresh
log.Fatal(http.ListenAndServe(":8080", bouncer.Middleware(mux)))
```

That's it: AI training crawlers get a 403, AI search crawlers and user-initiated fetches get
through, and anything *pretending* to be an AI crawler is blocked.

## Why

- **User-Agent strings are self-reported.** Blocking or allow-listing by User-Agent alone means
  trusting whoever wrote the header. aibouncer checks each claim with the verification method the
  operator itself documents, and tells you which method was used.
- **robots.txt is a polite sign on the door.** Several operators document that their
  user-initiated fetchers may not follow it (OpenAI for ChatGPT-User, Perplexity for
  Perplexity-User). aibouncer is the person standing next to the sign.
- **AI search is a traffic channel now.** If you work on SEO, GEO/AEO or growth, you want to know
  which AI engines read your pages and how many humans they send back. aibouncer reports both, from
  live traffic or from your existing access logs.

## What's inside

| | |
|---|---|
| **Catalog** | 34 AI agents from 14 operators, each linked to the operator's own documentation, classified by purpose: `training`, `search`, `user`, `agent`, `other`. |
| **Verification** | Official IP range lists (20 lists, snapshot embedded, live refresh), forward-confirmed reverse DNS, and Web Bot Auth (RFC 9421) signatures. |
| **Verdicts** | `verified`, `spoofed`, `unverifiable` or `not-ai`, with the method and a human-readable reason. |
| **Policy** | Allow or block per purpose or per agent; impostors blocked by default; rendered to robots.txt too. |
| **Referrals** | Detects human visits from ChatGPT, Perplexity, Gemini, Copilot, Claude, DeepSeek, Grok and more. |
| **`robotstxt`** | An RFC 9309 robots.txt parser and matcher (fuzzed, 99% test coverage). |
| **`webbotauth`** | Web Bot Auth verification **and signing**, tested against the RFC 9421 and IETF draft test vectors. |
| **CLI** | `aibouncer logs`, `robots`, `verify`, `agents`, `robots-gen`. |

Zero dependencies outside the Go standard library.

## Install

```bash
go get github.com/emorilebo/aibouncer          # library (Go 1.22+)
go install github.com/emorilebo/aibouncer/cmd/aibouncer@latest   # CLI
```

Prebuilt CLI binaries for Linux, macOS and Windows are attached to each
[release](https://github.com/emorilebo/aibouncer/releases).

## Verdicts

| Verdict | Meaning | Default action |
|---|---|---|
| `verified` | The request came from the operator's published network, passed forward-confirmed reverse DNS, or carried a valid Web Bot Auth signature. | Policy decides |
| `spoofed` | The operator publishes a way to verify the agent, and this request failed it. Someone borrowed the name. | **Block** |
| `unverifiable` | The operator publishes no verification method, the IP data is stale, DNS failed, or the IP is in a range the operator shares with cloud customers. *Not* evidence of spoofing. | Policy decides |
| `not-ai` | The request doesn't claim to be a known AI agent. | Allow |

"Unverifiable" is not an insult: it usually means the operator hasn't published a guest list.

## Policies

```go
// Block AI training, allow everything else, and let GPTBot in anyway.
policy := aibouncer.Policy{
	Purposes: map[aibouncer.Purpose]aibouncer.Action{aibouncer.PurposeTraining: aibouncer.Block},
	Agents:   map[string]aibouncer.Action{"openai-gptbot": aibouncer.Allow},
}

// Observe only: block nothing, not even impostors, and log everything.
observe := aibouncer.Policy{AllowSpoofed: true}
```

Rules apply in this order: impostors are blocked unless `AllowSpoofed` is set, then the agent's
ID rule, then its purpose rule, then allow. Agent IDs are listed by `aibouncer agents`.
Requests for `/robots.txt` are never blocked: under RFC 9309 a 4xx robots.txt means "no rules",
so blocking it would be like locking the door that has the "no entry" sign on it.

### The same policy as robots.txt

```go
fmt.Print(policy.RobotsTxt(aibouncer.DefaultCatalog()))
```

The output includes control tokens such as `Google-Extended` and `Applebot-Extended`, which never
appear in a User-Agent header and can only be expressed in robots.txt.

### Behind a proxy or load balancer

By default the client IP is the TCP peer (`r.RemoteAddr`), which can't be forged. Behind a proxy,
trust `X-Forwarded-For` only from your own proxies:

```go
aibouncer.New(aibouncer.WithClientIP(aibouncer.TrustedProxies(netip.MustParsePrefix("10.0.0.0/8"))))
```

Never trust `0.0.0.0/0`, or every scraper gets to pick its own IP address.

## Measuring AI traffic

```go
aibouncer.WithOnVisit(func(r *http.Request, v aibouncer.Visit) {
	switch {
	case v.Agent != nil:
		metrics.AICrawl(v.Agent.Operator, v.Agent.Name, v.Verdict.String())
	case v.Referral != nil:
		metrics.AIReferral(v.Referral.Assistant) // a human clicked through from an AI answer
	}
})
```

Handlers can also read the verdict with `aibouncer.VisitFromContext(r.Context())`.
ChatGPT's `utm_source=chatgpt.com` tag is documented by OpenAI. Referrer hosts for the other
assistants come from an independently maintained list (marked `reputable-observed` in the
catalog). Native apps often strip referrers, so treat referral counts as a floor, not a census.

## Web Bot Auth

Some agents sign their requests instead of (or as well as) using known IPs. OpenAI's ChatGPT agent
has no documented User-Agent token or IP list at all; a `Signature-Agent: "https://chatgpt.com"`
header plus an RFC 9421 signature is the only way to identify it. aibouncer verifies these
signatures automatically for agents in the catalog.

- Key directories are fetched only from URLs in the catalog, never from the request, so a scraper
  can't point your server at its own keys (or at your internal network).
- An unknown keyid triggers at most one directory refetch per minute.
- Both the current dictionary form and the legacy string form of `Signature-Agent` are supported.

Building an agent? The same package signs requests:

```go
err := webbotauth.Sign(req, privateKey, webbotauth.SignOptions{SignatureAgent: "https://agent.example"})
```

> **Interop note.** The signature in test vector A.2.2 of draft-meunier-web-bot-auth-architecture-05
> verifies only when the keyed `Signature-Agent` member is signed without quotes, although the
> draft's printed signature base (and RFC 9421 section 2.1.2) quote it. aibouncer tries the strict
> form first and accepts the unquoted form too; both encode the same value.
> [`TestKeyedMemberSerialisationVariants`](webbotauth/webbotauth_test.go) pins this down.

## CLI

### `aibouncer logs`: who's crawling you, and who's lying

Point it at nginx or Apache access logs (combined format, `.gz` supported, `-` for stdin):

```text
$ aibouncer logs /var/log/nginx/access.log
9 log lines, 1 unparsed (expected: combined log format)

AI crawler requests: 5
               AGENT   OPERATOR   PURPOSE  REQUESTS  VERIFIED  UNVERIFIABLE  SPOOFED  SPOOFING IPS
              GPTBot     OpenAI  training         3         2             0        1             1
           ClaudeBot  Anthropic  training         1         1             0        0             0
  Meta-ExternalAgent       Meta  training         1         0             1        0             0

Human visits referred by AI assistants: 2 (a lower bound: many apps strip referrers)
  ChatGPT     1
  Perplexity  1
```

(Output from the test fixture in [`cmd/aibouncer/main_test.go`](cmd/aibouncer/main_test.go).)
`-json` for machine-readable output, `-offline` to skip downloads and DNS.

### `aibouncer robots`: what does my robots.txt actually say to AI?

Pass a domain (`aibouncer robots example.com` fetches `https://example.com/robots.txt`) or a file:

```text
$ aibouncer robots robots.txt
robots.txt: robots.txt   path: /

AGENT                  OPERATOR                      PURPOSE   ACCESS   DECIDED BY
GPTBot                 OpenAI                        training  BLOCKED  Disallow: / (User-agent: GPTBot)
OAI-SearchBot          OpenAI                        search    allowed  no matching rule
ChatGPT-User           OpenAI                        user      allowed  no matching rule
OAI-AdsBot             OpenAI                        other     allowed  no matching rule
ClaudeBot              Anthropic                     training  allowed  no matching rule
...
```

`-path /blog/` checks a specific path; an unreachable robots.txt is reported, because RFC 9309
tells crawlers to treat it as "disallow everything".

Useful before a launch: OpenAI documents that sites opted out of OAI-SearchBot are not shown in
ChatGPT search answers, which is easy to do by accident with a broad `User-agent: *` rule.

### `aibouncer verify`, `agents`, `robots-gen`

```text
$ aibouncer verify -ua "Googlebot/2.1" 66.249.66.1
Googlebot (Google, search) from 66.249.66.1: VERIFIED
  IP is in https://developers.google.com/static/crawling/ipranges/common-crawlers.json

$ aibouncer verify -ua "Googlebot/2.1" 1.1.1.1
Googlebot (Google, search) from 1.1.1.1: SPOOFED
  IP is outside the published ranges and reverse DNS does not confirm the operator

$ aibouncer robots-gen -block training > ai-robots.txt
```

Exit codes: `0` ok/verified, `1` finding (spoofed agent or blocked crawler), `2` usage error,
`3` inconclusive.

## Agents covered

Researched on 2026-10-14 from each operator's own documentation; every name links to it.
Run `aibouncer agents` for the list your version ships with.

| Agent | Operator | Purpose | Verified by |
|---|---|---|---|
| [GPTBot](https://developers.openai.com/api/docs/bots) | OpenAI | training | IP list |
| [OAI-SearchBot](https://developers.openai.com/api/docs/bots) | OpenAI | search | IP list |
| [ChatGPT-User](https://developers.openai.com/api/docs/bots) | OpenAI | user | IP list |
| [OAI-AdsBot](https://developers.openai.com/api/docs/bots) | OpenAI | other | IP list |
| [ChatGPT agent](https://help.openai.com/en/articles/11845367-chatgpt-works-cloud-browser-allowlisting) | OpenAI | agent | Web Bot Auth |
| [ClaudeBot](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler) | Anthropic | training | IP list |
| [Claude-User](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler) | Anthropic | user | IP list |
| [Claude-SearchBot](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler) | Anthropic | search | IP list |
| [PerplexityBot](https://docs.perplexity.ai/docs/resources/perplexity-crawlers) | Perplexity | search | IP list |
| [Perplexity-User](https://docs.perplexity.ai/docs/resources/perplexity-crawlers) | Perplexity | user | IP list |
| [Googlebot](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers) | Google | search | IP list, reverse DNS |
| [Google-Extended](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers) | Google | training | robots.txt token only |
| [GoogleOther](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers) | Google | other | IP list, reverse DNS |
| [Google-CloudVertexBot](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers) | Google | other | IP list, reverse DNS |
| [Google-Agent](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) | Google | agent | IP list, reverse DNS, Web Bot Auth (experimental) |
| [Gemini Notebook fetcher](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) | Google | user | IP list, shared IP list, reverse DNS |
| [Bingbot](https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0) | Microsoft | search | IP list, reverse DNS |
| [Applebot](https://support.apple.com/en-us/119829) | Apple | search | IP list, reverse DNS |
| [Applebot-Extended](https://support.apple.com/en-us/119829) | Apple | training | robots.txt token only |
| [Meta-ExternalAgent](https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers) | Meta | training | User-Agent only (unverifiable) |
| [Meta-ExternalFetcher](https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers) | Meta | user | User-Agent only (unverifiable) |
| [Meta-WebIndexer](https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers) | Meta | search | User-Agent only (unverifiable) |
| [CCBot](https://commoncrawl.org/ccbot) | Common Crawl Foundation | other | IP list, reverse DNS |
| [Amazonbot](https://developer.amazon.com/amazonbot) | Amazon | training | IP list |
| [Amzn-SearchBot](https://developer.amazon.com/amazonbot) | Amazon | search | IP list |
| [Amzn-User](https://developer.amazon.com/amazonbot) | Amazon | user | IP list |
| [DuckAssistBot](https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot) | DuckDuckGo | search | IP list |
| [MistralAI-User](https://docs.mistral.ai/robots) | Mistral AI | user | IP list |
| [MistralAI-Index](https://docs.mistral.ai/robots) | Mistral AI | search | IP list |
| [MistralAI-Training](https://docs.mistral.ai/robots) | Mistral AI | training | User-Agent only (unverifiable) |
| [YouBot](https://docs.you.com/youbot) | You.com | search | documented CIDR, reverse DNS, Web Bot Auth |
| [Diffbot](https://www.diffbot.com/docs/crawl/faq/robots-txt) | Diffbot | search | User-Agent only (unverifiable) |
| [Diffbot-User](https://www.diffbot.com/docs/crawl/faq/robots-txt) | Diffbot | user | User-Agent only (unverifiable) |
| [AI2Bot](https://allenai.org/crawler) | Allen Institute for AI (Ai2) | training | User-Agent only (unverifiable) |

Purpose labels follow each operator's description; a few are judgement calls (for example Applebot
feeds Apple's search features, while Applebot-Extended controls training use). See
[docs/SOURCES.md](docs/SOURCES.md) for every source and the reasoning.

## How verification works

1. **Identify** the agent from the User-Agent token (whole-word, case-insensitive, longest match),
   or from a `Signature-Agent` header for signature-only agents.
2. **Signature**: if the request carries a Web Bot Auth signature and the signer is in the catalog,
   verify it against the operator's key directory. Valid means `verified`; invalid means `spoofed`.
3. **IP lists**: check the client IP against the operator's published lists and documented CIDRs.
4. **Reverse DNS**: for operators that document it (Google, Bing, Apple, Common Crawl, You.com),
   resolve the IP, require a host under the operator's domain, then resolve that host forward and
   require the original IP. A PTR record alone proves nothing.
5. **Fail open on doubt.** A miss counts as `spoofed` only when the evidence is conclusive. Stale
   lists (older than 7 days by default), DNS errors and ranges shared with cloud customers give
   `unverifiable`, so bad data never blocks a genuine crawler.

### Keeping the data fresh

The IP lists ship as an embedded snapshot, so verification works from the first request, even
offline. Call `Verifier.Run` (or `Refresh` from a cron job) to keep them current; failed downloads
keep the previous data. Operators add bots more often than Go modules get released, so the catalog
can also be extended at runtime with `aibouncer.LoadCatalog`.

## Security notes

- No dependencies outside the Go standard library.
- The client IP comes from the TCP peer unless you opt in to `TrustedProxies`.
- Reverse-DNS results are cached in a bounded cache, and concurrent lookups for the same IP are
  collapsed, so rotating scraper IPs can't exhaust memory or flood your resolver.
- `googleusercontent.com` is never accepted as reverse-DNS proof: any Google Cloud customer can get
  a PTR record there.
- Web Bot Auth key directories are only fetched from catalog URLs; key IDs are computed thumbprints,
  never trusted from the directory's `kid` field.
- The robots.txt matcher runs in linear time per rule, so hostile patterns like `/*a*a*a*a*b` can't
  stall `aibouncer robots`.

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Limitations

- **Seven agents can't be verified**, because their operators publish no IP list, DNS domain or
  signing key (Meta's three crawlers, MistralAI-Training, Diffbot's two, AI2Bot). They are reported
  as `unverifiable`, never as `spoofed`.
- **Published lists can lag.** Bing's `bingbot.json` was last regenerated in January 2024 even
  though Bing says to refresh it daily; that's why reverse DNS is checked before declaring a miss.
- **IPs alone can't tell DuckAssistBot from DuckDuckBot**: DuckDuckGo publishes byte-identical lists.
- **Referral detection is a lower bound** (see above).
- **Web Bot Auth support is Ed25519 only**, which is what the publishing operators use.
- **aibouncer is a bouncer, not a SWAT team.** It doesn't do general bot detection, rate limiting or
  fingerprinting. Pair it with your rate limiter and use `Visit.Verdict` as a signal.

## FAQ

### How do I verify that a request really comes from GPTBot in Go?
Use `aibouncer.NewVerifier().VerifyIP(ctx, agent, ip)` with the agent from
`DefaultCatalog().Identify(r.UserAgent())`. It checks the IP against OpenAI's published
`gptbot.json` list and returns `verified` or `spoofed`. In an HTTP server, `aibouncer.New().Middleware`
does this for every request and blocks impostors by default.

### How do I block AI training crawlers but stay visible in AI search?
Set `Policy{Purposes: {PurposeTraining: Block}}`. Training crawlers such as GPTBot, ClaudeBot and
CCBot are blocked, while search crawlers such as OAI-SearchBot, Claude-SearchBot and PerplexityBot
are allowed. Render the same policy with `Policy.RobotsTxt` so it also covers robots.txt-only
tokens like Google-Extended and Applebot-Extended.

### Does robots.txt stop AI crawlers?
Only the ones that choose to follow it. Most documented AI crawlers say they honour robots.txt, but
OpenAI and Perplexity document that their user-initiated fetchers (ChatGPT-User, Perplexity-User)
may not apply it. aibouncer enforces your policy on the request itself.

### How can I tell how much traffic ChatGPT or Perplexity sends to my site?
Run `aibouncer logs access.log` on existing logs, or use `WithOnVisit` in the middleware. Human
visits are recognised by ChatGPT's documented `utm_source=chatgpt.com` tag and by the Referer hosts
of 15 AI assistants. Apps that strip referrers make the count a lower bound.

### What is Web Bot Auth?
An IETF draft in which bots sign each HTTP request with an RFC 9421 HTTP Message Signature and
publish their public keys at `/.well-known/http-message-signatures-directory`. Websites can then
verify a bot cryptographically instead of by IP address. OpenAI's ChatGPT agent uses it, and Google
is experimenting with it for Google-Agent. aibouncer's `webbotauth` package verifies and creates
these signatures.

### What's the difference between Googlebot and Google-Extended?
Googlebot is the crawler that fetches pages. Google-Extended is a robots.txt control token with no
User-Agent of its own; according to Google, it controls whether content Google crawls may be used
to train future Gemini models. Blocking Google-Extended in robots.txt doesn't block Googlebot.

## Sources and methodology

Every catalog entry links to the operator's documentation, and [docs/SOURCES.md](docs/SOURCES.md)
lists every source fetched on 2026-10-14, with notes on stale lists and format quirks. Found an
outdated entry? Please open an issue with a link to the operator's page;
[CONTRIBUTING.md](CONTRIBUTING.md) explains how the catalog and snapshot are updated.

## Related projects by the same author

- [safe-dist](https://github.com/emorilebo/safe-dist): catch `.DS_Store`, `.env` files and private keys in build output before you ship it (C++ CLI + GitHub Action)
- [rag-poison-guard](https://www.npmjs.com/package/rag-poison-guard): sanitize untrusted content against indirect prompt injection in RAG pipelines
- [redact-ai-stream](https://www.npmjs.com/package/redact-ai-stream): bi-directional PII redaction stream for AI applications
- [hallucination-validator](https://www.npmjs.com/package/hallucination-validator): validate LLM output for link rot, dangerous code and hallucinations
- [npm_sentinel](https://crates.io/crates/npm_sentinel): detect npm supply-chain attacks in lifecycle scripts (Rust)

## About the author

Built by **[Godfrey Lebo](https://godfreylebo.dev)**, Senior Backend & Product Engineer and founder of Sether.
I build the backend, connect the product, and stay responsible for what happens after launch. Lately
that means open-source tooling for AI security and software supply-chain security.

[Website](https://godfreylebo.dev) · [GitHub](https://github.com/emorilebo) · [X / Twitter](https://x.com/emori_lebo) · [LinkedIn](https://www.linkedin.com/in/godfreylebo) · [Email](mailto:emorylebo@gmail.com)

## License

[MIT](LICENSE) © Godfrey Lebo
