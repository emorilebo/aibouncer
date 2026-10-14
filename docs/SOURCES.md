# Sources and methodology

This is the research behind aibouncer's agent catalog (`catalog.json`) and IP snapshot (`snapshot.json`).

All sources were fetched on **2026-10-14**. The machine-readable dataset, including verbatim supporting quotes for every entry, is [`research/ai_agents_research.json`](research/ai_agents_research.json).

## How the data was collected

- **Pages.** Doc pages were fetched with curl and converted to text. A few pages needed a different route:
  - Client-rendered pages (Bing help, Ai2, Meta, OpenAI Help Center) were read in a real browser pane.
  - Two pages could not be fetched directly, so they were read through the `r.jina.ai` reader proxy. That proxy is only a transport; the content is still the operator's own:
    - `help.openai.com` returned 403 to curl and WebFetch.
    - `support.apple.com` did not resolve over DNS from the research environment.
- **IP lists.** Every IP JSON was downloaded with `curl -sL -A "research (emorylebo@gmail.com)" <url>`. For each one, the HTTP status, redirects, Content-Type, `creationTime` and prefix counts were recorded.
- **Quotes.** Every quote in the JSON was checked by a script against the saved copy of its source page. Before comparing, whitespace was collapsed and curly quotes were made straight. The script reported 0 mismatches, and every quote has `verified_verbatim: true`. Part A and Part B quotes are at most 25 words. Part C quotes the RFC sentences in full.
- **Third-party sources.** These were used only to find official pages. The exception is Part B referrer hostnames, which no operator documents. For those, the Matomo-maintained list is used and labelled `reputable-observed`.

## Headline findings / corrections to assumptions

1. **Anthropic publishes IPs.** The source is `https://claude.com/crawling/bots.json`, linked from Anthropic's help article. It is a single shared list for ClaudeBot, Claude-User and Claude-SearchBot, with 38 IPv4 prefixes and `creationTime` 2026-10-07. Anthropic publishes no rDNS, and no full UA strings, only the tokens.
2. **Google moved its crawler docs and renamed its JSON files.**
   - Docs moved to `developers.google.com/crawling/docs/crawlers-fetchers/...`.
   - The JSON files moved to `/static/crawling/ipranges/`. `googlebot.json` is now `common-crawlers.json`, and the old URLs return 301.
   - There is a new `user-triggered-agents.json` for the new **Google-Agent** fetcher. Google-Agent is also experimenting with Web Bot Auth, using `Signature-Agent: g="https://agent.bot.goog"`.
   - NotebookLM's fetcher is now **Google-GeminiNotebook**. The old `Google-NotebookLM` token was "supported until August 2026".
3. **OpenAI's ChatGPT agent has no documented UA string and no IP list.**
   - It is verifiable only with Web Bot Auth / RFC 9421: `Signature-Agent: "https://chatgpt.com"`, keys at `https://chatgpt.com/.well-known/http-message-signatures-directory`.
   - The help article is now titled "ChatGPT Work's Cloud browser allowlisting".
   - OpenAI also documents a new **OAI-AdsBot** with its own `adsbot.json`.
4. **Amazon's IP lists are HTML pages with JSON embedded in them, not JSON endpoints.** The format is also inconsistent between them:
   - Amazonbot and Amzn-User use `ipv4Prefix` with bare IPs and no `/len`.
   - Amzn-SearchBot uses `ip_prefix` with `/32`.

   Amazon's current page documents no rDNS. Sample IPs PTR to `ec2-*.compute-1.amazonaws.com`. New tokens: **Amzn-SearchBot** and **Amzn-User**.
5. **The two DuckDuckGo JSONs are identical.** `duckassistbot.json` and `duckduckbot.json` were byte-for-byte the same, so IP alone cannot tell DuckAssistBot from DuckDuckBot.
6. **Mistral now has three bots: MistralAI-User, MistralAI-Index and MistralAI-Training.** Only User and Index have IP JSONs. The docs now call the assistant "Vibe".
7. **Meta changed its crawler list.** It adds **Meta-WebIndexer** (Meta AI search). FacebookBot is no longer listed. Meta publishes no IP list for any crawler.
8. **The 500 KiB figure in RFC 9309 is a minimum parsing limit, not a maximum file size** (§2.5: "MUST be at least 500 kibibytes").
9. **The official OpenAI `utm_source=chatgpt.com` statement is no longer at its URL.**
   - It was in the Publishers & Developers FAQ (article 12627856).
   - On 2026-10-14 that URL redirects to "ChatGPT Atlas retirement".
   - The quote was verified from the Wayback snapshot of 2026-10-04.

## Implementation notes

- **`creationTime` formats vary:**
  - `2026-10-14T14:46:02.000000` (no timezone)
  - `2026-10-07T00:00:00Z`
  - `2026-09-08T05:24:10.610952+00:00`
- **CCBot's JSON has extra keys:** `synctoken` (lower-case t) and `notes`.
- **Content-Type headers are unreliable.** OpenAI's `chatgpt-user.json` is served as `application/octet-stream`.
- **Some documented IP URLs redirect, so follow redirects:**
  - Perplexity documents `www.perplexity.com/*.json`, which returns 302 to `www.perplexity.ai`.
  - Apple documents `http://`, which returns 301 to `https://`.
- **Some lists look stale.** Bing says "Refresh this list daily", but its `bingbot.json` has `creationTime` 2024-01-03. Prefer FCrDNS (`search.msn.com`) for Bing.
- **`googleusercontent.com` rDNS is not proof of Google.** It and `user-triggered-fetchers.json` also cover Google Cloud customer traffic.
- **`AI2Bot` is not a valid RFC 9309 token.** It contains a digit, and the ABNF identifier allows only letters, `-` and `_`.
- **Grok referrals need host+path matching.** Matomo's Grok referrer is `x.com/i/grok`; matching the host alone would misclassify all X traffic.

## Live IP-range endpoints (2026-10-14)

| URL | HTTP | creationTime | prefixes (v4/v6) |
|---|---|---|---|
| https://openai.com/gptbot.json | 200 | 2026-09-22T02:00:07 | 18 (18/0) |
| https://openai.com/searchbot.json | 200 | 2026-01-02T11:00:00 | 39 (39/0) |
| https://openai.com/chatgpt-user.json | 200 (octet-stream) | 2026-10-07T16:05:32 | 234 (234/0) |
| https://openai.com/adsbot.json | 200 | 2026-05-12T03:00:00 | 2 (2/0) |
| https://claude.com/crawling/bots.json | 200 | 2026-10-07T00:00:00Z | 38 (38/0) |
| https://www.perplexity.com/perplexitybot.json → 302 → www.perplexity.ai | 200 | 2025-02-07T16:56:00 | 8 (8/0) |
| https://www.perplexity.com/perplexity-user.json → 302 → www.perplexity.ai | 200 | 2025-10-17T10:17:00 | 4 (4/0) |
| https://developers.google.com/static/crawling/ipranges/common-crawlers.json | 200 | 2026-10-14T14:46:02 | 317 (170/147) |
| https://developers.google.com/static/crawling/ipranges/special-crawlers.json | 200 | 2026-10-14T14:46:03 | 272 (136/136) |
| https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json | 200 | 2026-10-14T14:46:04 | 1068 (534/534) |
| https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json | 200 | 2026-10-14T14:46:03 | 504 (252/252) |
| https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json | 200 | 2026-10-14T14:46:03 | 20 (12/8) |
| https://developers.google.com/static/search/apis/ipranges/{googlebot,special-crawlers,user-triggered-fetchers,user-triggered-fetchers-google}.json | 301 → new paths above | – | – |
| https://www.bing.com/toolbox/bingbot.json | 200 | 2024-01-03T10:00:00 | 28 (28/0) |
| https://search.developer.apple.com/applebot.json (doc links http://, 301) | 200 | 2026-09-15T10:00:00 | 24 (24/0) |
| https://index.commoncrawl.org/ccbot.json | 200 | 2026-08-11T13:40:00Z | 5 (4/1) |
| https://developer.amazon.com/amazonbot/ip-addresses/ (HTML) | 200 | 2026-09-08T05:24:10 | 1292 (bare IPv4) |
| https://developer.amazon.com/amazonbot/searchbot-ip-addresses/ (HTML) | 200 | 2026-09-08T05:24:10 | 816 (`ip_prefix`, /32) |
| https://developer.amazon.com/amazonbot/live-ip-addresses/ (HTML) | 200 | 2025-11-04T15:57:38 | 1023 (bare IPv4) |
| https://duckduckgo.com/duckassistbot.json | 200 | 2026-09-01T12:44:58 | 486 (486/0) |
| https://mistral.ai/mistralai-user-ips.json | 200 | 2025-02-19T12:00:00 | 4 (4/0) |
| https://mistral.ai/mistralai-index-ips.json | 200 | 2026-04-19T12:00:00 | 2 (2/0) |

Web Bot Auth key directories, all 200 with `application/http-message-signatures-directory+json` where shown:

- `https://chatgpt.com/.well-known/http-message-signatures-directory`
- `https://agent.bot.goog/.well-known/http-message-signatures-directory`
- `https://you.com/.well-known/http-message-signatures-directory`

## Sources (all fetched 2026-10-14)

### Part A: operator documentation

| Operator | URL | Notes |
|---|---|---|
| OpenAI | https://developers.openai.com/api/docs/bots (and `.md` variant) | `platform.openai.com/docs/bots` 301s here |
| OpenAI | https://help.openai.com/en/articles/11845367-chatgpt-works-cloud-browser-allowlisting | Old slug `-chatgpt-agent-allowlisting` redirects; read in browser pane and via r.jina.ai |
| OpenAI | https://chatgpt.com/.well-known/http-message-signatures-directory | |
| Anthropic | https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler | Page dated April 7, 2026 |
| Anthropic | https://claude.com/crawling/bots.json | |
| Perplexity | https://docs.perplexity.ai/docs/resources/perplexity-crawlers | `docs.perplexity.ai/guides/bots` redirects here |
| Google | https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers | Last updated 2026-07-14 |
| Google | https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers | Last updated 2026-08-19 |
| Google | https://developers.google.com/crawling/docs/crawlers-fetchers/google-special-case-crawlers | |
| Google | https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests | Last updated 2026-03-20 |
| Google | https://developers.google.com/crawling/docs/crawlers-fetchers/web-bot-auth | Last updated 2026-10-13 |
| Google | https://agent.bot.goog/.well-known/http-message-signatures-directory | |
| Microsoft | https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0 | Browser pane |
| Microsoft | https://www.bing.com/webmasters/help/verify-bingbot-2195837f | Browser pane |
| Microsoft | https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26 | Redirected from `verifying-that-bingbot-is-bingbot-3905dc26`; browser pane |
| Apple | https://support.apple.com/en-us/119829 | Published Date September 04, 2026; via r.jina.ai |
| Meta | https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers | Updated May 21, 2026; `/docs/...` redirects here |
| Common Crawl | https://commoncrawl.org/ccbot | |
| Common Crawl | https://commoncrawl.org/faq | |
| Amazon | https://developer.amazon.com/amazonbot | |
| Amazon | https://developer.amazon.com/amazonbot/ip-addresses/ | |
| Amazon | https://developer.amazon.com/amazonbot/searchbot-ip-addresses/ | |
| Amazon | https://developer.amazon.com/amazonbot/live-ip-addresses/ | |
| DuckDuckGo | https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot | |
| DuckDuckGo | https://duckduckgo.com/duckduckgo-help-pages/results/duckduckbot | |
| DuckDuckGo | https://duckduckgo.com/duckassistbot.json | |
| DuckDuckGo | https://duckduckgo.com/duckduckbot.json | |
| Mistral | https://docs.mistral.ai/robots | |
| You.com | https://docs.you.com/youbot (`.md` variant) | |
| You.com | https://you.com/.well-known/http-message-signatures-directory | |
| Diffbot | https://www.diffbot.com/docs/crawl/faq/robots-txt | |
| Ai2 | https://allenai.org/crawler | Browser pane |
| Cohere | https://docs.cohere.com/docs/cohere-web-crawlers | Official "no bots" page; skipped |

### Part A: checked, nothing official found (skipped)

- **ByteDance** (Bytespider, TikTokSpider): searched bytedance.com; no official page.
- **xAI** (GrokBot etc.): searched x.ai and docs.x.ai; no crawler documentation.
- **Huawei PetalBot**:
  - `https://webmaster.petalsearch.com/site/petalbot` renders blank (JS app).
  - `https://aspiegel.com/petalbot` returns 404.
- **Amazon NovaAct**: `https://docs.aws.amazon.com/ai/responsible-ai/nova-act/overview.md` has no UA or robots text.

### Part B: referral attribution

| Source | URL | Evidence quality / notes |
|---|---|---|
| OpenAI FAQ (live) | https://help.openai.com/en/articles/12627856-publishers-and-developers-faq | Now redirects to `/en/articles/20001371-chatgpt-atlas-retirement` |
| OpenAI FAQ (archived) | https://web.archive.org/web/20261004224023/https://help.openai.com/en/articles/12627856-publishers-and-developers-faq | **Official**; archived copy of OpenAI's text |
| OpenAI Help Center | https://help.openai.com/en/articles/9237897-chatgpt-search | Official; no UTM statement found |
| Google Analytics | https://support.google.com/analytics/answer/9756891?hl=en | Official Google Analytics: AI Assistant channel; no host list |
| Matomo list | https://github.com/matomo-org/searchengine-and-social-list/blob/master/AIAssistants.yml | Reputable-observed. Raw: https://raw.githubusercontent.com/matomo-org/searchengine-and-social-list/master/AIAssistants.yml. Last commit 2026-07-15 |
| Search Engine Journal (2024 launch article) | https://www.searchenginejournal.com/searchgpt-launches-as-chatgpts-real-time-search-feature/531461/ | Reputable-observed corroboration for `utm_source=chatgpt.com` |
| Statcounter | https://gs.statcounter.com/ai-chatbot-market-share | Checked; does not publish referrer hostnames |

### Part C: robots.txt

- https://www.rfc-editor.org/rfc/rfc9309 (`.txt` variant parsed)
- https://www.rfc-editor.org/errata/rfc9309, which redirects to https://errata.rfc-editor.org/search/?rfc_number=9309&presentation=records. There are 4 errata, all "Reported".

## Uncertain / not verified

- **The OpenAI UTM statement is no longer live.** It is OpenAI's official text, but only on an archived copy.
- **Referrer hostnames for every assistant are vendor-curated (Matomo), not operator-documented.** Mobile apps often send no Referer.
- **Whether Mistral's rename to "Vibe" changed the `chat.mistral.ai` referrer host** is not verified.
- **Purpose classifications that needed judgement:**
  - CCBot → `other`: the operator does not say "training".
  - Google-CloudVertexBot → `other`.
  - Meta-ExternalFetcher → `user`: the doc also mentions agentic use.
  - Applebot → `search`: its data may also train models unless Applebot-Extended is disallowed.
  - Amazonbot → `training`: mixed purpose.
- **Gemini Notebook IP mapping:** Google documents only category-level files, not a per-fetcher mapping.
- **Bing.** The doc does not mention AI or Copilot. Its `bingbot.json` has not changed since 2024-01-03.
- **Meta's documented UA strings show a relative `(+/documentation/...)` path.** This is probably a rendering artifact; match the token only.
- **rDNS spot checks are observations, not documentation:** Google-Agent IP → `google-proxy-*.google.com`, YouBot → `*.search.you.com`.
