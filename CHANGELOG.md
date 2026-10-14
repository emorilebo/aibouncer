# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-14

### Added
- Catalog of 34 AI crawlers and agents from 14 operators, each linked to the operator's documentation,
  classified by purpose (training, search, user, agent, other).
- `Verifier`: verification against 20 official IP range lists (embedded snapshot plus live refresh),
  documented CIDRs and forward-confirmed reverse DNS, with `verified` / `spoofed` / `unverifiable` verdicts
  that fail open on stale data, DNS errors and ranges shared with cloud customers.
- `Bouncer` middleware with `Policy` (per purpose and per agent), impostor blocking by default,
  `TrustedProxies` client-IP extraction, `OnVisit` hook, and AI-assistant referral detection.
- `Policy.RobotsTxt` to render the same policy as robots.txt rules, including robots.txt-only tokens.
- `robotstxt` package: RFC 9309 parser and matcher.
- `webbotauth` package: Web Bot Auth (RFC 9421) verification and signing, key directories, tested
  against RFC 9421 appendix B.2.6 and draft-meunier-web-bot-auth-architecture-05 appendix A.2.
- `aibouncer` CLI: `logs`, `robots`, `verify`, `agents`, `robots-gen`, `snapshot`.

[0.1.0]: https://github.com/emorilebo/aibouncer/releases/tag/v0.1.0
