# Contributing

Thanks for helping keep the AI bot catalog honest. Issues and pull requests are welcome.

## Catalog changes

`catalog.json` must only contain facts the operator documents itself.

- Every agent needs a `docs` URL on the operator's own site. Third-party bot lists are fine for
  discovering a bot, never as the source.
- Use the exact User-Agent token and robots.txt token from that page.
- Only add `ip_ranges`, `reverse_dns`, `cidrs` or `web_bot_auth` if the operator documents them.
  A list that also covers the operator's cloud customers goes in `shared_ip_ranges`.
- Explain judgement calls (such as the purpose label) in the pull request description.

## Refreshing the IP snapshot

```bash
go run ./cmd/aibouncer snapshot -o snapshot.json
go test ./...
```

The command refuses to write a snapshot if any list fails to download or parse. Review the prefix
counts it prints: a sudden drop to a handful of prefixes usually means an operator changed its format.

## Development

```bash
go vet ./...
go test -race ./...
go test -run=^$ -fuzz=FuzzParseAndCheck -fuzztime=30s ./robotstxt/
go test -run=^$ -fuzz=FuzzVerifyDoesNotPanic -fuzztime=30s ./webbotauth/
```

The module has no dependencies outside the standard library; please keep it that way.
