// Package aibouncer identifies, verifies and governs AI crawlers and AI agents in Go web
// servers, and measures the human traffic AI assistants send you.
//
// Anyone can put "GPTBot" in a User-Agent header. aibouncer checks the claim the way the
// operators themselves document it: against their published IP range lists, with
// forward-confirmed reverse DNS, or with Web Bot Auth signatures (RFC 9421 HTTP Message
// Signatures). Every request gets a [Verdict]: [Verified], [Spoofed], [Unverifiable] (the
// operator publishes no way to check, or the data is stale), or [NotAI].
//
// A [Policy] then decides per purpose (training, search, user-initiated fetches, agents) or per
// agent whether to allow or block, and can render the same policy as robots.txt rules,
// including control tokens such as Google-Extended that only exist in robots.txt.
//
// Quick start:
//
//	bouncer := aibouncer.New(aibouncer.WithPolicy(aibouncer.Policy{
//		Purposes: map[aibouncer.Purpose]aibouncer.Action{aibouncer.PurposeTraining: aibouncer.Block},
//	}))
//	go bouncer.Verifier().Run(ctx, 12*time.Hour, nil) // keep IP lists fresh
//	http.ListenAndServe(":8080", bouncer.Middleware(mux))
//
// The catalog of agents is embedded and every entry links to the operator documentation it was
// taken from ([Agent.Docs]). IP range lists ship as a snapshot so verification works from the
// first request; [Verifier.Run] keeps them current.
//
// Subpackages:
//   - [github.com/emorilebo/aibouncer/robotstxt]: an RFC 9309 robots.txt parser and matcher.
//   - [github.com/emorilebo/aibouncer/webbotauth]: Web Bot Auth signature verification and signing.
package aibouncer
