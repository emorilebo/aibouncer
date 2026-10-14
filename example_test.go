package aibouncer_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"time"

	"github.com/emorilebo/aibouncer"
)

// Block AI training crawlers and impostors, allow AI search and user-initiated fetches, and log
// every AI visit.
func ExampleNew() {
	bouncer := aibouncer.New(
		aibouncer.WithPolicy(aibouncer.Policy{
			Purposes: map[aibouncer.Purpose]aibouncer.Action{aibouncer.PurposeTraining: aibouncer.Block},
		}),
		aibouncer.WithOnVisit(func(r *http.Request, v aibouncer.Visit) {
			if v.Agent != nil {
				log.Printf("%s %s %s -> %s", v.Agent.Name, v.Verdict, r.URL.Path, v.Action)
			}
		}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bouncer.Verifier().Run(ctx, 12*time.Hour, func(err error) { log.Print(err) })

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello, humans and well-behaved robots")
	})
	_ = http.ListenAndServe // http.ListenAndServe(":8080", bouncer.Middleware(mux))
}

// Behind a load balancer, trust X-Forwarded-For only from your own proxies.
func ExampleTrustedProxies() {
	bouncer := aibouncer.New(aibouncer.WithClientIP(
		aibouncer.TrustedProxies(netip.MustParsePrefix("10.0.0.0/8")),
	))
	_ = bouncer
}

func ExampleCatalog_Identify() {
	agent, ok := aibouncer.DefaultCatalog().Identify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot")
	fmt.Println(ok, agent.Name, agent.Operator, agent.Purpose)
	// Output: true GPTBot OpenAI training
}

func ExampleVerifier_VerifyIP() {
	// The embedded snapshot works offline; a long max age keeps this example deterministic.
	verifier := aibouncer.NewVerifier(aibouncer.WithReverseDNS(false), aibouncer.WithMaxAge(100*365*24*time.Hour))
	gptbot, _ := aibouncer.DefaultCatalog().Agent("openai-gptbot")

	fmt.Println(verifier.VerifyIP(context.Background(), gptbot, netip.MustParseAddr("132.196.86.5")).Verdict)
	fmt.Println(verifier.VerifyIP(context.Background(), gptbot, netip.MustParseAddr("203.0.113.9")).Verdict)
	// Output:
	// verified
	// spoofed
}

func ExampleVisitFromContext() {
	bouncer := aibouncer.New()
	handler := bouncer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if visit, ok := aibouncer.VisitFromContext(r.Context()); ok && visit.Referral != nil {
			fmt.Println("human visitor sent by", visit.Referral.Assistant)
		}
	}))

	r := httptest.NewRequest("GET", "/pricing?utm_source=chatgpt.com", nil)
	handler.ServeHTTP(httptest.NewRecorder(), r)
	// Output: human visitor sent by ChatGPT
}

func ExampleCatalog_DetectReferer() {
	referral, ok := aibouncer.DefaultCatalog().DetectReferer("https://www.perplexity.ai/search/best-go-middleware")
	fmt.Println(ok, referral.Assistant)
	// Output: true Perplexity
}
