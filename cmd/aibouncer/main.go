// Command aibouncer inspects AI crawler traffic: it verifies whether a request really came from
// the AI agent it names, audits a site's robots.txt for AI crawlers, summarises AI bot and AI
// referral traffic in access logs, and generates robots.txt rules.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/emorilebo/aibouncer"
)

const (
	exitOK           = 0
	exitFinding      = 1
	exitUsage        = 2
	exitInconclusive = 3
)

const usage = `aibouncer - check AI crawlers' IDs at the door

Usage:
  aibouncer agents     [-json]                          list known AI crawlers and how to verify them
  aibouncer verify     [-offline] [-max-age D] (-ua UA | -agent ID) IP
                                                        check whether IP really belongs to the agent
  aibouncer robots     [-path /] URL|FILE               show which AI crawlers a robots.txt allows
  aibouncer logs       [-offline] [-max-age D] [-json] FILE...
                                                        summarise AI bots and AI referrals in access logs
  aibouncer robots-gen [-block PURPOSES] [-block-agent IDS] [-allow-agent IDS]
                                                        print robots.txt rules for a policy
  aibouncer snapshot   [-o FILE]                        download all published IP lists (maintainers)
  aibouncer version

Exit codes: 0 ok/verified, 1 finding (spoofed agent, blocked crawler), 2 usage error,
3 inconclusive (unverifiable agent, network failure).

Docs: https://github.com/emorilebo/aibouncer
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	command, rest := args[0], args[1:]
	switch command {
	case "agents":
		return cmdAgents(rest, stdout, stderr)
	case "verify":
		return cmdVerify(ctx, rest, stdout, stderr)
	case "robots":
		return cmdRobots(ctx, rest, stdout, stderr)
	case "logs":
		return cmdLogs(ctx, rest, stdout, stderr)
	case "robots-gen":
		return cmdRobotsGen(rest, stdout, stderr)
	case "snapshot":
		return cmdSnapshot(ctx, rest, stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintf(stdout, "aibouncer %s (catalog researched %s, %d agents)\n",
			aibouncer.Version, aibouncer.DefaultCatalog().Generated, len(aibouncer.DefaultCatalog().Agents))
		return exitOK
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "aibouncer: unknown command %q\n\n%s", command, usage)
		return exitUsage
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseFlags parses flags and reports whether the command should continue, plus the exit code
// to use if it should not.
func parseFlags(fs *flag.FlagSet, args []string) (bool, int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, exitOK
		}
		return false, exitUsage
	}
	return true, exitOK
}

func cmdAgents(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("agents", stderr)
	asJSON := fs.Bool("json", false, "print the catalog as JSON")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	catalog := aibouncer.DefaultCatalog()
	if *asJSON {
		return writeJSON(stdout, catalog.Agents)
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tOPERATOR\tPURPOSE\tROBOTS.TXT\tVERIFIED BY")
	for _, a := range catalog.Agents {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Name, a.Operator, a.Purpose, a.RobotsTxt, verificationMethods(&a))
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d agents, researched %s. Sources: `aibouncer agents -json` (docs field).\n", len(catalog.Agents), catalog.Generated)
	return exitOK
}

func verificationMethods(a *aibouncer.Agent) string {
	var methods []string
	if len(a.IPRanges) > 0 {
		methods = append(methods, "ip-ranges")
	}
	if len(a.SharedIPRanges) > 0 {
		methods = append(methods, "shared-ip-ranges")
	}
	if len(a.CIDRs) > 0 {
		methods = append(methods, "documented-cidr")
	}
	if len(a.ReverseDNS) > 0 {
		methods = append(methods, "reverse-dns")
	}
	if a.WebBotAuth != nil {
		methods = append(methods, "web-bot-auth")
	}
	if a.RobotsOnly {
		return "robots.txt token only"
	}
	if len(methods) == 0 {
		return "user-agent only (unverifiable)"
	}
	return strings.Join(methods, ", ")
}

// newVerifier returns a verifier with live IP lists, or the embedded snapshot when offline.
func newVerifier(ctx context.Context, offline bool, maxAge time.Duration, stderr io.Writer) *aibouncer.Verifier {
	opts := []aibouncer.VerifierOption{aibouncer.WithReverseDNS(!offline)}
	if maxAge > 0 {
		opts = append(opts, aibouncer.WithMaxAge(maxAge))
	}
	verifier := aibouncer.NewVerifier(opts...)
	if offline {
		return verifier
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := verifier.Refresh(refreshCtx); err != nil {
		fmt.Fprintf(stderr, "warning: some IP lists could not be refreshed; using embedded data for those:\n  %s\n",
			strings.ReplaceAll(err.Error(), "\n", "\n  "))
	}
	return verifier
}
