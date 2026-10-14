# Security policy

aibouncer makes security decisions (who gets blocked, who counts as verified), so verification
bypasses are treated as vulnerabilities. Examples: a request that gets a `verified` verdict without
coming from the operator, a way to make the verifier fetch attacker-chosen URLs, or input that
crashes or stalls the middleware.

## Reporting

Please report privately to **emorylebo@gmail.com** with "aibouncer security" in the subject, or via
GitHub's "Report a vulnerability" button on the repository's Security tab if it is enabled. Include
a minimal reproduction if you can. You'll get an acknowledgement within a few days, and credit in the
release notes unless you prefer otherwise.

Outdated catalog data (a new bot, a moved IP list) is not a vulnerability: please open a regular issue
with a link to the operator's documentation.

## Supported versions

Fixes go into the latest release.
