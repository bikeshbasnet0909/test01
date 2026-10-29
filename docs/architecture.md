# Phishing Analysis MVP Architecture

## Scope and operating model

This service supports manual analyst-submitted email investigations. Input is either an original RFC 5322/MIME .eml file or pasted raw email text. The current implementation is stateless and read-only.

## Trust boundaries

1. **Analyst browser to API:** only authenticated, authorized security analysts should be permitted in an internal deployment. The current scaffold does not implement authentication and must remain bound to loopback.
2. **Untrusted email to parser:** all message content, headers, MIME metadata, URLs, filenames and embedded instructions are attacker-controlled. Enforce byte limits and never render HTML or execute attachments.
3. **Parser to analysis rules:** rules consume parsed evidence and produce findings with explicit limitations. Supplied Authentication-Results headers are observations, not proof of cryptographic validation.
4. **Analysis to analyst:** output is a triage aid. It must not trigger account changes, mail quarantine, sender blocking or other control changes.
5. **Future AI / external services:** no AI or external service is called in this milestone. Any future model integration requires Bank approval, data minimization, prompt-injection-resistant design, output validation and explicit egress controls.

## Logical flow

    Analyst
      -> authenticated UI (future)
      -> bounded intake API
      -> MIME/header parser
      -> deterministic indicators
      -> risk summary and evidence references
      -> analyst review and disposition (future)
      -> audited case storage (future)

## Current implementation

- FastAPI endpoints for .eml upload and pasted raw email.
- 2 MiB message limit.
- SHA-256 hash for the submitted bytes.
- Sender / Reply-To / Return-Path domain comparison.
- Observation of supplied authentication-result headers.
- URL extraction and local string-only indicators (IP-literal host, user-info, known shortener, HTTP).
- Attachment metadata and risky extension indicators; no attachment is opened or executed.
- Simple explainable score, explicitly not a probability.
- Unit tests for core behaviors.
- No persistence, authentication, DNS lookups, URL fetching, threat-intelligence calls, AI calls or response actions.

## Required before an internal pilot

- Integrate the Bank's approved identity provider with MFA and role-based authorization.
- Apply reverse-proxy TLS, security headers, CSRF protection if using cookies, request rate limits, upload limits at the proxy, and restrictive CORS.
- Add case and evidence persistence only after defining classification, encryption, access, retention, deletion, legal hold and audit requirements.
- Use a separate append-only audit trail; do not log full email bodies, credentials, tokens, or attachment contents.
- Ensure logs and errors do not disclose sensitive data.
- Validate and scan dependencies, container images and source code; run SAST, DAST, dependency scanning and penetration testing.
- Restrict network egress. URL inspection must use an isolated, controlled analysis service if later approved; protect against SSRF, DNS rebinding and private/internal IP access.
- Add malware scanning / sandboxing as a separate isolated capability, not inside the web API process.
- Test malformed MIME, deeply nested multipart messages, oversized headers, Unicode and IDN domains, duplicate headers, parser exceptions and decompression/resource exhaustion.
- Establish analyst runbooks, severity definitions, false-positive handling, evidence chain-of-custody, and escalation ownership.
- Obtain Information Security, Infrastructure, Privacy/Compliance and change-management approval before deployment.

## Risk scoring

The current score is a transparent sum of heuristic indicators with a 0–100 cap. It is not calibrated, does not prove maliciousness, and may double-count related indicators. Do not use it alone to automate a response or report it as a probability. Tune it against a labeled, approved corpus before any operational use.
