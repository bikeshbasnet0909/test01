# Internal Phishing Analysis Tool (MVP)

A read-only investigation assistant for authorized security analysts. Supports manual .eml upload and pasted RFC 5322 email content. The first milestone performs local, deterministic parsing and produces evidence-backed indicators. It does not visit URLs, execute attachments, send email content to an AI service, or take response actions.

## Current scope

- Parse raw email headers and MIME structure.
- Extract sender, reply-to, subject, authentication-result headers, URLs, and attachment metadata.
- Calculate a transparent heuristic score with explainable findings.
- Return the SHA-256 hash of the submitted message for evidence identification.
- Keep the first milestone stateless: message content is not persisted.
- Include unit tests for core indicators.

## Not production-ready

This repository is a development scaffold, not an approved banking production system. Before internal deployment, implement and validate the Bank's SSO/MFA integration, RBAC, CSRF protections if cookie-based auth is used, rate limiting, centralized audit logging, encrypted case/evidence storage, retention/deletion controls, dependency and container scanning, secrets management, TLS, security testing, and operational monitoring. Do not submit real customer or bank emails to a public repository or an unapproved AI provider.

## Run locally

Requires Python 3.11+.

    python -m venv .venv
    # Windows: .venv\Scripts\activate
    source .venv/bin/activate
    pip install -r requirements.txt
    uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

Open the interactive API docs at http://127.0.0.1:8000/docs for local development only. Do not expose this development server to a network.

## Test

    pytest -q

## API

- GET /health — liveness only; no sensitive data.
- POST /api/v1/analyze/eml — upload one .eml file as multipart form data.
- POST /api/v1/analyze/paste — submit raw email text in JSON as raw_email.

Both analysis endpoints are currently unauthenticated development endpoints. Bind only to loopback while developing. Do not deploy until authentication and authorization are implemented and independently reviewed.

## Analysis limitations

- Authentication results are read from supplied Authentication-Results / Received-SPF headers and are not cryptographically verified by this application. Pasted headers can be forged.
- The heuristic score is triage guidance, not a definitive verdict or a calibrated probability.
- URL reputation, sandboxing, SPF/DKIM/DMARC validation, threat-intelligence lookups, case persistence, AI explanations, and mail/SOC integrations are intentionally not implemented yet.
- URLs are extracted as text only. The application does not fetch them.
