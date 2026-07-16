# Sentinel — Enterprise LLM Security Firewall

A dependency-free full-stack B.Tech project demo that places a policy-enforcement gateway between enterprise users and an LLM.

## Run

```powershell
npm start
```

Open `http://localhost:3000`.

## Test

```powershell
npm test
```

## Included controls

- Prompt-injection and jailbreak pattern detection
- Obfuscated payload detection
- DLP scanning and redaction for API keys, secrets, Aadhaar, PAN, payment cards, and emails
- Role-aware policy enforcement for Developer, Finance, and Contractor access boundaries
- Output validation/redaction
- Token accounting, live metrics, and in-memory immutable-style audit events
- Responsive security operations dashboard

> This project uses deterministic local rules for a reliable demonstration. In production, replace the simulated model response with an authenticated provider adapter and persist audit events in a secured database.
