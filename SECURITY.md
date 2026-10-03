# Security Model & Policy - AI Security Shield

## Overview

AI Security Shield is a multi-layered browser defense system designed to protect users against phishing, deceptive look-alike domains, credential harvesting portals, and malicious web infrastructure.

---

## 1. Threat Model

The system defends against attacks within the browser navigation lifecycle:

| Threat Category | Attack Vector | Mitigation Architecture |
| :--- | :--- | :--- |
| **Brand Impersonation** | Typosquatting and hyphenated deceptive domains (e.g. `paypal-security-login.com`). | Registrable domain isolation and brand token cross-matching. |
| **Homograph & IDN Spoofing** | Punycode domains (`xn--...`) and visually confusable Unicode character sets. | Punycode flag detection, script disparity analysis, and weighted scoring. |
| **URL Obfuscation** | Embedded credentials (`user@host`), excessive subdomains, randomized sub-paths, abnormal ports. | Structural entropy metrics, URL sanitization, and heuristic rule scoring. |
| **Known Malicious Infrastructure** | Active phishing campaigns documented in threat feeds. | Supabase Community Threat Database indexed query before rendering. |
| **Novel / Zero-Day Social Engineering** | Newly registered domains with ambiguous structural indicators. | Server-side Gemini AI deep evaluation returning strict validated JSON. |
| **In-Page Overlay Hijacking** | Malicious sites attempting to modify or bypass in-DOM warning scripts. | Full-page isolated extension interstitial (`warning.html`) loaded via Chrome Web Accessible Resources. |

---

## 2. Privacy & Data Handling

AI Security Shield adheres to a strict data minimization policy:

- **Credential & Token Stripping:** Before any URL or telemetry is transmitted to the backend or AI models, passwords, usernames, authentication tokens (`token`, `access_token`, `jwt`), session identifiers (`phpsessid`), and URL fragments are redacted.
- **Structural Feature Transmission:** The AI analysis endpoint receives only domain structure (length, entropy, subdomains, protocol) rather than private user URL parameters.
- **Zero Secret Exposure:** The Google Gemini API key is maintained exclusively on the backend server (`GEMINI_API_KEY`) inside `.env`. No API secrets or private tokens are stored inside the browser extension package or client storage.
- **No Browsing History Profiling:** Telemetry lookups are ephemeral; URLs found to be benign (`SAFE`) are not permanently cataloged or associated with user identities.

---

## 3. Defense-in-Depth Pipeline

```
Incoming URL Navigation
       ↓
[1. URL Validation & Sanitization] (Strips tokens, auth params, fragments)
       ↓
[2. Local Feature Extraction] (Entropy, Punycode, brand impersonation, TLD, ports)
       ↓
[3. Local Weighted Heuristic Model] (Calculates baseline risk & confidence)
       ↓
[4. Community Threat Intelligence] (Indexed Supabase / in-memory lookup)
       ↓
[5. Conditional AI Assessment] (Invoked strictly when heuristics are ambiguous/suspicious)
       ↓
[6. Central Decision Arbiter] (SAFE | SUSPICIOUS | HIGH_RISK | UNKNOWN)
       ↓
[7. Isolated Mitigation Action] (Redirects to warning.html; triggers optional OS firewall)
```

---

## 4. Known Limitations

- **Heuristic Nature:** Automated detection based on heuristics and AI is probabilistic. It may occasionally flag unusual developmental sites (false positive) or fail to detect completely novel phishing sites before threat intelligence is updated (false negative).
- **Network Defender Dependency:** OS-level firewall injection (`local-network-defender`) requires administrative privileges (`netsh` on Windows / `iptables` on Linux) to apply kernel firewall rules. If run without elevated privileges or if the service is offline, browser-level protection remains active, but OS-level packet drops are skipped.
- **Intranet / IP Lookups:** Private RFC 1918 IP addresses (e.g. `192.168.x.x`, `10.x.x.x`) are not reported to community threat databases to protect internal corporate architectures.

---

## 5. Vulnerability Reporting

If you identify a security vulnerability or bypass in AI Security Shield, please report it responsibly by contacting the maintainers or filing a private security advisory. Do not publish zero-day proof-of-concept exploits publicly.
