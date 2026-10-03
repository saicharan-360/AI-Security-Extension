# AI Security Shield & Threat Intelligence

An enterprise-grade, privacy-first browser security extension and threat telemetry backend designed to detect and neutralize phishing, brand impersonation, credential harvesting, and malicious web infrastructure.

---

## 1. System Architecture

```
                                  [ Browser Navigation ]
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │ Chrome Extension (Manifest V3)│
                             │  - URL Privacy Sanitization   │
                             │  - Local Feature Extraction   │
                             │  - Weighted Heuristic Model   │
                             └───────────────┬───────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │                                           │
                       ▼                                           ▼
         ┌───────────────────────────┐               ┌───────────────────────────┐
         │ Security Telemetry API    │               │ Local Network Defender    │
         │  - Rate Limiting & Helmet │               │  - OS Kernel Firewall     │
         │  - Supabase Threat DB     │               │  - DNS Resolution         │
         │  - Server-side Gemini AI  │               │  - Outbound Packet Drop   │
         │    (Structured JSON Only) │               │    (Port 8080)            │
         └─────────────┬─────────────┘               └───────────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────┐
        │ Isolated Warning Page       │
        │ (warning.html Interstitial) │
        └─────────────────────────────┘
```

---

## 2. Key Components

1. **`AI-Security-Extension/`**: Chrome Manifest V3 extension featuring modular background service worker (`background.js`), URL parsing utilities (`utils/domain.js`), weighted heuristic risk model (`detection/local_model.js`), centralized multi-signal decision arbiter (`detection/decision_engine.js`), isolated warning interstitial (`warning.html`), and extension popup dashboard (`popup.html`).
2. **`security-backend/`**: Node.js & Express REST API with Helmet security headers, rate limiters, Zod input validation, Supabase persistence (with memory fallback), and secure server-side Google Gemini integration.
3. **`local-network-defender/`**: Local Python service running on port `8080` capable of injecting OS-level kernel firewall rules (`netsh` on Windows, `iptables` on Linux) to block all network communication with malicious IP addresses.

---

## 3. Getting Started

### Prerequisites
- Node.js (v18 or newer recommended)
- Python 3.9+ (optional, for local network firewall blocker)
- Google Chrome browser

---

### Step A: Configure and Start the Backend

1. Navigate to `security-backend`:
   ```powershell
   cd .\security-backend
   ```
2. Install dependencies:
   ```powershell
   npm install
   ```
3. Configure environment variables in `.env`:
   ```ini
   PORT=5000
   NODE_ENV=development

   # Supabase Configuration
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_ANON_KEY=your-anon-or-publishable-key

   # Server-side Gemini API Key (optional - falls back safely to heuristics if omitted)
   GEMINI_API_KEY=your-gemini-key
   ```
4. (Optional) Run database migration:
   Open your Supabase SQL Editor and execute the statements in [`security-backend/schema.sql`](file:///c:/Users/Sai%20Charan/OneDrive/Documents/AI-Security-Extension/CyberBoys-Project/security-backend/schema.sql).
5. Start the backend:
   ```powershell
   npm run dev
   # or
   npm start
   ```

---

### Step B: Load the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions`.
2. Toggle **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select the `CyberBoys-Project/AI-Security-Extension` directory.
5. The extension icon will appear in your Chrome toolbar. Click it to view protection status, active metrics, and user controls.

---

### Step C: (Optional) Run the Network Blocker

To enable OS-level kernel firewall packet dropping:
```powershell
cd .\local-network-defender
pip install flask flask-cors
# Run as Administrator for Windows Firewall netsh injection:
python network_blocker.py
```
*Note: If the network blocker is offline or not run with administrative privileges, browser-level protection and warning interstitials remain 100% operational.*

---

## 4. Detection Pipeline & Heuristics

The extension uses a layered defense pipeline:

1. **Validation & Normalization:** Checks scheme and structure. Strips sensitive query tokens (`token`, `auth`, `password`, `key`) for user privacy.
2. **Local Heuristic Analysis:** Computes Shannon entropy, checks for Punycode/IDN homograph patterns (`xn--`), detects brand impersonation (e.g. `paypal-update.com`), checks for raw IP addresses, excessive subdomains, and weighted TLD indicators.
3. **Community Threat Database:** Queries indexed Supabase threat records.
4. **Conditional AI Evaluation:** If local heuristics classify a domain as ambiguous or suspicious, a server-side request is sent to Gemini returning strictly structured JSON.
5. **Decision Arbitration:** Outputs one of four explicit states:
   - `SAFE`: Verified reputation or minimal benign indicators.
   - `SUSPICIOUS`: Corroborating risk patterns requiring user caution.
   - `HIGH_RISK`: Confirmed phishing, impersonation, or threat database match.
   - `UNKNOWN`: Non-web or unparseable protocol.
6. **Mitigation:** High-risk URLs are intercepted before page script execution and redirected to `warning.html`.

---

## 5. Automated Testing

To run the backend and detection heuristic test suites:
```powershell
cd .\security-backend
npm test
```
The test suite covers:
- Domain parsing & two-part ccTLD extraction (`.co.uk`, etc.)
- API health check
- Threat lookup & threat reporting
- Shannon entropy randomness
- Brand impersonation detection vs. official domains
- Suspicious TLD & raw IP address scoring
- Punycode & IDN homograph detection
- URL privacy sanitization & credential redaction
- Rate limiting and input validation

---

## 6. Troubleshooting

- **Backend says "Using in-memory database":** Make sure `SUPABASE_URL` and `SUPABASE_ANON_KEY` are provided in `.env`. The backend continues functioning with the in-memory fallback.
- **Chrome extension shows error loading background:** Ensure your Chrome version supports Manifest V3 ES modules (Chrome 91+). Check the service worker console at `chrome://extensions` for structured logs.
- **Local Network Defender returns permission notice:** Run your terminal as Administrator on Windows so `netsh advfirewall` can insert rules.
