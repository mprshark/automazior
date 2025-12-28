# Automazior ASM v1.3  
**Attack Surface Monitoring Engine**

**Developed by [Pranshu Pathak](https://github.com/mprshark)**

Automazior ASM v1.3 is a **backend-focused Attack Surface Monitoring (ASM) engine** designed to identify, structure, and interpret the external attack surface of a domain using **safe, controlled reconnaissance techniques**.

This project prioritizes **clarity, scope discipline, and explainable risk assessment** over aggressive scanning or exploitation.

---

## 🔍 What This Project Is

Automazior ASM v1.3 answers one core question:

> **"What is externally exposed for a given domain, and how risky is that exposure?"**

It is **not** a vulnerability scanner or a penetration testing tool.  
It is an **attack surface visibility and risk interpretation system**.

---

## 🎯 Core Capabilities

Given a domain, ASM v1.3 performs the following:

### 1. TCP Connect Port Scanning
- Checks if common web ports (80, 443) are reachable
- Uses lightweight socket-based TCP connect scans
- Provides fast confirmation of public exposure

### 2. SSL / TLS Posture (Enhanced)
- Detects whether SSL is enabled
- Validates certificate status with **retries**
- Calculates certificate expiry (`days_left`)
- Tracks **confidence levels** (high, medium, low)
- Uses **relaxed vs strict logic** for validation
- Includes **trust context notes** explaining validation decisions
- Identifies time-based crypto risk

### 3. HTTPS Security Headers Scanner
- Scans for critical security headers
- Evaluates header presence and configuration
- Identifies missing hardening controls
- Passive inspection only

### 4. Technology & Header Fingerprinting (Enhanced)
- Identifies web server and version (when exposed)
- Detects CDN presence or absence
- Distinguishes between **observed vs inferred** data
- Includes **uncertainty notes** for ambiguous detections
- Lists exposed HTTP headers

### 5. Subdomain Discovery (Passive)
- Queries Certificate Transparency (CT) logs
- No brute forcing
- No DNS flooding
- Tracks **discard accounting** (filtered/invalid subdomains)
- Identifies known, publicly issued subdomains

### 6. Optional Nmap Service Scan
- Safe TCP connect scans when enabled
- Service and version detection
- No scripts
- No aggressive flags
- No OS fingerprinting
- Confirms **what is actually running**, not just what headers claim

### 7. Optional SYN Scan (Best-Effort)
- Faster port discovery when available
- Requires elevated privileges
- Falls back gracefully if unavailable
- Best-effort execution model

### 8. Risk Interpretation (Confidence-Aware)
- Converts raw findings into a **risk score (0–100)**
- Assigns a **risk level**: `low`, `medium`, `high`
- Produces **human-readable reasons**
- **Aware of confidence + uncertainty** from all scanners
- Deduplicates signals to avoid score inflation
- Weighs findings based on detection confidence

Risk scoring is **explainable, conservative, and uncertainty-aware** by design.

### 9. Concurrent Execution
- Independent scanners run in parallel
- Improves performance significantly
- No shared mutable state
- Stable and predictable behavior

---

## 🧠 What ASM v1.3 Intentionally Does NOT Do

ASM v1.3 is **not** a vulnerability scanner.

**If something isn't listed in Core Capabilities above, it's out of scope for v1.3.**

It does **not**:
- Inject SQLi / XSS / SSTI payloads
- Perform directory brute forcing
- Run Nmap vulnerability scripts
- Exploit services
- Perform UDP scanning
- Perform OS fingerprinting
- Attempt authentication attacks
- Conduct active vulnerability assessment

These are intentionally excluded to keep ASM v1.3:
- safe
- non-intrusive
- legally cautious
- focused on surface visibility, not exploitation

**Everything else belongs in v2.**

---

## 🏗️ Architecture Overview

```
backend/
├── main.py                     # FastAPI entry point (concurrent execution)
├── schemas.py                  # Request schemas
├── scanners/
│   ├── port_scanner.py         # TCP connect port checks (80, 443)
│   ├── ssl_scanner.py          # SSL inspection with confidence & retries
│   ├── headers_scanner.py      # HTTPS security headers analysis
│   ├── tech_scanner.py         # Tech fingerprinting (observed vs inferred)
│   ├── subdomain_scanner.py    # Passive CT-based subdomain discovery
│   ├── nmap_scanner.py         # Raw Nmap execution (optional)
│   ├── nmap_parser.py          # XML → structured parsing
│   ├── nmap_service_scanner.py # Nmap orchestration
│   ├── syn_scanner.py          # Best-effort SYN scan (optional)
│   ├── risk_scorer.py          # Confidence-aware risk scoring
│   └── __init__.py
```

### Design Principles
- One responsibility per scanner
- Structured, machine-readable output
- Confidence tracking at every layer
- Uncertainty and context preserved
- No scanner depends on another
- Orchestration handled centrally

---

## 🔄 Scan Pipeline

1. TCP connect port scanning (80, 443)
2. SSL inspection with confidence tracking
3. HTTPS security headers analysis
4. Technology fingerprinting (observed vs inferred)
5. Subdomain discovery with discard accounting
6. Optional Nmap service detection
7. Optional SYN scan (best-effort)
8. Confidence-aware risk scoring
9. Final structured JSON output

All independent steps run **concurrently** where possible.

---

## 📦 Example Output (Simplified)

```json
{
  "domain": "example.com",
  "ports": {
    "80": "open",
    "443": "open"
  },
  "ssl": {
    "enabled": true,
    "valid": true,
    "days_left": 82,
    "confidence": "high",
    "validation_mode": "strict",
    "trust_context": "Certificate chain verified successfully"
  },
  "security_headers": {
    "strict-transport-security": "present",
    "content-security-policy": "missing",
    "x-frame-options": "present",
    "x-content-type-options": "present"
  },
  "technology": {
    "server": {
      "name": "nginx",
      "version": "1.24.0",
      "detection": "observed"
    },
    "cdn": false,
    "uncertainty_notes": []
  },
  "subdomains": {
    "found": ["www.example.com", "mail.example.com"],
    "discarded": 3,
    "discard_reasons": ["invalid format", "wildcard"]
  },
  "nmap": {
    "enabled": true,
    "services": [
      {
        "port": 22,
        "service": "ssh",
        "product": "OpenSSH",
        "version": "9.6p1"
      },
      {
        "port": 80,
        "service": "http",
        "product": "nginx",
        "version": "1.24.0"
      }
    ]
  },
  "syn_scan": {
    "enabled": false,
    "reason": "Requires elevated privileges"
  },
  "risk": {
    "score": 55,
    "level": "medium",
    "confidence_weighted": true,
    "reasons": [
      "Sensitive service exposed on port 22",
      "Service version detected: nginx 1.24.0",
      "Missing CSP header reduces security posture"
    ]
  }
}
```

---

## 🚀 How to Run

### Requirements

- Python 3.9+
- Nmap installed and accessible
- Windows / Linux / macOS

### Setup

```bash
git clone https://github.com/mprshark/automazior.git
cd automazior
python -m venv venv
venv\Scripts\activate   # Windows (use source venv/bin/activate on Linux/macOS)
pip install fastapi uvicorn requests
```

Ensure `nmap` is installed and accessible on your system.

### Run the API

```bash
cd backend
uvicorn main:app --reload
```

Open in browser:

```
http://127.0.0.1:8000/docs
```

Use the Swagger UI to submit scan requests.

### Example Request

```json
{
  "domain": "example.com"
}
```

---

## 🎛️ Interface Philosophy

ASM v1 is **API-first**.

- Swagger UI (`/docs`) is the intended interface
- No frontend is included by design
- This keeps focus on engine correctness and clarity

A frontend, if added, belongs in a future version.

---

## ⚖️ Risk Scoring Philosophy

- Exposure ≠ exploitation
- Scores are explainable
- **Confidence and uncertainty tracked at every layer**
- **Uncertain findings weighted appropriately**
- Signals are deduplicated
- Conservative by default
- Designed to inform, not alarm

ASM v1.3 answers:

> "What is exposed, how risky is that exposure, and **how confident are we in this assessment**?"

Not:

> "How do I break in?"

---

## 🛣️ Future Directions (Out of Scope for v1)

Potential future expansions:

- HTTP security header scoring
- DNS & WHOIS intelligence
- Scheduled monitoring
- Historical comparisons
- Configurable scan depth
- Optional vulnerability scanning (separate mode)

---

## 👥 Contributors

**Lead Developer:** [Pranshu Pathak](https://github.com/mprshark)

Contributions are welcome! If you'd like to contribute to Automazior ASM:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your contributions align with the project's scope philosophy: **if it's not in v1.3 Core Capabilities, it belongs in v2**.

---

## ⚠️ Legal & Ethical Notice

This project is intended for:

- self-owned assets
- authorized testing
- educational and research purposes

Always ensure you have permission before scanning any domain.

---

## 📌 Status

Automazior ASM v1.3 is **feature-complete, stable, and intentionally scoped**.

**No more, no less. If something isn't in Core Capabilities, it's v2.**
