# Automazior ASM v1  
**Attack Surface Monitoring Engine (Backend-First)**

Automazior ASM v1 is a **backend-focused Attack Surface Monitoring (ASM) engine** designed to identify, structure, and interpret the external attack surface of a domain using **safe, controlled reconnaissance techniques**.

This project prioritizes **clarity, scope discipline, and explainable risk assessment** over aggressive scanning or exploitation.

---

## 🔍 What This Project Is

Automazior ASM v1 answers one core question:

> **"What is externally exposed for a given domain, and how risky is that exposure?"**

It is **not** a vulnerability scanner or a penetration testing tool.  
It is an **attack surface visibility and risk interpretation system**.

---

## 🎯 Core Capabilities

Given a domain, ASM v1 performs the following:

### 1. Network Exposure (Fast Reachability)
- Checks if common web ports (80, 443) are reachable
- Uses lightweight socket-based checks
- Provides fast confirmation of public exposure

### 2. SSL / TLS Posture
- Detects whether SSL is enabled
- Validates certificate status
- Calculates certificate expiry (`days_left`)
- Identifies time-based crypto risk

### 3. Technology & Header Fingerprinting
- Identifies web server and version (when exposed)
- Detects CDN presence or absence
- Lists exposed HTTP headers
- Uses passive inspection only

### 4. Subdomain Discovery (Passive)
- Queries Certificate Transparency (CT) logs
- No brute forcing
- No DNS flooding
- Identifies known, publicly issued subdomains

### 5. Active Service Detection (Nmap)
- Safe TCP connect scans
- Service and version detection
- No scripts
- No aggressive flags
- No OS fingerprinting

This step confirms **what is actually running**, not just what headers claim.

### 6. Risk Interpretation
- Converts raw findings into a **risk score (0–100)**
- Assigns a **risk level**: `low`, `medium`, `high`
- Produces **human-readable reasons**
- Deduplicates signals to avoid score inflation

Risk scoring is **explainable and conservative** by design.

### 7. Concurrent Execution
- Independent scanners run in parallel
- Improves performance significantly
- No shared mutable state
- Stable and predictable behavior

---

## 🧠 What ASM v1 Intentionally Does NOT Do

ASM v1 is **not** a vulnerability scanner.

It does **not**:
- Inject SQLi / XSS / SSTI payloads
- Perform directory brute forcing
- Run Nmap vulnerability scripts
- Exploit services
- Perform UDP scanning
- Perform OS fingerprinting
- Attempt authentication attacks

These are intentionally excluded to keep ASM v1:
- safe
- non-intrusive
- legally cautious
- focused on surface visibility, not exploitation

---

## 🏗️ Architecture Overview

```
backend/
├── main.py                     # FastAPI entry point (concurrent execution)
├── schemas.py                  # Request schemas
├── scanners/
│   ├── port_scanner.py         # Fast socket-based port checks
│   ├── ssl_scanner.py          # SSL inspection
│   ├── tech_scanner.py         # Header & tech fingerprinting
│   ├── subdomain_scanner.py    # Passive CT-based subdomain discovery
│   ├── nmap_scanner.py         # Raw Nmap execution
│   ├── nmap_parser.py          # XML → structured parsing
│   ├── nmap_service_scanner.py # Nmap orchestration
│   ├── risk_scorer.py          # Deduplicated risk scoring logic
│   └── __init__.py
```

### Design Principles
- One responsibility per scanner
- Structured, machine-readable output
- No scanner depends on another
- Orchestration handled centrally

---

## 🔄 Scan Pipeline

1. Fast port reachability checks  
2. SSL inspection  
3. Technology fingerprinting  
4. Subdomain discovery  
5. Active service detection (Nmap)  
6. Risk scoring  
7. Final structured JSON output  

All independent steps run **concurrently**.

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
    "days_left": 82
  },
  "technology": {
    "server": "nginx/1.24.0",
    "cdn": false
  },
  "subdomains": [],
  "nmap": {
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
  "risk": {
    "score": 55,
    "level": "medium",
    "reasons": [
      "Sensitive service exposed on port 22",
      "Service version detected: nginx 1.24.0"
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
- Signals are deduplicated
- Conservative by default
- Designed to inform, not alarm

ASM v1 answers:

> "What is exposed, and how risky is that exposure?"

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

## ⚠️ Legal & Ethical Notice

This project is intended for:

- self-owned assets
- authorized testing
- educational and research purposes

Always ensure you have permission before scanning any domain.

---

## 📌 Status

Automazior ASM v1 is **feature-complete, stable, and intentionally scoped**.