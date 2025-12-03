# SOC IntelHub — IOC Triage Dashboard

SOC IntelHub is a Streamlit-based **IOC triage assistant** for SOC analysts and blue-teamers.

Given a single IOC (IP address, domain, or file hash), it:

- Enriches the IOC with **VirusTotal**, **AbuseIPDB**, and **AlienVault OTX**
- Calculates a **combined threat score (0–100)**
- Automatically infers likely **MITRE ATT&CK techniques**
- Provides **SOC next steps** + direct links to official MITRE pages
- Lets you **export a human-readable report** for documentation or handoff

> ⚠️ This is a **personal learning / interview project**, not a commercial product.  
> All APIs are used under public/free-tier non-commercial terms.

---

## 🔍 Key Features

### 1. Multi-source IOC Enrichment

#### **VirusTotal**
- Malicious / suspicious engine counts  
- Reputation score  
- Tags & community votes  
- Engine detections  
- WHOIS summary  
- ASN, network, hosting info  

#### **AbuseIPDB** (IP only)
- Abuse confidence score  
- Total reports (90 days)  
- Country, ISP, usage type  
- Top abuse categories  
- Last reported time  

#### **AlienVault OTX**
- Pulse count  
- Tags (malware families, threat types, campaigns)  
- Top 5 pulses by **recency + severity**  
- Associated hashes with VT links  
- Author, created/updated timestamps  

---

## 🎯 Unified Threat Score (0–100)

- **0–30** → Likely Clean  
- **31–69** → Suspicious  
- **70–100** → Malicious  

---

## 🧠 Scoring Model

### **VirusTotal Score (`vt_s`, 0–100)**

1. Start from **malicious engine count**  
   `3 × malicious_engines`
2. Add **+10** if VT reputation is **negative**
3. Add **+10 per matched threat keyword** in VT tags + comments  
   (e.g., `phish`, `ransom`, `c2`, `botnet`, `malware`, `keylogger`, etc.)
4. Cap at **100**

> Interprets: engine hits + reputation + contextual threat signals.

---

### **AbuseIPDB Score (`ab_s`, 0–100)**

Directly uses `abuseConfidenceScore`.

Context-only fields:
- Report count  
- Categories  
- ISP  
- Country  
- Usage type  
- Hostnames  

---

### **Combined Threat Score**

#### For **IP addresses**
- VT weight = **40%**  
- AbuseIPDB weight = **60%**

Small override:
> If VT is low (<20) but AbuseIPDB is extremely high (>85) with many reports → slight uplift.

#### For **domains & file hashes**
- VT weight = **100%**  
- AbuseIPDB not used  
- OTX used only as **context**, not scoring  

---

## 🎯 MITRE ATT&CK Mapping (Rule-Based)

The app infers techniques using:
- VT tags  
- Abuse categories  
- OTX tags  

Examples:

- `brute-force` → **T1110 — Brute Force**  
- `phish` → **T1566 — Phishing**  
- `c2` → **T1071 — Command & Control**  
- `ransom` → **T1486 — Ransomware**  
- `sql injection` → **T1190 — Exploit Public-Facing Application**  

Each technique shows:

- Technique ID & name  
- Tactic  
- Confidence score (40–95)  
- "Why this matters" explanation  
- SOC next steps  
- Direct MITRE ATT&CK link  

Only **top 3** techniques displayed to avoid clutter.

---

## 📝 Report Export (TXT)

Exports a clean `.txt` report with:

- IOC metadata  
- Threat score & verdict  
- Key VT / Abuse / OTX intel  
- Mapped MITRE techniques + next steps  
- Analyst-friendly formatting  

Useful for:
- Ticketing  
- Email escalation  
- Handoff documentation  

---

## 🛠️ Tech Stack

- **Python 3**
- **Streamlit**
- **Requests**
- **dotenv**
- VirusTotal API  
- AbuseIPDB API  
- AlienVault OTX API  

---

## 🚀 Running Locally

1️⃣ Install dependencies  
```bash
pip install -r requirements.txt
```

2️⃣ Add your API keys to `.env`  
```env
VT_API_KEY=your_key
ABUSE_API_KEY=your_key
OTX_API_KEY=your_key
```

3️⃣ Run the app  
```bash
streamlit run soc_intelhub.py
```

---

Actively maintained as a **portfolio project** demonstrating:

- Threat-intel enrichment  
- Multi-source scoring logic  
- Practical ATT&CK mapping  
- SOC-focused UI/UX & reporting  
