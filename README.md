SOC IntelHub — IOC Triage Dashboard

SOC IntelHub is a Streamlit-based IOC triage assistant for SOC analysts and blue-teamers.

Given a single IOC (IP address, domain, or file hash), it:

Enriches using VirusTotal, AbuseIPDB, and AlienVault OTX

Calculates a combined threat score (0–100)

Infers likely MITRE ATT&CK techniques

Provides SOC next steps with MITRE links

Allows report export (TXT)

⚠️ This is a personal learning / interview project, not a commercial product.
All APIs are used via public/free-tier non-commercial terms.

🌐 Live Demo

👉 https://soc-intel.streamlit.app/

(Replace with your actual Streamlit Cloud URL)

🔍 Key Features
1️⃣ Multi-source IOC Enrichment
VirusTotal

Malicious / suspicious engine counts

Reputation score

Tags & community votes

Engine detections

WHOIS summary

ASN, network, hosting info

AbuseIPDB (IP only)

Abuse confidence score

Total reports (90 days)

Country, ISP, usage type

Top abuse categories

Last reported timestamp

AlienVault OTX

Pulse count

Tags (malware families, threat types, campaigns)

Top 5 pulses by recency + severity

Associated hashes with VT links

Author & creation/update timestamps

🎯 Unified Threat Score (0–100)
Score	Meaning
0–30	Likely Clean
31–69	Suspicious
70–100	Malicious
🧠 Scoring Model
VirusTotal Score (vt_s, 0–100)

Start from malicious engine count
3 × malicious_engines

Add +10 if VT reputation < 0

Add +10 per matched threat keyword in tags/comments
(phish, ransom, c2, botnet, malware, keylogger, etc.)

Cap final VT score at 100

Represents: engine hits + reputation + contextual threat signals.

AbuseIPDB Score (ab_s, 0–100)

Directly uses abuseConfidenceScore.

Other fields used only as context, not scoring:

Categories

Report count

ISP, Country

Usage type

Hostnames

Combined Threat Score
For IP addresses

Weights:

VT → 40%

AbuseIPDB → 60%

Override rule:
If VT < 20 AND Abuse > 85 AND high reports → slight uplift.

For domains & file hashes

Only VirusTotal contributes to scoring

OTX used as context only

🎯 MITRE ATT&CK Mapping (Rule-Based)

Techniques are inferred using signals from:

VT tags

Abuse categories

OTX tags

Examples:

brute-force → T1110 — Brute Force

phish → T1566 — Phishing

c2 → T1071 — Command & Control

ransom → T1486 — Ransomware

Each technique includes:

Technique ID & Name

Tactic

Confidence score

“Why this matters” explanation

SOC next steps

Direct MITRE link

Only top 3 techniques shown for clarity.

📝 Report Export

Exports a clean .txt triage report containing:

IOC details

Final threat score & verdict

VT / AbuseIPDB / OTX highlights

MITRE mapping + SOC actions

Useful for:

Ticketing

Escalation

Shift handover

🛠️ Tech Stack

Python 3

Streamlit

Requests

dotenv

VirusTotal API

AbuseIPDB API

AlienVault OTX API

🚀 Running Locally
1️⃣ Install dependencies
pip install -r requirements.txt

2️⃣ Add your API keys

Create .env:

VT_API_KEY=your_key
ABUSE_API_KEY=your_key
OTX_API_KEY=your_key

3️⃣ Run the app
streamlit run Final.py

📌 Project Purpose

SOC IntelHub was built as a practical threat-intel learning project to demonstrate:

How to enrich IOC data using multiple public APIs

How to calculate multi-source threat scoring

How to map intel to MITRE ATT&CK

How to design SOC-friendly UI/UX

How to produce analyst-ready triage reports

This project showcases end-to-end SOC analysis workflow from
raw IOC → enrichment → scoring → MITRE mapping → report.