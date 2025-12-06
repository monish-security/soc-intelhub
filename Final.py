# soc_intelhub_mitre_v2.py — VT + Abuse scoring, OTX context, MITRE mapping, text report export
import os
import re
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
import streamlit as st

# -------------------------
# Config + load keys
# -------------------------
st.set_page_config(page_title="SOC IntelHub — IOC Triage Dashboard", layout="wide")
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

# -------------------------
# CSS — layout + theme
# -------------------------
st.markdown(r"""
<style>
:root{
  --bg-top:#07080b; --bg-bottom:#121417;
  --panel:#0f1216; --accent:#2aa9ff; --danger:#ff5c5c; --muted:#9aa3b2;
}

/* Center main content and control width */
.main .block-container {
  max-width: 1200px;
  padding-top: 2.5rem;
  padding-bottom: 3rem;
}

/* Background gradient + subtle geometric overlay */
body, .stApp {
  background:
    repeating-linear-gradient(60deg, rgba(255,255,255,0.012) 0px, rgba(255,255,255,0.012) 2px, transparent 2px, transparent 40px),
    repeating-linear-gradient(120deg, rgba(255,255,255,0.012) 0px, rgba(255,255,255,0.012) 2px, transparent 2px, transparent 40px),
    linear-gradient(180deg, var(--bg-top), var(--bg-bottom));
  background-blend-mode: overlay;
  color: #e6eef8;
}

/* Header / Title */
.header-wrap { text-align: center; margin-bottom: 20px; }
.header-title {
  font-size: 28px;
  font-weight: 900;
  background: linear-gradient(90deg, #2aa9ff, #8fd3ff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.header-underline {
  width: 240px; height: 3px; margin: 8px auto 0;
  background: linear-gradient(90deg, rgba(42,169,255,0), var(--accent), rgba(42,169,255,0));
  border-radius: 4px;
  box-shadow: 0 0 14px rgba(42,169,255,0.16);
}

/* Section headers */
.section-header {
  font-size: 21px;
  font-weight: 800;
  margin-bottom: 8px;
  background: linear-gradient(90deg,#2aa9ff,#8fd3ff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

/* Verdict */
.verdict {
  font-size: 22px;
  font-weight: 900;
  border-radius: 10px;
  padding: 14px 16px;
  margin-bottom: 16px;
}

/* Input box styling and strong focus override */
div[data-testid="stTextInput"] > label { color: #cfe6ff; font-weight:700; }
input[data-baseweb="input"], .stTextInput input, textarea {
  background: var(--panel) !important;
  border: 1px solid rgba(255,255,255,0.08) !important;
  color: #e6eef8 !important;
  padding: 10px 12px !important;
  border-radius: 10px !important;
  box-shadow: 0 6px 18px rgba(0,0,0,0.5);
}
input[data-baseweb="input"]:focus, .stTextInput input:focus, input[data-baseweb="input"]:focus-visible {
  outline: none !important;
  border: 1px solid var(--accent) !important;
  box-shadow: 0 0 12px rgba(42,169,255,0.45) !important;
}

/* Button */
div.stButton > button {
  background: linear-gradient(90deg,#177fbf,#2aa9ff) !important;
  color: white !important;
  border: none !important;
  padding: 8px 18px !important;
  border-radius: 10px !important;
  font-weight: 800;
  box-shadow: 0 8px 22px rgba(42,169,255,0.12);
  transition: transform .08s ease, box-shadow .1s;
}
div.stButton > button:hover { transform: translateY(-2px); }
div.stButton > button:active { transform: translateY(0) scale(0.995); }

/* Cards / panels */
.section-card {
  background: rgba(255,255,255,0.02);
  border: 1px solid rgba(255,255,255,0.05);
  border-radius: 12px;
  padding: 16px 14px;
  margin-top: 6px;
  margin-bottom: 16px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.4);
}

/* MITRE section slight highlight */
.mitre-section {
  background: radial-gradient(circle at top left, rgba(42,169,255,0.12), transparent 55%),
              rgba(255,255,255,0.02);
  border: 1px solid rgba(42,169,255,0.22);
}

/* Score badges and chips */
.score-badge {
  display:inline-block;
  padding:6px 10px;
  border-radius:999px;
  font-weight:800;
  margin:4px;
  font-size:13px;
}
.tag-chip {
  display:inline-block;
  padding:5px 9px;
  border-radius:14px;
  margin:4px 6px 4px 0;
  font-weight:700;
  font-size:13px;
  border:1px solid rgba(255,255,255,0.05);
}

/* small muted text + readability */
.small-muted { color: var(--muted); font-size:12px; }
.section-card p, .section-card li, .section-card span, .section-card div {
  line-height: 1.55;
}

/* Download button wrapper */
.report-download-wrap {
  display: flex;
  justify-content: center;
  margin-top: 18px;
  margin-bottom: 10px;
}

/* hide trailing 3-dots UI where present */
[data-testid="stTextInput"] [data-testid="StyledFullScreenButton"],
[data-testid="stTextInput"] button[aria-label="View options"] {
  display:none!important;
}
</style>
""", unsafe_allow_html=True)

# -------------------------
# Helpers
# -------------------------
def contrast_color(hexcolor: str) -> str:
    try:
        c = hexcolor.lstrip('#')
        r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
        luminance = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255
        return "#111" if luminance > 0.65 else "#fff"
    except Exception:
        return "#fff"

def score_color(score: int) -> str:
    try:
        s = int(score or 0)
    except Exception:
        s = 0
    if s >= 70: return "#ff5c5c"
    if s >= 31: return "#ff9a2b"
    return "#4cd37b"

def html_badge(value) -> str:
    try:
        v = int(value)
    except Exception:
        try:
            v = int(float(value))
        except Exception:
            v = 0
    bg = score_color(v)
    fg = contrast_color(bg)
    return f'<span class="score-badge" style="background:{bg}; color:{fg};">{v}</span>'

def html_chip(text, bg="#192938") -> str:
    txt = str(text) if text is not None else ""
    txt = txt.strip()
    fg = contrast_color(bg)
    return f'<span class="tag-chip" style="background:{bg}; color:{fg};">{txt}</span>'

def sanitize_list(raw):
    out = []
    if not raw:
        return out
    for item in raw:
        if item is None:
            continue
        if isinstance(item, dict):
            name = item.get("tag") or item.get("name") or item.get("value")
            if name:
                s = str(name).strip()
                if s and s.lower() not in ("null","none","nan"):
                    out.append(s)
        else:
            s = str(item).strip()
            if s and s.lower() not in ("null","none","nan","[]"):
                out.append(s)
    return out

def pretty_dt(s: str):
    try:
        return datetime.fromisoformat(s.replace("Z","+00:00")).strftime("%Y-%m-%d")
    except Exception:
        return s

# -------------------------
# IOC detection  (IP, domain, hash only)
# -------------------------
def detect_ioc_type(ioc: str) -> str:
    if not ioc or not isinstance(ioc, str):
        return "unsupported"
    s = ioc.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
        return "ip_address"
    if re.match(r"^[a-fA-F0-9]{32,64}$", s):
        return "file"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", s):
        return "domain"
    return "unsupported"

# -------------------------
# VirusTotal lookup + comments
# -------------------------
def vt_lookup(ioc: str, kind: str) -> dict:
    headers = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
    base = "https://www.virustotal.com/api/v3/"
    endpoint = f"ip_addresses/{ioc}" if kind == "ip_address" else f"{kind}s/{ioc}"
    try:
        r = requests.get(base + endpoint, headers=headers, timeout=25)
        r.raise_for_status()
    except Exception as e:
        return {"error": f"VT request failed: {e}"}
    j = r.json() or {}
    data = j.get("data") or {}
    attrs = data.get("attributes") or {}
    reputation = attrs.get("reputation", 0) or 0
    last_stats = attrs.get("last_analysis_stats") or {}
    malicious = last_stats.get("malicious", 0) or 0
    suspicious = last_stats.get("suspicious", 0) or 0
    tags = sanitize_list(attrs.get("tags") or [])
    asn = attrs.get("asn") or None
    as_owner = attrs.get("as_owner") or None
    network = attrs.get("network") or None
    whois = attrs.get("whois") or None
    total_votes = attrs.get("total_votes") or {}
    last_analysis_results = attrs.get("last_analysis_results") or {}
    return {
        "reputation": int(reputation),
        "malicious": int(malicious),
        "suspicious": int(suspicious),
        "tags": tags,
        "asn": asn,
        "as_owner": as_owner,
        "network": network,
        "whois": whois,
        "total_votes": total_votes,
        "last_analysis_results": last_analysis_results
    }

if "vt_comments_cache" not in st.session_state:
    st.session_state.vt_comments_cache = {}

def vt_comments(ioc: str, kind: str, limit: int = 6) -> list:
    key = f"{kind}:{ioc}"
    if key in st.session_state.vt_comments_cache:
        return st.session_state.vt_comments_cache[key]
    headers = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
    endpoints = []
    if kind == "ip_address":
        endpoints = [f"ip_addresses/{ioc}/comments", f"ip_addresses/{ioc}/relationships/comments"]
    elif kind == "domain":
        endpoints = [f"domains/{ioc}/comments", f"domains/{ioc}/relationships/comments"]
    comments = []
    for ep in endpoints:
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/{ep}", headers=headers, timeout=12)
            if r.status_code != 200:
                continue
            data = r.json().get("data") or []
            if isinstance(data, dict):
                data = data.get("data") or []
            for item in data[:limit]:
                txt = (item.get("attributes") or {}).get("text") or ""
                if txt and isinstance(txt, str):
                    comments.append(txt.strip())
            if comments:
                break
        except Exception:
            continue
    comments = [c for c in comments if c and isinstance(c, str)]
    st.session_state.vt_comments_cache[key] = comments
    return comments

# -------------------------
# AbuseIPDB lookup (IP only)
# -------------------------
CATEGORY_MAP = {
    1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS Attack",5:"FTP Brute-Force",6:"Ping of Death",
    7:"Phishing",8:"Fraud VoIP",9:"Open Proxy",10:"Web Spam",11:"Email Spam",12:"Blog Spam",13:"VPN IP",
    14:"Port Scan",15:"Hacking",16:"SQL Injection",17:"Spoofing",18:"Brute Force",19:"Bad Web Bot",
    20:"Exploited Host",21:"Web App Attack",22:"SSH",23:"IoT Targeted"
}
def abuse_lookup(ioc: str) -> dict:
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return {"error": "Only IPv4 supported."}
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"} if ABUSE_API_KEY else {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ioc, "maxAgeInDays": "90", "verbose": True},
            timeout=20
        )
        r.raise_for_status()
    except Exception as e:
        return {"error": f"AbuseIPDB request failed: {e}"}
    payload = r.json() or {}
    d = payload.get("data") or {}
    cats = []
    for rep in d.get("reports") or []:
        if isinstance(rep.get("categories"), list) and rep.get("categories"):
            for c in rep.get("categories"):
                mapped = CATEGORY_MAP.get(c, str(c))
                if mapped and mapped not in cats:
                    cats.append(mapped)
        elif rep.get("category") is not None:
            try:
                cid = int(rep.get("category"))
                mapped = CATEGORY_MAP.get(cid, str(cid))
                if mapped and mapped not in cats:
                    cats.append(mapped)
            except Exception:
                raw = rep.get("category")
                if raw and str(raw) not in cats:
                    cats.append(str(raw))
    if not cats and d.get("categories"):
        for c in d.get("categories") or []:
            mapped = CATEGORY_MAP.get(c, str(c))
            if mapped and mapped not in cats:
                cats.append(mapped)
    top = cats[:3]
    return {
        "score": int(d.get("abuseConfidenceScore", 0) or 0),
        "reports": int(d.get("totalReports", 0) or 0),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage": d.get("usageType"),
        "domain": d.get("domain"),
        "hostnames": d.get("hostnames") or [],
        "last": d.get("lastReportedAt"),
        "categories": top
    }

# -------------------------
# AlienVault OTX integration (context only)
# -------------------------
def _map_kind_to_otx(kind: str):
    if kind == "ip_address":
        return "IPv4"
    if kind == "domain":
        return "domain"
    if kind == "file":
        return "file"
    return None

def otx_lookup_raw(ioc: str, kind: str) -> dict:
    otx_type = _map_kind_to_otx(kind)
    if not otx_type:
        return {"error": f"OTX: Unsupported IOC type: {kind}"}
    if not OTX_API_KEY:
        return {"error": "OTX: Missing OTX_API_KEY"}

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general"
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        return resp.json() or {}
    except Exception as e:
        return {"error": f"OTX request failed: {e}"}

CRITICAL_TAGS = {
    "ransomware","c2","botnet","trojan","malware","exploit",
    "phishing","spyware","keylogger","backdoor"
}

def pulse_recency_score(pulse: dict) -> int:
    ts = pulse.get("modified") or pulse.get("created")
    if not ts:
        return 0
    try:
        dt = datetime.fromisoformat(ts.replace("Z","+00:00"))
        days_old = (datetime.now(timezone.utc) - dt).days
        if days_old < 7:
            return 5
        if days_old < 30:
            return 3
        if days_old < 180:
            return 1
        return 0
    except Exception:
        return 0

def pulse_severity_score(pulse: dict) -> int:
    tags = [t.lower() for t in (pulse.get("tags") or [])]
    return sum(1 for t in tags if t in CRITICAL_TAGS)

def pulse_rank_score(pulse: dict) -> float:
    return 0.6 * pulse_recency_score(pulse) + 0.4 * pulse_severity_score(pulse)

def otx_normalize(raw: dict) -> dict:
    if not raw or "error" in raw:
        return {
            "pulse_count": 0,
            "tags": [],
            "references": [],
            "pulses": [],
            "associated_files": []
        }

    general = raw.get("general", raw)
    pulse_info = general.get("pulse_info", {})
    pulses = pulse_info.get("pulses", []) or []
    tags = pulse_info.get("tags", []) or []
    refs = pulse_info.get("references", []) or []

    pulses_sorted = sorted(pulses, key=pulse_rank_score, reverse=True)

    associated = []
    for p in pulses_sorted:
        if isinstance(p.get("files"), list):
            for f in p["files"]:
                h = f.get("sha256") or f.get("hash") or f.get("md5")
                label = None
                if isinstance(f.get("analysis"), dict):
                    labels = f["analysis"].get("av_labels") or []
                    label = labels[0] if labels else None
                dt = pretty_dt(f.get("date")) if f.get("date") else None
                if h:
                    associated.append((h, label, dt))
        if isinstance(p.get("related_samples"), list):
            for s in p["related_samples"]:
                h = s.get("hash") or s.get("sha256")
                label = s.get("malware_family") or s.get("label")
                dt = pretty_dt(s.get("date")) if s.get("date") else None
                if h:
                    associated.append((h, label, dt))

    return {
        "pulse_count": len(pulses_sorted),
        "tags": sanitize_list(tags),
        "references": refs,
        "pulses": pulses_sorted,
        "associated_files": associated
    }

# -------------------------
# Scoring & indicators
# -------------------------
TAG_WORDS = ["phish","ransom","c2","ssh","brute","botnet","credential","trojan",
             "spyware","malware","keylogger","port","scan","sql","injection"]

def vt_score(vt: dict, comments: list) -> int:
    try:
        s = int(vt.get("malicious", 0)) * 3
    except Exception:
        s = 0
    if int(vt.get("reputation", 0) or 0) < 0:
        s += 10
    text = " ".join([*(vt.get("tags") or []), " ".join(comments or [])]).lower()
    for w in TAG_WORDS:
        if w in text:
            s += 10
    return min(100, s)

def risk_indicators(vt: dict, comments: list) -> list:
    text = " ".join([*(vt.get("tags") or []), " ".join(comments or [])]).lower()
    found = []
    map_friendly = {
        "phish":"Phishing","ransom":"Ransomware","c2":"Command & Control","ssh":"SSH activity",
        "brute":"Brute-force","botnet":"Botnet","credential":"Credential theft","trojan":"Trojan",
        "spyware":"Spyware/keylogging","malware":"Malware activity","port":"Port scan","sql":"SQL injection"
    }
    for w in TAG_WORDS:
        if w in text and map_friendly.get(w) not in found:
            found.append(map_friendly.get(w))
        if len(found) >= 6:
            break
    return found

def combined_score(kind: str, vt_s: int, ab_s: int, reports: int) -> int:
    # VT + Abuse ONLY. OTX is context, not numeric.
    if kind == "ip_address":
        vt_w, ab_w = 0.4, 0.6
    else:  # domain / file -> VT only
        vt_w, ab_w = 1.0, 0.0

    c = vt_s * vt_w + ab_s * ab_w

    # strong Abuse override if VT is low but Abuse + reports are very high
    if kind == "ip_address" and vt_s < 20 and ab_s > 85 and reports > 30:
        c += 5

    return min(100, round(c))

# -------------------------
# MITRE ATT&CK mapping (rule-based + explanations)
# -------------------------
MITRE_RULES = [
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "phrases": ["phishing", "phish"],
        "why": "Used when attackers lure users via malicious emails or links to gain initial foothold.",
        "recommendations": [
            "Review email gateway logs for similar sender, subject and URLs.",
            "Hunt proxy/DNS logs for clicks to the same domain or URL paths.",
            "Check for credential reuse or suspicious logins following phishing attempts."
        ]
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "phrases": ["ransomware", "ransom"],
        "why": "Indicates payloads that encrypt data or demand ransom after compromise.",
        "recommendations": [
            "Check affected hosts for encryption processes, unusual file extensions or ransom notes.",
            "Validate recent backups and isolation status of impacted systems.",
            "Search EDR logs for initial access vector that led to ransomware execution."
        ]
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol (C2 over HTTP/HTTPS)",
        "tactic": "Command and Control",
        "phrases": ["c2", "command & control"],
        "why": "Suggests malware using HTTP/HTTPS or similar protocols to talk to a C2 server.",
        "recommendations": [
            "Inspect outbound HTTP/HTTPS traffic for rare domains, URIs or JA3 fingerprints.",
            "Check firewall/proxy logs for persistent beacons to a small set of IPs/domains.",
            "Block or sinkhole suspicious C2 domains and monitor for fallback infrastructure."
        ]
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "phrases": ["brute force", "brute-force", "bruteforce"],
        "why": "Points to repeated login attempts aiming to guess passwords on services.",
        "recommendations": [
            "Review authentication logs (VPN, AD, SSH, web) for repeated failures from same IP.",
            "Temporarily block offending IPs or apply stricter rate limiting.",
            "Check for any successful logins following long failure streaks from the same source."
        ]
    },
    {
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "phrases": ["port scan", "port scanning", "scan"],
        "why": "Indicates scanning to discover open ports and services inside or outside the network.",
        "recommendations": [
            "Identify internal assets targeted by the scanning IP and their exposure level.",
            "Correlate with IDS/IPS alerts for port scan or network sweep behaviour.",
            "Monitor for follow-up exploitation attempts against discovered services."
        ]
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application (SQLi/Web Attack)",
        "tactic": "Initial Access",
        "phrases": ["sql injection", "web app attack"],
        "why": "Suggests attempts to exploit internet-facing web applications (e.g., SQLi, RCE).",
        "recommendations": [
            "Review web server and WAF logs around timestamps associated with this IOC.",
            "Look for error spikes, suspicious parameters, or payload patterns in HTTP requests.",
            "Validate patching level and hardening of exposed web apps targeted by this IOC."
        ]
    },
    {
        "id": "T1056",
        "name": "Input Capture (Keylogging)",
        "tactic": "Credential Access",
        "phrases": ["keylogger", "keylogging"],
        "why": "Indicates malware families that capture keystrokes or user input.",
        "recommendations": [
            "Search EDR for known keylogger binaries or persistence mechanisms.",
            "Check for unusual processes injecting into browsers or credential managers.",
            "Force credential reset for users active on potentially infected endpoints."
        ]
    },
    {
        "id": "T1555",
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "phrases": ["credential theft", "credential stealing"],
        "why": "Associated with stealing secrets from browsers, password managers, or OS stores.",
        "recommendations": [
            "Inspect endpoints for tools targeting browser profile data or LSASS memory.",
            "Monitor for access to password vault files or exports.",
            "Initiate credential reset and monitor for unusual sign-in locations or devices."
        ]
    },
    {
        "id": "T1021.004",
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "phrases": ["ssh"],
        "why": "SSH-related brute force or misuse suggests lateral movement or remote access attempts.",
        "recommendations": [
            "Review SSH logs for failed and successful logins from the suspicious IP.",
            "Enforce key-based auth and disable password login where possible.",
            "Check for new or unauthorized SSH keys on critical servers."
        ]
    }
]

def map_to_mitre(vt_norm: dict, indicators: list, ab: dict, otx_norm: dict):
    vt_terms = (vt_norm.get("tags") or []) + (indicators or [])
    ab_terms = (ab.get("categories") or []) if ab else []
    otx_terms = (otx_norm.get("tags") or []) if otx_norm else []

    vt_text = " ".join([str(t) for t in vt_terms]).lower()
    ab_text = " ".join([str(t) for t in ab_terms]).lower()
    otx_text = " ".join([str(t) for t in otx_terms]).lower()

    results = {}

    for rule in MITRE_RULES:
        phrases = rule["phrases"]
        sources = set()

        for ph in phrases:
            if ph in vt_text:
                sources.add("VirusTotal / Tags")
            if ph in ab_text:
                sources.add("AbuseIPDB / Categories")
            if ph in otx_text:
                sources.add("AlienVault OTX / Tags")

        if sources:
            conf = 40 + 20 * len(sources)
            conf = min(conf, 95)
            tid = rule["id"]
            if tid in results:
                results[tid]["confidence"] = max(results[tid]["confidence"], conf)
                results[tid]["sources"].update(sources)
            else:
                results[tid] = {
                    "id": tid,
                    "name": rule["name"],
                    "tactic": rule["tactic"],
                    "confidence": conf,
                    "sources": set(sources),
                    "why": rule.get("why", ""),
                    "recommendations": rule.get("recommendations", [])
                }

    mapped = list(results.values())
    mapped.sort(key=lambda x: x["confidence"], reverse=True)
    return mapped

# -------------------------
# Text report builder
# -------------------------
def build_report(ioc, display_kind, vt_norm, vt_s, comments, ab, ab_s,
                 otx_norm, mitre_hits, indicators, comb, verdict_text):
    lines = []
    lines.append("SOC IntelHub — IOC Triage Report")
    lines.append("===============================")
    lines.append(f"IOC: {ioc}")
    lines.append(f"Type: {display_kind}")
    lines.append(f"Final Verdict: {verdict_text} ({comb}/100)")
    lines.append("")

    # VT
    lines.append("VirusTotal Intelligence")
    lines.append("-----------------------")
    if "error" in vt_norm:
        lines.append("VirusTotal data not available.")
    else:
        lines.append(f"- Threat Score: {vt_s}")
        lines.append(f"- Malicious Engines: {vt_norm.get('malicious',0)}")
        lines.append(f"- Suspicious Engines: {vt_norm.get('suspicious',0)}")
        lines.append(f"- Reputation: {vt_norm.get('reputation',0)}")
        if vt_norm.get("asn") or vt_norm.get("as_owner"):
            lines.append(f"- ASN: {vt_norm.get('asn')} — {vt_norm.get('as_owner')}")
        if vt_norm.get("network"):
            lines.append(f"- Network: {vt_norm.get('network')}")
        vt_tags = [t for t in (vt_norm.get("tags") or []) if t]
        if vt_tags:
            lines.append(f"- VT Tags: {', '.join(vt_tags[:15])}")
        safe_comments = [c for c in (comments or []) if c]
        if safe_comments:
            lines.append("")
            lines.append("Top Community Comments:")
            for c in safe_comments[:5]:
                lines.append(f"  • {c}")

    lines.append("")
    # Abuse
    lines.append("AbuseIPDB Intelligence")
    lines.append("-----------------------")
    if not ab or "error" in ab:
        lines.append("AbuseIPDB data not available for this IOC.")
    else:
        lines.append(f"- Abuse Confidence: {ab_s}")
        lines.append(f"- Total Reports (90d): {ab.get('reports',0)}")
        if ab.get("country") or ab.get("isp"):
            lines.append(f"- Country: {ab.get('country')} | ISP: {ab.get('isp')}")
        if ab.get("usage"):
            lines.append(f"- Usage Type: {ab.get('usage')}")
        if ab.get("domain"):
            lines.append(f"- Domain: {ab.get('domain')}")
        cats = [c for c in (ab.get("categories") or []) if c]
        if cats:
            lines.append(f"- Categories: {', '.join(cats)}")
        if ab.get("hostnames"):
            lines.append(f"- Hostnames: {', '.join(ab.get('hostnames') or [])}")

    lines.append("")
    # OTX
    lines.append("AlienVault OTX Context")
    lines.append("----------------------")
    if not otx_norm or otx_norm.get("pulse_count",0) == 0:
        lines.append("No OTX pulses associated with this IOC.")
    else:
        lines.append(f"- Pulses Found: {otx_norm['pulse_count']}")
        otx_tags = [t for t in (otx_norm.get("tags") or []) if t]
        if otx_tags:
            lines.append(f"- Common Tags: {', '.join(otx_tags[:15])}")
        if otx_norm.get("references"):
            lines.append("- Example References:")
            for r in otx_norm["references"][:3]:
                lines.append(f"  • {r}")

    lines.append("")
    safe_inds = [str(i) for i in (indicators or []) if i]
    if safe_inds:
        lines.append(f"High-Level Threat Indicators: {', '.join(safe_inds[:10])}")
        lines.append("")

    # MITRE
    lines.append("MITRE ATT&CK Mapping (Inferred)")
    lines.append("--------------------------------")
    if not mitre_hits:
        lines.append("No strong MITRE techniques inferred from current intel.")
    else:
        for t in mitre_hits[:3]:
            lines.append(f"{t['id']} — {t['name']}  (Tactic: {t['tactic']})")
            lines.append(f"- Confidence: {t['confidence']}")
            srcs = ", ".join(sorted(list(t['sources']))) if t.get("sources") else "N/A"
            lines.append(f"- Sources: {srcs}")
            if t.get("why"):
                lines.append(f"- Why this matters: {t['why']}")
            recs = t.get("recommendations") or []
            if recs:
                lines.append("  SOC Next Steps:")
                for r in recs:
                    lines.append(f"    • {r}")
            lines.append("")

    lines.append("Report generated by SOC IntelHub.")
    return "\n".join(lines)

# -------------------------
# UI
# -------------------------
st.markdown(
    '<div class="header-wrap"><div class="header-title">SOC IntelHub — IOC Triage Dashboard</div>'
    '<div class="header-underline"></div></div>',
    unsafe_allow_html=True
)

ioc = st.text_input("Enter IOC (IP, domain, file hash)")
analyze = st.button("Analyze") or (ioc and st.session_state.get("last_ioc") != ioc)
st.session_state["last_ioc"] = ioc

if analyze:
    if not ioc or not ioc.strip():
        st.warning("Please enter an IOC first.")
    else:
        kind = detect_ioc_type(ioc)
        if kind == "unsupported":
            st.warning("Currently this dashboard supports IP addresses, domains and file hashes. Please input one of those.")
        else:
            kind_label_map = {
                "ip_address": "IP address",
                "domain": "Domain",
                "file": "File hash"
            }
            display_kind = kind_label_map.get(kind, kind)
            st.markdown(f"**Detected Type:** `{display_kind}`")

            vt = vt_lookup(ioc, kind)
            comments = vt_comments(ioc, kind)
            ab = abuse_lookup(ioc) if kind == "ip_address" else {"score": 0, "reports": 0, "categories": []}
            otx_raw = otx_lookup_raw(ioc, kind)
            otx_norm = otx_normalize(otx_raw)

            vt_norm = {
                "reputation": int(vt.get("reputation", vt.get("rep", 0) or 0)),
                "malicious": int(vt.get("malicious", vt.get("mal", 0) or 0)),
                "suspicious": int(vt.get("suspicious", vt.get("sus", 0) or 0)),
                "tags": sanitize_list(vt.get("tags") or []),
                "asn": vt.get("asn"),
                "as_owner": vt.get("as_owner"),
                "network": vt.get("network"),
                "whois": vt.get("whois"),
                "last_analysis_results": vt.get("last_analysis_results") or {},
                "total_votes": vt.get("total_votes") or {}
            }

            vt_s = vt_score(vt_norm, comments)
            ab_s = int(ab.get("score", 0) or 0)
            reports = int(ab.get("reports", 0) or 0)

            # indicators used both for UI and MITRE mapping
            inds = risk_indicators(vt_norm, comments)

            comb = combined_score(kind, vt_s, ab_s, reports)

            vc = score_color(comb)
            verdict_text = "Malicious" if comb >= 70 else "Suspicious" if comb >= 31 else "Likely Clean"
            st.markdown(
                f'<div class="verdict" style="background:{vc}; color:{contrast_color(vc)}">'
                f"⚖️ Final Verdict: {verdict_text} — {comb}/100</div>",
                unsafe_allow_html=True
            )

            left, right = st.columns([2, 1])

            # ----------------- VirusTotal panel -----------------
            with left:
                st.markdown('<div class="section-card">', unsafe_allow_html=True)
                st.markdown('<div class="section-header">🔍 VirusTotal Intelligence</div>', unsafe_allow_html=True)
                if "error" in vt:
                    st.info("VirusTotal data is not available for this IOC right now (no data returned or API/network limit).")
                else:
                    m1, m2, m3, m4 = st.columns(4)
                    m1.markdown(f"**Threat Score**<br>{html_badge(vt_s)}", unsafe_allow_html=True)
                    m2.markdown(f"**Malicious**<br>{html_badge(vt_norm['malicious'])}", unsafe_allow_html=True)
                    m3.markdown(f"**Suspicious**<br>{html_badge(vt_norm['suspicious'])}", unsafe_allow_html=True)
                    m4.markdown(f"**Reputation**<br>{html_badge(vt_norm['reputation'])}", unsafe_allow_html=True)

                    st.write(f"**ASN:** {vt_norm.get('asn')} — {vt_norm.get('as_owner')}")
                    st.write(f"**Network:** {vt_norm.get('network')}")
                    tags = vt_norm.get("tags") or []
                    if tags:
                        chips = " ".join([html_chip(t) for t in tags[:8]])
                        st.markdown(chips, unsafe_allow_html=True)
                    else:
                        st.write("**Tags:** None")

                    votes = vt_norm.get("total_votes") or {}
                    if votes:
                        st.write(f"**Community Votes:** 👍 {votes.get('harmless',0)}  👎 {votes.get('malicious',0)}")

                    if inds:
                        st.markdown("**🚨 Possible Threat Indicators:**")
                        st.markdown(" ".join([html_chip(i,"#ff9a2b") for i in inds]), unsafe_allow_html=True)

                    st.markdown("**💬 Community Insights:**")
                    if comments:
                        for c in comments:
                            st.write(f"• {c}")
                    else:
                        st.write("_No community comments available._")

                    with st.expander("🔍 Engine Detections / Top Vendor Classifications"):
                        engs = vt_norm.get("last_analysis_results") or {}
                        flagged = []
                        for engine, vals in engs.items():
                            if not vals or not isinstance(vals, dict):
                                continue
                            cat = vals.get("category")
                            res = vals.get("result")
                            if cat in ("malicious","suspicious") and res:
                                flagged.append((engine, res))
                        if flagged:
                            for e, r in flagged[:30]:
                                bg = "#ff8b8b" if "mal" in r.lower() else "#ffc08a"
                                fg = contrast_color(bg)
                                st.markdown(
                                    f"- **{e}** → <span style='background:{bg}; color:{fg}; "
                                    f"padding:4px 8px; border-radius:8px'>{r}</span>",
                                    unsafe_allow_html=True
                                )
                        else:
                            st.write("No engine detections reported.")

                    with st.expander("📄 WHOIS"):
                        whois_text = vt_norm.get("whois") or "No WHOIS data"
                        st.text_area("WHOIS", whois_text, height=160)

                    vt_link = {
                        "ip_address": f"https://www.virustotal.com/gui/ip-address/{ioc}",
                        "domain": f"https://www.virustotal.com/gui/domain/{ioc}",
                        "file": f"https://www.virustotal.com/gui/file/{ioc}"
                    }.get(kind, f"https://www.virustotal.com/gui/search/{ioc}")
                    st.markdown(f"[Open VirusTotal Report]({vt_link})")
                st.markdown('</div>', unsafe_allow_html=True)

                # --------------- AlienVault OTX panel ---------------
                st.markdown('<div class="section-card">', unsafe_allow_html=True)
                st.markdown('<div class="section-header">🛰️ AlienVault OTX Intelligence</div>', unsafe_allow_html=True)

                if "error" in otx_raw:
                    st.info("AlienVault OTX data is not available for this IOC (no pulses returned or API/network issue).")
                elif otx_norm.get("pulse_count", 0) == 0:
                    st.info("No OTX pulses associated with this IOC.")
                else:
                    st.markdown(
                        f"**Pulses Found:** {html_badge(otx_norm['pulse_count'])}",
                        unsafe_allow_html=True
                    )

                    otx_tags = otx_norm.get("tags") or []
                    if otx_tags:
                        chips = " ".join([html_chip(t) for t in otx_tags[:8]])
                        st.markdown("**Tags:** " + chips, unsafe_allow_html=True)

                    pulses = otx_norm.get("pulses") or []
                    if pulses:
                        with st.expander("🧠 Pulse Details (top 5 by recency & severity)"):
                            for idx, p in enumerate(pulses[:5], start=1):
                                name = p.get("name","Unnamed Pulse")
                                author = p.get("author_name")
                                created = pretty_dt(p.get("created")) if p.get("created") else None
                                modified = pretty_dt(p.get("modified")) if p.get("modified") else None

                                st.markdown(f"**{idx}. {name}**")
                                meta_lines = []
                                if author:
                                    meta_lines.append(f"- **Author:** {author}")
                                if created:
                                    meta_lines.append(f"- **Created:** {created}")
                                if modified:
                                    meta_lines.append(f"- **Updated:** {modified}")
                                if meta_lines:
                                    st.markdown("\n".join(meta_lines))

                                ptags = p.get("tags",[]) or []
                                if ptags:
                                    shown_tags = ptags[:8]
                                    chips = " ".join([html_chip(t) for t in shown_tags])
                                    extra = len(ptags) - len(shown_tags)
                                    if extra > 0:
                                        chips += f" <span class='small-muted'>+{extra} more</span>"
                                    st.markdown("**Tags:** " + chips, unsafe_allow_html=True)

                                desc = p.get("description","")
                                if desc:
                                    st.markdown(f"<span class='small-muted'>{desc[:300]}...</span>", unsafe_allow_html=True)

                                prefs = p.get("references") or []
                                if prefs:
                                    st.markdown("**References:**")
                                    for r in prefs[:3]:
                                        st.markdown(f"- [{r}]({r})")

                                pulse_id = p.get("id")
                                if pulse_id:
                                    pulse_url = f"https://otx.alienvault.com/pulse/{pulse_id}"
                                    st.markdown(f"[View full pulse on OTX]({pulse_url})")

                                st.markdown("---")

                    assoc = otx_norm.get("associated_files") or []
                    if assoc:
                        st.markdown("**Associated Files / Hashes (from pulses):**")
                        for (h, label, dt) in assoc[:5]:
                            ltxt = f" — {label}" if label else ""
                            dtxt = f" ({dt})" if dt else ""
                            vt_file_link = f"https://www.virustotal.com/gui/file/{h}"
                            st.markdown(
                                f"[`{h[:12]}…`]({vt_file_link}){ltxt}{dtxt}",
                                unsafe_allow_html=True
                            )

                st.markdown('</div>', unsafe_allow_html=True)

            # ----------------- AbuseIPDB panel -----------------
            with right:
                st.markdown('<div class="section-card">', unsafe_allow_html=True)
                st.markdown('<div class="section-header">🌐 AbuseIPDB Intelligence</div>', unsafe_allow_html=True)
                if kind != "ip_address":
                    st.info("Not an IP — skipping AbuseIPDB lookup.")
                elif "error" in ab:
                    msg = ab["error"]
                    if "Read timed out" in msg:
                        st.info("AbuseIPDB is taking too long to respond. Showing VT and OTX results only for now.")
                    else:
                        st.info("AbuseIPDB data is not available for this IP at the moment.")
                else:
                    st.markdown(f"**Abuse Confidence** {html_badge(ab_s)}", unsafe_allow_html=True)
                    st.write(f"**Total Reports:** {ab.get('reports',0)}")
                    st.write(f"**Country:** {ab.get('country')}  |  **ISP:** {ab.get('isp')}")
                    st.write(f"**Usage:** {ab.get('usage')}")
                    st.write(f"**Domain:** {ab.get('domain')}")
                    cats = ab.get("categories") or []
                    if cats:
                        cats_html = " ".join([html_chip(c,"#ff9a2b") for c in cats])
                        st.markdown("**Categories:** " + cats_html, unsafe_allow_html=True)
                    else:
                        st.write("**Categories:** None")
                    if ab.get("hostnames"):
                        st.write("**Hostnames:** " + ", ".join(ab.get("hostnames") or []))
                    if ab.get("last"):
                        try:
                            dt = datetime.fromisoformat(ab["last"].replace("Z", "+00:00"))
                            days = (datetime.now(timezone.utc) - dt).days
                            st.caption(f"{ab.get('reports',0)} reports in 90 days — last seen {days} days ago")
                        except Exception:
                            st.caption(f"{ab.get('reports',0)} reports in 90 days")
                st.markdown('</div>', unsafe_allow_html=True)

            # ----------------- MITRE ATT&CK panel (Top 3 + actions + MITRE link) -----------------
            st.markdown('<div class="section-card mitre-section">', unsafe_allow_html=True)
            st.markdown('<div class="section-header">🎯 MITRE ATT&CK Mapping (Auto)</div>', unsafe_allow_html=True)

            mitre_hits = map_to_mitre(vt_norm, inds, ab, otx_norm)

            if not mitre_hits:
                st.info("No strong MITRE ATT&CK techniques inferred from current intel signals.")
            else:
                top_hits = mitre_hits[:3]  # show only top 3 to avoid clutter
                st.markdown(
                    f"<span class='small-muted'>Showing top {len(top_hits)} inferred techniques by confidence.</span>",
                    unsafe_allow_html=True
                )
                for t in top_hits:
                    st.markdown(f"**{t['id']} — {t['name']}**  \n*Tactic:* {t['tactic']}")
                    st.markdown(f"Confidence: {html_badge(t['confidence'])}", unsafe_allow_html=True)
                    if t['sources']:
                        chips = ' '.join([html_chip(s, '#172a3a') for s in sorted(t['sources'])])
                        st.markdown('Sources: ' + chips, unsafe_allow_html=True)

                    mitre_url = f"https://attack.mitre.org/techniques/{t['id']}/"
                    st.markdown(f"[Open on MITRE ATT&CK]({mitre_url})")

                    if t.get("why"):
                        st.markdown(f"**Why this matters:** {t['why']}")
                    recs = t.get("recommendations") or []
                    if recs:
                        st.markdown("**SOC next steps:**")
                        for r in recs:
                            st.markdown(f"- {r}")

                    st.markdown('---')

            st.markdown('</div>', unsafe_allow_html=True)

            # ----------------- Download text report -----------------
            report_text = build_report(
                ioc=ioc,
                display_kind=display_kind,
                vt_norm=vt_norm,
                vt_s=vt_s,
                comments=comments,
                ab=ab,
                ab_s=ab_s,
                otx_norm=otx_norm,
                mitre_hits=mitre_hits,
                indicators=inds,
                comb=comb,
                verdict_text=verdict_text
            )
            safe_ioc_for_name = re.sub(r"[^A-Za-z0-9_.-]", "_", ioc)
            file_name = f"soc_intelhub_report_{safe_ioc_for_name}.txt"

            st.markdown('<div class="report-download-wrap">', unsafe_allow_html=True)
            st.download_button(
                label="📥 Download Text Report (.txt)",
                data=report_text,
                file_name=file_name,
                mime="text/plain"
            )
            st.markdown('</div>', unsafe_allow_html=True)
