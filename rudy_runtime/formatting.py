"""Pure helpers for formatting /ip results; kept free of Discord imports so they are easy to test."""

import ipaddress
import re

DISCORD_MESSAGE_LIMIT=2000

def validate_ip(ip):
    """True for any valid IPv4 or IPv6 address string."""
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def clean_banner(banner):
    """Strip HTML tags and collapse whitespace so a service banner fits on one line (max 100 chars)."""
    banner=re.sub(r'<[^>]+>','',banner)
    # Shodan banners contain real CR/LF/tab characters; collapse them so each port stays on one line
    banner=re.sub(r'\s+',' ',banner).strip()
    return banner[:100]+"..." if len(banner)>100 else banner

def split_message(m,limit=DISCORD_MESSAGE_LIMIT):
    """Split text on line boundaries into chunks Discord accepts; over-long lines are hard-wrapped."""
    chunks=[]
    cur=""
    for line in m.split("\n"):
        # a single line longer than the limit is hard-wrapped
        while len(line)>=limit:
            if cur:
                chunks.append(cur)
                cur=""
            chunks.append(line[:limit])
            line=line[limit:]
        if len(cur)+len(line)+1>limit:
            chunks.append(cur)
            cur=""
        cur+=line+"\n"
    if cur.strip():
        chunks.append(cur)
    return chunks or ["No data found."]

def summarize_virustotal(vt):
    """Short human summary of a VirusTotal v3 IP report: detections, reputation and network owner."""
    a=vt.get("data",{}).get("attributes",{})
    if not a:
        return ["VirusTotal: no data"]
    st=a.get("last_analysis_stats",{})
    out=[f"VirusTotal: {st.get('malicious',0)} malicious, {st.get('suspicious',0)} suspicious, {st.get('harmless',0)} harmless"]
    for key,label in (("reputation","Reputation"),("as_owner","AS owner"),("asn","ASN"),("country","Country"),("network","Network")):
        if a.get(key) not in (None,""):
            out.append(f"{label}: {a[key]}")
    return out
