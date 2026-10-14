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

def canonical_ip(text):
    """Canonical string for an IP ("2001:DB8::0001" -> "2001:db8::1", " 8.8.8.8 " -> "8.8.8.8"), or None if invalid."""
    try:
        return str(ipaddress.ip_address((text or "").strip()))
    except ValueError:
        return None

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

def summarize_shodan(host):
    """Owner, OS, hostnames and known CVEs from a Shodan host report, then one line per open port."""
    out=[]
    for key,label in (("org","Organization"),("isp","ISP"),("os","OS")):
        if host.get(key):
            out.append(f"{label}: {host[key]}")
    if host.get("hostnames"):
        out.append("Hostnames: "+", ".join(host["hostnames"][:5]))
    vulns=host.get("vulns") or []
    if vulns:
        shown=sorted(vulns)[:5]
        more=f" (+{len(vulns)-5} more)" if len(vulns)>5 else ""
        out.append(f"Known CVEs: {', '.join(shown)}{more}")
    for d in sorted(host.get("data",[]),key=lambda d:d.get("port",0)):
        out.append(f"Port {d.get('port')}/{d.get('transport','tcp')} - {clean_banner(d.get('data',''))}")
    return out

def _vcard(entity,field):
    """First value of a vCard field (e.g. "fn", "email") in an RDAP entity's jCard."""
    for item in (entity.get("vcardArray") or [None,[]])[1]:
        if item and item[0]==field:
            return item[3]
    return None

def summarize_rdap(rdap):
    """Network name, address range, country, owner and abuse contact from an RDAP IP network object (RFC 9083)."""
    out=[]
    if rdap.get("name"):
        out.append(f"Network: {rdap['name']}"+(f" ({rdap['handle']})" if rdap.get("handle") else ""))
    if rdap.get("startAddress") and rdap.get("endAddress"):
        out.append(f"Range: {rdap['startAddress']} - {rdap['endAddress']}")
    if rdap.get("country"):
        out.append(f"Registered country: {rdap['country']}")
    entities=list(rdap.get("entities",[]))
    # abuse contacts are usually nested under the registrant entity
    for e in list(entities):
        entities.extend(e.get("entities",[]))
    owner=next((_vcard(e,"fn") for e in entities if "registrant" in e.get("roles",[]) and _vcard(e,"fn")),None)
    if owner:
        out.append(f"Owner: {owner}")
    abuse=next((_vcard(e,"email") for e in entities if "abuse" in e.get("roles",[]) and _vcard(e,"email")),None)
    if abuse:
        out.append(f"Abuse contact: {abuse}")
    return out

def summarize_abuseipdb(report):
    """Abuse confidence, report count and usage type from an AbuseIPDB v2 /check response."""
    d=report.get("data") or {}
    if "abuseConfidenceScore" not in d:
        return ["AbuseIPDB: no data"]
    out=[f"AbuseIPDB: {d['abuseConfidenceScore']}% abuse confidence, {d.get('totalReports',0)} reports in 90 days"]
    if d.get("lastReportedAt"):
        out.append(f"Last reported: {d['lastReportedAt'][:10]}")
    if d.get("usageType"):
        out.append(f"Usage type: {d['usageType']}")
    return out
