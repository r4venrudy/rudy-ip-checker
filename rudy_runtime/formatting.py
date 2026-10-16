"""Pure helpers for formatting /ip results; kept free of Discord imports so they are easy to test."""

import ipaddress
import re
from datetime import datetime, timezone

DISCORD_MESSAGE_LIMIT=2000

def canonical_ip(text):
    """Canonical string for an IP ("2001:DB8::0001" -> "2001:db8::1", " 8.8.8.8 " -> "8.8.8.8"), or None if invalid."""
    try:
        addr=ipaddress.ip_address((text or "").strip())
    except ValueError:
        return None
    # "::ffff:8.8.8.8" (an IPv4 address written as IPv6, as some logs do) is really 8.8.8.8
    if addr.version==6 and addr.ipv4_mapped:
        addr=addr.ipv4_mapped
    return str(addr)

def escape_md(text):
    """Escape Discord markdown in text from external sources (banners, hostnames, registry names)."""
    # brackets too: a banner like "[Login](https://...)" would otherwise render as a masked link
    return re.sub(r"([\\*_~`|\[\]])",r"\\\1",str(text))

_HOSTNAME=re.compile(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")

def hostname_from(text):
    """"https://Example.com/path" or "example.com." -> "example.com"; None when it is not a hostname."""
    host=(text or "").strip().lower()
    if "://" in host:
        host=host.split("://",1)[1]
    host=host.split("/",1)[0].split(":",1)[0].rstrip(".")
    return host if _HOSTNAME.fullmatch(host) else None

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
            # AS owner names come from registry data and can contain markdown characters
            out.append(f"{label}: {escape_md(str(a[key]))}")
    if st.get('malicious'):
        # which engines flagged it is more useful than the count alone
        engines=[name for name,r in (a.get("last_analysis_results") or {}).items() if r.get("category")=="malicious"]
        if engines:
            out.append("Flagged by: "+", ".join(sorted(engines)[:8])+(f" (+{len(engines)-8} more)" if len(engines)>8 else ""))
    if isinstance(a.get("last_analysis_date"),int):
        out.append("Last analysed: "+datetime.fromtimestamp(a["last_analysis_date"],timezone.utc).strftime("%Y-%m-%d"))
    return out

def summarize_shodan(host):
    """Owner, OS, hostnames and known CVEs from a Shodan host report, then one line per open port."""
    out=[]
    for key,label in (("org","Organization"),("isp","ISP"),("os","OS")):
        if host.get(key):
            out.append(f"{label}: {escape_md(host[key])}")
    if host.get("tags"):
        # Shodan's own labels: vpn, tor, cloud, honeypot, self-signed, compromised...
        out.append("Tags: "+", ".join(escape_md(t) for t in host["tags"][:8]))
    if host.get("last_update"):
        out.append(f"Last scanned by Shodan: {str(host['last_update'])[:10]}")
    if host.get("hostnames"):
        out.append("Hostnames: "+", ".join(escape_md(h) for h in host["hostnames"][:5]))
    vulns=host.get("vulns") or []
    if vulns:
        shown=sorted(vulns)[:5]
        more=f" (+{len(vulns)-5} more)" if len(vulns)>5 else ""
        out.append(f"Known CVEs: {', '.join(shown)}{more}")
    for d in sorted(host.get("data",[]),key=lambda d:d.get("port",0)):
        out.append(f"Port {d.get('port')}/{d.get('transport','tcp')} - {escape_md(clean_banner(d.get('data','')))}")
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
        out.append(f"Network: {escape_md(rdap['name'])}"+(f" ({escape_md(rdap['handle'])})" if rdap.get("handle") else ""))
    if rdap.get("startAddress") and rdap.get("endAddress"):
        out.append(f"Range: {rdap['startAddress']} - {rdap['endAddress']}")
    if rdap.get("country"):
        out.append(f"Registered country: {rdap['country']}")
    # when the block was allocated and last changed; a fresh allocation is common for throwaway hosting
    for e in rdap.get("events") or []:
        if e.get("eventAction")=="registration" and e.get("eventDate"):
            out.append(f"Registered: {str(e['eventDate'])[:10]}")
        elif e.get("eventAction")=="last changed" and e.get("eventDate"):
            out.append(f"Last changed: {str(e['eventDate'])[:10]}")
    entities=list(rdap.get("entities",[]))
    # abuse contacts are usually nested under the registrant entity
    for e in list(entities):
        entities.extend(e.get("entities",[]))
    owner=next((_vcard(e,"fn") for e in entities if "registrant" in e.get("roles",[]) and _vcard(e,"fn")),None)
    if owner:
        out.append(f"Owner: {escape_md(owner)}")
    abuse=next((_vcard(e,"email") for e in entities if "abuse" in e.get("roles",[]) and _vcard(e,"email")),None)
    if abuse:
        # addresses like abuse_team@... would otherwise turn into italics
        out.append(f"Abuse contact: {escape_md(abuse)}")
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
    if d.get("domain"):
        out.append(f"Domain: {escape_md(d['domain'])}")
    # whitelisted means AbuseIPDB treats it as a known-good service (big DNS resolvers, crawlers)
    if d.get("isWhitelisted"):
        out.append("Whitelisted by AbuseIPDB")
    return out

def summarize_greynoise(report):
    """Whether GreyNoise saw the address mass-scanning (noise) or knows it as a benign service (riot)."""
    if report.get("riot"):
        return [f"Known benign service: {escape_md(report.get('name') or 'yes')}"]
    if report.get("noise"):
        out=[f"Seen scanning the internet: {escape_md(report.get('classification') or 'unknown')}"]
        if report.get("name") and report["name"]!="unknown":
            out[0]+=f" ({escape_md(report['name'])})"
        if report.get("last_seen"):
            out.append(f"Last seen: {str(report['last_seen'])[:10]}")
        return out
    return ["Not seen scanning the internet"]

def build_report(ip,results,failed):
    """Group the /ip output by source, in a fixed order, with a bold header per source.

    results maps source name -> raw response (None when the source had nothing), failed is the set of
    sources whose lookup raised. Sources that were skipped (no API key) are left out entirely.
    """
    tor_ipv6=ipaddress.ip_address(ip).version==6
    # the exit list is IPv4 only, but AbuseIPDB (when configured) knows IPv6 exits too
    abuse_tor=((results.get("AbuseIPDB") or {}).get("data") or {}).get("isTor")
    def tor_lines(r):
        if tor_ipv6:
            if isinstance(abuse_tor,bool):
                return [f"Exit node: {'Yes' if abuse_tor else 'No'} (from AbuseIPDB)"]
            return ["Not checked (the public exit list only has IPv4 addresses)"]
        return ["Exit node: Yes" if ip in r else "Exit node: No"] if r is not None else []
    order=(
        ("Shodan",lambda r:summarize_shodan(r) if r else ["No data for this address"]),
        ("Tor",tor_lines),
        ("WHOIS",lambda r:summarize_rdap(r) if r else ["No registry data"]),
        ("VirusTotal",lambda r:summarize_virustotal(r) if r else ["No data for this address"]),
        ("AbuseIPDB",lambda r:summarize_abuseipdb(r) if r else []),
        ("GreyNoise",lambda r:summarize_greynoise(r) if r else []),
    )
    out=[]
    for name,fmt in order:
        if name in failed:
            lines=["Lookup failed"]
        elif name not in results:
            continue
        else:
            lines=fmt(results[name])
        if lines:
            out.append(f"**{name}**")
            out.extend(lines)
            out.append("")
    return "\n".join(out).strip()
