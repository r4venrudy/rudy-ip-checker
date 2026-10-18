"""Pure helpers for formatting /ip results; kept free of Discord imports so they are easy to test."""

import ipaddress
import re
from urllib.parse import urlsplit
from datetime import datetime, timezone

DISCORD_MESSAGE_LIMIT=2000

def canonical_ip(text):
    """Canonical string for an IP ("2001:DB8::0001" -> "2001:db8::1", " 8.8.8.8 " -> "8.8.8.8"), or None if invalid."""
    try:
        addr=ipaddress.ip_address((text or "").strip())
    except ValueError:
        return None
    if addr.version==6 and addr.scope_id is not None:
        return None
    # "::ffff:8.8.8.8" (an IPv4 address written as IPv6, as some logs do) is really 8.8.8.8
    if addr.version==6 and addr.ipv4_mapped:
        addr=addr.ipv4_mapped
    return str(addr)

def escape_md(text):
    """Escape Discord markdown in text from external sources (banners, hostnames, registry names)."""
    # brackets too: a banner like "[Login](https://...)" would otherwise render as a masked link
    return re.sub(r"([\\*_~`|\[\]])",r"\\\1",str(text))

_HOSTNAME=re.compile(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9])?)")

def hostname_from(text):
    """"https://Example.com/path" or "example.com." -> "example.com"; None when it is not a hostname."""
    text=(text or "").strip()
    if any(ord(c)<32 or c.isspace() or c=='\\' for c in text):
        return None
    try:
        url=urlsplit(text if "://" in text else "https://"+text)
        if url.scheme not in ("http","https") or url.username is not None or url.password is not None:
            return None
        if url.port is not None and not 1<=url.port<=65535:
            return None
        host=(url.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    except (ValueError,UnicodeError):
        return None
    return host if _HOSTNAME.fullmatch(host) else None

def clean_banner(banner):
    """Strip HTML tags and collapse whitespace so a service banner fits on one line (max 100 chars)."""
    banner=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',banner)
    banner=re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]','',banner)
    banner=re.sub(r'<[^>]+>','',banner)
    # Shodan banners contain real CR/LF/tab characters; collapse them so each port stays on one line
    banner=re.sub(r'\s+',' ',banner).strip()
    return banner[:100]+"..." if len(banner)>100 else banner

def split_message(m,limit=DISCORD_MESSAGE_LIMIT):
    """Split text on line boundaries into chunks Discord accepts; over-long lines are hard-wrapped."""
    if type(limit) is not int or not 1<=limit<=DISCORD_MESSAGE_LIMIT:
        raise ValueError("Message limit must be an integer from 1 to 2000")
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
            out.append("Flagged by: "+", ".join(escape_md(name) for name in sorted(engines)[:8])+(f" (+{len(engines)-8} more)" if len(engines)>8 else ""))
    if type(a.get("last_analysis_date")) is int:
        try:
            date=datetime.fromtimestamp(a["last_analysis_date"],timezone.utc).strftime("%Y-%m-%d")
        except (OverflowError,OSError,ValueError):
            pass
        else:
            out.append("Last analysed: "+date)
    return out

def summarize_shodan(host):
    """Owner, OS, hostnames and known CVEs from a Shodan host report, then one line per open port."""
    out=[]
    for key,label in (("org","Organization"),("isp","ISP"),("os","OS")):
        if host.get(key):
            out.append(f"{label}: {escape_md(host[key])}")
    tags = host.get("tags")
    if isinstance(tags, list) and tags:
        # Shodan's own labels: vpn, tor, cloud, honeypot, self-signed, compromised...
        out.append("Tags: "+", ".join(escape_md(t) for t in tags[:8]))
    if host.get("last_update"):
        out.append(f"Last scanned by Shodan: {str(host['last_update'])[:10]}")
    hostnames = host.get("hostnames")
    if isinstance(hostnames, list) and hostnames:
        out.append("Hostnames: "+", ".join(escape_md(h) for h in hostnames[:5]))
    vulns=host.get("vulns") or []
    if isinstance(vulns, dict):
        vulns = list(vulns)
    elif not isinstance(vulns, (list, tuple, set)):
        vulns = []
    vulns = [v for v in vulns if isinstance(v, str)]
    if vulns:
        shown=sorted(vulns)[:5]
        more=f" (+{len(vulns)-5} more)" if len(vulns)>5 else ""
        out.append(f"Known CVEs: {', '.join(escape_md(v) for v in shown)}{more}")
    records = host.get("data")
    if isinstance(records, list):
        ports = [d for d in records if isinstance(d, dict) and type(d.get("port")) is int and 0 <= d["port"] <= 65535]
        for d in sorted(ports, key=lambda item: item["port"]):
            transport = d.get("transport")
            banner = d.get("data")
            out.append(f"Port {d['port']}/{escape_md(transport if isinstance(transport, str) else 'tcp')} - {escape_md(clean_banner(banner if isinstance(banner, str) else ''))}")
    return out

def _vcard(entity,field):
    """First value of a vCard field (e.g. "fn", "email") in an RDAP entity's jCard."""
    card=entity.get("vcardArray")
    if not isinstance(card,list) or len(card)!=2 or not isinstance(card[1],list):
        return None
    for item in card[1]:
        if isinstance(item,list) and len(item)>=4 and item[0]==field and isinstance(item[3],str):
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
    events=rdap.get("events")
    for e in events if isinstance(events,list) else []:
        if not isinstance(e,dict):
            continue
        if e.get("eventAction")=="registration" and e.get("eventDate"):
            out.append(f"Registered: {str(e['eventDate'])[:10]}")
        elif e.get("eventAction")=="last changed" and e.get("eventDate"):
            out.append(f"Last changed: {str(e['eventDate'])[:10]}")
    entities=[]
    roots=rdap.get("entities")
    pending=list(reversed(roots)) if isinstance(roots,list) else []
    seen=set()
    # Iterative traversal includes contacts nested more than one level deep.
    while pending:
        entity=pending.pop()
        if not isinstance(entity,dict) or id(entity) in seen:
            continue
        seen.add(id(entity))
        entities.append(entity)
        children=entity.get("entities")
        if isinstance(children,list):
            pending.extend(reversed(children))
    def has_role(entity,role):
        roles=entity.get("roles")
        return isinstance(roles,list) and role in roles
    owner=next((_vcard(e,"fn") for e in entities if has_role(e,"registrant") and _vcard(e,"fn")),None)
    if owner:
        out.append(f"Owner: {escape_md(owner)}")
    abuse=next((_vcard(e,"email") for e in entities if has_role(e,"abuse") and _vcard(e,"email")),None)
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
        out.append(f"Usage type: {escape_md(d['usageType'])}")
    if d.get("domain"):
        out.append(f"Domain: {escape_md(d['domain'])}")
    # whitelisted means AbuseIPDB treats it as a known-good service (big DNS resolvers, crawlers)
    if d.get("isWhitelisted"):
        out.append("Whitelisted by AbuseIPDB")
    return out

def summarize_greynoise(report):
    """Whether GreyNoise saw the address mass-scanning (noise) or knows it as a benign service (riot)."""
    if report.get("riot") is not True and not isinstance(report.get("noise"),bool):
        return ["GreyNoise: no data"]
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
        ("AbuseIPDB",lambda r:summarize_abuseipdb(r or {})),
        ("GreyNoise",lambda r:summarize_greynoise(r or {})),
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
