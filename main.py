import os
import sys
from PIL import Image
import json
import logging
import discord
import aiohttp
import asyncio
import whois
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import re
import ipaddress

def raven_fail():
    print("Kabul etmesende mahçupsun - r4ven.leet. Fotoğrafımı geri yükle")
    sys.exit(1)

BASE=os.path.dirname(os.path.abspath(__file__))
RAVEN=os.path.join(BASE,"raven.png")

if not os.path.isfile(RAVEN):
    raven_fail()

try:
    with Image.open(RAVEN) as img:
        img.verify()
except:
    raven_fail()

executor=ThreadPoolExecutor()
DISCORD_MESSAGE_LIMIT=2000
RATE_LIMIT=5

handler=logging.StreamHandler()
handler.addFilter(lambda record:'Shard ID None has successfully RESUMED session' not in record.getMessage())
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def load_config():
    with open('config.json','r') as f:
        return json.load(f)

def check_configurations(config):
    required=['TOKEN','SHODAN_KEY','VIRUSTOTAL_API_KEY']
    missing=[k for k in required if not config.get(k)]
    if missing:
        logging.error("config.json is missing: %s",", ".join(missing))
    return not missing

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def clean_banner(banner):
    banner=re.sub(r'<[^>]+>','',banner)
    banner=re.sub(r'\s+;|\\n|\\r|\\t',' ',banner)
    return banner[:100]+"..." if len(banner)>100 else banner

def split_message(m,limit=DISCORD_MESSAGE_LIMIT):
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
    a=vt.get("data",{}).get("attributes",{})
    if not a:
        return ["VirusTotal: no data"]
    st=a.get("last_analysis_stats",{})
    out=[f"VirusTotal: {st.get('malicious',0)} malicious, {st.get('suspicious',0)} suspicious, {st.get('harmless',0)} harmless"]
    for key,label in (("reputation","Reputation"),("as_owner","AS owner"),("asn","ASN"),("country","Country"),("network","Network")):
        if a.get(key) not in (None,""):
            out.append(f"{label}: {a[key]}")
    return out

class AClient(discord.Client):
    def __init__(self,shodan_key,virustotal_key):
        super().__init__(intents=discord.Intents.default())
        self.shodan_key=shodan_key
        self.virustotal_key=virustotal_key
        self.session=None
        self.tor_cache=None
        self.tree=discord.app_commands.CommandTree(self)
        self.rate_limiter=asyncio.Semaphore(RATE_LIMIT)

    async def setup_hook(self):
        # aiohttp sessions must be created inside the running event loop
        self.session=aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20))

    async def close(self):
        if self.session:
            await self.session.close()
        executor.shutdown(wait=False)
        await super().close()

    async def fetch_shodan_host_info(self,ip):
        url=f"https://api.shodan.io/shodan/host/{ip}"
        params={'key':self.shodan_key,'minify':'false'}
        async with self.session.get(url,params=params) as r:
            return await r.json() if r.status==200 else None

    async def fetch(self,url):
        async with self.session.get(url) as r:
            return await r.text()

    async def get_tor_exit_nodes(self):
        # the exit list is ~1 MB and changes slowly, so reuse it for 30 minutes
        now=asyncio.get_running_loop().time()
        if self.tor_cache and now-self.tor_cache[0]<1800:
            return self.tor_cache[1]
        t=await self.fetch("https://check.torproject.org/exit-addresses")
        nodes={l.split()[1] for l in t.splitlines() if l.startswith("ExitAddress")}
        self.tor_cache=(now,nodes)
        return nodes

    async def fetch_whois_data(self,ip):
        loop=asyncio.get_event_loop()
        return await loop.run_in_executor(None,whois.whois,ip)

    async def get_virustotal_data(self,ip):
        h={'x-apikey':self.virustotal_key}
        u=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        async with self.session.get(u,headers=h) as r:
            return await r.json()

    async def send_split_messages(self,i,m):
        chunks=split_message(m)
        if not i.response.is_done():
            await i.response.defer(ephemeral=False)
        await i.followup.send(chunks[0])
        for c in chunks[1:]:
            await i.followup.send(c)

def run_discord_bot(token,shodan_key,virustotal_key):
    c=AClient(shodan_key,virustotal_key)

    @c.event
    async def on_ready():
        await c.tree.sync()
        await c.change_presence(activity=discord.Activity(type=discord.ActivityType.watching,name=f"/ip on {len(c.guilds)} servers"))

    @c.tree.command(name="ip",description="Retrieve comprehensive information about an IP address.")
    async def ip(interaction:discord.Interaction,ip:str):
        if not validate_ip(ip):
            await interaction.response.send_message("Invalid IP address.",ephemeral=True)
            return
        if not ipaddress.ip_address(ip).is_global:
            await interaction.response.send_message("That is a private or reserved address; public sources have no data for it.",ephemeral=True)
            return
        await interaction.response.defer(ephemeral=False)
        info=[]
        async def section(name,coro):
            try:
                return await coro
            except Exception as e:
                logging.warning("%s lookup failed for %s: %s",name,ip,e)
                info.append(f"{name}: lookup failed")
                return None
        s=await section("Shodan",c.fetch_shodan_host_info(ip))
        if s:
            for d in s.get("data",[]):
                info.append(f"Port {d.get('port')} - {clean_banner(d.get('data',''))}")
        tor=await section("Tor",c.get_tor_exit_nodes())
        if tor is not None:
            info.append("Tor: Yes" if ip in tor else "Tor: No")
        w=await section("WHOIS",c.fetch_whois_data(ip))
        if w:
            for k,v in w.items():
                info.append(f"{k}: {v}")
        vt=await section("VirusTotal",c.get_virustotal_data(ip))
        if vt:
            info.extend(summarize_virustotal(vt))
        await c.send_split_messages(interaction,"\n".join(info))

    c.run(token)

if __name__=="__main__":
    config=load_config()
    if check_configurations(config):
        run_discord_bot(config["TOKEN"],config["SHODAN_KEY"],config["VIRUSTOTAL_API_KEY"])
