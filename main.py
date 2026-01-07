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
    return all(k in config for k in required)

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

class AClient(discord.Client):
    def __init__(self,shodan_key,virustotal_key):
        super().__init__(intents=discord.Intents.default())
        self.shodan_key=shodan_key
        self.virustotal_key=virustotal_key
        self.session=aiohttp.ClientSession()
        self.tree=discord.app_commands.CommandTree(self)
        self.rate_limiter=asyncio.Semaphore(RATE_LIMIT)

    async def close(self):
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
        t=await self.fetch("https://check.torproject.org/exit-addresses")
        return [l.split()[1] for l in t.splitlines() if l.startswith("ExitAddress")]

    async def fetch_whois_data(self,ip):
        loop=asyncio.get_event_loop()
        return await loop.run_in_executor(None,whois.whois,ip)

    async def get_virustotal_data(self,ip):
        h={'x-apikey':self.virustotal_key}
        u=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        async with self.session.get(u,headers=h) as r:
            return await r.json()

    async def send_split_messages(self,i,m):
        chunks=[]
        cur=""
        for line in m.split("\n"):
            if len(cur)+len(line)>DISCORD_MESSAGE_LIMIT:
                chunks.append(cur)
                cur=""
            cur+=line+"\n"
        if cur:
            chunks.append(cur)
        if not i.response.is_done():
            await i.response.defer(ephemeral=False)
        await i.followup.send(chunks[0])
        for c in chunks[1:]:
            await i.channel.send(c)

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
        await interaction.response.defer(ephemeral=False)
        info=[]
        s=await c.fetch_shodan_host_info(ip)
        if s:
            for d in s.get("data",[]):
                info.append(f"Port {d.get('port')} - {clean_banner(d.get('data',''))}")
        tor=await c.get_tor_exit_nodes()
        info.append("Tor: Yes" if ip in tor else "Tor: No")
        w=await c.fetch_whois_data(ip)
        for k,v in w.items():
            info.append(f"{k}: {v}")
        vt=await c.get_virustotal_data(ip)
        for k,v in vt.get("data",{}).get("attributes",{}).items():
            info.append(f"{k}: {v}")
        await c.send_split_messages(interaction,"\n".join(info))

    c.run(token)

if __name__=="__main__":
    config=load_config()
    if check_configurations(config):
        run_discord_bot(config["TOKEN"],config["SHODAN_KEY"],config["VIRUSTOTAL_API_KEY"])
