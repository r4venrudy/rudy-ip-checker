import os
import sys
from PIL import Image
import logging
import discord
import aiohttp
import asyncio
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

RATE_LIMIT=5

handler=logging.StreamHandler()
handler.addFilter(lambda record:'Shard ID None has successfully RESUMED session' not in record.getMessage())
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

from rudy_runtime.config import load_config as load_runtime_config
from rudy_runtime.cooldown import Cooldown, seconds_from_env
from rudy_runtime.formatting import build_report, canonical_ip, split_message

# VirusTotal's free tier allows 4 requests a minute, so space out each user's lookups
cooldown=Cooldown(seconds_from_env(os.environ.get("COOLDOWN_SECONDS"),15))

def load_config():
    return load_runtime_config({'TOKEN':'DISCORD_TOKEN','SHODAN_KEY':'SHODAN_KEY','VIRUSTOTAL_API_KEY':'VIRUSTOTAL_API_KEY'})

class AClient(discord.Client):
    def __init__(self,shodan_key,virustotal_key):
        super().__init__(intents=discord.Intents.default())
        self.shodan_key=shodan_key
        self.virustotal_key=virustotal_key
        self.session=None
        self.tor_cache=None
        self.tor_lock=asyncio.Lock()
        self.tree=discord.app_commands.CommandTree(self)
        self.rate_limiter=asyncio.Semaphore(RATE_LIMIT)

    async def setup_hook(self):
        # aiohttp sessions must be created inside the running event loop
        self.session=aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20))
        # sync once at startup; on_ready also fires on every reconnect
        await self.tree.sync()

    async def close(self):
        if self.session:
            await self.session.close()
        await super().close()

    async def fetch_shodan_host_info(self,ip):
        url=f"https://api.shodan.io/shodan/host/{ip}"
        params={'key':self.shodan_key,'minify':'false'}
        async with self.session.get(url,params=params) as r:
            if r.status==404:
                return None
            if r.status in (401,403):
                raise RuntimeError("Shodan rejected the API key")
            if r.status==429:
                raise RuntimeError("Shodan rate limit reached")
            r.raise_for_status()
            return await r.json()

    async def fetch(self,url):
        async with self.session.get(url) as r:
            r.raise_for_status()
            return await r.text()

    async def get_tor_exit_nodes(self):
        # the exit list is ~1 MB and changes slowly, so reuse it for 30 minutes;
        # the lock makes lookups that arrive together share one download
        async with self.tor_lock:
            return await self._tor_exit_nodes()

    async def _tor_exit_nodes(self):
        now=asyncio.get_running_loop().time()
        if self.tor_cache and now-self.tor_cache[0]<1800:
            return self.tor_cache[1]
        t=await self.fetch("https://check.torproject.org/exit-addresses")
        nodes={l.split()[1] for l in t.splitlines() if l.startswith("ExitAddress")}
        if not nodes:
            # an error page or empty body would otherwise make every address look like "Tor: No"
            raise RuntimeError("Tor exit list was empty")
        self.tor_cache=(now,nodes)
        return nodes

    async def fetch_rdap(self,ip):
        # python-whois only understands domains and returned an all-empty record for IPs;
        # rdap.org redirects to the regional registry (ARIN, RIPE, ...) that owns the block
        async with self.session.get(f"https://rdap.org/ip/{ip}",headers={'Accept':'application/rdap+json'}) as r:
            if r.status==404:
                return None
            r.raise_for_status()
            return await r.json(content_type=None)

    async def get_virustotal_data(self,ip):
        h={'x-apikey':self.virustotal_key}
        u=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        async with self.session.get(u,headers=h) as r:
            if r.status in (401,403):
                raise RuntimeError("VirusTotal rejected the API key")
            if r.status==429:
                raise RuntimeError("VirusTotal quota exceeded")
            r.raise_for_status()
            return await r.json()

    async def get_abuseipdb(self,ip):
        # optional source: only queried when ABUSEIPDB_KEY is set
        key=os.environ.get("ABUSEIPDB_KEY")
        if not key:
            return None
        params={'ipAddress':ip,'maxAgeInDays':'90'}
        async with self.session.get("https://api.abuseipdb.com/api/v2/check",params=params,headers={'Key':key,'Accept':'application/json'}) as r:
            if r.status in (401,403):
                raise RuntimeError("AbuseIPDB rejected the API key")
            if r.status==429:
                raise RuntimeError("AbuseIPDB daily limit reached")
            r.raise_for_status()
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

    async def update_presence():
        await c.change_presence(activity=discord.Activity(type=discord.ActivityType.watching,name=f"/ip on {len(c.guilds)} servers"))

    @c.event
    async def on_ready():
        logging.info("Logged in as %s on %d servers",c.user,len(c.guilds))
        await update_presence()

    @c.event
    async def on_guild_join(guild):
        await update_presence()

    @c.event
    async def on_guild_remove(guild):
        await update_presence()

    @c.tree.command(name="ip",description="Retrieve comprehensive information about an IP address.")
    async def ip(interaction:discord.Interaction,ip:str):
        # canonical form, so "2001:DB8::0001" and " 8.8.8.8 " match the Tor list and APIs
        ip=canonical_ip(ip)
        if ip is None:
            await interaction.response.send_message("Invalid IP address.",ephemeral=True)
            return
        if not ipaddress.ip_address(ip).is_global:
            await interaction.response.send_message("That is a private or reserved address; public sources have no data for it.",ephemeral=True)
            return
        wait=cooldown.take(interaction.user.id)
        if wait:
            await interaction.response.send_message(f"Please wait {int(wait)+1} seconds before the next lookup.",ephemeral=True)
            return
        await interaction.response.defer(ephemeral=False)
        async with c.rate_limiter:
            await run_lookup(interaction,ip)

    async def run_lookup(interaction,ip):
        results,failed={},set()
        async def section(name,coro):
            try:
                results[name]=await coro
            except Exception as e:
                logging.warning("%s lookup failed for %s: %s",name,ip,e)
                failed.add(name)
        sources=[
            ("Shodan",c.fetch_shodan_host_info(ip)),
            ("Tor",c.get_tor_exit_nodes()),
            ("WHOIS",c.fetch_rdap(ip)),
            ("VirusTotal",c.get_virustotal_data(ip)),
        ]
        if os.environ.get("ABUSEIPDB_KEY"):
            sources.append(("AbuseIPDB",c.get_abuseipdb(ip)))
        # the sources are independent, so query them at the same time
        await asyncio.gather(*(section(name,coro) for name,coro in sources))
        await c.send_split_messages(interaction,build_report(ip,results,failed))

    c.run(token)

if __name__=="__main__":
    try:
        config=load_config()
    except ValueError as e:
        logging.error("%s (set them as environment variables or in config.json)",e)
        raise SystemExit(1)
    if '--check-config' in sys.argv:
        print('Configuration and dependencies ready')
        raise SystemExit(0)
    run_discord_bot(config["TOKEN"],config["SHODAN_KEY"],config["VIRUSTOTAL_API_KEY"])
