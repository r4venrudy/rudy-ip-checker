import json
import logging
import discord
import aiohttp
import asyncio
from shodan import Shodan
import whois
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import re
import base64
from io import BytesIO
import ipaddress

executor = ThreadPoolExecutor()

DISCORD_MESSAGE_LIMIT = 2000
RATE_LIMIT = 5
SHODAN_SCAN_SLEEP = 30

handler = logging.StreamHandler()
handler.addFilter(lambda record: 'Shard ID None has successfully RESUMED session' not in record.getMessage())
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --------------------- CONFIG ---------------------
def load_config():
    with open('config.json', 'r') as file:
        return json.load(file)

def check_configurations(config):
    required_keys = ['TOKEN', 'SHODAN_KEY', 'VIRUSTOTAL_API_KEY']
    missing_keys = [key for key in required_keys if key not in config]
    if missing_keys:
        logging.error(f"Missing keys in config.json: {', '.join(missing_keys)}")
        return False
    return True

# --------------------- IP VALIDATION ---------------------
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# --------------------- UTILITY FUNCTIONS ---------------------
def clean_banner(banner: str) -> str:
    banner_no_html = re.sub(r'<[^>]+>', '', banner)
    cleaned = re.sub(r'\s+;|\\n|\\r|\\t', ' ', banner_no_html)
    return cleaned[:100] + "..." if len(cleaned) > 100 else cleaned

# --------------------- DISCORD CLIENT ---------------------
class AClient(discord.Client):
    def __init__(self, shodan_api_key, virustotal_api_key):
        super().__init__(intents=discord.Intents.default())
        self.shodan_key = shodan_api_key
        self.virustotal_key = virustotal_api_key
        self.session = aiohttp.ClientSession()
        self.tree = discord.app_commands.CommandTree(self)
        self.activity = discord.Activity(type=discord.ActivityType.watching, name="/ip")
        self.rate_limiter = asyncio.Semaphore(RATE_LIMIT)

    async def close(self):
        await self.session.close()
        executor.shutdown(wait=False)
        await super().close()

    # --------------------- SHODAN ---------------------
    async def fetch_shodan_host_info(self, ip):
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {'key': self.shodan_key, 'minify': 'false'}
        async with self.session.get(url, params=params) as response:
            if response.status == 200:
                return await response.json()
            elif response.status == 404:
                logging.info(f"No data found for IP {ip} on Shodan.")
                return None
            else:
                logging.error(f"Shodan API error {response.status} for IP {ip}")
                return None

    async def request_shodan_scan(self, ip):
        url = f"https://api.shodan.io/shodan/scan?key={self.shodan_key}"
        data = {"ips": ip}
        async with self.session.post(url, json=data) as response:
            if response.status == 200:
                return await response.json(), False
            elif response.status == 401:
                logging.error(f"Shodan scan limit reached for IP {ip}.")
                return None, True
            else:
                logging.error(f"Shodan scan request failed for IP {ip} with status {response.status}")
                return None, False

    async def check_shodan_scan_status(self, scan_id):
        url = f"https://api.shodan.io/shodan/scan/{scan_id}?key={self.shodan_key}"
        async with self.session.get(url) as response:
            if response.status == 200:
                return await response.json()
            logging.error(f"Failed to fetch Shodan scan status {scan_id}, status {response.status}")
            return None

    # --------------------- VIRUSTOTAL ---------------------
    async def fetch_virustotal_endpoint(self, endpoint):
        headers = {'x-apikey': self.virustotal_key}
        async with self.session.get(endpoint, headers=headers) as response:
            return await response.json()

    async def get_virustotal_data(self, ip):
        API_URL = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        ip_data = await self.fetch_virustotal_endpoint(API_URL)
        whois_data = await self.fetch_virustotal_endpoint(f"{API_URL}/historical_whois")
        urls_data = await self.fetch_virustotal_endpoint(f"{API_URL}/urls")
        comments_data = await self.fetch_virustotal_endpoint(f"{API_URL}/comments")

        last_analysis_results = ip_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

        comments_info = []
        for comment in comments_data.get("data", []):
            attr = comment.get("attributes", {})
            date = attr.get("date")
            if date: date = datetime.utcfromtimestamp(date).strftime('%Y-%m-%d %H:%M:%S')
            comments_info.append({
                "date": date,
                "html": attr.get("html"),
                "tags": attr.get("tags", []),
                "text": attr.get("text"),
                "votes": attr.get("votes", {})
            })

        return {
            "ip_info": ip_data.get("data", {}).get("attributes", {}),
            "whois_info": whois_data.get("data", []),
            "urls_info": urls_data.get("data", []),
            "comments_info": comments_info,
            "last_analysis_results": last_analysis_results
        }

    # --------------------- TOR ---------------------
    async def get_tor_exit_nodes(self):
        TOR_EXIT_LIST_URL = "https://check.torproject.org/exit-addresses"
        try:
            text = await self.fetch(self.session, TOR_EXIT_LIST_URL)
            return [line.split(" ")[1] for line in text.splitlines() if line.startswith("ExitAddress")]
        except Exception as e:
            logging.error(f"Error fetching Tor exit nodes: {e}")
            return []

    async def fetch(self, session, url):
        async with session.get(url) as response:
            return await response.text()

    # --------------------- GEOLOCATION ---------------------
    async def get_geolocation(self, ip):
        url = f"https://ipinfo.io/{ip}/json"
        async with self.session.get(url) as response:
            if response.status == 200:
                try:
                    return await response.json()
                except json.JSONDecodeError:
                    logging.error(f"Invalid JSON response for IP {ip}")
            else:
                logging.error(f"Geolocation API error {response.status} for IP {ip}")
            return None

    # --------------------- WHOIS ---------------------
    async def fetch_whois_data(self, ip):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, whois.whois, ip)

    # --------------------- MESSAGE UTILITIES ---------------------
    async def send_split_messages(self, interaction, message: str):
        chunks, current_chunk = [], ""
        lines = message.split("\n")
        for line in lines:
            while len(line) > DISCORD_MESSAGE_LIMIT:
                sub_line = line[:DISCORD_MESSAGE_LIMIT]
                if len(current_chunk) + len(sub_line) > DISCORD_MESSAGE_LIMIT:
                    chunks.append(current_chunk)
                    current_chunk = ""
                current_chunk += sub_line + "\n"
                line = line[DISCORD_MESSAGE_LIMIT:]
            if len(current_chunk) + len(line) > DISCORD_MESSAGE_LIMIT:
                chunks.append(current_chunk)
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"
        if current_chunk:
            chunks.append(current_chunk)

        if not interaction.response.is_done():
            await interaction.response.defer(ephemeral=False)
        await interaction.followup.send(content=chunks[0])
        for chunk in chunks[1:]:
            await interaction.channel.send(chunk)


# --------------------- BOT ---------------------
def run_discord_bot(token, shodan_api_key, virustotal_api_key):
    client = AClient(shodan_api_key, virustotal_api_key)

    @client.event
    async def on_ready():
        await client.tree.sync()
        logging.info(f"{client.user} is ready and running in {len(client.guilds)} servers.")
        for guild in client.guilds:
            logging.info(f" - {guild.name} (Owner: {guild.owner_id})")
        await client.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=f"/ip on {len(client.guilds)} servers"))

    @client.tree.command(name="ip", description="Retrieve comprehensive information about an IP address.")
    async def ip(interaction: discord.Interaction, ip: str):
        if not validate_ip(ip):
            await interaction.response.send_message("Invalid IP address.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=False)
        current_message = f"Scanning and analyzing `{ip}` for `{interaction.user.name}`...\n"
        status_message = await interaction.followup.send(current_message)

        info = []
        open_ports = []

        # --------------------- SHODAN ---------------------
        try:
            shodan_data = await client.fetch_shodan_host_info(ip)
            if shodan_data:
                info.append(f"**Shodan Data for {ip}:**")
                for service in shodan_data.get('data', []):
                    banner = clean_banner(service.get('data', 'No banner'))
                    port = service.get('port', 'N/A')
                    product = service.get('product', 'N/A')
                    os_info = service.get('os', 'N/A')
                    location = f"{service.get('location', {}).get('city','Unknown')}, {service.get('location', {}).get('country_name','Unknown')}"
                    info.append(f"Port {port} - {product} - {os_info} - {location} - Banner: {banner}")
                    open_ports.append({"link": f"{ip}:{port}", "summary": f"{product}, {os_info}"})
        except Exception as e:
            logging.error(f"Shodan error: {e}")
            info.append("Error fetching Shodan data.")

        # --------------------- TOR ---------------------
        try:
            exit_nodes = await client.get_tor_exit_nodes()
            info.append(f"Tor exit node: {'Yes' if ip in exit_nodes else 'No'}")
        except Exception as e:
            logging.error(f"TOR error: {e}")

        # --------------------- WHOIS ---------------------
        try:
            whois_data = await client.fetch_whois_data(ip)
            if whois_data:
                info.append(f"**WHOIS Data for {ip}:**")
                for key, value in whois_data.items():
                    info.append(f"{key}: {value}")
        except Exception as e:
            logging.error(f"WHOIS error: {e}")

        # --------------------- VIRUSTOTAL ---------------------
        try:
            vt_data = await client.get_virustotal_data(ip)
            info.append("**VirusTotal Data:**")
            ip_info = vt_data.get("ip_info", {})
            for k, v in ip_info.items():
                info.append(f"{k}: {v}")
        except Exception as e:
            logging.error(f"VirusTotal error: {e}")

        await client.send_split_messages(interaction, "\n".join(info))

    client.run(token)


# --------------------- MAIN ---------------------
if __name__ == "__main__":
    config = load_config()
    if check_configurations(config):
        run_discord_bot(config.get("TOKEN"), config.get("SHODAN_KEY"), config.get("VIRUSTOTAL_API_KEY"))