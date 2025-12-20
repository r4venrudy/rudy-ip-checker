##############################################
#          IP Checker Discord Bot            #
##############################################

Description:
-------------
This Discord bot provides comprehensive information about any IPv4 or IPv6 address.
It integrates multiple data sources including Shodan, VirusTotal, WHOIS, Tor exit nodes, and geolocation services.
The bot fetches open ports, service banners, historical Whois, VirusTotal analysis, and can even display screenshots for certain services.
All results are neatly formatted for Discord messages and embeds.

Key Features:
-------------
1. Shodan:
   - Fetch open ports, services, operating system info, SSL info, and locations.
   - Initiates scans if historical data is not enough.

2. VirusTotal:
   - Retrieve IP details, historical Whois data, URLs associated with the IP, community comments, and last analysis results.

3. WHOIS Lookup:
   - Provides registration and ownership details for the IP address.

4. TOR Exit Node Check:
   - Checks whether the IP is a TOR exit node.

5. Geolocation:
   - Returns city, region, country, timezone, postal code, and Google Maps link.

6. Screenshot Support:
   - Displays screenshots of services if available in Shodan data.

7. Handles Long Messages:
   - Automatically splits messages if they exceed Discord's 2000-character limit.

8. Modular & Safe:
   - API calls are wrapped to prevent the bot from crashing.
   - Reuses aiohttp session to reduce overhead.
   - Async-compatible for efficient performance.

Requirements:
-------------
- Python 3.10+
- Libraries:
    discord.py >= 2.3
    aiohttp
    shodan
    python-whois
- Shodan API Key
- VirusTotal API Key
- Discord Bot Token

Installation:
-------------
1. Clone or download this repository.
2. Install Python dependencies:
   pip install -r requirements.txt
   (or install manually: discord.py, aiohttp, shodan, python-whois)
3. Create a `config.json` file in the same folder with the following structure:
   {
       "TOKEN": "YOUR_DISCORD_BOT_TOKEN",
       "SHODAN_KEY": "YOUR_SHODAN_API_KEY",
       "VIRUSTOTAL_API_KEY": "YOUR_VIRUSTOTAL_API_KEY"
   }
4. Run the bot:
   python ip_checker_bot.py

Usage:
------
1. Invite the bot to your Discord server.
2. Use the slash command `/ip <IP_ADDRESS>` in any channel the bot has access to.
   Example: `/ip 8.8.8.8`
3. The bot will reply with:
   - Shodan analysis
   - VirusTotal analysis
   - WHOIS information
   - TOR exit node status
   - Geolocation info with Google Maps link
   - Open ports and possible services
   - Screenshots if available
4. Long results are split across multiple messages to fit Discord limits.

Notes:
------
- Ensure your Shodan API key has sufficient credits if you plan to request scans.
- VirusTotal limits may apply based on the API tier.
- WHOIS lookups may be slow for certain IP addresses since the library performs blocking network calls in a separate thread.
- TOR exit node list is fetched from the official TOR project list; it may take a few seconds.
- All IP addresses are validated before processing.

Logging:
--------
- The bot logs detailed information in the console, including API errors, connection issues, and command usage.
- Unnecessary Shard info logs are filtered out automatically.

Extending:
----------
- Add more API integrations by creating new async methods similar to `fetch_shodan_host_info` or `get_virustotal_data`.
- Add more command options in the Discord bot by using `client.tree.command`.
- Customize logging and error handling in the `AClient` class.

Support:
--------
- For issues with API keys, consult Shodan and VirusTotal documentation.
- For Discord bot issues, ensure the bot has proper permissions in your server.

Author:
-------
- Created by @r4ven.leet
- Designed for cybersecurity research, IP intelligence, and network reconnaissance.

License:
--------
- Use responsibly. Not intended for malicious purposes. Ensure compliance with all local laws and API terms of service.
