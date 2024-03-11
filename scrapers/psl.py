import asyncio
import functools
import httpx
import aiometer
import logging
from typing import List, Dict, Optional
from scraper import Scraper

class PSLScraper(Scraper):
    def __init__(self, headers: Optional[Dict[str, str]]=None, max_concurrent: int=50):
        super().__init__("https://publicsuffix.org/list/public_suffix_list.dat", max_concurrent=max_concurrent)

    async def get_data(self) -> List[Dict[str, str]]:
        logging.debug("Fetching PSL data")
        psl_url = self.base_url
        async with httpx.AsyncClient() as client:
            response = await client.get(psl_url)
            if response.status_code == 200:
                psl_data = response.text.splitlines()
                psl_domains = [line for line in psl_data if line and not line.startswith('//') and not line.startswith('!')]
                found_whois_servers = await self.query_whois_servers(psl_domains)
                # Deduplicate the found_whois_servers
                found_whois_servers = list({v['whois_server']: v for v in found_whois_servers}.values())
                return found_whois_servers
            else:
                logging.error("Failed to fetch PSL data")
                return []

    async def query_whois_servers(self, domains: list) -> List[Dict[str, str]]:
        found_whois_servers = []

        async def whois_query(domain):
            logging.debug(f"Querying WHOIS for domain: {domain}")
            # Standard WHOIS server and port
            whois_server = "whois.iana.org"
            port = 43

            try:
                # Open a connection to the WHOIS server
                reader, writer = await asyncio.open_connection(whois_server, port)
                # Send the query followed by CRLF
                query = f"{domain}\r\n".encode()
                writer.write(query)
                await writer.drain()

                # Read the response
                response = await reader.read(-1)  # Read until EOF

                # Extract the WHOIS server from the response
                whois_server_url = None
                for line in response.decode().splitlines():
                    if line.lower().startswith('whois:'):
                        whois_server_url = line.split(':')[1].strip()
                        break

                if whois_server_url:
                    domain_extension = self.extract_tld(domain)
                    found_whois_servers.append({'domain_extension': domain_extension, 'whois_server': whois_server_url})
                    logging.info(f"Found WHOIS server for {domain_extension}: {whois_server_url}")
                else:
                    logging.debug(f"No WHOIS server found for {domain}")

            except Exception as e:
                logging.error(f"Error querying WHOIS for {domain}: {e}")

            finally:
                writer.close()
                await writer.wait_closed()

        # Run the WHOIS queries with controlled concurrency
        await aiometer.run_all(
            [functools.partial(whois_query, domain) for domain in domains],
            max_at_once=self.max_concurrent
        )

        return found_whois_servers