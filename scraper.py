import asyncio
import socket
import functools
import httpx
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import aiometer
import logging
from typing import List, Set, Dict, Optional
import argparse
from urllib.parse import urljoin

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


MAX_CONCURRENT = 50


class Fetcher:
    """
    A utility class for making asynchronous HTTP requests.
    """
    @staticmethod
    async def fetch_text(url: str, headers: Optional[Dict[str, str]]=None) -> str:
        # Add a default user-agent if none is provided
        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.text


class Scraper:
    """
    A generic scraper class.
    """
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]]=None):
        # Add a default user-agent if none is provided in the headers
        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")
        self.base_url = base_url
        self.headers = headers

    async def get_html(self, path: str="") -> str:
        url = urljoin(self.base_url, path)
        return await Fetcher.fetch_text(url, self.headers)

    def parse_links(self, html: str, link_pattern: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        scheme, netloc = urlparse(self.base_url).scheme, urlparse(self.base_url).netloc
        links = [
            f"{scheme}://{netloc}{link.get('href')}"
            for link in soup.find_all("a", href=True) if re.match(link_pattern, link.get('href'))
        ]
        return links

    def extract_tld(self, domain: str) -> str:
        """
        Extract the top-level domain (TLD) from a given domain name.

        Args:
            domain (str): The full domain name.

        Returns:
            str: The TLD of the domain.
        """
        # Split the domain by dots and take the last part as the TLD
        parts = domain.split('.')
        # In case of a single-part domain (highly unlikely in this context), return it as is
        return parts[-1] if len(parts) > 0 else domain

    async def get_data(self) -> Set[str]:
        """
        Override this in a subclass to implement specific scraping and data extraction logic.
        """
        return set()


# Example Implementation for IANA Scraper
class IANAScraper(Scraper):
    def __init__(self, headers: Optional[Dict[str, str]]=None):
        super().__init__("https://www.iana.org/domains/root/db")
    
    # Uses aiometer for controlled concurrency
    async def get_data(self) -> Set[str]:
        html = await self.get_html()
        domain_links = self.parse_links(html, r"^/domains/root/db/")
        logging.info(f"Found {len(domain_links)} domain links to process.")

        # Fetch WHOIS servers concurrently, respecting speed constraints
        whois_servers = await self.fetch_whois_servers(set(domain_links))
        return whois_servers

    async def fetch_whois_servers(self, links: Set[str]) -> Set[Dict[str, str]]:
        whois_servers_with_domains = set()
        async with httpx.AsyncClient() as client:
            async def fetch_server(link):
                domain_extension = link.split('/')[-1].replace('.html', '')
                try:
                    resp = await client.get(link)
                    resp.raise_for_status()
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    article = soup.find('article', class_='hemmed sidenav')
                    # If the <article> tag is found
                    if article:
                        paragraphs = article.find_all('p')
                        for p in paragraphs:
                            if 'WHOIS Server:' in p.text:
                                # Splitting the text to extract the WHOIS server's value
                                whois_server = p.text.split('WHOIS Server:')[1].strip()
                                return {'domain_extension': domain_extension, 'whois_server': whois_server}
                except Exception as e:
                    logging.warning(f"Failed to extract WHOIS server from {link}: {e}")
                return None

            tasks = [functools.partial(fetch_server, link) for link in links]
            results = await aiometer.run_all(tasks, max_at_once=MAX_CONCURRENT)
            whois_servers_with_domains.update(filter(None, results))
        return whois_servers_with_domains

    def parse_links(self, html: str, link_pattern: str) -> Set[str]:
        soup = BeautifulSoup(html, "html.parser")
        scheme, netloc = urlparse(self.base_url).scheme, urlparse(self.base_url).netloc
        links = {
            f"{scheme}://{netloc}{link.get('href')}"
            for link in soup.find_all("a", href=True) if re.match(link_pattern, link.get('href'))
        }
        return links


# Example Implementation for PSL Scraper
class PSLScraper(Scraper):
    async def get_data(self) -> List[Dict[str, str]]:
        logging.debug("Fetching PSL data")
        psl_url = self.base_url
        async with httpx.AsyncClient() as client:
            response = await client.get(psl_url)
            if response.status_code == 200:
                psl_data = response.text.splitlines()
                psl_domains = [line for line in psl_data if line and not line.startswith('//') and not line.startswith('!')]
                found_whois_servers = await self.query_whois_servers(psl_domains)
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
                    logging.debug(f"Found WHOIS server for {domain_extension}: {whois_server_url}")
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
            max_at_once=MAX_CONCURRENT
        )

        return found_whois_servers


# Modify the main function to include arguments parsing
async def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Scrape WHOIS servers from IANA or PSL")
    parser.add_argument("source", choices=["iana", "psl"], help="The data source to scrape: 'iana' for IANA WHOIS servers, 'psl' for Public Suffix List WHOIS servers")
    args = parser.parse_args()

    # Depending on the argument, perform the corresponding scraping
    if args.source == "iana":
        iana_scraper = IANAScraper()
        iana_data = await iana_scraper.get_data()
        logging.info(f"IANA Data: {iana_data}")
    elif args.source == "psl":
        psl_scraper = PSLScraper("https://publicsuffix.org/list/public_suffix_list.dat")
        psl_data = await psl_scraper.get_data()
        logging.info(f"PSL Data: {psl_data}")

if __name__ == "__main__":
    asyncio.run(main())
