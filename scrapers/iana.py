import functools
import httpx
from bs4 import BeautifulSoup
import aiometer
import logging
from typing import List, Set, Dict, Optional
from scraper import Scraper


class IANAScraper(Scraper):
    def __init__(self, headers: Optional[Dict[str, str]]=None, max_concurrent: int=50):
        super().__init__("https://www.iana.org/domains/root/db", max_concurrent=max_concurrent)

    async def get_data(self) -> List[Dict[str, str]]:
        domain_links = await self.get_domain_links("http://data.iana.org/TLD/tlds-alpha-by-domain.txt")
        # Fetch WHOIS servers concurrently, respecting speed constraints
        whois_servers = await self.fetch_whois_servers(domain_links)
        return whois_servers

    async def get_domain_links(self, url: str) -> Set[str]:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            domains = {f"{self.base_url}/{line.lower()}.html" for line in lines if not line.startswith("#")}
        return domains

    async def fetch_whois_servers(self, links: Set[str]) -> List[Dict[str, str]]:
        found_whois_servers = []  # Changed to a list
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
                                logging.info(f"Found WHOIS server for {domain_extension}: {whois_server}")
                                return {'domain_extension': domain_extension, 'whois_server': whois_server}
                except Exception as e:
                    logging.warning(f"Failed to extract WHOIS server from {link}: {e}")
                return None

            tasks = [functools.partial(fetch_server, link) for link in links]
            results = await aiometer.run_all(tasks, max_at_once=self.max_concurrent)
            found_whois_servers.extend(filter(None, results))  # Use extend for lists
        return found_whois_servers
