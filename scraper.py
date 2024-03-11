import httpx
from typing import List, Dict, Optional
from urllib.parse import urljoin


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
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]]=None, max_concurrent: int=50):
        # Add a default user-agent if none is provided in the headers
        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")
        self.base_url = base_url
        self.headers = headers
        self.max_concurrent = max_concurrent

    async def get_html(self, path: str="") -> str:
        url = urljoin(self.base_url, path)
        return await Fetcher.fetch_text(url, self.headers)

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

    async def get_data(self) -> List[Dict[str, str]]:
        """
        Override this in a subclass to implement specific scraping and data extraction logic.
        """
        raise NotImplementedError("Override this in a subclass to implement specific scraping and data extraction logic.")
