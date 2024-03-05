
import asyncio
import functools
import httpx
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import aiometer
import logging

# Set up basic configuration for logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

async def fetch(client, request):
    try:
        response = await client.send(request)
        return {
            'text': response.text,
            'status_code': response.status_code,
            'url': request.url
        }
    except Exception as e:
        logging.warning(f"{request.url}\tFAILED")
        pass

async def fetch_tcp(client):
    pass

async def process_list(client, requests, speed_config=(16, 8)):
    max_at_once, max_per_second = speed_config
    jobs = [functools.partial(fetch, client, request) for request in requests]
    results = await aiometer.run_all(
        jobs,
        max_at_once=max_at_once,
        max_per_second=max_per_second
    )
    return results

def find_after_text(text, search, return_after=True):
    pattern = re.compile(fr"{text}(.*)$", re.IGNORECASE)
    result = pattern.match(search)
    if result:
        if return_after:
            return result.group()
        return result.group().replace(text, "")
    return None

# IANA
async def scan_iana():
    iana_url = "https://www.iana.org/domains/root/db"
    speed_config = (40, 20)
    headers = {'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'}

    client = httpx.AsyncClient()
    iana_first_page_request = [
        httpx.Request("GET", iana_url, headers=headers)
    ]
    iana_first_page = await process_list(client, iana_first_page_request, speed_config)
    iana_links = get_iana_domain_links(iana_url, iana_first_page[0]['text'])

    iana_whois_detail_pages = [
        httpx.Request("GET", link, headers=headers)
        for link in iana_links
    ]
    iana_detail_pages = await process_list(client, iana_whois_detail_pages, speed_config)
    for detail_page in iana_detail_pages:
        if detail_page:
            iana_whois_domain = get_iana_whois_domain(detail_page['text'])
            if iana_whois_domain:
                logging.info(f"{iana_whois_domain}\t{detail_page['url']}\t{detail_page['status_code']}")

def get_iana_domain_links(url, html_page):
    soup = BeautifulSoup(html_page, "html.parser")
    scheme = urlparse(url).scheme
    netloc = urlparse(url).netloc
    links = [
        f"{scheme}://{netloc}{link.get('href')}"
        for link in soup.find("table", {"class": "iana-table"}).find_all_next("a") if "/domains/root/db/" in link.get('href')
    ]
    return links

def get_iana_whois_domain(html):
    soup = BeautifulSoup(html, "html.parser")
    article = soup.find("article", class_="sidenav")
    if article and article.text:
        for line in article.text.splitlines():
            result = find_after_text("WHOIS Server: ", line, False)
            if result:
                return result
            else:
                logging.debug(f"WHOIS server for {line}: NOT FOUND")

## PSL
async def scan_psl():
    psl_url = "https://publicsuffix.org/list/public_suffix_list.dat"

    async with httpx.AsyncClient() as client:
        response = await client.get(psl_url)
        if response.status_code == 200:
            psl_data = response.text.splitlines()

    psl_domains = [line for line in psl_data if line and not line.startswith('//')]

    found_whois_servers = {}

    async def whois_query(domain):
        cmd = f"echo {domain} | nc whois.iana.org 43"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode()

        whois_server = None
        for line in output.splitlines():
            if line.lower().startswith('whois:'):
                whois_server = line.split(':')[1].strip()
                break

        if whois_server:
            found_whois_servers[domain] = whois_server
            logging.debug(f"WHOIS server for {domain}: {whois_server}")
        else:
            logging.debug(f"WHOIS server for {domain}: NOT FOUND")

        if stderr:
            logging.error(f"WHOIS query error for {domain}: {stderr.decode()}")

    max_concurrent_whois = 50
    await aiometer.run_all(
        [functools.partial(whois_query, domain) for domain in psl_domains],
        max_at_once=max_concurrent_whois
    )

    logging.info("\nFound WHOIS servers:")
    for domain, server in found_whois_servers.items():
        logging.info(f"{domain}: {server}")

async def main():
    # await scan_iana()
    await scan_psl()

if __name__ == "__main__":
    asyncio.run(main())
