import re
import asyncio
import functools
import aiometer
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse

async def fetch(client, request):
    try:
        response = await client.send(request)
        print(f"{request.url}\t{response.status_code}")
        return {
            'text': response.text,
            'status_code': response.status_code,
            'url': request.url
        }
    except Exception as e:
        # Sometimes a reques fails, but we don't care about that we will scrape it later
        print(f"{request.url}\tFAILED")
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
    # https://data.iana.org/TLD/tlds-alpha-by-domain.txt
    # Maybe scrape them faster by: echo a.ABARTH | nc whois.iana.org 43  ?
    
    iana_url = "https://www.iana.org/domains/root/db"

    # speed settings for iana.org without breaking (max_at_once, max_per_second)
    speed_config = (40, 20)

    # Headers are required by iana.org
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
            print(f"{iana_whois_domain}\t{detail_page['url']}\t{detail_page['status_code']}")
    
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

## PSL

async def scan_psl():
    psl_url = "https://publicsuffix.org/list/public_suffix_list.dat"

    client = httpx.AsyncClient()
    psl_first_page_request = [
        httpx.Request("GET", psl_url)
    ]
    psl_first_page = await process_list(client, psl_first_page_request)
    print(psl_first_page[0]['text'])


async def main():
    await scan_iana()
    # await scan_psl()

if __name__ == "__main__":
    asyncio.run(main())
