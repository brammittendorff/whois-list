import re
import asyncio
from urllib.parse import urlparse
import concurrent.futures
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import cpu_count 
import numpy as np 

import aiohttp
from bs4 import BeautifulSoup

num_cores = cpu_count()
max_concurrency = 1
max_concurrency_per_host = 3
sem = asyncio.Semaphore(max_concurrency)

async def fetch(session, url):
    print(url)
    print(sem)
    async with sem: # semaphore limits num of simultaneous downloads 
        async with session.get(url) as response:
            if response.status != 200:
                response.raise_for_status()
            return await response.text()

async def fetch_task(pages_for_task):
    print(pages_for_task)
    async with aiohttp.ClientSession() as session:
        tasks = [ 
            fetch(page, session) 
            for page in pages_for_task if len(page)
        ] 
        list_of_lists = await asyncio.gather(*tasks) 
        return sum(list_of_lists, []) 
 
def asyncio_wrapper(pages_for_task):
    return asyncio.run(fetch_task(pages_for_task))

def asyncio_rate_limit_get(pages):
    executor = ProcessPoolExecutor(max_workers=num_cores)
    print(num_cores)
    print(np.array_split(pages, num_cores))
    print(type(pages))
    tasks = [ 
        executor.submit(asyncio_wrapper, pages_for_task) 
        for pages_for_task in np.array_split(pages, num_cores) if len(pages_for_task)
    ]
    doneTasks, _ = concurrent.futures.wait(tasks) 

    results = [ 
        item.result() 
        for item in doneTasks 
    ]

    return results

async def scan_iana():
    iana_url = ["https://www.iana.org/domains/root/db"]
    whois_domains = []
    # iana_first_page = asyncio_rate_limit_get(iana_url)
    # print(iana_first_page)
    urls = ['https://nerd.host']
    test = asyncio_rate_limit_get(urls)
    print(test)
    
    # iana_links = get_iana_domain_links(iana_url, iana_first_page)
    # html_sub_pages = asyncio_rate_limit_get(iana_links)
    # for sub_page in html_sub_pages:
    #     print(get_iana_whois_domain(sub_page))
    #     whois_domains.append(get_iana_whois_domain(sub_page))
    # return whois_domains

def get_iana_domain_links(url, html_page):
    soup = BeautifulSoup(html_page, "html.parser")
    scheme = urlparse(url).scheme
    netloc = urlparse(url).netloc
    links = [
        f"{scheme}://{netloc}{link.get('href')}"
        for link in soup.find("table", class_="iana-table").find_all_next("a")
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

def find_after_text(text, search, return_after=True):
    pattern = re.compile(fr"{text}(.*)$", re.IGNORECASE)
    result = pattern.match(search)
    if result:
        if return_after:
            return result.group()
        return result.group().replace(text, "")
    return None

async def main():
    return await scan_iana()

# Run program
loop = asyncio.get_event_loop() 
loop.run_until_complete(main())
