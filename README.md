
# A Simple Whois List Scraper

For now we get the data from:

- https://www.iana.org/domains/root/db

And then scrape the whois servers so we know where to get the information from (fast).

Additionally, we also get data from:

- https://publicsuffix.org/list/public_suffix_list.dat

This allows us to gather a comprehensive list of whois servers across different top-level domains (TLDs) and public suffixes.

## DB Scheme

tlds

id,tld,source,created_at,updated_at

whois

id,tld_id,server,speed,created_at,updated_at


## Implementation Details

We use asynchronous programming (with `asyncio` and `httpx`) to fetch data concurrently, improving the efficiency of our scraper. We also utilize `aiometer` to manage the rate of our requests to avoid overwhelming the servers.

### Logging

Basic logging is set up to debug and track the progress of our scrapes, including any potential errors that might occur during the process.

### Unique Features

- **Concurrency Control**: We can adjust the number of concurrent requests and the rate at which they are made to optimize performance without getting blocked by the servers.
- **Error Handling**: The scraper is designed to handle errors gracefully, logging warnings for failed requests without stopping the entire process.
- **Data Extraction**: Utilizes `BeautifulSoup` for parsing HTML content and extracting relevant data, such as whois server information.
- **Command Line Whois Queries**: For domains listed in the Public Suffix List, we perform whois queries using the command line to find the corresponding whois server.

### Future Improvements

- Implement a database to store the scraped whois server information for easy retrieval and analysis.
- Expand the list of sources from which whois server information is scraped to cover more TLDs and domain types.
- Improve error handling and logging for better debuggability and monitoring of the scraping process.
