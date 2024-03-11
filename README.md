
# WHOIS Servers Scraper

This script allows you to scrape the WHOIS servers from the IANA website or the Public Suffix List (PSL).

## Usage

You can run the script with the following command:

python scraper.py [source] [--time] [--count]

Here is a description of the arguments:

- `source`: This argument is required. It specifies the data source to scrape. You can specify either `iana` for IANA WHOIS servers or `psl` for Public Suffix List WHOIS servers.
- `--time`: This argument is optional. If specified, the script will show the scraping completion time.
- `--count`: This argument is optional. If specified, the script will count the number of data entries from the source.

## Example

Here is an example of how to run the script:

python scraper.py iana --time --count

This command will scrape the WHOIS servers from the IANA website, show the scraping completion time, and count the number of data entries.

## Output

The script will output the scraped WHOIS servers in the following format:

[
    {
        "domain_extension": "com",
        "whois_server": "whois.verisign-grs.com"
    },
    ...
]

Each object in the array represents a domain extension and its corresponding WHOIS server.

## Dependencies

This script requires the following Python libraries:

- `httpx`
- `beautifulsoup4`
- `aiometer`
- `argparse`
- `logging`
- `time`
- `functools`
- `re`
- `asyncio`

Please ensure to install the required libraries before running the script. You can install them with pip:

pip install httpx beautifulsoup4 aiometer

## Note

The script uses controlled concurrency to make the scraping process faster and to respect the speed constraints of the websites. The maximum number of concurrent tasks is defined by the `MAX_CONCURRENT` constant in the script. You can adjust this value according to your needs and the capabilities of your system.
