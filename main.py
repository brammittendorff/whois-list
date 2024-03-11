
import asyncio
import time
import logging
import argparse
from scrapers.iana import IANAScraper
from scrapers.psl import PSLScraper

# Modify the main function to include arguments parsing
async def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Scrape WHOIS servers from IANA or PSL")
    parser.add_argument("source", choices=["iana", "psl"], help="The data source to scrape: 'iana' for IANA WHOIS servers, 'psl' for Public Suffix List WHOIS servers")
    parser.add_argument("--time", action="store_true", help="Show scraping completion time")
    parser.add_argument("--count", action="store_true", help="Count the number of data entries from the source")
    parser.add_argument("--concurrency", type=int, default=50, help="Number of concurrent tasks")
    parser.add_argument("--log", type=str, default="INFO", help="Set logging level")
    args = parser.parse_args()

    logging.basicConfig(level=args.log, format='%(asctime)s - %(levelname)s - %(message)s')

    start_time = time.time()  # Capture the start time

    # Depending on the argument, perform the corresponding scraping
    if args.source == "iana":
        iana_scraper = IANAScraper(max_concurrent=args.concurrency)
        iana_data = await iana_scraper.get_data()
        logging.info(iana_data)
        if args.count:
            logging.info(f"Count of IANA data: {len(iana_data)}")
    elif args.source == "psl":
        psl_scraper = PSLScraper(max_concurrent=args.concurrency)
        psl_data = await psl_scraper.get_data()
        logging.info(psl_data)
        if args.count:
            logging.info(f"Count of PSL data: {len(psl_data)}")

    if args.time:
        end_time = time.time()  # Capture the end time
        duration = end_time - start_time  # Calculate the duration
        logging.info(f"Scraping completed in {duration:.2f} seconds.")  # Log the duration

if __name__ == "__main__":
    asyncio.run(main())
