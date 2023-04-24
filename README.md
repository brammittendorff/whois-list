# A Simple Whoist List Scraper

For now we get the data from:

- https://www.iana.org/domains/root/db

And then scrape the whois servers so we know where to get the information from (fast).


DB Scheme

```
tlds

id,tld,source,created_at,updated_at

whois

id,tld_id,server,speed,created_at,updated_at

```