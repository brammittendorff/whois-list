import socket
import logging
import itertools
import string
import concurrent.futures
import time
import random
import re
import argparse
import json
from collections import defaultdict
from collections import deque

class TldConfig:
    def __init__(self, initial_batch_size=10, max_batch_size=100, min_batch_size=1, initial_delay=1):
        self.batch_size = initial_batch_size
        self.max_batch_size = max_batch_size
        self.min_batch_size = min_batch_size
        self.delay = initial_delay
        self.consecutive_successes = 0
        self.rate_limit_history = deque(maxlen=5)  # Keep track of last 5 rate limit events

# Configure logging to capture errors
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to perform a WHOIS query to a specified WHOIS server
def custom_whois_query(domain, whois_server, port=43, timeout=10):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((whois_server, port))
            s.sendall((domain + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            response_text = response.decode('utf-8', errors='ignore')
            if "error: ratelimit exceeded" in response_text.lower():
                logging.warning(f"Rate limit exceeded for {domain} on {whois_server}")
                return "ratelimit"
            if "refer:" in response_text:
                refer_whois_server = response_text.split("refer:")[1].split()[0].strip()
                logging.info(f"Redirecting WHOIS query to {refer_whois_server}")
                return custom_whois_query(domain, refer_whois_server)
            return response_text
    except socket.timeout:
        logging.error(f"Timeout error querying WHOIS server {whois_server} for {domain}")
        return "timeout"
    except Exception as e:
        logging.error(f"Error querying WHOIS server {whois_server} for {domain}: {e}")
        return None

# Function to extract domain information from WHOIS response
def extract_domain_info(whois_response):
    creation_date = re.search(r'Creation Date:\s?(.+)', whois_response)
    status = re.search(r'Status:\s?(.+)', whois_response)
    domain_name = re.search(r'Domain Name:\s?(.+)', whois_response)
    
    info = {
        "creation_date": creation_date.group(1).strip() if creation_date else "Unknown",
        "status": status.group(1).strip() if status else "Unknown",
        "domain_name": domain_name.group(1).strip() if domain_name else "Unknown",
    }
    
    return info

# Function to test the response time and success rate of WHOIS servers
def test_whois_server(whois_server, test_domain, test_retries=3):
    total_time = 0
    successful_attempts = 0
    
    for _ in range(test_retries):
        start_time = time.time()
        response = custom_whois_query(test_domain, whois_server)
        end_time = time.time()
        
        if response:
            response_time = end_time - start_time
            logging.info(f"WHOIS server {whois_server} responded in {response_time:.4f} seconds.")
            total_time += response_time
            successful_attempts += 1
        else:
            logging.error(f"WHOIS server {whois_server} did not respond successfully.")
    
    if successful_attempts > 0:
        return total_time / successful_attempts  # Return average response time
    else:
        return float('inf')  # Return a high value if no successful attempts

# Function to determine the best WHOIS servers
def find_best_whois_servers(whois_servers, tld, top_n=2):
    test_domain = f"example.{tld}"
    server_performance = {}
    
    for whois_server in whois_servers:
        avg_time = test_whois_server(whois_server, test_domain)
        if avg_time != float('inf'):
            server_performance[whois_server] = avg_time
    
    # Sort servers by response time and return the top_n fastest servers
    sorted_servers = sorted(server_performance, key=server_performance.get)
    best_servers = sorted_servers[:top_n]
    
    logging.info(f"Best WHOIS servers selected for .{tld}: {best_servers}")
    return best_servers

# Function to check if a domain is available using the best WHOIS servers
def check_domain(domain, whois_servers, retries=5, initial_delay=0.1):
    server_index = 0
    delay = initial_delay
    for attempt in range(retries):
        whois_server = whois_servers[server_index]
        
        response = custom_whois_query(domain, whois_server)
        if response == "ratelimit":
            logging.warning(f"Rate limit hit for {domain} on {whois_server}. Backing off...")
            return "ratelimit"  # Return "ratelimit" immediately
        
        if response == "timeout":
            logging.warning(f"Timeout for {domain} on {whois_server}. Retrying...")
            time.sleep(delay)
            delay *= 1.5  # Slightly increase delay for timeouts
            continue  # Retry the same domain after a timeout
        
        if response:
            # Generic checks for domain availability
            domain_available = any(phrase in response.lower() for phrase in [
                "no match", "not found", "available", "free", "status: free", "domain not found", "is free",
                "no entries found", "%% not found", "no information available", f"{domain} is free"
            ])
            
            # Generic checks for taken domains
            domain_taken = any(phrase in response for phrase in [
                "Domain Name:", "domain:", "status: active", "status: ok", "status:      active",
                "Registry Domain ID:", "Registrar:", "Registrant:", "status:                        ACTIVE",
                "created:", "last modified:", "renewal date:", "option created:"
            ])

            if domain_available:
                logging.info(f"{domain} is available (checked via {whois_server})!")
                return domain
            elif domain_taken:
                logging.info(f"{domain} is taken (checked via {whois_server}).")
                return None
            
            logging.warning(f"Ambiguous WHOIS response from {whois_server} for {domain}, retrying...")
            logging.debug(f"Response: {response}")
        else:
            logging.warning(f"No response from {whois_server} for {domain}, retrying...")
        
        server_index = (server_index + 1) % len(whois_servers)
        time.sleep(delay)
        delay = min(delay * 1.5, 30)  # Increase delay, but cap it at 30 seconds

    logging.error(f"Failed to check {domain} after {retries} attempts, skipping.")
    return None

def generate_domains(tld, limit=1000000):
    chars = string.ascii_lowercase + string.digits + "-"
    count = 0
    tld_length = len(tld.lstrip('.'))

    # 1-character domains (skip for TLDs with 3 characters or less)
    if tld_length > 3:
        for char in chars:
            if count >= limit:
                logging.info(f"Reached limit of {limit} domains")
                return
            if char != '-':
                yield char + tld
                count += 1

    # 2-character domains (if applicable, skip for 3-character TLDs)
    if tld_length != 3:
        for combo in itertools.product(chars, repeat=2):
            if count >= limit:
                logging.info(f"Reached limit of {limit} domains")
                return
            domain = ''.join(combo)
            if domain[0] != '-' and domain[-1] != '-':
                yield domain + tld
                count += 1

    # 3 to 5 character domains
    for length in range(3, 6):
        for combo in itertools.product(chars, repeat=length):
            if count >= limit:
                logging.info(f"Reached limit of {limit} domains")
                return
            domain = ''.join(combo)
            if domain[0] != '-' and domain[-1] != '-' and '--' not in domain:
                yield domain + tld
                count += 1

    # 6+ character domains (limited patterns for demonstration)
    patterns = [
        (chars,) * 6,       # 6-character domains
        (chars,) * 7,       # 7-character domains
    ]

    for pattern in patterns:
        for combo in itertools.product(*pattern):
            if count >= limit:
                logging.info(f"Reached limit of {limit} domains")
                return
            domain = ''.join(combo)
            if domain[0] != '-' and domain[-1] != '-' and '--' not in domain:
                yield domain + tld
                count += 1

    logging.info(f"Generated {count} domains in total")

def scan_domains_in_batches(domains, whois_servers, tld_configs, max_workers=10):
    all_available_domains = []
    batches = defaultdict(list)
    
    # Organize domains into batches based on their TLD
    for domain in domains:
        tld = domain.split('.')[-1]
        batches[tld].append(domain)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        while batches:
            for tld, domains in list(batches.items()):
                config = tld_configs[tld]
                
                batch = domains[:config.batch_size]
                batches[tld] = domains[config.batch_size:]
                
                if not batches[tld]:
                    del batches[tld]
                
                # Submit the batch to be processed by the executor
                future_to_domain = {executor.submit(check_domain, domain, whois_servers, 5, config.delay): domain for domain in batch}
                available_domains = []
                rate_limit_hits = 0
                timeout_hits = 0
                retry_domains = []
                
                # Process the futures as they complete
                for future in concurrent.futures.as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                        if result == "ratelimit":
                            rate_limit_hits += 1
                            retry_domains.append(domain)  # Add domain to retry list if rate limited
                        elif result == "timeout":
                            timeout_hits += 1
                            retry_domains.append(domain)  # Add domain to retry list if timeout occurred
                        elif result:
                            available_domains.append(result)
                    except Exception as e:
                        logging.error(f"Exception for {domain}: {e}")
                        retry_domains.append(domain)  # Add domain to retry list in case of other errors

                all_available_domains.extend(available_domains)

                # Add retry domains back to the batch for the next round
                if retry_domains:
                    if tld in batches:
                        batches[tld] = retry_domains + batches[tld]
                    else:
                        batches[tld] = retry_domains

                # Update rate limit history
                config.rate_limit_history.append(rate_limit_hits)
                
                # Calculate the average rate limit hits from the history
                avg_rate_limit_hits = sum(config.rate_limit_history) / len(config.rate_limit_history)

                logging.info(f"Batch size: {config.batch_size}, Rate limit hits: {rate_limit_hits}, Timeout hits: {timeout_hits}, Avg rate limit hits: {avg_rate_limit_hits:.2f}, Domains to retry: {len(retry_domains)}")
                
                if rate_limit_hits > 0 or timeout_hits > 0:
                    config.consecutive_successes = 0
                    # Decrease batch size more aggressively if rate limit or timeout hits occurred
                    config.batch_size = max(config.batch_size // (rate_limit_hits + timeout_hits + 1), config.min_batch_size)
                    # Increase delay based on rate limit or timeout hits
                    config.delay = min(config.delay * (rate_limit_hits + timeout_hits + 1), 30)
                    logging.debug(f"Rate limit or timeout hit for {tld}. Decreasing batch size to {config.batch_size} and increasing delay to {config.delay:.2f} seconds")
                else:
                    config.consecutive_successes += 1
                    if config.consecutive_successes >= 5:  # Increase this threshold for more conservative growth
                        config.batch_size = min(config.batch_size + 1, config.max_batch_size)
                        config.delay = max(config.delay * 0.9, 0.5)  # Decrease delay more slowly
                        logging.debug(f"Successful batch for {tld}. Increasing batch size to {config.batch_size} and decreasing delay to {config.delay:.2f} seconds")

                time.sleep(config.delay)

    return all_available_domains

def process_batch_with_error_handling(batch, whois_servers, max_workers):
    if not batch:
        logging.info("Empty batch, skipping processing.")
        return [], False, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(check_domain, domain, whois_servers): domain for domain in batch}
        available_domains = []
        timeout_errors_occurred = False
        rate_limit_hit = False
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                if result == "timeout":
                    timeout_errors_occurred = True
                elif result == "ratelimit":
                    rate_limit_hit = True
                elif result:
                    available_domains.append(result)
            except Exception as e:
                logging.error(f"Exception for {domain}: {e}")
                timeout_errors_occurred = True

        return available_domains, timeout_errors_occurred, rate_limit_hit

def main():
    start_time = time.time()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Check domain availability using WHOIS servers.")
    parser.add_argument("--tld", required=True, help="Comma-separated list of TLDs to check (e.g., 'nl,de,com')")
    parser.add_argument("--whois_servers_file", required=True, help="Path to JSON file containing WHOIS server list")
    args = parser.parse_args()

    tlds = args.tld.split(',')

    logging.info(f"Starting domain scan for TLDs: {tlds}")

    # Load WHOIS server data from JSON
    with open(args.whois_servers_file, 'r') as file:
        whois_server_data = json.load(file)

    logging.info(f"Loaded WHOIS server data from {args.whois_servers_file}")

    # Define TLD-specific configurations
    default_config = TldConfig(initial_batch_size=1000, max_batch_size=10000, min_batch_size=1, initial_delay=0)
    tld_configs = defaultdict(lambda: default_config)
    
    # Override default config for specific TLDs if needed
    tld_configs['nl'] = TldConfig(initial_batch_size=1, max_batch_size=5, min_batch_size=1, initial_delay=1)

    all_available_domains = []

    for tld in tlds:
        logging.info(f"Starting scan for .{tld} domains")
        
        # Find the best WHOIS servers for the current TLD
        best_whois_servers = find_best_whois_servers(
            [server['whois_server'] for server in whois_server_data if server['domain_extension'] == tld],
            tld
        )

        if not best_whois_servers:
            logging.error(f"No suitable WHOIS server found for TLD: {tld}")
            continue

        logging.info(f"Best WHOIS servers for .{tld}: {best_whois_servers}")

        # Generate domains of all lengths
        logging.info(f"Generating domains for .{tld}")
        all_domains = generate_domains(f".{tld}", limit=1000000)

        # Run the domain checks in batches using the best WHOIS servers
        logging.info(f"Starting domain availability checks for .{tld}")
        available_domains = scan_domains_in_batches(all_domains, best_whois_servers, tld_configs)
        all_available_domains.extend(available_domains)

        logging.info(f"Completed scan for .{tld} domains. Available domains: {available_domains}")

    logging.info(f"All available domains: {all_available_domains}")
    logging.info(f"Total scan completed in {time.time() - start_time:.2f} seconds")

    print(f"All available domains: {all_available_domains}")
    print(f"Total scan completed in {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()