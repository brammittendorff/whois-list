import socket
import logging
import itertools
import string
import concurrent.futures
import time
import re
import argparse
import json
import math
from collections import defaultdict, deque
import os
import random

class TldConfig:
    def __init__(self, initial_batch_size=1, max_batch_size=5, min_batch_size=1, initial_delay=0.5):
        self.batch_size = initial_batch_size if initial_batch_size <= max_batch_size else max_batch_size
        self.max_batch_size = max_batch_size
        self.min_batch_size = min_batch_size
        self.delay = initial_delay  # Use the delay from cache
        self.consecutive_successes = 0
        self.consecutive_failures = 0  # Track consecutive failures
        self.rate_limit_history = deque(maxlen=5)
        self.batch_size_history = deque(maxlen=100)  # Store the last 100 batch sizes
        self.delay_history = deque(maxlen=100)  # Store the last 100 delays
    
    def adjust_batch_size_and_delay(self):
        """Adjust batch size and delay based on recent history."""
        if any(hit > 0 for hit in self.rate_limit_history):
            self.consecutive_failures += 1
            self.consecutive_successes = 0

            # Increase delay more aggressively if rate limit hits persist
            self.delay = min(self.delay * 2, 30)
        else:
            self.consecutive_successes += 1
            self.consecutive_failures = 0

            # Decrease delay cautiously after successful batches
            if self.consecutive_successes >= 3:
                self.delay = max(self.delay * 0.8, 0.0)  # Allow delay to go down to 0.0

        # Store adjustments in history
        self.delay_history.append(self.delay)
    
    def get_optimal_config(self):
        """Get the most frequent or median configuration for batch size and delay from history."""
        if self.delay_history:
            optimal_delay = max(set(self.delay_history), key=self.delay_history.count)
        else:
            optimal_delay = self.delay
        
        return self.batch_size, optimal_delay

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Known patterns for rate limit, timeout, and ambiguous responses
RATE_LIMIT_PATTERNS = [
    "error: ratelimit exceeded",
    "access control limit exceeded",
    "too many requests",
    "service temporarily unavailable",
    "connection refused"
]

TIMEOUT_PATTERNS = [
    "connection timed out",
    "network is unreachable",
    "connection reset by peer",
    "timed out"
]

AMBIGUOUS_PATTERNS = [
    "status: unknown"
]

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
            
            # Check for rate limit patterns
            if any(pattern in response_text.lower() for pattern in RATE_LIMIT_PATTERNS):
                logging.warning(f"Rate limit exceeded for {domain} on {whois_server}")
                return "ratelimit"
            
            # Check for ambiguous patterns
            if any(pattern in response_text.lower() for pattern in AMBIGUOUS_PATTERNS):
                logging.warning(f"Ambiguous WHOIS response from {whois_server} for {domain}, retrying...")
                logging.debug(f"Response: {response_text}")
                return "ambiguous"
            
            # Check for timeout patterns
            if any(pattern in response_text.lower() for pattern in TIMEOUT_PATTERNS):
                logging.warning(f"Timeout detected in WHOIS response from {whois_server} for {domain}")
                return "timeout"
            
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

def parse_whois_response(response):
    """
    Parse the WHOIS response to extract key information.
    """
    info = {
        'domain_name': None,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'name_servers': [],
        'status': []
    }
    
    lines = response.lower().split('\n')
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            if 'domain name' in key:
                info['domain_name'] = value
            elif 'registrar' in key:
                info['registrar'] = value
            elif 'creation date' in key or 'created' in key:
                info['creation_date'] = value
            elif 'expiration date' in key or 'registry expiry date' in key:
                info['expiration_date'] = value
            elif 'name server' in key:
                info['name_servers'].append(value)
            elif 'status' in key:
                info['status'].append(value)
    
    return info

def check_domain(domain, whois_servers, retries=5, delay=None, is_benchmark=False):
    server_index = 0
    if delay is None:
        delay = 0.1  # Use a default delay if none is provided
    
    initial_delay = delay  # Store the initial delay
    
    logging.debug(f"Starting domain check for {domain} with delay {delay} seconds.")
    
    for attempt in range(retries):
        whois_server = whois_servers[server_index]
        
        logging.debug(f"Attempt {attempt + 1} for {domain}. Current delay: {delay} seconds.")
        response = custom_whois_query(domain, whois_server)
        
        if response in ["ratelimit", "timeout", "ambiguous"]:
            logging.warning(f"Issue detected for {domain} on {whois_server}: {response}.")
            if is_benchmark:
                logging.debug(f"Skipping retry during benchmark for {domain}.")
                return None  # Exit immediately without retrying if it's a benchmark
            else:
                logging.warning(f"Retrying after {delay} seconds...")
                time.sleep(delay)  # Apply the delay before retrying
                if attempt < retries - 1:  # Don't increase delay on the last attempt
                    delay = initial_delay  # Reset delay to initial value for consistent retries
                logging.debug(f"New delay after issue: {delay} seconds.")
                continue  # Retry the same domain

        if response:
            parsed_info = parse_whois_response(response)
            
            # Integrated checks for domain availability
            domain_available = any(phrase in response.lower() for phrase in [
                "no match", "not found", "available", "free", "status: free", "domain not found", "is free",
                "no entries found", "%% not found", "no information available", f"{domain} is free",
                "%% not found",  # .fr specific
                "status:\tavailable",  # .be specific
                "status:             available"  # .it specific
            ])
            
            # Integrated checks for taken domains
            domain_taken = any(phrase in response.lower() for phrase in [
                "domain name:", "domain:", "status: active", "status: ok", "status:      active",
                "registry domain id:", "registrar:", "registrant:", "status:                        active",
                "created:", "last modified:", "renewal date:", "option created:", "status: connect",
                "status:                        active",  # .fr specific
                "status:\tnot available",  # .be specific
                "status:             ok"  # .it specific
            ])

            # Additional checks based on parsed information
            if parsed_info['domain_name'] or parsed_info['registrar'] or parsed_info['creation_date']:
                domain_taken = True
            
            if parsed_info['status']:
                if any('available' in status for status in parsed_info['status']):
                    domain_available = True
                elif any(status in ['active', 'ok', 'registered'] for status in parsed_info['status']):
                    domain_taken = True

            if domain_available and not domain_taken:
                logging.info(f"{domain} is available (checked via {whois_server})!")
                return domain
            elif domain_taken:
                logging.info(f"{domain} is taken (checked via {whois_server}).")
                return None
            
            logging.warning(f"Unexpected WHOIS response from {whois_server} for {domain}, with response {response} retrying...")
            logging.debug(f"Response: {response}")
            logging.debug(f"Parsed info: {parsed_info}")
        else:
            logging.warning(f"No response from {whois_server} for {domain}, retrying...")
        
        if not is_benchmark:
            server_index = (server_index + 1) % len(whois_servers)
            time.sleep(delay)  # Apply the delay before moving to the next attempt
            delay = min(delay * 1.5, 30)  # Exponential backoff with a maximum cap
            logging.debug(f"New delay after regular retry: {delay} seconds.")
        else:
            break  # If benchmarking, exit the loop after the first attempt

    logging.error(f"Failed to check {domain} after {retries} attempts, skipping.")
    return None

def generate_domains(tld, min_length=3, max_length=16):
    chars = string.ascii_lowercase + string.digits + "-"
    tld = tld.lstrip('.')

    for length in range(min_length, max_length + 1):
        for combo in itertools.product(chars, repeat=length):
            domain = ''.join(combo)
            if is_valid_domain(domain):
                yield domain + '.' + tld

def count_valid_domains(min_length, max_length):
    total = 0
    alphabet_size = 36  # 26 letters + 10 digits
    
    for length in range(min_length, max_length + 1):
        # Calculate all possible combinations
        all_combinations = alphabet_size ** length
        
        # Subtract combinations starting with dash
        invalid_start = alphabet_size ** (length - 1)
        
        # Subtract combinations ending with dash
        invalid_end = alphabet_size ** (length - 1)
        
        # Add back combinations that were subtracted twice (starting and ending with dash)
        double_counted = alphabet_size ** (length - 2)
        
        # Calculate valid combinations for this length
        valid = all_combinations - invalid_start - invalid_end + double_counted
        
        total += valid

    return total

def is_valid_domain(domain):
    # Check if the domain is valid
    if domain[0] == '-' or domain[-1] == '-':
        return False
    if not any(c.isalnum() for c in domain):
        return False
    # Allow consecutive dashes, but not at the start or end
    if domain.startswith('--') or domain.endswith('--'):
        return False
    return True

def scan_domains_in_batches(domains, whois_servers, tld_configs, max_workers=10, is_benchmark=False):
    all_available_domains = []
    batches = defaultdict(list)

    # Group domains by TLD
    for domain in domains:
        tld = domain.split('.')[-1]
        batches[tld].append(domain)

    while batches:
        for tld, domains in list(batches.items()):
            config = tld_configs[tld]

            logging.debug(f"Current TLD: {tld}, Batch Size: {config.max_batch_size}, Delay: {config.delay}")

            batch = domains[:config.max_batch_size]
            batches[tld] = domains[config.max_batch_size:]

            if not batches[tld]:
                del batches[tld]

            rate_limit_hits = 0
            timeout_hits = 0
            available_domains = []
            failed_domains = []

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_domain = {
                    executor.submit(check_domain, domain, whois_servers, 5, config.delay, is_benchmark): domain 
                    for domain in batch
                }

                for future in concurrent.futures.as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                        if result == "ratelimit":
                            rate_limit_hits += 1
                            failed_domains.append(domain)
                        elif result == "timeout" or result == "ambiguous":
                            timeout_hits += 1
                            failed_domains.append(domain)
                        elif result:
                            available_domains.append(result)
                    except Exception as e:
                        logging.error(f"Exception for {domain}: {e}")
                        failed_domains.append(domain)

            all_available_domains.extend(available_domains)

            logging.info(f"Batch size: {config.max_batch_size}, Rate limit hits: {rate_limit_hits}, Timeout hits: {timeout_hits}")
            
            if failed_domains:
                batches[tld] = failed_domains + batches[tld]  # Re-add failed domains to the front of the queue

            # Apply delay before processing the next batch
            if config.delay > 0:
                logging.debug(f"Sleeping for {config.delay} seconds before processing the next batch.")
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

# Function to load the existing benchmark cache or create a new one
def load_benchmark_cache(cache_file="benchmark_cache.json"):
    if os.path.exists(cache_file):
        with open(cache_file, "r") as file:
            return json.load(file)
    return {}

def save_benchmark_cache(cache, cache_file="benchmark_cache.json"):
    logging.info(f"Saving benchmark cache to {cache_file}")
    logging.debug(f"Cache content: {cache}")  # Add this line to debug the cache content
    if os.path.exists(cache_file):
        with open(cache_file, "r+") as file:
            existing_cache = json.load(file)
            existing_cache.update(cache)
            file.seek(0)
            json.dump(existing_cache, file, indent=4)
    else:
        with open(cache_file, "w") as file:
            json.dump(cache, file, indent=4)

def generate_benchmark_domains(tld, count=100):
    """Generate a fixed number of domains for benchmarking."""
    chars = string.ascii_lowercase + string.digits + "-"
    domains = []
    length = 1
    while len(domains) < count:
        for combo in itertools.product(chars, repeat=length):
            domain = ''.join(combo)
            if is_valid_domain(domain):
                domains.append(f"{domain}.{tld}")
                if len(domains) == count:
                    return domains
        length += 1

def dynamic_benchmark_tld_config(tld, whois_servers, initial_rate=1, max_rate=1000, rate_step=2, max_retries=5, cache_file="benchmark_cache.json"):
    cache = load_benchmark_cache(cache_file)
    
    if tld in cache:
        logging.info(f"Loading benchmark results from cache for .{tld}")
        config_data = cache[tld]
        return TldConfig(
            initial_batch_size=config_data.get('initial_batch_size', 1),
            max_batch_size=config_data.get('max_batch_size', max_rate),
            min_batch_size=config_data.get('min_batch_size', 1),
            initial_delay=config_data.get('initial_delay', 0.1)
        )

    # Generate exactly 100 test domains
    test_domains = generate_benchmark_domains(tld)

    rate = initial_rate
    optimal_rate = initial_rate
    optimal_delay = 0.1
    delay_performance_history = {}
    consecutive_rate_limit_hits = 0
    rate_limited = False
    block_duration = 0
    adaptive_delay = 0.1
    rate_limit_window = deque(maxlen=10)
    last_good_settings = {'rate': initial_rate, 'delay': 0.1}

    while rate <= max_rate:
        logging.info(f"Benchmarking with request rate: {rate} requests per second and delay: {adaptive_delay:.3f} seconds")
        config = TldConfig(initial_batch_size=rate, max_batch_size=rate, min_batch_size=1, initial_delay=adaptive_delay)
        tld_configs = {tld: config}

        if block_duration > 0:
            logging.warning(f"Waiting for {block_duration:.2f} seconds due to previous rate limiting")
            time.sleep(block_duration)
            block_duration = 0

        try:
            start_time = time.time()
            available_domains = scan_domains_in_batches(
                test_domains[:min(rate, len(test_domains))],
                whois_servers,
                tld_configs,
                max_workers=rate,
                is_benchmark=True
            )
            end_time = time.time()
            
            rate_limit_hits = sum(config.rate_limit_history)
            timeout_hits = sum(1 for domain in available_domains if domain == "timeout")
            
            delay_performance_history[adaptive_delay] = rate_limit_hits
            
            actual_rate = len(test_domains[:min(rate, len(test_domains))]) / (end_time - start_time)
            rate_limit_window.append(rate_limit_hits > 0)
        except Exception as e:
            logging.error(f"Exception during benchmark: {e}")
            rate_limit_hits = rate  # Assume all hits were rate limited
            rate_limit_window.append(True)
            break  # Stop the benchmark if an exception occurs

        recent_rate_limits = sum(rate_limit_window)

        if rate_limit_hits > 0 or recent_rate_limits > len(rate_limit_window) // 2:
            logging.warning(f"Rate limit hits detected with rate {rate}. Adjusting parameters.")
            consecutive_rate_limit_hits += 1
            rate_limited = True
            
            if consecutive_rate_limit_hits >= 3:
                block_duration = min(30, block_duration * 2 + random.uniform(1, 5))
            
            rate = max(initial_rate, rate // rate_step)
            adaptive_delay = min(30, adaptive_delay * 1.5)
        else:
            rate_limited = False
            consecutive_rate_limit_hits = 0
            optimal_rate = rate
            optimal_delay = adaptive_delay
            last_good_settings = {'rate': rate, 'delay': adaptive_delay}
            
            if actual_rate < rate * 0.9:  # If actual rate is significantly lower than expected
                adaptive_delay = max(0.01, adaptive_delay * 0.9)  # Decrease delay cautiously
            else:
                rate = min(max_rate, rate * rate_step)
                adaptive_delay = max(0.01, adaptive_delay * 0.95)  # Decrease delay slightly

        if consecutive_rate_limit_hits >= 5:
            logging.warning("Too many consecutive rate limit hits; stabilizing at the previous optimal rate.")
            break

        if rate >= 100 and optimal_delay <= 0.05 and not rate_limited:
            logging.info("High-capacity TLD detected. Early stopping benchmark.")
            break

    best_delay = min(delay_performance_history, key=delay_performance_history.get, default=optimal_delay)
    logging.info(f"Best configuration determined: Rate: {optimal_rate}, Delay: {best_delay:.3f} seconds")

    save_benchmark_cache({tld: {
        'initial_batch_size': 1,
        'max_batch_size': optimal_rate,
        'min_batch_size': 1,
        'initial_delay': best_delay
    }}, cache_file)

    return TldConfig(max_batch_size=optimal_rate, initial_delay=best_delay)

def calculate_processing_time(tld, config, num_domains):
    """
    Calculate the estimated processing time for a given TLD.
    
    :param tld: The TLD being processed
    :param config: The TldConfig object for the TLD
    :param num_domains: The number of domains to process
    :return: A dictionary containing the processing time in various units
    """
    batch_size = config.max_batch_size
    delay = config.delay
    processing_time_per_domain = 0.1  # Assuming 0.1 seconds per domain

    time_per_batch = (batch_size * processing_time_per_domain) + delay
    total_batches = -(-num_domains // batch_size)  # Ceiling division
    total_time_seconds = total_batches * time_per_batch

    days = total_time_seconds / (24 * 3600)
    weeks = days / 7
    years = days / 365.25

    return {
        "tld": tld,
        "seconds": total_time_seconds,
        "days": days,
        "weeks": weeks,
        "years": years
    }

def main():
    start_time = time.time()
    parser = argparse.ArgumentParser(description="Check domain availability using WHOIS servers.")
    parser.add_argument("--tld", required=True, help="Comma-separated list of TLDs to check (e.g., 'nl,de,com')")
    parser.add_argument("--whois_servers_file", required=True, help="Path to JSON file containing WHOIS server list")
    parser.add_argument("--benchmark", action="store_true", help="Benchmark and auto-configure TLD settings")
    parser.add_argument("--cache_file", default="benchmark_cache.json", help="File to store benchmark results")
    parser.add_argument("--auto-confirm", action="store_true", help="Skip user confirmation and proceed with scan")
    parser.add_argument("--min-length", type=int, default=3, help="Minimum length of domain names to generate (default: 3)")
    parser.add_argument("--max-length", type=int, default=16, help="Maximum length of domain names to generate (default: 16)")
    args = parser.parse_args()

    tlds = args.tld.split(',')

    logging.info(f"Starting domain scan for TLDs: {tlds}")

    with open(args.whois_servers_file, 'r') as file:
        whois_server_data = json.load(file)

    logging.info(f"Loaded WHOIS server data from {args.whois_servers_file}")

    tld_configs = {}
    processing_times = []

    # Benchmark and configure TLDs
    for tld in tlds:
        logging.info(f"Configuring for .{tld} domains")
        
        best_whois_servers = find_best_whois_servers(
            [server['whois_server'] for server in whois_server_data if server['domain_extension'] == tld],
            tld
        )

        if not best_whois_servers:
            logging.error(f"No suitable WHOIS server found for TLD: {tld}")
            continue

        logging.info(f"Best WHOIS servers for .{tld}: {best_whois_servers}")

        if args.benchmark:
            logging.info(f"Benchmarking TLD configuration for .{tld}")
            config = dynamic_benchmark_tld_config(
                tld, best_whois_servers, cache_file=args.cache_file
            )
        else:
            config = TldConfig(initial_batch_size=1, max_batch_size=10000, min_batch_size=1, initial_delay=0)

        tld_configs[tld] = config

    # Calculate and display processing times
    total_domains = count_valid_domains(args.min_length, args.max_length) * len(tlds)
    logging.info(f"Total domains to be checked: {total_domains}")
    total_days = 0
    print("\nEstimated processing times:")
    for tld, config in tld_configs.items():
        proc_time = calculate_processing_time(tld, config, num_domains=total_domains)
        processing_times.append(proc_time)
        print(f".{tld}: {proc_time['days']:.2f} days")
        total_days += proc_time['days']
    print(f"\nTotal estimated processing time: {total_days:.2f} days ({total_days/7:.2f} weeks, {total_days/365.25:.2f} years)")

    # Ask for user confirmation if auto-confirm is not set
    if not args.auto_confirm:
        user_input = input("Do you want to proceed with the scan? (y/n): ")
        if user_input.lower() != 'y':
            print("Scan cancelled by user.")
            return
    else:
        print("Auto-confirm enabled. Proceeding with scan...")

    # Proceed with scanning
    all_available_domains = []
    for tld, config in tld_configs.items():
        logging.info(f"Starting scan for .{tld} domains")
        logging.info(f"Generating domains for .{tld}")
        all_domains = generate_domains(tld, args.min_length, args.max_length)

        logging.info(f"Starting domain availability checks for .{tld}")
        available_domains = scan_domains_in_batches(all_domains, find_best_whois_servers(
            [server['whois_server'] for server in whois_server_data if server['domain_extension'] == tld],
            tld
        ), {tld: config})
        all_available_domains.extend(available_domains)

        logging.info(f"Completed scan for .{tld} domains. Available domains: {available_domains}")

    logging.info(f"All available domains: {all_available_domains}")
    logging.info(f"Total scan completed in {time.time() - start_time:.2f} seconds")

    print(f"All available domains: {all_available_domains}")
    print(f"Total scan completed in {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
