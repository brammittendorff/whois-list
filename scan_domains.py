import socket
import logging
import itertools
import string
import concurrent.futures
import time
import re
import argparse
import json

# Configure logging to capture errors
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
            # Handle cases where the response includes a reference to another WHOIS server
            if "refer:" in response_text:
                refer_whois_server = response_text.split("refer:")[1].split()[0].strip()
                logging.info(f"Redirecting WHOIS query to {refer_whois_server}")
                return custom_whois_query(domain, refer_whois_server)
            return response_text
    except socket.timeout:
        logging.error(f"Timeout error querying WHOIS server {whois_server} for {domain}")
        return "timeout"  # Special flag to indicate a timeout occurred
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
def check_domain(domain, whois_servers, retries=5, delay=10):
    server_index = 0
    valid_responses = []
    for attempt in range(retries):
        for _ in range(len(whois_servers)):  # Loop through all servers
            whois_server = whois_servers[server_index]
            server_index = (server_index + 1) % len(whois_servers)  # Round-robin selection

            response = custom_whois_query(domain, whois_server)
            if response:
                valid_responses.append((whois_server, response))
                info = extract_domain_info(response)
                
                if "No match" in response or "not found" in response or "available" in response.lower():
                    logging.info(f"{domain} is available (checked via {whois_server})!")
                    return domain
                elif "Domain Name:" in response or "Status: active" in response or "Domain Status:" in response:
                    logging.debug(f"{domain} is taken (checked via {whois_server}).")
                    return None
                else:
                    logging.warning(f"Ambiguous WHOIS response from {whois_server} for {domain}, retrying...")
                    logging.debug(f"WHOIS response for {domain} from {whois_server}:\n{response}")
            else:
                logging.warning(f"No response from {whois_server} for {domain}, retrying...")

        # If we have multiple valid responses, compare them
        if len(valid_responses) > 1:
            consistent = all(resp == valid_responses[0][1] for _, resp in valid_responses)
            if consistent:
                logging.debug(f"Consistent responses for {domain} across WHOIS servers.")
            else:
                logging.warning(f"Inconsistent WHOIS responses for {domain} across servers. Skipping.")

        logging.debug(f"Retrying {domain} in {delay * (2 ** attempt):.2f} seconds...")
        time.sleep(delay * (2 ** attempt))  # Exponential backoff

    logging.error(f"Failed to check {domain} after {retries} attempts, skipping.")
    return None

# Function to generate domains from 3 to 5 characters long (skipping 2 characters for certain TLDs)
def generate_domains_3_to_5(tld):
    chars = string.ascii_lowercase + string.digits
    for length in range(3, 6):  # Start from 3 characters
        for combo in itertools.product(chars, repeat=length):
            yield ''.join(combo) + tld

# Function to generate domains for 1 and 2 characters for non-skipped TLDs and 6+ characters for all TLDs
def generate_domains_1_and_6_plus(tld):
    chars = string.ascii_lowercase
    digits = string.digits

    # 1-character domains
    for combo in itertools.product(chars, repeat=1):
        yield ''.join(combo) + tld

    # 2-character domains (only if TLD is not in the skipped list)
    if tld not in [".com", ".nl"]:  # Add other country TLDs if needed
        for combo in itertools.product(chars + digits, repeat=2):
            yield ''.join(combo) + tld

    # 6+ character domains
    patterns = [
        (chars, chars, chars, chars, chars, chars),            # 6-letter domains
        (chars, chars, chars, chars, digits, digits),          # 4 letters + 2 digits
        (chars, chars, chars, digits, digits, digits),         # 3 letters + 3 digits
        (chars, chars, chars, chars, chars, chars, chars),     # 7-letter domains
        (chars, chars, chars, chars, chars, digits),           # 5 letters + 1 digit
        (chars, chars, chars, chars, chars, chars, digits),    # 6 letters + 1 digit
        (chars, chars, chars, chars, digits, digits, digits),  # 4 letters + 3 digits
        (chars, chars, chars, chars, chars, chars, chars, digits), # 7 letters + 1 digit
    ]

    for pattern in patterns:
        for combo in itertools.product(*pattern):
            yield ''.join(combo) + tld

# Function to run the domain checks in parallel with reduced concurrency and batch processing
def scan_domains_in_batches(domains, whois_servers, initial_batch_size=50, max_batch_size=1000, min_batch_size=10, max_workers=10):
    all_available_domains = []
    batch = []
    total_time = 0
    total_queries = 0
    current_batch_size = initial_batch_size
    dynamic_delay = 0  # Initialize dynamic_delay to 0

    def adjust_batch_size(avg_time_per_domain, timeout_errors_occurred):
        nonlocal current_batch_size
        if timeout_errors_occurred:
            # If timeout errors occurred, decrease the batch size
            current_batch_size = max(current_batch_size - 10, min_batch_size)
            logging.debug(f"Timeout errors occurred. Decreasing batch size to {current_batch_size}")
        elif not timeout_errors_occurred:
            # If no errors and average time is good, increase the batch size
            if avg_time_per_domain < 0.5 and current_batch_size < max_batch_size:
                current_batch_size = min(current_batch_size + 10, max_batch_size)
                logging.debug(f"Increasing batch size to {current_batch_size}")
            elif avg_time_per_domain > 1.0 and current_batch_size > min_batch_size:
                current_batch_size = max(current_batch_size - 10, min_batch_size)
                logging.debug(f"Decreasing batch size to {current_batch_size}")

    for domain in domains:
        batch.append(domain)
        if len(batch) >= current_batch_size:
            start_time = time.time()
            available_domains, timeout_errors_occurred = process_batch_with_error_handling(batch, whois_servers, max_workers)
            batch_time = time.time() - start_time
            all_available_domains.extend(available_domains)
            batch = []

            # Update total time and queries
            total_time += batch_time
            total_queries += len(available_domains)

            # Calculate average response time per domain in the batch
            avg_time_per_domain = total_time / total_queries if total_queries > 0 else 0
            logging.debug(f"Average WHOIS query time per domain: {avg_time_per_domain:.4f} seconds")

            # Adjust the batch size based on performance and errors
            adjust_batch_size(avg_time_per_domain, timeout_errors_occurred)

            # Dynamic delay based on the average time per domain
            # Initialize dynamic_delay to 0 at the start
            dynamic_delay = max(0, dynamic_delay + (avg_time_per_domain * current_batch_size) - 0.5)  # Adjust the calculation as needed
            dynamic_delay = min(dynamic_delay, 10)  # Ensure it doesn't exceed 10 seconds
            dynamic_delay = max(dynamic_delay, 0)   # Ensure it doesn't go below 0 seconds

            logging.debug(f"Waiting {dynamic_delay:.2f} seconds before processing the next batch...")
            time.sleep(dynamic_delay)


    # Process any remaining domains in the last batch
    if batch:
        available_domains, timeout_errors_occurred = process_batch_with_error_handling(batch, whois_servers, max_workers)
        all_available_domains.extend(available_domains)
        if timeout_errors_occurred:
            logging.error(f"Final batch encountered errors and could not be retried.")

    return all_available_domains

def process_batch_with_error_handling(batch, whois_servers, max_workers):
    if not batch:
        logging.info("Empty batch, skipping processing.")
        return [], False

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(check_domain, domain, whois_servers): domain for domain in batch}
        available_domains = []
        timeout_errors_occurred = False
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                if result == "timeout":
                    timeout_errors_occurred = True  # Specifically flag a timeout error
                elif result:
                    available_domains.append(result)
            except Exception as e:
                logging.error(f"Exception for {domain}: {e}")
                timeout_errors_occurred = True  # Treat exceptions as timeout errors for this purpose

        return available_domains, timeout_errors_occurred

def main():
    start_time = time.time()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Check domain availability using WHOIS servers.")
    parser.add_argument("--tld", required=True, help="Comma-separated list of TLDs to check (e.g., 'nl,de,com')")
    parser.add_argument("--whois_servers_file", required=True, help="Path to JSON file containing WHOIS server list")
    args = parser.parse_args()

    tlds = args.tld.split(',')

    # Load WHOIS server data from JSON
    with open(args.whois_servers_file, 'r') as file:
        whois_server_data = json.load(file)

    all_available_domains = []

    for tld in tlds:
        # Find the best WHOIS servers for the current TLD
        best_whois_servers = find_best_whois_servers([server['whois_server'] for server in whois_server_data if server['domain_extension'] == tld], tld)

        if not best_whois_servers:
            logging.error(f"No suitable WHOIS server found for TLD: {tld}")
            continue

        # Generate domains for 3 to 5 characters, skipping 2-character domains for certain TLDs
        domains_3_to_5 = generate_domains_3_to_5(f".{tld}")
        
        # Generate 1-character domains and 2-character domains for non-skipped TLDs and 6+ characters for all TLDs
        domains_1_and_6_plus = generate_domains_1_and_6_plus(f".{tld}")

        # Combine both generators
        all_domains = itertools.chain(domains_3_to_5, domains_1_and_6_plus)

        # Run the domain checks in batches using the best WHOIS servers
        available_domains = scan_domains_in_batches(all_domains, best_whois_servers)
        all_available_domains.extend(available_domains)

    print(f"Available domains: {all_available_domains}")
    print(f"Completed in {time.time() - start_time} seconds")

if __name__ == "__main__":
    main()
