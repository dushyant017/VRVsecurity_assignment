
import re
import csv
from collections import defaultdict, Counter

# Regex pattern to match log entries
# ip: Captures the IP address (e.g., 192.168.1.1).
# method: Captures the HTTP method (e.g., GET, POST).
# endpoint: Captures the accessed URL or resource path (e.g., /home, /login).
# status: Captures the HTTP status code (e.g., 200, 401).
# message: Captures the trailing message, typically including error descriptions (e.g., "Invalid credentials").
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) .* "(?P<method>\w+) (?P<endpoint>/[^\s]*) HTTP/\d\.\d" (?P<status>\d+) .*"(?P<message>.*)"'
)

# File paths
log_file = "sample.log"
output_file = "log_analysis_results.csv"

# Initialize dictionaries for storing the counts of ip, endpoints and failed logins
requests_per_ip = defaultdict(int)
endpoint_access_counts = Counter()
failed_logins = defaultdict(int)

# Parse the log file
with open(log_file, "r") as file:
    for line in file:
        match = log_pattern.search(line)
        if match:
            ip = match.group("ip")
            endpoint = match.group("endpoint")
            status = match.group("status")
            message = match.group("message")

            # Count requests per IP
            requests_per_ip[ip] += 1

            # Count endpoint accesses
            endpoint_access_counts[endpoint] += 1

            # Count failed login attempts (HTTP 401 or "Invalid credentials")
            if status == "401" or "Invalid credentials" in message:
                failed_logins[ip] += 1

# Determine the most frequently accessed endpoint
most_accessed_endpoint, most_accessed_count = endpoint_access_counts.most_common(1)[0]

# Display results in the terminal
print("\nRequests per IP Address:")
print(f"{'IP Address':<20} {'Request Count':<15}")
for ip, count in sorted(requests_per_ip.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip:<20} {count:<15}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

print("\nSuspicious Activity Detected:")
print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
for ip, count in failed_logins.items():
    print(f"{ip:<20} {count:<20}")

# Save results to CSV
with open(output_file, mode="w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    # Write Requests per IP
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in sorted(requests_per_ip.items(), key=lambda x: x[1], reverse=True):
        writer.writerow([ip, count])

    # Write Most Accessed Endpoint
    writer.writerow([])
    writer.writerow(["Most Frequently Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint, most_accessed_count])

    # Write Suspicious Activity
    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Attempts"])
    for ip, count in failed_logins.items():
        writer.writerow([ip, count])

print(f"\nResults saved to {output_file}")
