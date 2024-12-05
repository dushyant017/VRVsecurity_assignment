# Log File Analyzer

## Overview
This Python script processes log files to extract and analyze key information, including:
- Number of requests per IP address.
- Most frequently accessed endpoint.
- Detection of failed login attempts.

The script supports clear terminal output and saves results to a CSV file.

---

## Features
1. Count Requests per IP Address:
   - Parses the log file to identify requests from each IP address.
   - Displays the count of requests per IP in descending order.

2. Identify the Most Frequently Accessed Endpoint:
   - Extracts endpoints from the log file.
   - Identifies and displays the most accessed endpoint and its count.

3. Detect Failed Login Attempts:
   - Detects failed login attempts (HTTP status code `401` with optional error message).
   - Flags IPs exceeding a configurable threshold (default: 10 failed attempts).

4. CSV Export:
   - Saves analysis results to a `log_analysis_results.csv` file with three sections:
     - Requests per IP: `IP Address`, `Request Count`.
     - Most Accessed Endpoint: `Endpoint`, `Access Count`.
     - Suspicious Activity: `IP Address`, `Failed Login Count`.

---

## Dependencies
- Python 3.7 or higher
- Required libraries: 
  - 're' for regular expressions
  - 'csv' for CSV file handling
  - 'collections' for efficient counting


---

## Usage
1. Save the log file (e.g., 'sample.log') in the same directory as the script.
2. Run the script.
