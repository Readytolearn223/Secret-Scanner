#!/usr/bin/env python3
import os
import re
import argparse
import logging


# Setup Logging

logging.basicConfig(
    filename='secret_scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# Common Regex Patterns

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
    "Generic API Key": r"(?i)(api[-_]?key|apikey|auth[-_]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    "Password": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    "Private Key Start": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,48}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}"
}


# File Scanning Function

def scan_file(file_path):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, start=1):
                for name, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, line):
                        findings.append((file_path, line_num, name, line.strip()))
                        logging.warning(f"[{name}] found in {file_path}:{line_num}")
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")
    return findings


# Directory Scanning Function

def scan_directory(directory):
    all_findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            findings = scan_file(file_path)
            all_findings.extend(findings)
    return all_findings


# CLI Interface

def main():
    parser = argparse.ArgumentParser(
        description=" Secret Scanner - Detect hardcoded secrets in files or directories."
    )
    parser.add_argument(
        "path",
        help="Path to file or directory to scan"
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional: output file to save report (default: print to console)"
    )
    args = parser.parse_args()

    path = args.path
    logging.info(f"Started scanning: {path}")

    if os.path.isfile(path):
        results = scan_file(path)
    elif os.path.isdir(path):
        results = scan_directory(path)
    else:
        print("Invalid path. Please provide a valid file or directory.")
        return

    # Reporting Results
   
    if results:
        report_lines = []
        for file_path, line_num, name, line_content in results:
            report_lines.append(
                f"[{name}] in {file_path} (line {line_num}): {line_content}"
            )

        report = "\n".join(report_lines)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f" Scan complete. Report saved to: {args.output}")
        else:
            print("\n===  Secret Scan Report ===")
            print(report)
    else:
        print(" No secrets found.")
    logging.info("Scan completed successfully.")

if __name__ == "__main__":
    main()
