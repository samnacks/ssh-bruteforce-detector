"""SSH Brute-Force Detector
Parses an SSH auth log, counts failed logins per IP, and flags suspicious IPs.

Usage:
    python log_analyzer.py sample_auth.log --threshold 5
"""
import argparse
import re
from collections import Counter, defaultdict

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze(path, threshold):
    attempts = Counter()
    users_tried = defaultdict(set)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = FAILED_PATTERN.search(line)
            if match:
                ip, user = match.group("ip"), match.group("user")
                attempts[ip] += 1
                users_tried[ip].add(user)

    flagged = {ip: n for ip, n in attempts.items() if n >= threshold}
    return attempts, users_tried, flagged


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attempts.")
    parser.add_argument("logfile", help="Path to the auth log file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts needed to flag an IP (default: 5)")
    args = parser.parse_args()

    attempts, users_tried, flagged = analyze(args.logfile, args.threshold)

    print(f"Total failed attempts: {sum(attempts.values())}")
    print(f"Unique IPs with failures: {len(attempts)}")
    print(f"\nSuspicious IPs (>= {args.threshold} failures):")

    if not flagged:
        print("  None found.")
    for ip, count in sorted(flagged.items(), key=lambda x: -x[1]):
        users = ", ".join(sorted(users_tried[ip]))
        print(f"  {ip}  |  {count} failures  |  users tried: {users}")


if __name__ == "__main__":
    main()
