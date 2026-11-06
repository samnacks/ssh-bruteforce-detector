# SSH Brute-Force Detector

A small Python tool that analyses SSH authentication logs and flags IP addresses
with repeated failed logins, a common sign of brute-force attacks.

## Features
- Parses failed SSH login attempts with regex
- Counts failures per IP and tracks usernames attempted
- Flags IPs above a configurable threshold
- Includes a synthetic sample log for testing (no real data)

## Usage
```bash
python log_analyzer.py sample_auth.log --threshold 5
```

## Example output
```
Total failed attempts: ...
Suspicious IPs (>= 5 failures):
  203.0.113.45  |  8 failures  |  users tried: admin, guest, oracle, ...
```

## How it maps to real SOC work
- Detects credential-stuffing and brute-force patterns
- Highlights usernames attackers try (root, admin, test)
- Low-failure IPs that later succeed (typos) are not flagged, reducing false positives

## Roadmap
- [ ] Detect successful login after many failures (possible compromise)
- [ ] Export report to CSV/JSON
- [ ] Add IP geolocation and reputation lookup
- [ ] Simple dashboard

## Notes
Sample IPs use documentation ranges (RFC 5737). No real user data is included.

## Author
[Your name], BSc Microbiology, transitioning into cybersecurity.
