# Spoofability

Analyzes a domain's email security configuration by inspecting its SPF, DKIM, and DMARC DNS records and provides a risk assessment to determine how vulnerable the domain is to email spoofing and impersonation.

**100% Vibe Coded by [Grok](https://x.com/i/grok)**

## Features

- **SPF Check**: Detects the presence of an SPF record and analyzes its policy.
- **DKIM Check**: Attempts to retrieve DKIM records using common selectors and validates their structure.
- **DMARC Check**: Evaluates the domain's DMARC policy and coverage.
- **Risk Scoring**: Calculates a spoofability risk score and provides a summary of weaknesses.

## Requirements

- Python 3.6+
- [dnspython](https://pypi.org/project/dnspython/)

## Installation

```bash
pip install dnspython
```

## Usage

```bash
python spoofability.py example.com
```

Replace `example.com` with the domain you want to analyze.

## Example Output

```
Analyzing email security for example.com...

SPF Analysis:
Status: Present
Details: Strong SPF policy (-all) detected: Rejects unauthorized senders
Record: v=spf1 include:_spf.google.com -all
--------------------------------------------------
DKIM Analysis:
Status: Present
Details: Found 1 DKIM record(s) | Selector 'google': Valid
--------------------------------------------------
DMARC Analysis:
Status: Present
Details: Primary policy=reject: Spoofed emails blocked | Subdomain policy matches primary: reject
Record: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
--------------------------------------------------

Spoofability Assessment:
Risk Level: Low (Score: 10)
Summary: Domain is well-protected against spoofing.
--------------------------------------------------
```

## Note

- This tool uses a fixed set of common DKIM selectors. It may not detect all DKIM configurations.
