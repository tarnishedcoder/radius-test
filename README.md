# RADIUS Security Auditor & Compliance Utility

A lightweight, high-performance RADIUS (Remote Authentication Dial-In User Service) client simulator and active security auditing tool written in Python.

> ⚠️ WARNING: Only run this tool against systems you own or have explicit authorization to test. Unauthorized authentication attempts or scanning can be illegal and unethical.

## Overview

This repository contains a small utility to craft RFC 2865-compliant RADIUS Access-Request packets, send them to a target RADIUS server, and validate response authenticators using the shared secret.

Use cases include diagnostics, testing RADIUS configurations in lab environments, and learning how RADIUS password obfuscation and authenticators work.

## Features

- Build Access-Request packets with User-Name and User-Password attributes
- RFC 2865 password obfuscation (MD5-based, per the standard)
- Send packets over UDP and measure round-trip time (RTT)
- Verify Response Authenticator using the shared secret
- Human-friendly colored terminal output
- No external dependencies — uses the Python standard library

## Requirements

- Python 3.8 or later

## Installation

Clone the repository and run the script directly:

```bash
git clone https://github.com/tarnishedcoder/radius-test.git
cd radius-test
python3 radius_security_auditor.py -h
```

(Optional) Use a virtual environment if you prefer isolation.

## Usage

Basic invocation:

```bash
python3 radius_security_auditor.py -t <TARGET_IP> -u <USERNAME> -w <PASSWORD> -s <SHARED_SECRET>
```

Command-line options:

- `-t`, `--target`  : Target IP address or hostname of the RADIUS server (default: `127.0.0.1`)
- `-p`, `--port`    : Target UDP port (default: `1812`)
- `-u`, `--username`: Username to test (required)
- `-w`, `--password`: Cleartext password to test (required)
- `-s`, `--secret`  : The shared secret configured on the server (required)
- `-i`, `--id`      : Packet Identifier (0–255), default: `1`

Example:

```bash
python3 radius_security_auditor.py -t 192.168.1.50 -u administrator -w "SecurePassword123!" -s testing123
```

## How it works (high level)

1. The script generates a 16-byte Request Authenticator and encrypts the provided password per RFC 2865.
2. It assembles a RADIUS Access-Request packet (header + attributes) and sends it over UDP to the target.
3. On receiving a response, the script computes the expected Response Authenticator as:

```
MD5(Code + ID + Length + RequestAuthenticator + Attributes + SharedSecret)
```

and compares this value to the Authenticator field in the response to validate shared-secret alignment.

## Output

The script prints a concise Security Assessment Report including:

- Response RTT (ms)
- Transaction result: Access-Accept, Access-Reject, Access-Challenge, or other
- Shared secret verification status (VALID / INVALID)

## Security & Legal

- Only test systems you own or have explicit permission to test.
- Avoid rate-limiting or brute-force usage; this tool is intended for single-target diagnostics and learning.
- Never commit real shared secrets or credentials to version control.

## Contributing

Contributions are welcome. Please open an issue for feature requests or bug reports, and submit pull requests for code changes. When adding features that affect packet construction or cryptography, include unit tests demonstrating RFC-conformant behavior.

## Suggested Tests

- Unit tests for `encrypt_radius_password` against known vectors
- Tests that `craft_access_request` produces correct header length and TLV encoding
- Tests for `verify_response_authenticator` that accept valid responses and reject tampered ones

## Development Notes

- The tool intentionally uses only the Python standard library for portability.
- Password obfuscation follows RFC 2865 — keep shared secrets secure and rotate them as appropriate.

