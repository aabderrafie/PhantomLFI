# PhantomLFI

**LFI / RFI Payload Generation Framework**

Done by **D4rk0ps**

---

## Overview

PhantomLFI is a modular payload generation framework for Local File Inclusion (LFI) and Remote File Inclusion (RFI) testing. It generates payload URLs — no HTTP requests are sent.

## Features

- **Directory Traversal** — Depth 1–10, Linux + Windows targets, encoding variants, slash bypasses
- **PHP Wrappers** — `php://filter`, `php://input`, `data://`, `expect://`, `zip://`, `phar://`, `file://`
- **RFI Protocols** — `http://`, `https://`, `ftp://`, `ftps://`, `sftp://`, `gopher://`, `dict://`, `tftp://`, `ldap://`, `ldaps://`, `jar://`, `netdoc://`, `data://`
- **Encoding Engine** — URL, double URL, mixed, null byte, Unicode, case randomization, slash bypass pipeline
- **Log & Config Paths** — Apache, Nginx, PHP sessions, SSH keys, web configs
- **Output** — Colorized terminal, grouped by category, save to file

## Installation

```bash
git clone https://github.com/D4rk0ps/PhantomLFI.git
cd PhantomLFI
pip install colorama   # optional, for colored output
```

## Usage

```bash
# LFI payloads
python3 main.py --url "http://target.com/page.php?file=" --lfi

# RFI payloads with attacker host
python3 main.py --url "http://target.com/page.php?file=" --rfi --attacker-host 10.10.14.5

# All payloads, depth 8, save to file
python3 main.py --url "http://target.com/page.php?file=" --all --depth 8 -o output/results.txt

# Linux-only, no color
python3 main.py --url "http://target.com/page.php?file=" --lfi --os linux --no-color

# Windows-only, depth 4
python3 main.py --url "http://target.com/page.php?file=" --lfi --os windows --depth 4
```

## Options

| Flag | Description |
|---|---|
| `--url` | Base URL with injectable parameter (required) |
| `--lfi` | Generate LFI payloads |
| `--rfi` | Generate RFI payloads |
| `--all` | Generate LFI + RFI payloads |
| `--depth [1-10]` | Traversal depth (default: 6) |
| `--attacker-host` | Attacker IP for RFI (default: ATTACKER_IP) |
| `--os` | Target OS: `linux`, `windows`, `both` (default: both) |
| `-o / --output` | Save results to file |
| `--no-color` | Disable colored output |

## Project Structure

```
PhantomLFI/
├── main.py                 # CLI entry point
├── core/
│   ├── generator.py        # Central payload orchestrator
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
