"""
Utility functions for PhantomLFI.
"""

import os
import re

try:
    from colorama import Fore, Style
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


COLOR_MAP = {
    "red": Fore.RED if COLORAMA_AVAILABLE else "",
    "green": Fore.GREEN if COLORAMA_AVAILABLE else "",
    "yellow": Fore.YELLOW if COLORAMA_AVAILABLE else "",
    "blue": Fore.BLUE if COLORAMA_AVAILABLE else "",
    "magenta": Fore.MAGENTA if COLORAMA_AVAILABLE else "",
    "cyan": Fore.CYAN if COLORAMA_AVAILABLE else "",
    "white": Fore.WHITE if COLORAMA_AVAILABLE else "",
    "reset": Style.RESET_ALL if COLORAMA_AVAILABLE else "",
    "bright": Style.BRIGHT if COLORAMA_AVAILABLE else "",
}


def print_colored(text: str, color: str = "white", use_color: bool = True):
    """Print text with optional color."""
    if use_color and COLORAMA_AVAILABLE and color in COLOR_MAP:
        print(f"{COLOR_MAP[color]}{text}{COLOR_MAP['reset']}")
    else:
        print(text)


def banner(use_color: bool = True):
    """Display the PhantomLFI banner."""
    art = r"""
    ╔════════════════════════════════════════════════════════════════════════╗
    ║                                                                        ║
    ║     ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗   ║
    ║     ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║   ║
    ║     ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║   ║
    ║     ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║   ║
    ║     ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║   ║
    ║     ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝   ║
    ║                                                                        ║
    ║              ██╗     ███████╗██╗                                        ║
    ║              ██║     ██╔════╝██║        PhantomLFI v1.0                 ║
    ║              ██║     █████╗  ██║        Done by D4rk0ps                 ║
    ║              ██║     ██╔══╝  ██║                                        ║
    ║              ███████╗██║     ██║                                        ║
    ║              ╚══════╝╚═╝     ╚═╝                                        ║
    ║                                                                        ║
    ╚════════════════════════════════════════════════════════════════════════╝
    """
    if use_color and COLORAMA_AVAILABLE:
        print(f"{COLOR_MAP['bright']}{COLOR_MAP['cyan']}{art}{COLOR_MAP['reset']}")
    else:
        print(art)


def write_output(filepath: str, lines: list):
    """Write payload lines to an output file."""
    directory = os.path.dirname(filepath)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    with open(filepath, "w", encoding="utf-8") as f:
        for line in lines:
            clean = _strip_ansi(line)
            f.write(clean + "\n")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from a string."""
    ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_pattern.sub("", text)


def sanitize_url(url: str) -> str:
    """Ensure the base URL ends appropriately for payload concatenation."""
    if url.endswith("="):
        return url
    if url.endswith("/"):
        return url
    return url
