import argparse
import sys

from scanner.loader import ScanError
from scanner.report import (build_result, print_json_report, print_text_report,
                            write_html, write_json)
from scanner.rules import rule_detectors

RULES = rule_detectors()


def main():
    parser = argparse.ArgumentParser(description="Deterministic AArch64 Errata Scanner")
    parser.add_argument("--elf", required=True, help="Path to the linked ELF binary to scan")
    parser.add_argument("--rule", default="843419", choices=sorted(RULES),
                        help="Errata rule to apply")
    parser.add_argument("--format", choices=("text", "json"), default="text",
                        help="Report format")
    parser.add_argument("--json", metavar="FILE", help="Also write a JSON report")
    parser.add_argument("--html", metavar="FILE", help="Also write an HTML report")
    parser.add_argument("--plain", action="store_true",
                        help="Plain text output (no colours or boxes)")
    args = parser.parse_args()

    try:
        findings = RULES[args.rule](args.elf)
    except ScanError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        print_json_report(findings, args.elf)
    else:
        print_text_report(findings, args.elf, plain=args.plain)

    if args.json or args.html:
        result = build_result(findings, args.elf, [args.rule])
        if args.json:
            write_json(result, args.json)
            print(f"JSON report: {args.json}")
        if args.html:
            write_html(result, args.html)
            print(f"HTML report: {args.html}")
    return 1 if findings else 0   # 0 = clean, 1 = findings, 2 = error


if __name__ == "__main__":
    sys.exit(main())