import argparse
import sys

from scanner.loader import ScanError
from scanner.report import print_json_report, print_text_report
from scanner.rules import rule_detectors

RULES = rule_detectors()


def main():
    parser = argparse.ArgumentParser(description="Deterministic AArch64 Errata Scanner")
    parser.add_argument("--elf", required=True, help="Path to the linked ELF binary to scan")
    parser.add_argument("--rule", default="843419", choices=sorted(RULES),
                        help="Errata rule to apply")
    parser.add_argument("--format", choices=("text", "json"), default="text",
                        help="Report format")
    args = parser.parse_args()

    try:
        findings = RULES[args.rule](args.elf)
    except ScanError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        print_json_report(findings, args.elf)
    else:
        print_text_report(findings, args.elf)
    return 1 if findings else 0   # 0 = clean, 1 = findings, 2 = error


if __name__ == "__main__":
    sys.exit(main())