import argparse
import sys

import yaml
from scanner.loader import ScanError
from scanner.report import (build_result, print_json_report, print_text_report,
                            write_html, write_json)
from scanner.engine import detect_rule
from scanner.rules import load_rules


def main():
    try:
        configured_rules = load_rules()
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(description="Deterministic AArch64 Errata Scanner")
    parser.add_argument("--elf", help="Path to the linked ELF binary to scan")
    parser.add_argument("--rule", default="843419", choices=["all", *sorted(configured_rules)],
                        help="Errata rule to apply")
    parser.add_argument("--validate-rules", action="store_true",
                        help="Validate all production YAML rules and exit")
    parser.add_argument("--format", choices=("text", "json"), default="text",
                        help="Report format")
    parser.add_argument("--json", metavar="FILE", help="Also write a JSON report")
    parser.add_argument("--html", metavar="FILE", help="Also write an HTML report")
    parser.add_argument("--plain", action="store_true",
                        help="Plain text output (no colours or boxes)")
    args = parser.parse_args()

    if args.validate_rules:
        print("Validating rules...")
        for rule_id in sorted(configured_rules):
            print(f"[OK] {configured_rules[rule_id].path.name}")
        print("All rules valid.")
        return 0
    if not args.elf:
        parser.error("--elf is required unless --validate-rules is used")

    try:
        if args.rule == "all":
            rules_checked = sorted(configured_rules)
            findings = []
            for rule_id in rules_checked:
                rule = configured_rules[rule_id]
                findings.extend(detect_rule(
                    args.elf,
                    rule.path,
                    mitigation_detector=rule.mitigation_detector,
                ))
        else:
            rules_checked = [args.rule]
            rule = configured_rules[args.rule]
            findings = detect_rule(
                args.elf,
                rule.path,
                mitigation_detector=rule.mitigation_detector,
            )
    except (ScanError, OSError, ValueError, KeyError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        print_json_report(findings, args.elf)
    else:
        print_text_report(findings, args.elf, plain=args.plain)

    if args.json or args.html:
        result = build_result(findings, args.elf, rules_checked)
        if args.json:
            write_json(result, args.json)
            print(f"JSON report: {args.json}")
        if args.html:
            write_html(result, args.html)
            print(f"HTML report: {args.html}")
    return 1 if any(f["status"] == "VULNERABLE" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())